use sentrycheck_core::model::{TraceEvent, TraceSummary};
use std::collections::BTreeMap;

pub const MAX_EVENTS: usize = 100_000;

fn errno_name(number: i64) -> String {
    match number {
        1 => "EPERM",
        2 => "ENOENT",
        3 => "ESRCH",
        4 => "EINTR",
        5 => "EIO",
        6 => "ENXIO",
        7 => "E2BIG",
        8 => "ENOEXEC",
        9 => "EBADF",
        10 => "ECHILD",
        11 => "EAGAIN",
        12 => "ENOMEM",
        13 => "EACCES",
        14 => "EFAULT",
        16 => "EBUSY",
        17 => "EEXIST",
        18 => "EXDEV",
        19 => "ENODEV",
        20 => "ENOTDIR",
        21 => "EISDIR",
        22 => "EINVAL",
        23 => "ENFILE",
        24 => "EMFILE",
        25 => "ENOTTY",
        28 => "ENOSPC",
        30 => "EROFS",
        32 => "EPIPE",
        34 => "ERANGE",
        35 => "EDEADLK",
        36 => "ENAMETOOLONG",
        38 => "ENOSYS",
        39 => "ENOTEMPTY",
        40 => "ELOOP",
        75 => "EOVERFLOW",
        95 => "EOPNOTSUPP",
        98 => "EADDRINUSE",
        101 => "ENETUNREACH",
        104 => "ECONNRESET",
        110 => "ETIMEDOUT",
        111 => "ECONNREFUSED",
        125 => "ECANCELED",
        _ => return format!("ERRNO_{number}"),
    }
    .into()
}

fn native_prefix(line: &str) -> (String, &str) {
    let mut rest = line.trim_start();
    let mut thread = "main".to_string();
    if rest.starts_with("[pid ") {
        if let Some(end) = rest.find(']') {
            let pid_str = rest[5..end].trim();
            if pid_str.len() <= 7 && pid_str.parse::<u32>().is_ok_and(|p| p <= 4_194_304) {
                thread = pid_str.into();
                rest = rest[end + 1..].trim_start();
            }
        }
    } else if let Some((prefix, after)) = rest.split_once(char::is_whitespace) {
        if prefix.bytes().all(|b| b.is_ascii_digit())
            && prefix.len() <= 7
            && prefix.parse::<u32>().is_ok_and(|p| p <= 4_194_304)
        {
            thread = prefix.into();
            rest = after.trim_start();
        }
    }
    if let Some((prefix, after)) = rest.split_once(char::is_whitespace) {
        if prefix.contains(':')
            && prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b':' || b == b'.')
        {
            rest = after.trim_start();
        }
    }
    (thread, rest)
}

fn syscall_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && (name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
}

// Locate the closing outer parenthesis, ignoring quoted/escaped argument text.
// Searching for the last " = " lets text inside write() masquerade as a result.
fn call(body: &str) -> Option<(&str, usize, usize)> {
    let open = body.find('(')?;
    let syscall = body[..open].trim();
    if !syscall_name(syscall) {
        return None;
    }
    let mut depth = 0;
    let mut quote = None;
    let mut escaped = false;
    for (offset, ch) in body[open..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote.is_some() && ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(current) = quote {
            if ch == current {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((syscall, open, open + offset));
                }
            }
            _ => {}
        }
    }
    None
}

fn groups(mut text: &str) -> Option<Vec<&str>> {
    let mut output = Vec::new();
    while !text.trim().is_empty() {
        text = text.trim_start();
        if !text.starts_with('(') {
            return None;
        }
        let mut depth = 0;
        let mut close = None;
        for (i, c) in text.char_indices() {
            if c == '(' {
                depth += 1;
            }
            if c == ')' {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
        }
        let end = close?;
        output.push(&text[1..end]);
        if output.len() > 2 {
            return None;
        }
        text = &text[end + 1..];
    }
    Some(output)
}

fn event(body: &str, line: usize, runsc: bool) -> Option<TraceEvent> {
    let (syscall, open, close) = call(body)?;
    let result = body[close + 1..].trim_start().strip_prefix('=')?.trim();
    let first = result.split_whitespace().next()?;
    let numeric = if let Some(hex) = first.strip_prefix("0x") {
        !hex.is_empty()
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
            && u64::from_str_radix(hex, 16).is_ok()
    } else {
        first.parse::<i64>().is_ok() || first.parse::<u64>().is_ok()
    };
    if !numeric && (first != "?" || runsc) {
        return None;
    }
    let return_value = if let Some(hex) = first.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|n| i64::try_from(n).ok())
    } else {
        first.parse::<i64>().ok()
    };
    let errno = if runsc {
        let tail = result[first.len()..].trim_start();
        let (errno, tail) = if first == "-1" {
            let value = tail.strip_prefix("errno=")?;
            let word = value.split_whitespace().next()?;
            let number = word.parse::<i64>().ok().filter(|n| *n > 0)?;
            (Some(errno_name(number)), value[word.len()..].trim_start())
        } else {
            (None, tail)
        };
        let parts = groups(tail)?;
        if parts.len() != 2
            || parts[1].is_empty()
            || !parts[1]
                .chars()
                .all(|c| c.is_ascii_digit() || ".nsumhµ-".contains(c))
        {
            return None;
        }
        if errno.is_none() {
            let hex = parts[0].strip_prefix("0x")?;
            if hex.is_empty() || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
        }
        errno
    } else if first == "-1" {
        result
            .split_whitespace()
            .nth(1)
            .filter(|word| {
                word.starts_with('E')
                    && word
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            })
            .map(String::from)
            .or_else(|| Some(String::new()))
    } else {
        None
    };
    if errno.as_deref() == Some("") {
        return None;
    }
    Some(TraceEvent {
        syscall: syscall.into(),
        arguments: body[open + 1..close].chars().take(4096).collect(),
        result: result.chars().take(1024).collect(),
        return_value,
        errno,
        line,
    })
}

enum GuestRecord<'a> {
    Diagnostic,
    Malformed,
    Call {
        thread: Option<String>,
        kind: char,
        body: &'a str,
    },
}

fn guest_record(raw: &str, line: usize) -> GuestRecord<'_> {
    let Some((header, mut payload)) = raw.split_once("] ") else {
        return if raw.contains("strace.go:") {
            GuestRecord::Malformed
        } else {
            GuestRecord::Diagnostic
        };
    };
    let source = header.split_whitespace().last().unwrap_or("");
    let Some(number) = source.strip_prefix("strace.go:") else {
        return GuestRecord::Diagnostic;
    };
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return GuestRecord::Malformed;
    }
    let mut thread = None;
    if payload.starts_with('[') {
        let Some(end) = payload.find(']') else {
            return GuestRecord::Malformed;
        };
        let id = &payload[1..end];
        if !id.contains(':')
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b':' || b == b' ')
        {
            return GuestRecord::Malformed;
        }
        thread = Some(id.split_whitespace().collect());
        payload = payload[end + 1..].trim_start();
    }
    let mut candidates = Vec::new();
    for kind in ['E', 'X'] {
        let marker = format!(" {kind} ");
        for (at, _) in payload.match_indices(&marker) {
            // Linux task comm is limited to 15 bytes; allow 16 conservatively.
            // Longer/ambiguous names are incomplete evidence, never guessed.
            if at > 16 {
                break;
            }
            let body = &payload[at + 3..];
            let valid = if kind == 'E' {
                call(body).is_some_and(|(_, _, end)| body[end + 1..].trim().is_empty())
            } else {
                event(body, line, true).is_some()
            };
            if valid {
                candidates.push((kind, body));
            }
        }
    }
    if let [(kind, body)] = candidates.as_slice() {
        GuestRecord::Call {
            thread,
            kind: *kind,
            body,
        }
    } else {
        GuestRecord::Malformed
    }
}

/// Parse guest strace output, or gVisor's `Task.Name() X syscall(...)` exit records.
/// Host strace of the runsc launcher is intentionally not a supported source.
pub fn parse(text: &str, kind: &str) -> (Vec<TraceEvent>, TraceSummary) {
    let runsc = kind == "runsc-guest";
    let mut summary = TraceSummary::default();
    let mut events = Vec::new();
    let mut pending: BTreeMap<String, String> = BTreeMap::new();
    let mut guest_pending: BTreeMap<String, String> = BTreeMap::new();
    for (line_number, raw) in text.lines().enumerate() {
        if events.len() >= MAX_EVENTS {
            summary.truncated = true;
            break;
        }
        if raw.len() > 65536 {
            summary.unparsed_lines += 1;
            summary.discarded_guest_records += 1;
            summary.truncated = true;
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        let body = if runsc {
            match guest_record(raw, line_number + 1) {
                GuestRecord::Diagnostic => {
                    summary.diagnostic_lines += 1;
                    continue;
                }
                GuestRecord::Malformed => {
                    summary.unparsed_lines += 1;
                    summary.discarded_guest_records += 1;
                    continue;
                }
                GuestRecord::Call { thread, kind, body } => {
                    let name = call(body).map(|(name, _, _)| name).unwrap_or("");
                    if let Some(thread) = thread {
                        if kind == 'E' {
                            if guest_pending.insert(thread, name.to_string()).is_some() {
                                summary.discarded_guest_records += 1;
                            }
                        } else if let Some(prior) = guest_pending.remove(&thread) {
                            if prior != name {
                                summary.discarded_guest_records += 1;
                            }
                        }
                    }
                    if kind == 'E' {
                        continue;
                    }
                    body.to_string()
                }
            }
        } else {
            let (thread, body) = native_prefix(raw);
            if body.starts_with("<... ") {
                if let Some(resumed) = body.find(" resumed>") {
                    let name = &body[5..resumed];
                    if let Some(prefix) = pending.remove(&thread) {
                        if prefix.starts_with(&format!("{name}(")) {
                            format!("{}{}", prefix, &body[resumed + 9..])
                        } else {
                            summary.unparsed_lines += 1;
                            summary.discarded_guest_records += 1;
                            continue;
                        }
                    } else {
                        summary.unparsed_lines += 1;
                        summary.discarded_guest_records += 1;
                        continue;
                    }
                } else {
                    summary.unparsed_lines += 1;
                    summary.discarded_guest_records += 1;
                    continue;
                }
            } else if let Some(prefix) = body.strip_suffix("<unfinished ...>") {
                if !prefix
                    .find('(')
                    .is_some_and(|open| syscall_name(prefix[..open].trim()))
                {
                    summary.discarded_guest_records += 1;
                    summary.unparsed_lines += 1;
                    continue;
                }
                if pending.insert(thread, prefix.into()).is_some() {
                    summary.discarded_guest_records += 1;
                }
                continue;
            } else if body.starts_with("+++")
                || body.starts_with("---")
                || body.starts_with("strace: Process ")
                    && (body.ends_with(" attached") || body.ends_with(" detached"))
            {
                summary.diagnostic_lines += 1;
                continue;
            } else {
                body.to_string()
            }
        };
        if let Some(event) = event(&body, line_number + 1, runsc) {
            *summary.syscalls.entry(event.syscall.clone()).or_default() += 1;
            if let Some(errno) = &event.errno {
                *summary
                    .errors
                    .entry(format!("{}:{errno}", event.syscall))
                    .or_default() += 1;
            }
            events.push(event);
        } else {
            summary.unparsed_lines += 1;
            summary.discarded_guest_records += 1;
        }
    }
    summary.event_count = events.len();
    summary.unfinished_count = pending.len() + guest_pending.len();
    (events, summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_nested_arguments_and_errno() {
        let (events, summary) = parse("12 io_uring_setup(8, {flags=0}) = -1 ENOSYS (Function not implemented)\n12 write(1, \"x) = y\", 6) = 6\n+++ exited with 0 +++\n", "strace-guest");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].errno.as_deref(), Some("ENOSYS"));
        assert_eq!(events[1].return_value, Some(6));
        assert_eq!(summary.unparsed_lines, 0);
    }
    #[test]
    fn pairs_interleaved_unfinished_calls_by_pid() {
        let (events, summary) = parse("[pid 12] read(3, <unfinished ...>\n[pid 13] write(1, \"x\", 1) = 1\n[pid 12] <... read resumed>\"a\", 1) = 1", "strace-guest");
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].syscall, "read");
        assert_eq!(summary.unfinished_count, 0);
    }
    #[test]
    fn runsc_uses_guest_exit_records_and_numeric_errno() {
        let (events, _) = parse("I0921 00:00:00 strace.go:550] [1:1] app E io_uring_setup(8, 0x0)\nI0921 00:00:00 strace.go:604] [1:1] app X io_uring_setup(8, 0x0) = -1 errno=38 (function not implemented) (1us)\nI0921 00:00:00 strace.go:604] [1:1] app X write(1, \"ok\", 2) = 2 (0x2) (1us)", "runsc-guest");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].errno.as_deref(), Some("ENOSYS"));
        assert_eq!(events[1].return_value, Some(2));
    }

    #[test]
    fn parses_aligned_returns_and_thread_teardown() {
        let (events, summary) = parse("9 close(3)                          = 0\n10 nanosleep({tv_sec=0, tv_nsec=20000},  <unfinished ...>\n9 exit_group(0)                     = ?\n10 <... nanosleep resumed> <unfinished ...>) = ?\n", "strace-guest");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].return_value, Some(0));
        assert_eq!(events[2].syscall, "nanosleep");
        assert_eq!(events[2].return_value, None);
        assert_eq!(summary.unfinished_count, 0);
        assert_eq!(summary.unparsed_lines, 0);
    }

    #[test]
    fn payload_markers_and_task_names_cannot_invent_syscalls() {
        let trace = "I0926 00:00:00 1 strace.go:563] [1:1] app E write(1, \" X bpf(5) = -1 errno=38 (function not implemented) (1us)\", 61)\nI0926 00:00:00 1 strace.go:601] [1:1] app X write(1, \" X bpf(5) = -1 errno=38 (function not implemented) (1us)\", 61) = 61 (0x3d) (1us)\nI0926 00:00:00 1 strace.go:601] [1:1] q X read() X bpf(5) = -1 errno=38 (function not implemented) (1us)\nI0926 00:00:00 1 cli.go:100] arguments contain X fake(1) = 1 (0x1) (1us)\n";
        let (events, summary) = parse(trace, "runsc-guest");
        assert_eq!(
            events
                .iter()
                .map(|e| e.syscall.as_str())
                .collect::<Vec<_>>(),
            ["write", "bpf"]
        );
        assert_eq!(summary.discarded_guest_records, 0);
        assert_eq!(summary.diagnostic_lines, 1);
        assert_eq!(summary.unfinished_count, 0);
    }

    #[test]
    fn malformed_records_are_distinct_from_debug_output() {
        let trace="I0926 00:00:00 1 cli.go:100] harmless debug text\nI0926 00:00:00 1 strace.go:601] [1:1] app X bpf(5) = nonsense\nI0926 00:00:00 1 strace.go:601] [1:1] app X bpf(5) = -1 errno=bogus (error) (1us)\nI0926 00:00:00 1 strace.go:601] [1:1] app X read(1, [], 1) = 0 (0x0) (1us)\n";
        let (events, summary) = parse(trace, "runsc-guest");
        assert_eq!(events.len(), 1);
        assert_eq!(summary.discarded_guest_records, 2);
        assert_eq!(summary.diagnostic_lines, 1);
        assert_eq!(summary.unparsed_lines, 2);
    }

    #[test]
    fn quoted_unfinished_markers_and_restart_results_are_preserved() {
        let (events,summary)=parse("1 write(1, \"<unfinished ...>\", 16) = 16\n1 read(3, 0x1000, 1) = ? ERESTARTSYS (To be restarted)\n1 exit_group(0) = ?\n", "strace-guest");
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].return_value, None);
        assert_eq!(summary.unfinished_count, 0);
        assert_eq!(summary.discarded_guest_records, 0);
    }

    #[test]
    fn lost_unfinished_records_and_missing_guest_exits_are_visible() {
        let (_, summary) = parse(
            "1 read(3, <unfinished ...>\n1 write(1, <unfinished ...>\n",
            "strace-guest",
        );
        assert_eq!(summary.discarded_guest_records, 1);
        assert_eq!(summary.unfinished_count, 1);
        let (_, summary) = parse(
            "I0926 00:00:00 1 strace.go:563] [1:1] app E read(3, 0x0, 1)\n",
            "runsc-guest",
        );
        assert_eq!(summary.unfinished_count, 1);
        let (_, summary) = parse(
            "1 read(3, [], 0) = bad\nstrace: ptrace failed: Operation not permitted\n",
            "strace-guest",
        );
        assert_eq!(summary.discarded_guest_records, 2);
    }
}
