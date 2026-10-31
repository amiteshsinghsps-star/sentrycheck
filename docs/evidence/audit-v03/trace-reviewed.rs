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
            thread = rest[5..end].trim().into();
            rest = rest[end + 1..].trim_start();
        }
    } else if let Some((prefix, after)) = rest.split_once(char::is_whitespace) {
        if prefix.bytes().all(|b| b.is_ascii_digit()) {
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

fn event(body: &str, line: usize, runsc: bool) -> Option<TraceEvent> {
    let open = body.find('(')?;
    let syscall = body[..open].trim();
    if syscall.is_empty()
        || !syscall
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || !syscall.as_bytes()[0].is_ascii_alphabetic() && !syscall.starts_with('_')
    {
        return None;
    }
    let separator = body.rfind(" = ")?;
    let arguments_end = body[..separator].trim_end();
    if !arguments_end.ends_with(')') {
        return None;
    }
    let close = arguments_end.len() - 1;
    if close < open {
        return None;
    }
    let result = body[separator + 3..].trim();
    let first = result.split_whitespace().next()?;
    let return_value = if let Some(hex) = first.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|n| i64::try_from(n).ok())
    } else {
        first.parse::<i64>().ok()
    };
    let errno = if runsc {
        result
            .split("errno=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .map(errno_name)
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
    } else {
        None
    };
    Some(TraceEvent {
        syscall: syscall.into(),
        arguments: body[open + 1..close].chars().take(4096).collect(),
        result: result.chars().take(1024).collect(),
        return_value,
        errno,
        line,
    })
}

/// Parse guest strace output, or gVisor's `Task.Name() X syscall(...)` exit records.
/// Host strace of the runsc launcher is intentionally not a supported source.
pub fn parse(text: &str, kind: &str) -> (Vec<TraceEvent>, TraceSummary) {
    let runsc = kind == "runsc-guest";
    let mut summary = TraceSummary::default();
    let mut events = Vec::new();
    let mut pending: BTreeMap<String, String> = BTreeMap::new();
    for (line_number, raw) in text.lines().enumerate() {
        if events.len() >= MAX_EVENTS {
            summary.truncated = true;
            break;
        }
        if raw.len() > 65536 {
            summary.unparsed_lines += 1;
            summary.truncated = true;
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        let body = if runsc {
            if let Some((_, rest)) = raw.split_once(" X ") {
                rest.to_string()
            } else {
                if !raw.contains(" E ") {
                    summary.unparsed_lines += 1;
                }
                continue;
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
                            continue;
                        }
                    } else {
                        summary.unparsed_lines += 1;
                        continue;
                    }
                } else {
                    summary.unparsed_lines += 1;
                    continue;
                }
            } else if let Some(start) = body.find("<unfinished ...>") {
                pending.insert(thread, body[..start].into());
                continue;
            } else if body.starts_with("+++")
                || body.starts_with("---")
                || body.starts_with("strace:")
            {
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
        }
    }
    summary.event_count = events.len();
    summary.unfinished_count = pending.len();
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
}
