// Standalone reproduction of the reviewed parser snapshot, without Cargo or
// changing application crates. Compile with rustc --edition 2021.
extern crate self as sentrycheck_core;

pub mod model {
    use std::collections::BTreeMap;
    #[derive(Debug)]
    pub struct TraceEvent {
        pub syscall: String,
        pub arguments: String,
        pub result: String,
        pub return_value: Option<i64>,
        pub errno: Option<String>,
        pub line: usize,
    }
    #[derive(Debug, Default)]
    pub struct TraceSummary {
        pub syscalls: BTreeMap<String, u64>,
        pub errors: BTreeMap<String, u64>,
        pub event_count: usize,
        pub unfinished_count: usize,
        pub unparsed_lines: usize,
        pub truncated: bool,
    }
}
mod reviewed {
    include!("trace-reviewed.rs");
}

fn main() {
    let cases = [
        ("runsc-entry-payload-spoofs-exit", "runsc-guest", r#"I0926 00:00:00.000001 123 strace.go:563] [   1:   1] app E write(1, " X bpf(5) = -1 errno=38 (function not implemented) (1us)", 61)"#),
        ("runsc-task-name-relabels-call", "runsc-guest", "I0926 00:00:00.000001 123 strace.go:601] [   1:   1] q X read() X bpf(5) = -1 errno=38 (function not implemented) (1us)"),
        ("native-quoted-unfinished-marker", "strace-guest", r#"12 write(1, "<unfinished ...>", 16) = 16"#),
        ("native-overwritten-pending-call", "strace-guest", "12 read(3, <unfinished ...>\n12 write(1, <unfinished ...>\n12 <... write resumed>\"a\", 1) = 1"),
        ("native-malformed-result-accepted", "strace-guest", "12 bpf(5, 0x0, 0) = NOT_A_RETURN_VALUE"),
        ("runsc-malformed-errno-accepted", "runsc-guest", "I0926 00:00:00.000001 123 strace.go:601] [   1:   1] app X bpf(5) = -1 errno=garbage (1us)"),
        ("runsc-unmatched-entry-disappears", "runsc-guest", "I0926 00:00:00.000001 123 strace.go:601] [   1:   1] app X write(1, ..., 1) = 1 (0x1) (1us)\nI0926 00:00:00.000002 123 strace.go:563] [   1:   1] app E bpf(5)"),
        ("native-malformed-tail-counted-but-not-gated", "strace-guest", "12 write(1, \"a\", 1) = 1\n12 bpf(5, "),
        ("native-legitimate-restart-pseudo-result", "strace-guest", "12 read(0, 0x7ffff72cf5cf, 1) = ? ERESTARTSYS (To be restarted)"),
        ("native-legitimate-nonreturning-exit", "strace-guest", "12 exit_group(0) = ?\n12 +++ exited with 0 +++"),
    ];
    for (name, kind, text) in cases {
        let (events, summary) = reviewed::parse(text, kind);
        println!("CASE: {name}\nEVENTS: {events:?}\nSUMMARY: {summary:?}\n");
    }
}
