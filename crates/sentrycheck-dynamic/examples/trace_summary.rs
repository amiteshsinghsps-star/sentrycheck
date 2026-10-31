//! Reparse retained traces without rerunning or reattesting a workload.
use std::io::Read;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !matches!(args[0].as_str(), "strace-guest" | "runsc-guest") {
        return Err("usage: trace_summary <strace-guest|runsc-guest> <trace-path>".into());
    }
    const LIMIT: u64 = 32 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(&args[1])?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err("trace exceeds the 32 MiB capture budget".into());
    }
    let (_, summary) = sentrycheck_dynamic::trace::parse(std::str::from_utf8(&bytes)?, &args[0]);
    println!("{}", serde_json::to_string(&summary)?);
    Ok(())
}
