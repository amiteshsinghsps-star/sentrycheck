use crate::args::Args;
use sentrycheck_core::Result;
use sentrycheck_kb::diff::{compare, Snapshot};
use std::path::Path;

pub fn run(args: Args) -> Result<i32> {
    args.only(&["format"], &[])?;
    let format = args.format()?;
    if args.positionals.len() != 3 || args.positionals[0] != "diff" {
        return Err("expected: sentrycheck kb diff OLD.json NEW.json [--format human|json]".into());
    }
    let before = Snapshot::load(Path::new(&args.positionals[1]))
        .map_err(|error| format!("old snapshot: {error}"))?;
    let after = Snapshot::load(Path::new(&args.positionals[2]))
        .map_err(|error| format!("new snapshot: {error}"))?;
    let diff = compare(&before, &after)?;
    if format == "json" {
        println!(
            "{}",
            serde_json::to_string_pretty(&diff).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "Knowledge base: {} -> {}",
            diff.before.snapshot_version, diff.after.snapshot_version
        );
        println!(
            "Source commits: {} -> {}",
            diff.before.source_commit, diff.after.source_commit
        );
        let s = &diff.summary;
        println!(
            "Support rows: {} added, {} removed, {} changed, {} unchanged",
            s.rows_added, s.rows_removed, s.rows_changed, s.rows_unchanged
        );
        println!(
            "Changed labels: {}; documentation: {}; syscall numbers: {}; source locations: {}",
            s.support_status_changes, s.detail_changes, s.number_changes, s.source_location_changes
        );
        println!(
            "Gap definitions: {} added, {} removed, {} changed; {} have changed provenance",
            s.gaps_added, s.gaps_removed, s.gap_definition_changes, s.gap_provenance_changes
        );
        for row in &diff.support_changes {
            let old = row
                .before
                .as_ref()
                .map(|e| e.row.status.as_str())
                .unwrap_or("absent (unknown)");
            let new = row
                .after
                .as_ref()
                .map(|e| e.row.status.as_str())
                .unwrap_or("absent (unknown)");
            println!(
                "  {:5} {:28} {:7} {old} -> {new}{}{}{}",
                row.architecture,
                row.syscall,
                row.change,
                if row.detail_changed {
                    " [documentation]"
                } else {
                    ""
                },
                if row.number_changed { " [number]" } else { "" },
                if row.source_location_changed {
                    " [source location]"
                } else {
                    ""
                }
            );
        }
        for note in &diff.interpretation {
            println!("Note: {note}");
        }
    }
    // Differences are an informational result, never a failed workload verdict.
    Ok(0)
}
