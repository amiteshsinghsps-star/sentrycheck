//! Embed validated evidence in a prebuilt, self-contained Astro viewer.
//! Node/Astro is a contributor build tool, never an end-user runtime dependency.
use crate::{args::Args, report};
use sentrycheck_core::model::{Report, TargetRuntime, MAX_REPORT_BYTES};
use sentrycheck_core::util::{
    atomic_write, now_seconds, read_bounded, sha256, timestamp, validate_digest,
};
use sentrycheck_core::Result;
use sentrycheck_kb::KnowledgeBase;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const TEMPLATE: &str = include_str!("../../../frontend/template.html");
const SLOT: &str = "\"__SENTRYCHECK_DATA__\"";

// JSON escaping alone does not stop the HTML parser from recognizing </script>.
fn script_json(value: &Value) -> Result<String> {
    let serialized = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let mut safe = String::with_capacity(serialized.len());
    for c in serialized.chars() {
        match c {
            '<' => safe.push_str("\\u003c"),
            '>' => safe.push_str("\\u003e"),
            '&' => safe.push_str("\\u0026"),
            '\u{2028}' => safe.push_str("\\u2028"),
            '\u{2029}' => safe.push_str("\\u2029"),
            _ => safe.push(c),
        }
    }
    Ok(safe)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("SARIF lacks a valid {key}"))
}

/// SARIF omits trace events and static sites. Check the export contract without
/// pretending that its experiment can undergo the full report consistency check.
fn sarif_target(value: &Value) -> Result<(TargetRuntime, String)> {
    if value["version"] != "2.1.0" {
        return Err("render supports report schema 1.0 or SENTRYCHECK SARIF 2.1.0".into());
    }
    let runs = value["runs"]
        .as_array()
        .ok_or("SARIF runs must be an array")?;
    if runs.len() != 1 || runs[0]["tool"]["driver"]["name"] != "SENTRYCHECK" {
        return Err("render requires exactly one SENTRYCHECK SARIF run".into());
    }
    let run = &runs[0];
    let properties = &run["properties"];
    let status = text(properties, "scanStatus")?;
    if !matches!(status, "complete" | "incomplete") || properties["schemaVersion"] != "1.0" {
        return Err("unsupported SARIF scan status or schema".into());
    }
    text(properties, "image")?;
    let assessment = text(properties, "assessment")?;
    for key in ["imageDigest", "profileSha256"] {
        if !properties[key].is_null() {
            validate_digest(text(properties, key)?)?;
        }
    }
    if !properties["provenance"].is_null()
        && !matches!(
            properties["provenance"].as_str(),
            Some("locally-executed" | "imported-user-supplied")
        )
    {
        return Err("invalid SARIF execution provenance".into());
    }
    if status == "complete"
        && (properties["provenance"] != "locally-executed"
            || properties["imageDigest"].is_null()
            || properties["profileSha256"].is_null())
    {
        return Err("complete SARIF lacks local execution identity".into());
    }
    let invocations = run["invocations"]
        .as_array()
        .ok_or("SARIF lacks invocations")?;
    if invocations.len() != 1
        || invocations[0]["executionSuccessful"].as_bool() != Some(status == "complete")
    {
        return Err("SARIF invocation contradicts scan status".into());
    }
    let target: TargetRuntime = serde_json::from_value(properties["targetRuntime"].clone())
        .map_err(|e| format!("invalid SARIF target: {e}"))?;
    if !matches!(target.name.as_str(), "gvisor" | "kata")
        || !matches!(target.architecture.as_str(), "amd64" | "arm64" | "386")
        || target.version.is_empty()
    {
        return Err("invalid SARIF target runtime".into());
    }
    let rules = run["tool"]["driver"]["rules"]
        .as_array()
        .ok_or("SARIF lacks rules")?;
    let mut ids = BTreeSet::new();
    for rule in rules {
        if !ids.insert(text(rule, "id")?) || !text(rule, "helpUri")?.starts_with("https://") {
            return Err("SARIF has duplicate rules or lacks HTTPS citations".into());
        }
    }
    let mut incompatible = false;
    let mut performance = false;
    let mut common_tier = None;
    for result in run["results"].as_array().ok_or("SARIF lacks results")? {
        if !ids.contains(text(result, "ruleId")?) {
            return Err("SARIF result references an unknown rule".into());
        }
        if let Some(index) = result.get("ruleIndex") {
            let rule = index
                .as_u64()
                .and_then(|i| usize::try_from(i).ok())
                .and_then(|i| rules.get(i));
            if !rule.is_some_and(|r| r["id"] == result["ruleId"]) {
                return Err("SARIF rule index contradicts its rule ID".into());
            }
        }
        text(&result["message"], "text")?;
        let p = &result["properties"];
        let (class, level) = match text(p, "severity")? {
            "hard-failure" => ("F1", "error"),
            "silent-degradation" => ("F2", "warning"),
            "performance-regression" => ("F3", "warning"),
            "compatibility-risk" => ("unconfirmed", "note"),
            _ => return Err("unknown SARIF severity".into()),
        };
        if p["failureClass"] != class || result["level"] != level {
            return Err("SARIF finding severity contradicts its classification".into());
        }
        incompatible |= matches!(class, "F1" | "F2");
        performance |= class == "F3";
        let tier = text(p, "evidenceTier")?;
        if !matches!(
            tier,
            "dynamic-native-only" | "dynamic-runsc-diff" | "dynamic-kata-diff"
        ) || tier == "dynamic-runsc-diff" && target.name != "gvisor"
            || tier == "dynamic-kata-diff" && target.name != "kata"
            || class != "unconfirmed" && tier == "dynamic-native-only"
        {
            return Err("SARIF result overstates its evidence tier".into());
        }
        if common_tier.is_some_and(|prior| prior != tier)
            || properties
                .get("evidenceTier")
                .is_some_and(|declared| declared != tier)
        {
            return Err("SARIF evidence tiers contradict one another".into());
        }
        common_tier = Some(tier);
    }
    if let Some(tier) = properties.get("evidenceTier") {
        if !matches!(
            tier.as_str(),
            Some(
                "static-only" | "dynamic-native-only" | "dynamic-runsc-diff" | "dynamic-kata-diff"
            )
        ) || status == "complete"
            && !matches!(
                tier.as_str(),
                Some("dynamic-runsc-diff" | "dynamic-kata-diff")
            )
            || tier == "dynamic-runsc-diff" && target.name != "gvisor"
            || tier == "dynamic-kata-diff" && target.name != "kata"
        {
            return Err("SARIF run has an invalid evidence tier".into());
        }
    }
    let expected = if incompatible {
        "incompatibility-observed"
    } else if performance {
        "performance-regression-observed"
    } else if status == "complete" {
        "no-incompatibility-observed-in-profile"
    } else {
        "insufficient-evidence"
    };
    if assessment != expected {
        return Err("SARIF assessment contradicts findings/status".into());
    }
    Ok((target, text(properties, "kbSnapshot")?.to_string()))
}

fn output_path(requested: &str, inputs: &[&Path], force: bool) -> Result<PathBuf> {
    let requested = Path::new(requested);
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(requested)
    };
    // Check all existing ancestors before normalizing '..': even a symlink/..
    // spelling must not redirect output into an unrelated directory.
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err("render output cannot traverse symlinks".into())
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
            _ => {}
        }
    }
    let mut clean = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !clean.pop() {
                    return Err("invalid render output path".into());
                }
            }
            _ => clean.push(component.as_os_str()),
        }
    }
    let html = clean
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm"));
    let destination = if html && !clean.is_dir() {
        clean
    } else {
        clean.join("index.html")
    };
    if let Ok(metadata) = fs::symlink_metadata(&destination) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("render destination must be a regular HTML file".into());
        }
        let existing = fs::canonicalize(&destination).map_err(|e| e.to_string())?;
        for input in inputs {
            if fs::canonicalize(input).map_err(|e| e.to_string())? == existing {
                return Err("render cannot overwrite its report or KB input".into());
            }
        }
        if !force {
            return Err("render output already exists; use --force to replace it".into());
        }
    }
    Ok(destination)
}

pub fn run(args: Args) -> Result<i32> {
    args.only(&["output", "kb"], &["force"])?;
    let source = Path::new(args.single_positional("report or SENTRYCHECK SARIF file")?);
    let requested = args
        .value("output")
        .ok_or("render requires --output report.html or a directory")?;
    let kb_path = args.value("kb").map(Path::new);
    let mut inputs = vec![source];
    if let Some(path) = kb_path {
        inputs.push(path);
    }
    let destination = output_path(requested, &inputs, args.flag("force"))?;
    let bytes = read_bounded(source, MAX_REPORT_BYTES)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("render JSON: {e}"))?;
    let (kind, target, snapshot) = if value["report_kind"] == "runtime-comparison" {
        crate::matrix::validate(&value)?;
        let report: Report = serde_json::from_value(value["reports"][0].clone())
            .map_err(|e| format!("matrix report: {e}"))?;
        ("matrix", report.target_runtime, report.kb_snapshot_version)
    } else if value.get("schema_version").is_some() {
        let decoded: Report =
            serde_json::from_slice(&bytes).map_err(|e| format!("report JSON: {e}"))?;
        report::validate(&decoded)?;
        (
            "report",
            decoded.target_runtime,
            decoded.kb_snapshot_version,
        )
    } else {
        let (target, snapshot) = sarif_target(&value)?;
        ("sarif", target, snapshot)
    };
    let kb = if let Some(path) = kb_path {
        KnowledgeBase::load(path)?
    } else {
        KnowledgeBase::bundled()?
    };
    let matching = kb.snapshot_version == snapshot && kb.covers(&target);
    if kb_path.is_some() && !matching {
        return Err(
            "explicit KB must match the report snapshot, runtime release, and architecture".into(),
        );
    }
    let kb_note = if matching {
        "Attached KB has the same snapshot identifier and runtime target; report citations remain authoritative."
    } else {
        "No matching KB snapshot embedded. Existing report citations are retained."
    };
    let payload = json!({"report":value,"kb":if matching { Some(kb) } else { None },
        "input_kind":kind,"input_sha256":sha256(&bytes),"rendered_at":timestamp(now_seconds()),
        "generator_version":env!("CARGO_PKG_VERSION"),
        "validation":{"semantic_consistency":kind!="sarif","authenticated":false,"kb_note":kb_note}});
    if TEMPLATE.matches(SLOT).count() != 1 {
        return Err(
            "invalid embedded viewer template; rebuild frontend before packaging the CLI".into(),
        );
    }
    let html = TEMPLATE.replacen(SLOT, &script_json(&payload)?, 1);
    if args.flag("force") {
        atomic_write(&destination, html.as_bytes())?;
    } else {
        let parent = destination.parent().ok_or("invalid HTML destination")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // create_new also protects an output created concurrently after the check.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|e| format!("create HTML: {e}"))?;
        let written = file
            .write_all(html.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = written {
            let _ = fs::remove_file(&destination);
            return Err(format!("write HTML: {error}"));
        }
    }
    println!("Rendered offline report: {}\nExport succeeded; scan outcome and evidence limits remain visible. Signature not verified.", destination.display());
    Ok(0)
}
