use sentrycheck_core::model::WorkloadProfile;
use sentrycheck_core::util::read_bounded;
use sentrycheck_core::Result;
use serde_json::{Map, Value};
use std::path::Path;

/// Deliberately constrained TOML: top-level scalar keys and one-line JSON-compatible
/// arrays/strings. Rejecting unsupported syntax is safer than silently ignoring it.
pub fn parse(text: &str) -> Result<WorkloadProfile> {
    let mut value = if text.trim_start().starts_with('{') {
        serde_json::from_str::<Value>(text).map_err(|e| format!("profile JSON: {e}"))?
    } else {
        let mut object = Map::new();
        for (index, line) in text.lines().enumerate() {
            let line = strip_comment(line).trim();
            if line.is_empty() {
                continue;
            }
            let (key, raw) = line
                .split_once('=')
                .ok_or_else(|| format!("profile line {}: expected key = value", index + 1))?;
            let key = key.trim();
            if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("profile line {}: invalid key", index + 1));
            }
            let raw = raw.trim();
            let parsed = if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
                Value::String(raw[1..raw.len() - 1].to_string())
            } else {
                serde_json::from_str(raw).map_err(|e| {
                    format!(
                        "profile line {}: {e}; strings/arrays use JSON-compatible quoting",
                        index + 1
                    )
                })?
            };
            if object.insert(key.into(), parsed).is_some() {
                return Err(format!("duplicate profile key: {key}"));
            }
        }
        Value::Object(object)
    };
    let object = value.as_object_mut().ok_or("profile must be an object")?;
    let known = [
        "name",
        "description",
        "command",
        "env",
        "timeout_seconds",
        "repetitions",
        "expected_exit_code",
        "compare_stdout",
        "compare_stderr",
        "timing_ratio",
        "timing_min_native_ms",
        "coverage",
    ];
    for key in object.keys() {
        if !known.contains(&key.as_str()) {
            return Err(format!("unknown profile key: {key}"));
        }
    }
    let profile: WorkloadProfile =
        serde_json::from_value(value).map_err(|e| format!("profile schema: {e}"))?;
    validate(&profile)?;
    Ok(profile)
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    let mut escape = false;
    for (i, c) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote == Some('"') && c == '\\' {
            escape = true;
            continue;
        }
        if quote == Some(c) {
            quote = None;
        } else if quote.is_none() && (c == '"' || c == '\'') {
            quote = Some(c);
        } else if quote.is_none() && c == '#' {
            return &line[..i];
        }
    }
    line
}

pub fn validate(profile: &WorkloadProfile) -> Result<()> {
    if profile.name.is_empty() || profile.name.len() > 200 {
        return Err("profile name must contain 1..200 characters".into());
    }
    if !(1..=3600).contains(&profile.timeout_seconds) {
        return Err("timeout_seconds must be 1..3600".into());
    }
    if !(1..=20).contains(&profile.repetitions) {
        return Err("repetitions must be 1..20".into());
    }
    if !(0..=255).contains(&profile.expected_exit_code) {
        return Err("expected_exit_code must be a Linux process exit status from 0 to 255".into());
    }
    if profile.command.first().is_some_and(String::is_empty) {
        return Err("the profile executable cannot be empty".into());
    }
    if profile.command.len() > 256
        || profile
            .command
            .iter()
            .any(|s| s.contains('\0') || s.len() > 65536)
    {
        return Err("profile command is too large or contains NUL".into());
    }
    if profile.env.len() > 256
        || profile
            .env
            .iter()
            .any(|s| !s.contains('=') || s.starts_with('=') || s.contains('\0'))
    {
        return Err("environment entries must be KEY=value".into());
    }
    if !profile.timing_ratio.is_finite() || profile.timing_ratio <= 1.0 {
        return Err("timing_ratio must be finite and greater than one".into());
    }
    if !matches!(profile.coverage.as_str(), "smoke" | "representative") {
        return Err("coverage must be smoke or representative".into());
    }
    Ok(())
}

pub fn load(path: &Path) -> Result<WorkloadProfile> {
    let data = read_bounded(path, 1024 * 1024)?;
    parse(std::str::from_utf8(&data).map_err(|_| "profile is not UTF-8")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profiles_preserve_literal_arguments_and_reject_typos() {
        let profile = parse("name = \"hello\"\ncommand = [\"/bin/echo\", \"hello # world\"] # comment\nrepetitions = 3\ncoverage = \"representative\"").unwrap();
        assert_eq!(profile.command[1], "hello # world");
        assert!(parse("name=\"x\"\ntimeout_second=10").is_err());
        assert!(parse("name=\"x\"\nname=\"y\"").is_err());
        assert!(parse("name=\"x\"\nrepetitions=0").is_err());
        assert!(parse("name=\"x\"\nexpected_exit_code=-1").is_err());
        assert!(parse("name=\"x\"\nexpected_exit_code=256").is_err());
        assert!(parse("name=\"x\"\ncommand=[\"\"]").is_err());
        assert!(parse("name=\"x\"\nexpected_exit_code=255").is_ok());
    }
}
