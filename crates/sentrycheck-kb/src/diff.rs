//! Structural, release-pinned snapshot comparison. A table delta is not an
//! execution result; a removed row has unknown support, not "unimplemented".
use crate::{Gap, KnowledgeBase};
use sentrycheck_core::model::Citation;
use sentrycheck_core::util::{read_bounded, sha256, timestamp};
use sentrycheck_core::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SupportRow {
    pub architecture: String,
    pub number: u64,
    pub syscall: String,
    pub status: String,
    pub detail: String,
    pub source_line: u64,
}

#[derive(Deserialize)]
struct TypedRows {
    syscall_support: Vec<SupportRow>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotIdentity {
    pub snapshot_version: String,
    pub created_at: String,
    pub input_sha256: String,
    pub runtime_releases: BTreeMap<String, Vec<String>>,
    pub source_commit: String,
    pub source_hashes: BTreeMap<String, String>,
}

pub struct Snapshot {
    kb: KnowledgeBase,
    rows: BTreeMap<(String, String), SupportRow>,
    identity: SnapshotIdentity,
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
}

fn nonempty_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn unique<T: Ord>(values: &[T]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn date(value: &str) -> bool {
    if value.len() != 10
        || !value.is_ascii()
        || &value[4..5] != "-"
        || &value[7..8] != "-"
        || !value
            .bytes()
            .enumerate()
            .filter(|(i, _)| *i != 4 && *i != 7)
            .all(|(_, b)| b.is_ascii_digit())
    {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        value[..4].parse::<u32>(),
        value[5..7].parse::<u32>(),
        value[8..].parse::<u32>(),
    ) else {
        return false;
    };
    let days = match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    year >= 1970 && day > 0 && day <= days
}

fn utc(value: &str) -> bool {
    value.len() == 20
        && value.is_ascii()
        && date(&value[..10])
        && &value[10..11] == "T"
        && &value[13..14] == ":"
        && &value[16..17] == ":"
        && &value[19..] == "Z"
        && value[11..19]
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b':')
        && value[11..13].parse::<u32>().is_ok_and(|x| x < 24)
        && value[14..16].parse::<u32>().is_ok_and(|x| x < 60)
        && value[17..19].parse::<u32>().is_ok_and(|x| x < 60)
}

fn https(value: &str) -> bool {
    value.strip_prefix("https://").is_some_and(|rest| {
        let host = rest.split('/').next().unwrap_or("");
        !host.is_empty()
            && !host.contains('@')
            && !value.chars().any(|c| c.is_whitespace() || c.is_control())
    })
}

impl Snapshot {
    pub fn load(path: &Path) -> Result<Self> {
        Self::from_bytes(&read_bounded(path, 16 * 1024 * 1024)?)
    }

    /// The v1 support rows have no runtime/version column. They are understood
    /// only in their existing gVisor, single-release format. Future or ambiguous
    /// matrices must introduce an explicit schema, not inherit these semantics.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let kb = KnowledgeBase::from_bytes(bytes)?;
        let typed: TypedRows = serde_json::from_slice(bytes)
            .map_err(|e| format!("invalid syscall support table: {e}"))?;
        if !token(&kb.snapshot_version)
            || kb.created_at != timestamp(kb.created_at_unix)
            || !hex(&kb.source_commit, 40)
        {
            return Err(
                "KB diff requires a valid snapshot identity, UTC timestamp and source commit"
                    .into(),
            );
        }
        let versions = kb
            .runtime_releases
            .get("gvisor")
            .filter(|versions| versions.len() == 1)
            .ok_or("KB diff schema 1.0 requires one explicit gVisor release")?;
        let version = &versions[0];
        let release_valid = version.split_once('.').is_some_and(|(date, revision)| {
            date.len() == 8
                && date.bytes().all(|b| b.is_ascii_digit())
                && self::date(&format!("{}-{}-{}", &date[..4], &date[4..6], &date[6..]))
                && !revision.is_empty()
                && revision.bytes().all(|b| b.is_ascii_digit())
        });
        if !release_valid
            || kb
                .runtime_releases
                .iter()
                .any(|(runtime, releases)| runtime != "gvisor" && !releases.is_empty())
        {
            return Err(
                "ambiguous or unsupported release scope in schema 1.0 support table".into(),
            );
        }
        for file in ["linux64.go", "compatibility.md", "syscalls.go"] {
            if !kb.source_hashes.get(file).is_some_and(|hash| hex(hash, 64)) {
                return Err(format!("missing or invalid pinned source hash for {file}"));
            }
        }
        if kb
            .source_hashes
            .iter()
            .any(|(name, hash)| !token(name) || !hex(hash, 64))
        {
            return Err("invalid KB source hash metadata".into());
        }
        if typed.syscall_support.is_empty() || typed.syscall_support.len() > 20_000 {
            return Err("empty or oversized syscall support table".into());
        }
        let mut rows = BTreeMap::new();
        let mut numbers = BTreeSet::new();
        for row in typed.syscall_support {
            if !matches!(row.architecture.as_str(), "amd64" | "arm64")
                || !token(&row.syscall)
                || !matches!(row.status.as_str(), "full" | "partial" | "unimplemented")
                || !nonempty_text(&row.detail)
                || row.source_line == 0
                || row.source_line > 10_000_000
                || row.number > u32::MAX as u64
            {
                return Err("invalid syscall support row".into());
            }
            let key = (row.architecture.clone(), row.syscall.clone());
            if !numbers.insert((row.architecture.clone(), row.number))
                || rows.insert(key, row).is_some()
            {
                return Err("duplicate syscall name or number within an architecture".into());
            }
        }
        for gap in &kb.entries {
            if !token(&gap.id)
                || !nonempty_text(&gap.category)
                || !nonempty_text(&gap.description)
                || !nonempty_text(&gap.citation.title)
                || !https(&gap.citation.url)
                || !utc(&gap.citation.retrieved_at)
                || !date(&gap.first_observed)
                || !date(&gap.last_verified)
                || gap.first_observed > gap.last_verified
                || !unique(&gap.architectures)
                || !unique(&gap.runtime_versions)
                || !unique(&gap.syscalls)
                || !unique(&gap.syscall_numbers)
                || !unique(&gap.subsystems)
                || !matches!(
                    gap.severity_class.as_str(),
                    "hard-failure" | "silent-degradation" | "performance-regression"
                )
            {
                return Err(format!("invalid or duplicated gap definition: {}", gap.id));
            }
            if gap.applicability == "observational" {
                if gap.runtime != "any"
                    || gap.status != "observational"
                    || !gap.runtime_versions.is_empty()
                    || !gap.architectures.is_empty()
                {
                    return Err(format!(
                        "observational gap has misleading release scope: {}",
                        gap.id
                    ));
                }
                continue;
            }
            if gap.runtime != "gvisor"
                || gap.runtime_versions != *versions
                || gap
                    .architectures
                    .iter()
                    .any(|arch| !matches!(arch.as_str(), "amd64" | "arm64"))
                || !matches!(
                    gap.status.as_str(),
                    "full" | "partial" | "unimplemented" | "behavioral-divergence"
                )
                || gap.citation.source_revision.as_deref() != Some(kb.source_commit.as_str())
                || !gap.citation.url.starts_with(&format!(
                    "https://github.com/google/gvisor/blob/{}/",
                    kb.source_commit
                ))
            {
                return Err(format!(
                    "inconsistent pinned gap scope or citation: {}",
                    gap.id
                ));
            }
            if !gap.syscalls.is_empty() {
                if gap.syscalls.len() != gap.syscall_numbers.len() {
                    return Err(format!(
                        "gap syscall/number mapping is ambiguous: {}",
                        gap.id
                    ));
                }
                for arch in &gap.architectures {
                    for (syscall, number) in gap.syscalls.iter().zip(&gap.syscall_numbers) {
                        if !rows
                            .get(&(arch.clone(), syscall.clone()))
                            .is_some_and(|row| row.number == *number && row.status == gap.status)
                        {
                            return Err(format!(
                                "gap contradicts syscall support table: {}",
                                gap.id
                            ));
                        }
                    }
                }
            }
        }
        let identity = SnapshotIdentity {
            snapshot_version: kb.snapshot_version.clone(),
            created_at: kb.created_at.clone(),
            input_sha256: sha256(bytes),
            runtime_releases: kb.runtime_releases.clone(),
            source_commit: kb.source_commit.clone(),
            source_hashes: kb.source_hashes.clone(),
        };
        Ok(Self { kb, rows, identity })
    }

    fn citation(&self, row: &SupportRow) -> Citation {
        Citation {
            title: format!(
                "gVisor release-{} syscall table",
                self.kb.runtime_releases["gvisor"][0]
            ),
            url: format!(
                "https://github.com/google/gvisor/blob/{}/pkg/sentry/syscalls/linux/linux64.go#L{}",
                self.kb.source_commit, row.source_line
            ),
            source_revision: Some(self.kb.source_commit.clone()),
            retrieved_at: self.kb.created_at.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RowEvidence {
    pub row: SupportRow,
    pub citation: Citation,
}

#[derive(Debug, Serialize)]
pub struct SupportChange {
    pub runtime: &'static str,
    pub architecture: String,
    pub syscall: String,
    pub change: &'static str,
    pub status_changed: bool,
    pub detail_changed: bool,
    pub number_changed: bool,
    pub source_location_changed: bool,
    pub before: Option<RowEvidence>,
    pub after: Option<RowEvidence>,
}

#[derive(Debug, Serialize)]
pub struct GapChange {
    pub id: String,
    pub change: &'static str,
    pub definition_fields_changed: Vec<String>,
    pub provenance_fields_changed: Vec<String>,
    pub before: Option<Gap>,
    pub after: Option<Gap>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub rows_added: usize,
    pub rows_removed: usize,
    pub rows_changed: usize,
    pub rows_unchanged: usize,
    pub support_status_changes: usize,
    pub detail_changes: usize,
    pub number_changes: usize,
    pub source_location_changes: usize,
    pub gaps_added: usize,
    pub gaps_removed: usize,
    pub gap_definition_changes: usize,
    pub gap_provenance_changes: usize,
}

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub schema_version: &'static str,
    pub kind: &'static str,
    pub before: SnapshotIdentity,
    pub after: SnapshotIdentity,
    pub authenticated: bool,
    pub source_hashes_verified: bool,
    pub interpretation: Vec<&'static str>,
    pub summary: Summary,
    pub snapshot_fields_changed: Vec<String>,
    pub support_changes: Vec<SupportChange>,
    pub gap_changes: Vec<GapChange>,
}

fn changed_fields(a: &Value, b: &Value, fields: &[&str]) -> Vec<String> {
    fields
        .iter()
        .filter(|field| a[**field] != b[**field])
        .map(|field| (*field).to_string())
        .collect()
}

pub fn compare(before: &Snapshot, after: &Snapshot) -> Result<DiffReport> {
    let mut summary = Summary::default();
    let mut support_changes = Vec::new();
    for (architecture, syscall) in before
        .rows
        .keys()
        .chain(after.rows.keys())
        .collect::<BTreeSet<_>>()
    {
        let key = (architecture.clone(), syscall.clone());
        let old = before.rows.get(&key);
        let new = after.rows.get(&key);
        if old == new {
            summary.rows_unchanged += 1;
            continue;
        }
        let paired = old.zip(new);
        let status_changed = paired.is_some_and(|(a, b)| a.status != b.status);
        let detail_changed = paired.is_some_and(|(a, b)| a.detail != b.detail);
        let number_changed = paired.is_some_and(|(a, b)| a.number != b.number);
        let source_location_changed = paired.is_some_and(|(a, b)| a.source_line != b.source_line);
        let change = match (old, new) {
            (None, Some(_)) => {
                summary.rows_added += 1;
                "added"
            }
            (Some(_), None) => {
                summary.rows_removed += 1;
                "removed"
            }
            _ => {
                summary.rows_changed += 1;
                "changed"
            }
        };
        summary.support_status_changes += usize::from(status_changed);
        summary.detail_changes += usize::from(detail_changed);
        summary.number_changes += usize::from(number_changed);
        summary.source_location_changes += usize::from(source_location_changed);
        support_changes.push(SupportChange {
            runtime: "gvisor",
            architecture: architecture.clone(),
            syscall: syscall.clone(),
            change,
            status_changed,
            detail_changed,
            number_changed,
            source_location_changed,
            before: old.map(|row| RowEvidence {
                row: row.clone(),
                citation: before.citation(row),
            }),
            after: new.map(|row| RowEvidence {
                row: row.clone(),
                citation: after.citation(row),
            }),
        });
    }
    let old_gaps: BTreeMap<_, _> = before.kb.entries.iter().map(|gap| (&gap.id, gap)).collect();
    let new_gaps: BTreeMap<_, _> = after.kb.entries.iter().map(|gap| (&gap.id, gap)).collect();
    let mut gap_changes = Vec::new();
    for id in old_gaps
        .keys()
        .chain(new_gaps.keys())
        .collect::<BTreeSet<_>>()
    {
        let old = old_gaps.get(id).copied();
        let new = new_gaps.get(id).copied();
        let a = serde_json::to_value(old).map_err(|e| e.to_string())?;
        let b = serde_json::to_value(new).map_err(|e| e.to_string())?;
        if a == b {
            continue;
        }
        let definition_fields_changed = changed_fields(
            &a,
            &b,
            &[
                "runtime",
                "architectures",
                "category",
                "status",
                "description",
                "syscalls",
                "syscall_numbers",
                "subsystems",
                "severity_class",
                "applicability",
            ],
        );
        let provenance_fields_changed = changed_fields(
            &a,
            &b,
            &[
                "runtime_versions",
                "first_observed",
                "last_verified",
                "citation",
            ],
        );
        let change = match (old, new) {
            (None, Some(_)) => {
                summary.gaps_added += 1;
                "added"
            }
            (Some(_), None) => {
                summary.gaps_removed += 1;
                "removed"
            }
            _ => {
                summary.gap_definition_changes +=
                    usize::from(!definition_fields_changed.is_empty());
                summary.gap_provenance_changes +=
                    usize::from(!provenance_fields_changed.is_empty());
                "changed"
            }
        };
        gap_changes.push(GapChange {
            id: (*id).clone(),
            change,
            definition_fields_changed,
            provenance_fields_changed,
            before: old.cloned(),
            after: new.cloned(),
        });
    }
    let a = serde_json::to_value(&before.kb).map_err(|e| e.to_string())?;
    let b = serde_json::to_value(&after.kb).map_err(|e| e.to_string())?;
    Ok(DiffReport {
        schema_version: "1.0", kind: "knowledge-base-diff",
        before: before.identity.clone(), after: after.identity.clone(),
        authenticated: false, source_hashes_verified: false,
        interpretation: vec![
            "This is a comparison of declared release support, not observed workload compatibility.",
            "A removed row means absent from that snapshot; its support is unknown, not unimplemented.",
            "Support labels, documentation, syscall numbering and source location changes are counted separately.",
            "Input SHA-256 identifies the supplied bytes. Source hashes and commits are declared metadata, not re-downloaded or authenticated by this offline command.",
            "Imported first_observed/last_verified timestamps are provenance; they do not establish historical detection accuracy.",
        ],
        summary,
        snapshot_fields_changed: changed_fields(&a, &b, &["snapshot_version", "created_at", "created_at_unix", "runtime_releases", "source_commit", "source_hashes", "runtime_fallback_rules", "notes"]),
        support_changes, gap_changes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundled() -> Vec<u8> {
        include_bytes!("../../../kb/snapshot.json").to_vec()
    }

    #[test]
    fn identical_snapshot_has_no_changes() {
        let snapshot = Snapshot::from_bytes(&bundled()).unwrap();
        let result = compare(&snapshot, &snapshot).unwrap();
        assert!(result.support_changes.is_empty());
        assert!(result.gap_changes.is_empty());
        assert!(result.snapshot_fields_changed.is_empty());
        assert_eq!(result.summary.rows_unchanged, snapshot.rows.len());
        assert!(!result.authenticated);
        assert!(!result.source_hashes_verified);
    }

    #[test]
    fn removed_row_does_not_infer_unsupported() {
        let bytes = bundled();
        let before = Snapshot::from_bytes(&bytes).unwrap();
        let mut changed: Value = serde_json::from_slice(&bytes).unwrap();
        changed["syscall_support"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["syscall"] != "read");
        let after = Snapshot::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
        let result = compare(&before, &after).unwrap();
        assert_eq!(result.summary.rows_removed, 2);
        assert_eq!(result.summary.support_status_changes, 0);
        assert!(result
            .support_changes
            .iter()
            .all(|change| change.after.is_none() && !change.status_changed));
    }

    #[test]
    fn invalid_or_ambiguous_rows_fail_closed() {
        let original: Value = serde_json::from_slice(&bundled()).unwrap();
        for field in ["status", "architecture", "source_line"] {
            let mut bad = original.clone();
            bad["syscall_support"][0][field] = Value::String("unknown".into());
            assert!(Snapshot::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        let mut bad = original.clone();
        let first = bad["syscall_support"][0].clone();
        bad["syscall_support"].as_array_mut().unwrap().push(first);
        assert!(Snapshot::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad = original;
        bad["runtime_releases"]["gvisor"]
            .as_array_mut()
            .unwrap()
            .push(Value::String("20260914.0".into()));
        assert!(Snapshot::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
}
