use crate::Result;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{}: expected a regular file (symlinks are not followed)",
            path.display()
        ));
    }
    if metadata.len() > limit {
        return Err(format!("{} exceeds the {limit}-byte limit", path.display()));
    }
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > limit {
        return Err(format!("{} grew beyond its size limit", path.display()));
    }
    Ok(data)
}

/// Normalize a path in an OCI/Linux namespace, without interpreting it as a host path.
pub fn image_relative(path: &str) -> Result<String> {
    if path.is_empty() || path.contains('\\') || path.contains('\0') || path.starts_with('/') {
        return Err(format!("unsafe relative path: {path:?}"));
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." || parts.is_empty() && part.as_bytes().get(1) == Some(&b':') {
            return Err(format!("unsafe relative path: {path:?}"));
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err("empty relative path".into());
    }
    Ok(parts.join("/"))
}

pub fn safe_relative(path: &str) -> Result<PathBuf> {
    let normalized = image_relative(path)?;
    // Colons are ordinary Linux filename characters (e.g. Debian package metadata).
    // They must never become NTFS alternate data streams during host filesystem I/O.
    #[cfg(windows)]
    if normalized.contains(':') {
        return Err(format!("unsafe Windows relative path: {path:?}"));
    }
    let result = PathBuf::from(normalized);
    if result
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe host relative path: {path:?}"));
    }
    Ok(result)
}

pub fn checked_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = safe_relative(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.components() {
        path.push(part);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if metadata.file_type().is_symlink() {
                return Err(format!("refusing symlink traversal: {}", path.display()));
            }
        }
    }
    Ok(path)
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err("refusing to overwrite a symlink".into());
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = path.with_extension(format!("{}.{}.tmp", std::process::id(), stamp));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(file);
    // Windows rename does not replace existing files. The destination is always a regular,
    // bounded artifact in the requested workspace, never a directory.
    #[cfg(windows)]
    if path.is_file() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

pub fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn timestamp(seconds: u64) -> String {
    let days = (seconds / 86400) as i64;
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(m <= 2);
    let rem = seconds % 86400;
    format!(
        "{year:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn validate_digest(digest: &str) -> Result<&str> {
    match digest.strip_prefix("sha256:") {
        Some(hex)
            if hex.len() == 64
                && hex
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) =>
        {
            Ok(hex)
        }
        _ => Err(format!("invalid SHA-256 digest: {digest:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_cannot_escape() {
        for path in [
            "../evil",
            "a/../../b",
            "/etc/passwd",
            "C:/windows",
            "a\\b",
            "./",
            "",
        ] {
            assert!(safe_relative(path).is_err(), "{path}");
        }
        assert_eq!(
            safe_relative("./usr/bin/a").unwrap(),
            PathBuf::from("usr/bin/a")
        );
    }
    #[test]
    fn known_dates_and_hashes() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(951782400), "2000-02-29T00:00:00Z");
        assert_eq!(
            sha256(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(validate_digest("sha256:../../evil").is_err());
    }

    #[test]
    fn linux_image_names_are_not_windows_paths() {
        let name = "var/lib/dpkg/info/gcc-14-base:amd64.list";
        assert_eq!(image_relative(name).unwrap(), name);
        #[cfg(windows)]
        assert!(safe_relative(name).is_err());
        #[cfg(unix)]
        assert!(safe_relative(name).is_ok());
        for bad in ["../escape", "./C:/escape", "a/../../escape", "/absolute"] {
            assert!(image_relative(bad).is_err());
        }
    }
}
