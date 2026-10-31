//! Images are overlaid in memory. Archive paths are never passed to `tar::unpack`.
use crate::util::{
    checked_join, image_relative, read_bounded, safe_relative, sha256, validate_digest,
};
use crate::Result;
use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

pub const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_TOTAL: u64 = 1024 * 1024 * 1024;
const MAX_FILES: usize = 100_000;

#[derive(Clone, Debug)]
pub enum FileContent {
    Regular(Arc<Vec<u8>>),
    Symlink(String),
    Directory,
}

#[derive(Clone, Debug)]
pub struct ImageFile {
    pub content: FileContent,
    pub mode: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageConfig {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub user: String,
}

impl ImageConfig {
    pub fn command(&self) -> Vec<String> {
        self.entrypoint.iter().chain(&self.cmd).cloned().collect()
    }
}

#[derive(Clone, Debug)]
pub struct Image {
    pub reference: String,
    pub digest: Option<String>,
    pub architecture: String,
    pub os: String,
    pub config: ImageConfig,
    pub files: BTreeMap<String, ImageFile>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    digest: String,
    size: u64,
    media_type: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Debug, Deserialize)]
struct Platform {
    architecture: String,
    os: String,
    #[serde(default)]
    variant: Option<String>,
    #[serde(default, rename = "os.version")]
    os_version: Option<String>,
    #[serde(default, rename = "os.features")]
    os_features: Vec<String>,
    #[serde(default)]
    features: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    manifests: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    config: Descriptor,
    layers: Vec<Descriptor>,
}

fn decode<T: serde::de::DeserializeOwned>(data: &[u8], name: &str) -> Result<T> {
    serde_json::from_slice(data).map_err(|e| format!("invalid {name}: {e}"))
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecutionConfig {
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    working_dir: Option<String>,
    user: Option<String>,
}

#[derive(Deserialize)]
struct RootFs {
    #[serde(rename = "type")]
    kind: String,
    diff_ids: Vec<String>,
}

#[derive(Deserialize)]
struct ConfigDocument {
    #[serde(flatten)]
    platform: Platform,
    config: Option<ExecutionConfig>,
    rootfs: RootFs,
}

fn validate_platform(platform: &Platform, arch: &str) -> Result<()> {
    if platform.architecture != arch || platform.os != "linux" {
        return Err(format!(
            "requested linux/{arch}; image declares {}/{}",
            platform.os, platform.architecture
        ));
    }
    let variant = platform.variant.as_deref().unwrap_or("");
    if !variant.is_empty() && !matches!((arch, variant), ("amd64", "v1") | ("arm64", "v8")) {
        return Err(format!(
            "unsupported CPU variant linux/{arch}/{variant}; CPU feature requirements cannot be represented or verified by this scanner"
        ));
    }
    if !platform.features.is_empty() {
        return Err("image declares CPU features that this scanner cannot verify".into());
    }
    if platform
        .os_version
        .as_deref()
        .is_some_and(|v| !v.is_empty())
        || !platform.os_features.is_empty()
    {
        return Err("image declares OS version/features that this scanner cannot verify".into());
    }
    Ok(())
}

fn config(data: &[u8]) -> Result<(Platform, ImageConfig, Vec<String>)> {
    let document: ConfigDocument = decode(data, "image config")?;
    if document.rootfs.kind != "layers" {
        return Err("image rootfs.type must be layers".into());
    }
    let cfg = document.config.unwrap_or_default();
    let settings = ImageConfig {
        entrypoint: cfg.entrypoint.unwrap_or_default(),
        cmd: cfg.cmd.unwrap_or_default(),
        env: cfg.env.unwrap_or_default(),
        working_dir: cfg.working_dir.unwrap_or_else(|| "/".into()),
        user: cfg.user.unwrap_or_default(),
    };
    if settings
        .entrypoint
        .iter()
        .chain(&settings.cmd)
        .chain(&settings.env)
        .chain([&settings.working_dir, &settings.user])
        .any(|value| value.contains('\0'))
    {
        return Err("image execution settings contain a NUL byte".into());
    }
    if settings.command().first().is_some_and(String::is_empty) {
        return Err("image command has an empty executable name".into());
    }
    if settings
        .env
        .iter()
        .any(|pair| pair.split_once('=').is_none_or(|(key, _)| key.is_empty()))
    {
        return Err("image Env entries must have a nonempty KEY=VALUE form".into());
    }
    if !settings.working_dir.is_empty() && !settings.working_dir.starts_with('/') {
        return Err("relative image WorkingDir is unsupported; use an absolute Linux path".into());
    }
    for diff in &document.rootfs.diff_ids {
        validate_digest(diff)?;
    }
    Ok((document.platform, settings, document.rootfs.diff_ids))
}

fn blob(root: &Path, descriptor: &Descriptor, limit: u64) -> Result<Vec<u8>> {
    let hex = validate_digest(&descriptor.digest)?;
    if descriptor.size > limit {
        return Err("OCI descriptor exceeds size limit".into());
    }
    let data = read_bounded(&checked_join(root, &format!("blobs/sha256/{hex}"))?, limit)?;
    if data.len() as u64 != descriptor.size {
        return Err(format!("size mismatch for {}", descriptor.digest));
    }
    if sha256(&data) != descriptor.digest {
        return Err(format!("digest mismatch for {}", descriptor.digest));
    }
    Ok(data)
}

fn is_index_media(media: &str) -> bool {
    matches!(
        media,
        "application/vnd.oci.image.index.v1+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

fn is_manifest_media(media: &str) -> bool {
    matches!(
        media,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
    )
}

fn select<'a>(index: &'a Index, arch: &str) -> Result<&'a Descriptor> {
    if index.schema_version != 2 {
        return Err("OCI index schemaVersion must be 2".into());
    }
    let candidates: Vec<_> = index
        .manifests
        .iter()
        // OCI permits unrelated artifact media types in an index. They are not
        // workload candidates and must not make a single image ambiguous.
        .filter(|d| is_index_media(&d.media_type) || is_manifest_media(&d.media_type))
        .collect();
    let matches: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|d| {
            d.platform
                .as_ref()
                .map(|p| p.architecture == arch && p.os == "linux")
                .unwrap_or(candidates.len() == 1)
        })
        .collect();
    match matches.as_slice() {
        [descriptor] => Ok(descriptor),
        [] => Err(format!("no unambiguous linux/{arch} image in OCI index")),
        _ => Err(format!(
            "multiple linux/{arch} manifests; supply an OCI layout with a single image/tag"
        )),
    }
}

fn layer_bytes(data: &[u8], media: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    match media {
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip" => {
            MultiGzDecoder::new(data)
                .take(MAX_TOTAL + 1)
                .read_to_end(&mut result)
                .map_err(|e| format!("gzip layer: {e}"))?;
        }
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar"
        | "application/vnd.docker.image.rootfs.diff.tar" => result.extend_from_slice(data),
        "application/vnd.oci.image.layer.v1.tar+zstd"
        | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd" => {
            return Err(
                "zstd layers are not supported; use skopeo copy --dest-compress-format gzip".into(),
            );
        }
        _ => return Err(format!("unsupported image layer media type: {media}")),
    }
    if result.len() as u64 > MAX_TOTAL {
        return Err("uncompressed layer exceeds 1 GiB budget".into());
    }
    Ok(result)
}

pub fn load_oci(root: &Path, arch: &str) -> Result<Image> {
    let layout: Value = decode(
        &read_bounded(&checked_join(root, "oci-layout")?, 4096)?,
        "oci-layout",
    )?;
    if layout["imageLayoutVersion"] != "1.0.0" {
        return Err("unsupported OCI image layout version".into());
    }
    let mut index: Index = decode(
        &read_bounded(&checked_join(root, "index.json")?, 16 * 1024 * 1024)?,
        "index",
    )?;
    let (manifest, digest) = {
        let mut found = None;
        for _ in 0..4 {
            let descriptor = select(&index, arch)?;
            if let Some(platform) = &descriptor.platform {
                validate_platform(platform, arch)?;
            }
            let bytes = blob(root, descriptor, 16 * 1024 * 1024)?;
            if is_index_media(&descriptor.media_type) {
                index = decode(&bytes, "nested index")?;
            } else if is_manifest_media(&descriptor.media_type) {
                found = Some((
                    decode::<Manifest>(&bytes, "manifest")?,
                    descriptor.digest.clone(),
                ));
                break;
            } else {
                return Err(format!(
                    "unsupported OCI media type: {}",
                    descriptor.media_type
                ));
            }
        }
        found.ok_or("nested OCI indexes exceed depth limit")?
    };
    if manifest.schema_version != 2 {
        return Err("image manifest schemaVersion must be 2".into());
    }
    if !matches!(
        manifest.config.media_type.as_str(),
        "application/vnd.oci.image.config.v1+json"
            | "application/vnd.docker.container.image.v1+json"
    ) {
        return Err("manifest descriptor does not name a supported image config media type".into());
    }
    let (platform, config, diffs) = config(&blob(root, &manifest.config, 16 * 1024 * 1024)?)?;
    validate_platform(&platform, arch)?;
    if diffs.len() != manifest.layers.len() {
        return Err("rootfs.diff_ids must bind every image layer".into());
    }
    let mut image = Image {
        reference: root.display().to_string(),
        digest: Some(digest),
        architecture: platform.architecture,
        os: platform.os,
        config,
        files: BTreeMap::new(),
        warnings: vec![],
    };
    if manifest.layers.len() > 512 {
        return Err("too many image layers".into());
    }
    let mut expanded = 0u64;
    for (descriptor, diff) in manifest.layers.iter().zip(&diffs) {
        let bytes = layer_bytes(&blob(root, descriptor, MAX_TOTAL)?, &descriptor.media_type)?;
        expanded += bytes.len() as u64;
        if expanded > MAX_TOTAL * 4 {
            return Err("image exceeds 4 GiB cumulative unpacking budget".into());
        }
        validate_digest(diff)?;
        if sha256(&bytes) != *diff {
            return Err(format!(
                "uncompressed diff_id mismatch for {}",
                descriptor.digest
            ));
        }
        apply_layer(&mut image, &bytes)?;
    }
    Ok(image)
}

pub fn apply_layer(image: &mut Image, bytes: &[u8]) -> Result<()> {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut additions = BTreeMap::new();
    let mut whiteouts = BTreeSet::new();
    let mut opaque = BTreeSet::new();
    let mut hardlinks = Vec::new();
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for (count, entry) in archive.entries().map_err(|e| e.to_string())?.enumerate() {
        if count >= MAX_FILES {
            return Err("layer exceeds file-count limit".into());
        }
        let entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let raw = String::from_utf8(entry.path_bytes().to_vec())
            .map_err(|_| "non-UTF-8 image path is unsupported")?;
        if raw == "." || raw == "./" {
            continue;
        }
        let name = image_relative(raw.trim_end_matches('/'))?;
        if !paths.insert(name.clone()) {
            return Err(format!("duplicate path in layer: {name}"));
        }
        let (parent, base) = name.rsplit_once('/').unwrap_or(("", &name));
        let join = |part: &str| {
            if parent.is_empty() {
                part.to_string()
            } else {
                format!("{parent}/{part}")
            }
        };
        let header = entry.header();
        let kind = header.entry_type();
        if base.starts_with(".wh.")
            && (!kind.is_file() || header.size().map_err(|e| e.to_string())? != 0)
        {
            return Err(format!("whiteout must be an empty regular file: {name}"));
        }
        if base == ".wh..wh..opq" {
            opaque.insert(parent.to_string());
            continue;
        }
        if let Some(target) = base.strip_prefix(".wh.") {
            if target.is_empty() {
                return Err("empty whiteout target".into());
            }
            whiteouts.insert(image_relative(&join(target))?);
            continue;
        }
        let mode = header.mode().map_err(|e| e.to_string())? & 0o777;
        let content = if kind.is_file() {
            let size = header.size().map_err(|e| e.to_string())?;
            if size > MAX_FILE {
                return Err(format!("{name}: file exceeds 256 MiB limit"));
            }
            total += size;
            if total > MAX_TOTAL {
                return Err("layer file data exceeds memory budget".into());
            }
            let mut data = Vec::new();
            entry
                .take(MAX_FILE + 1)
                .read_to_end(&mut data)
                .map_err(|e| e.to_string())?;
            if data.len() as u64 != size {
                return Err(format!("truncated tar file: {name}"));
            }
            FileContent::Regular(Arc::new(data))
        } else if kind.is_dir() {
            FileContent::Directory
        } else if kind.is_symlink() {
            let target = String::from_utf8(
                entry
                    .link_name_bytes()
                    .ok_or("symlink without target")?
                    .to_vec(),
            )
            .map_err(|_| "non-UTF-8 symlink target is unsupported")?;
            if target.contains('\0') || target.contains('\\') {
                return Err("invalid symlink target".into());
            }
            FileContent::Symlink(target)
        } else if kind.is_hard_link() {
            let target = String::from_utf8(
                entry
                    .link_name_bytes()
                    .ok_or("hardlink without target")?
                    .to_vec(),
            )
            .map_err(|_| "non-UTF-8 hardlink target is unsupported")?;
            let target = image_relative(&target)?;
            hardlinks.push((name, target));
            continue;
        } else {
            image
                .warnings
                .push(format!("{name}: device/FIFO/special archive entry omitted"));
            continue;
        };
        if additions
            .insert(name.clone(), ImageFile { content, mode })
            .is_some()
        {
            return Err(format!("duplicate path in layer: {name}"));
        }
    }
    // Whiteouts only remove lower-layer entries, even if they occur last in a tar.
    image.files.retain(|name, _| {
        !opaque.contains("")
            && !whiteouts.contains(name)
            && !name.rmatch_indices('/').any(|(index, _)| {
                let ancestor = &name[..index];
                whiteouts.contains(ancestor) || opaque.contains(ancestor)
            })
    });
    for (name, file) in additions {
        if !matches!(file.content, FileContent::Directory) {
            remove_descendants(&mut image.files, &name);
        }
        image.files.insert(name, file);
    }
    for (name, target) in hardlinks {
        let file = image
            .files
            .get(&target)
            .ok_or_else(|| format!("unresolved hardlink: {name} -> {target}"))?;
        if !matches!(file.content, FileContent::Regular(_)) {
            return Err("hardlink target must be a regular file".into());
        }
        // A hardlink shares its target inode, including the target permissions.
        let file = file.clone();
        remove_descendants(&mut image.files, &name);
        image.files.insert(name, file);
    }
    if image.files.len() > MAX_FILES {
        return Err("image exceeds 100,000 file limit".into());
    }
    let size: usize = image
        .files
        .values()
        .map(|f| match &f.content {
            FileContent::Regular(bytes) => bytes.len(),
            _ => 0,
        })
        .sum();
    if size as u64 > MAX_TOTAL {
        return Err("image exceeds 1 GiB in-memory rootfs budget".into());
    }
    Ok(())
}

fn remove_descendants(files: &mut BTreeMap<String, ImageFile>, name: &str) {
    // Prefixes occupy a contiguous range in the ordered map. Scanning every
    // existing file for every new file made ordinary large layers quadratic.
    let prefix = format!("{name}/");
    let descendants: Vec<_> = files
        .range(prefix.clone()..)
        .take_while(|(path, _)| path.starts_with(&prefix))
        .map(|(path, _)| path.clone())
        .collect();
    for descendant in descendants {
        files.remove(&descendant);
    }
}

pub fn load_path(path: &Path, arch: &str) -> Result<Image> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err("input path may not be a symlink".into());
    }
    if metadata.is_dir() && path.join("oci-layout").exists() {
        return load_oci(path, arch);
    }
    let mut image = Image {
        reference: path.display().to_string(), digest: None, architecture: arch.into(), os: "linux".into(),
        config: ImageConfig::default(), files: BTreeMap::new(), warnings: vec!["Local ELF/rootfs input has no verified OCI image identity; admission attestations require an OCI manifest digest.".into()],
    };
    if metadata.is_file() {
        let data = read_bounded(path, MAX_FILE)?;
        if !data.starts_with(b"\x7fELF") {
            return Err("input must be an ELF, a rootfs directory, or an OCI layout (use skopeo for archives/registry images)".into());
        }
        image.files.insert(
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            ImageFile {
                content: FileContent::Regular(Arc::new(data)),
                mode: 0o755,
            },
        );
    } else {
        fn visit(
            root: &Path,
            path: &Path,
            image: &mut Image,
            total: &mut u64,
            depth: usize,
        ) -> Result<()> {
            if depth > 128 {
                return Err("rootfs directory nesting exceeds limit".into());
            }
            let mut entries: Vec<_> = fs::read_dir(path)
                .map_err(|e| e.to_string())?
                .collect::<std::result::Result<_, _>>()
                .map_err(|e| e.to_string())?;
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                if image.files.len() >= MAX_FILES {
                    return Err("rootfs file-count limit exceeded".into());
                }
                let path = entry.path();
                let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                let name = path
                    .strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .replace('\\', "/");
                safe_relative(&name)?;
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    meta.permissions().mode() & 0o777
                };
                #[cfg(not(unix))]
                let mode = if meta.is_dir() { 0o755 } else { 0o644 };
                let content = if meta.file_type().is_symlink() {
                    FileContent::Symlink(
                        fs::read_link(&path)
                            .map_err(|e| e.to_string())?
                            .to_string_lossy()
                            .into(),
                    )
                } else if meta.is_dir() {
                    visit(root, &path, image, total, depth + 1)?;
                    FileContent::Directory
                } else if meta.is_file() {
                    let data = read_bounded(&path, MAX_FILE)?;
                    *total += data.len() as u64;
                    if *total > MAX_TOTAL {
                        return Err("rootfs exceeds memory budget".into());
                    }
                    FileContent::Regular(Arc::new(data))
                } else {
                    image.warnings.push(format!("special file skipped: {name}"));
                    continue;
                };
                image.files.insert(name, ImageFile { content, mode });
            }
            Ok(())
        }
        visit(path, path, &mut image, &mut 0, 0)?;
    }
    Ok(image)
}

/// Materialization is only needed for an explicitly requested Linux runtime execution.
/// All regular files are created before symlinks; any file beneath a symlink is rejected.
pub fn materialize(image: &Image, root: &Path) -> Result<()> {
    if root.exists() {
        return Err("runtime rootfs must be a new directory".into());
    }
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let mut inodes = BTreeMap::new();
    for (name, file) in &image.files {
        let mut parent = Path::new(name).parent();
        while let Some(p) = parent {
            let key = p.to_string_lossy().replace('\\', "/");
            if image
                .files
                .get(&key)
                .is_some_and(|f| !matches!(f.content, FileContent::Directory))
            {
                return Err(format!("archive path has a non-directory ancestor: {name}"));
            }
            parent = p.parent();
        }
        if matches!(file.content, FileContent::Symlink(_)) {
            continue;
        }
        let path = checked_join(root, name)?;
        match &file.content {
            FileContent::Directory => fs::create_dir_all(&path).map_err(|e| e.to_string())?,
            FileContent::Regular(data) => {
                fs::create_dir_all(path.parent().ok_or("file has no parent")?)
                    .map_err(|e| e.to_string())?;
                let identity = Arc::as_ptr(data);
                if let Some(existing) = inodes.get(&identity) {
                    fs::hard_link(existing, &path).map_err(|e| format!("rootfs hardlink: {e}"))?;
                } else {
                    fs::write(&path, data.as_ref()).map_err(|e| e.to_string())?;
                    inodes.insert(identity, path.clone());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(file.mode))
                        .map_err(|e| e.to_string())?;
                }
            }
            _ => {}
        }
    }
    for (name, file) in &image.files {
        if let FileContent::Symlink(target) = &file.content {
            let path = checked_join(root, name)?;
            fs::create_dir_all(path.parent().ok_or("symlink has no parent")?)
                .map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, path).map_err(|e| e.to_string())?;
            }
            #[cfg(not(unix))]
            {
                let _ = (target, path);
                return Err("rootfs symlink materialization requires Linux".into());
            }
        }
    }
    // Delay directory modes until every child and symlink exists. Reverse path
    // order visits descendants before their ancestors, including mode-000 dirs.
    #[cfg(unix)]
    for (name, file) in image.files.iter().rev() {
        if matches!(file.content, FileContent::Directory) {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                checked_join(root, name)?,
                fs::Permissions::from_mode(file.mode),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Restore owner traversal permission before deleting a privately owned rootfs.
/// The caller must first stop the runtime and verify ownership/location of the
/// root. This is not safe against a concurrent process replacing paths. Symlink
/// targets and regular files are never chmodded or traversed.
pub fn prepare_removal(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("cleanup root must be a real, privately owned directory".into());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut visited = 0usize;
    while let Some(directory) = pending.pop() {
        let metadata = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode() | 0o700;
            fs::set_permissions(&directory, fs::Permissions::from_mode(mode))
                .map_err(|e| e.to_string())?;
        }
        for entry in fs::read_dir(&directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            visited += 1;
            if visited > MAX_FILES * 2 {
                return Err("rootfs cleanup exceeds traversal budget".into());
            }
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_configuration_rejects_malformed_execution_settings() {
        let base = serde_json::json!({"architecture":"amd64","os":"linux","config":{"Entrypoint":["/app"],"Cmd":[],"Env":["A=B"],"WorkingDir":"/","User":"0"},"rootfs":{"type":"layers","diff_ids":[]}});
        assert!(config(&serde_json::to_vec(&base).unwrap()).is_ok());
        for (key, value) in [
            ("Entrypoint", serde_json::json!("/app")),
            ("Cmd", serde_json::json!(["ok", 42])),
            ("Env", serde_json::json!([false])),
            ("Env", serde_json::json!(["INVALID"])),
            ("WorkingDir", serde_json::json!(123)),
            ("WorkingDir", serde_json::json!("relative")),
            ("User", serde_json::json!(false)),
            ("Entrypoint", serde_json::json!([""])),
            ("Cmd", serde_json::json!(["\u{0}"])),
        ] {
            let mut bad = base.clone();
            bad["config"][key] = value;
            assert!(config(&serde_json::to_vec(&bad).unwrap()).is_err(), "{key}");
        }
        let mut bad = base.clone();
        bad["rootfs"]["type"] = serde_json::json!("future-format");
        assert!(config(&serde_json::to_vec(&bad).unwrap()).is_err());
        bad = base;
        bad["rootfs"]["diff_ids"] = serde_json::json!([1]);
        assert!(config(&serde_json::to_vec(&bad).unwrap()).is_err());
    }

    #[test]
    fn unsupported_platform_requirements_are_not_silently_dropped() {
        for variant in ["v2", "v3", "v4", "unknown"] {
            let p: Platform = serde_json::from_value(
                serde_json::json!({"architecture":"amd64","os":"linux","variant":variant}),
            )
            .unwrap();
            assert!(validate_platform(&p, "amd64").is_err());
        }
        for (arch, variant) in [("amd64", "v1"), ("arm64", "v8")] {
            let p: Platform = serde_json::from_value(
                serde_json::json!({"architecture":arch,"os":"linux","variant":variant}),
            )
            .unwrap();
            assert!(validate_platform(&p, arch).is_ok());
        }
        let p: Platform = serde_json::from_value(
            serde_json::json!({"architecture":"amd64","os":"linux","os.features":["unverified"]}),
        )
        .unwrap();
        assert!(validate_platform(&p, "amd64").is_err());
        let p: Platform = serde_json::from_value(
            serde_json::json!({"architecture":"amd64","os":"linux","features":["sse4"]}),
        )
        .unwrap();
        assert!(validate_platform(&p, "amd64").is_err());
    }

    #[test]
    fn gzip_members_and_media_types_are_interpreted_exactly() {
        use std::io::Write;
        let mut first = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        first.write_all(b"first").unwrap();
        let mut bytes = first.finish().unwrap();
        let mut second = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        second.write_all(b"second").unwrap();
        bytes.extend(second.finish().unwrap());
        assert_eq!(
            layer_bytes(&bytes, "application/vnd.oci.image.layer.v1.tar+gzip").unwrap(),
            b"firstsecond"
        );
        assert!(layer_bytes(&bytes, "application/fake+gzip").is_err());
        bytes.extend_from_slice(b"garbage");
        assert!(layer_bytes(&bytes, "application/vnd.oci.image.layer.v1.tar+gzip").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn directory_modes_survive_materialization_and_cleanup_skips_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "sentrycheck-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&base).unwrap();
        let outside = base.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o500)).unwrap();
        let mut image = blank();
        image.files.insert(
            "private".into(),
            ImageFile {
                content: FileContent::Directory,
                mode: 0o700,
            },
        );
        image.files.insert(
            "private/locked".into(),
            ImageFile {
                content: FileContent::Directory,
                mode: 0,
            },
        );
        image.files.insert(
            "private/locked/file".into(),
            ImageFile {
                content: FileContent::Regular(Arc::new(b"data".to_vec())),
                mode: 0o600,
            },
        );
        image.files.insert(
            "external".into(),
            ImageFile {
                content: FileContent::Symlink(outside.to_string_lossy().into()),
                mode: 0o777,
            },
        );
        let root = base.join("rootfs");
        materialize(&image, &root).unwrap();
        assert_eq!(
            fs::metadata(root.join("private"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("private/locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0
        );
        prepare_removal(&root).unwrap();
        assert_eq!(
            fs::metadata(&outside).unwrap().permissions().mode() & 0o777,
            0o500
        );
        fs::remove_dir_all(&root).unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    fn blank() -> Image {
        Image {
            reference: "fixture".into(),
            digest: None,
            architecture: "amd64".into(),
            os: "linux".into(),
            config: ImageConfig::default(),
            files: BTreeMap::new(),
            warnings: vec![],
        }
    }
    fn tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, name, *data).unwrap();
        }
        tar.into_inner().unwrap()
    }
    #[test]
    fn whiteouts_only_delete_lower_layers() {
        let mut img = blank();
        apply_layer(&mut img, &tar(&[("x/old", b"old"), ("gone", b"bye")])).unwrap();
        apply_layer(
            &mut img,
            &tar(&[
                ("x/new", b"new"),
                ("x/.wh..wh..opq", b""),
                (".wh.gone", b""),
            ]),
        )
        .unwrap();
        assert!(img.files.contains_key("x/new"));
        assert!(!img.files.contains_key("x/old"));
        assert!(!img.files.contains_key("gone"));
    }
    #[test]
    fn replacement_file_hides_lower_directory() {
        let mut img = blank();
        apply_layer(&mut img, &tar(&[("a/b", b"x")])).unwrap();
        apply_layer(&mut img, &tar(&[("a", b"y")])).unwrap();
        assert!(!img.files.contains_key("a/b"));
    }

    #[test]
    fn nested_whiteouts_and_replacements_preserve_sibling_prefixes() {
        let mut image = blank();
        apply_layer(
            &mut image,
            &tar(&[
                ("a/deep/old", b"old"),
                ("a/other", b"old"),
                ("ab/keep", b"keep"),
                ("b/deep/old", b"old"),
                ("bb/keep", b"keep"),
            ]),
        )
        .unwrap();
        apply_layer(
            &mut image,
            &tar(&[
                ("a/.wh.deep", b""),
                ("a/deep/new", b"new"),
                ("b/.wh..wh..opq", b""),
                ("b/deep/new", b"new"),
            ]),
        )
        .unwrap();
        assert!(!image.files.contains_key("a/deep/old"));
        assert!(!image.files.contains_key("b/deep/old"));
        for path in ["a/other", "a/deep/new", "b/deep/new", "ab/keep", "bb/keep"] {
            assert!(image.files.contains_key(path), "{path}");
        }
        apply_layer(&mut image, &tar(&[("a", b"replacement")])).unwrap();
        assert!(!image.files.contains_key("a/other"));
        assert!(image.files.contains_key("ab/keep"));
    }
    #[test]
    fn duplicate_layer_paths_rejected() {
        assert!(apply_layer(&mut blank(), &tar(&[("a", b"1"), ("a", b"2")])).is_err());
    }

    fn linked_tar(alias: &str) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(&mut header, "target", &b"data"[..])
            .unwrap();
        let mut link = tar::Header::new_gnu();
        link.set_entry_type(tar::EntryType::Link);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_link_name("target").unwrap();
        link.set_cksum();
        archive
            .append_data(&mut link, alias, std::io::empty())
            .unwrap();
        archive.into_inner().unwrap()
    }

    #[test]
    fn duplicate_hardlink_and_regular_path_is_rejected() {
        assert!(apply_layer(&mut blank(), &linked_tar("target")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_replaces_lower_directory_and_preserves_shared_content() {
        let mut image = blank();
        apply_layer(&mut image, &tar(&[("alias/old-child", b"old")])).unwrap();
        apply_layer(&mut image, &linked_tar("alias")).unwrap();
        assert!(!image.files.contains_key("alias/old-child"));
        assert_eq!(image.files["alias"].mode, 0o600);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "sentrycheck-hardlink-{}-{stamp}",
            std::process::id()
        ));
        materialize(&image, &root).unwrap();
        fs::write(root.join("target"), b"changed through the other name").unwrap();
        assert_eq!(
            fs::read(root.join("alias")).unwrap(),
            b"changed through the other name"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
