use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

const MAX_TRUSTED_PATH_COMPONENTS: usize = 64;

#[derive(Clone, Copy)]
pub struct TreeLimits {
    pub maximum_depth: usize,
    pub maximum_entries: usize,
    pub maximum_files: usize,
}

fn relative_components(path: &Path, allow_empty: bool) -> io::Result<Vec<&OsStr>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if parts.len() >= MAX_TRUSTED_PATH_COMPONENTS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "verification path exceeds its component limit",
                    ));
                }
                parts.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "verification path must remain relative to its trusted root",
                ));
            }
        }
    }
    if parts.is_empty() && !allow_empty {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verification file path must not be empty",
        ));
    }
    Ok(parts)
}

fn component_metadata(
    trusted_root: &Path,
    relative_path: &Path,
    final_directory: bool,
) -> io::Result<Vec<fs::Metadata>> {
    let parts = relative_components(relative_path, final_directory)?;
    let root_metadata = fs::symlink_metadata(trusted_root)?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusted verification root must be a non-symlink directory",
        ));
    }
    let mut snapshots = Vec::with_capacity(parts.len().saturating_add(1));
    snapshots.push(root_metadata);
    let mut current = trusted_root.to_path_buf();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verification path component must not be a symlink",
            ));
        }
        let is_final = index.saturating_add(1) == parts.len();
        if !is_final || final_directory {
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verification path component must be a directory",
                ));
            }
        } else if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verification input must be a regular file",
            ));
        }
        snapshots.push(metadata);
    }
    Ok(snapshots)
}

#[cfg(unix)]
fn same_observable_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_observable_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

fn read_file_bounded_with_hook<F>(
    trusted_root: &Path,
    relative_path: &Path,
    maximum_bytes: usize,
    before_open: F,
) -> io::Result<Vec<u8>>
where
    F: FnOnce() -> io::Result<()>,
{
    let before = component_metadata(trusted_root, relative_path, false)?;
    let before_file = before.last().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "verification file metadata is absent",
        )
    })?;
    let maximum_bytes_u64 = u64::try_from(maximum_bytes).unwrap_or(u64::MAX);
    if before_file.len() > maximum_bytes_u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verification input exceeds its byte limit",
        ));
    }
    before_open()?;
    let path = trusted_root.join(relative_path);
    let file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file()
        || opened.len() > maximum_bytes_u64
        || !same_observable_state(before_file, &opened)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verification input changed while being opened",
        ));
    }
    let read_limit = maximum_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid read limit"))?;
    let capacity = usize::try_from(opened.len())
        .unwrap_or(maximum_bytes)
        .min(maximum_bytes);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(u64::try_from(read_limit).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)?;
    let after = component_metadata(trusted_root, relative_path, false)?;
    if before.len() != after.len()
        || before
            .iter()
            .zip(&after)
            .any(|(left, right)| !same_observable_state(left, right))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verification input changed while being read",
        ));
    }
    if bytes.len() > maximum_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verification input exceeds its byte limit",
        ));
    }
    Ok(bytes)
}

pub fn read_file_bounded(
    trusted_root: &Path,
    relative_path: &Path,
    maximum_bytes: usize,
) -> io::Result<Vec<u8>> {
    read_file_bounded_with_hook(trusted_root, relative_path, maximum_bytes, || Ok(()))
}

pub fn collect_regular_files_bounded(
    trusted_root: &Path,
    relative_root: &Path,
    extensions: &[&str],
    limits: TreeLimits,
) -> io::Result<BTreeSet<String>> {
    if limits.maximum_entries == 0 || limits.maximum_files == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tree limits must be positive",
        ));
    }
    let root_before = component_metadata(trusted_root, relative_root, true)?;
    let root = trusted_root.join(relative_root);

    fn scan(
        root: &Path,
        directory: &Path,
        depth: usize,
        extensions: &[&str],
        limits: TreeLimits,
        entries_seen: &mut usize,
        files: &mut BTreeSet<String>,
    ) -> io::Result<()> {
        let before = fs::symlink_metadata(directory)?;
        if before.file_type().is_symlink() || !before.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verification directory must remain a non-symlink directory",
            ));
        }
        let entries = fs::read_dir(directory)?;
        for entry_result in entries {
            *entries_seen = entries_seen.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "entry counter overflow")
            })?;
            if *entries_seen > limits.maximum_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verification tree exceeds its entry limit",
                ));
            }
            let entry = entry_result?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verification tree contains a symlink",
                ));
            }
            if file_type.is_dir() {
                let child_depth = depth.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "depth counter overflow")
                })?;
                if child_depth > limits.maximum_depth {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "verification tree exceeds its depth limit",
                    ));
                }
                scan(
                    root,
                    &path,
                    child_depth,
                    extensions,
                    limits,
                    entries_seen,
                    files,
                )?;
                continue;
            }
            if !file_type.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verification tree contains a non-regular entry",
                ));
            }
            if !matches!(
                path.extension().and_then(|value| value.to_str()),
                Some(extension) if extensions.contains(&extension)
            ) {
                continue;
            }
            if files.len() >= limits.maximum_files {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "verification tree exceeds its file limit",
                ));
            }
            let relative = path.strip_prefix(root).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "path escaped verification root")
            })?;
            files.insert(relative.to_string_lossy().replace('\\', "/"));
        }
        let after = fs::symlink_metadata(directory)?;
        if after.file_type().is_symlink()
            || !after.is_dir()
            || !same_observable_state(&before, &after)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "verification directory changed while being scanned",
            ));
        }
        Ok(())
    }

    let mut files = BTreeSet::new();
    let mut entries_seen = 0usize;
    scan(
        &root,
        &root,
        0,
        extensions,
        limits,
        &mut entries_seen,
        &mut files,
    )?;
    let root_after = component_metadata(trusted_root, relative_root, true)?;
    if root_before.len() != root_after.len()
        || root_before
            .iter()
            .zip(&root_after)
            .any(|(left, right)| !same_observable_state(left, right))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "verification root changed while being scanned",
        ));
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new() -> Self {
            let ordinal = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "pcapraven-verifier-{}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create verifier test directory");
            Self(path)
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn bounded_read_accepts_n_and_rejects_n_plus_one() {
        let temp = TempDirectory::new();
        let path = temp.0.join("input");
        fs::write(&path, b"1234").expect("write bounded input");
        assert_eq!(
            read_file_bounded(&temp.0, Path::new("input"), 4).expect("read exact bound"),
            b"1234"
        );
        assert!(read_file_bounded(&temp.0, Path::new("input"), 3).is_err());
    }

    #[test]
    fn bounded_read_detects_observable_path_replacement() {
        let temp = TempDirectory::new();
        let path = temp.0.join("input");
        let replacement = temp.0.join("replacement");
        fs::write(&path, b"original").expect("write original input");
        fs::write(&replacement, b"different-length").expect("write replacement input");

        let result = read_file_bounded_with_hook(&temp.0, Path::new("input"), 32, || {
            fs::remove_file(&path)?;
            fs::rename(&replacement, &path)
        });

        assert!(result.is_err());
    }

    #[test]
    fn traversal_rejects_file_root() {
        let temp = TempDirectory::new();
        let root = temp.0.join("file-root");
        fs::write(&root, b"not a directory").expect("write file root");
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new("file-root"),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 1,
                    maximum_entries: 4,
                    maximum_files: 4,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn traversal_stops_at_entry_cap_in_large_directory() {
        let temp = TempDirectory::new();
        for index in 0..1024 {
            fs::write(temp.0.join(format!("entry-{index:04}.txt")), b"")
                .expect("write large-directory entry");
        }
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 1,
                    maximum_entries: 32,
                    maximum_files: 8,
                }
            )
            .is_err()
        );
    }

    #[test]
    fn traversal_enforces_entry_file_and_depth_limits() {
        let temp = TempDirectory::new();
        let nested = temp.0.join("one");
        fs::create_dir(&nested).expect("create nested directory");
        fs::write(nested.join("a.pcap"), b"").expect("write first file");
        fs::write(nested.join("b.pcap"), b"").expect("write second file");
        let exact = TreeLimits {
            maximum_depth: 1,
            maximum_entries: 3,
            maximum_files: 2,
        };
        assert_eq!(
            collect_regular_files_bounded(&temp.0, Path::new(""), &["pcap"], exact)
                .expect("exact traversal bounds")
                .len(),
            2
        );
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 0,
                    ..exact
                }
            )
            .is_err()
        );
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_entries: 2,
                    ..exact
                }
            )
            .is_err()
        );
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_files: 1,
                    ..exact
                }
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_is_rejected_before_file_open_or_directory_scan() {
        use std::os::unix::fs::symlink;
        use std::sync::atomic::AtomicBool;

        let trusted = TempDirectory::new();
        let external = TempDirectory::new();
        fs::write(external.0.join("outside.pcap"), b"must-not-be-consumed")
            .expect("write external file");
        symlink(&external.0, trusted.0.join("linked")).expect("create ancestor symlink");

        let reached_open = AtomicBool::new(false);
        let read_result =
            read_file_bounded_with_hook(&trusted.0, Path::new("linked/outside.pcap"), 64, || {
                reached_open.store(true, Ordering::Relaxed);
                Ok(())
            });
        assert!(read_result.is_err());
        assert!(!reached_open.load(Ordering::Relaxed));
        assert!(
            collect_regular_files_bounded(
                &trusted.0,
                Path::new("linked"),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 1,
                    maximum_entries: 4,
                    maximum_files: 4,
                }
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn traversal_rejects_directory_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        let external = TempDirectory::new();
        fs::write(external.0.join("outside.pcap"), b"outside").expect("write external file");
        symlink(&external.0, temp.0.join("linked")).expect("create directory symlink");
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 4,
                    maximum_entries: 8,
                    maximum_files: 8,
                }
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_and_traversal_reject_file_and_root_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDirectory::new();
        let target = temp.0.join("target.pcap");
        fs::write(&target, b"target").expect("write symlink target");
        let file_link = temp.0.join("file-link.pcap");
        symlink(&target, &file_link).expect("create file symlink");
        assert!(read_file_bounded(&temp.0, Path::new("file-link.pcap"), 16).is_err());
        assert!(
            collect_regular_files_bounded(
                &temp.0,
                Path::new(""),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 1,
                    maximum_entries: 8,
                    maximum_files: 8,
                }
            )
            .is_err()
        );

        let parent = TempDirectory::new();
        let root_link = parent.0.join("root-link");
        symlink(&temp.0, &root_link).expect("create root symlink");
        assert!(
            collect_regular_files_bounded(
                &parent.0,
                Path::new("root-link"),
                &["pcap"],
                TreeLimits {
                    maximum_depth: 1,
                    maximum_entries: 8,
                    maximum_files: 8,
                }
            )
            .is_err()
        );
    }
}
