use std::path::{Path, PathBuf};

use tokio::fs;

use super::StoreError;

/// Creates the parent directory for a file path.
pub(super) async fn create_parent_dir(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path.parent() else {
        return Err(StoreError::InvalidPath(path.to_path_buf()));
    };
    fs::create_dir_all(parent).await?;
    Ok(())
}

/// Removes a file and treats an already-missing file as success.
pub(super) async fn remove_file_if_exists(path: PathBuf) -> Result<(), StoreError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StoreError::Io(error)),
    }
}

/// Hard-links an existing published file to a rollback path.
///
/// Returns `Ok(false)` when the source file does not exist.
pub(super) async fn backup_existing_file(source: &Path, backup: &Path) -> Result<bool, StoreError> {
    match fs::hard_link(source, backup).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error)),
    }
}

/// Removes a rollback backup only when one was created.
pub(super) async fn remove_backup_file(path: &Path, exists: bool) -> Result<(), StoreError> {
    if exists {
        remove_file_if_exists(path.to_path_buf()).await?;
    }
    Ok(())
}

/// Best-effort rollback that removes a newly published file and restores a backup.
pub(super) async fn rollback_published_file(path: &Path, backup: &Path, had_previous: bool) {
    let _ = remove_file_if_exists(path.to_path_buf()).await;
    if had_previous {
        let _ = fs::rename(backup, path).await;
    }
}
