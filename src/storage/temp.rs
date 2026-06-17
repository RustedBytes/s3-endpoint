use std::path::{Path, PathBuf};

use tokio::{
    fs::{self, File},
    io::{AsyncWriteExt, BufWriter},
    runtime::Handle,
};
use uuid::Uuid;

use super::{StoreError, fs_util::remove_file_if_exists};
use crate::s3::types::{BucketName, ObjectKey};

/// Temporary object writer returned by [`crate::storage::FileObjectStore::create_temp_object`].
pub struct TempObjectWriter {
    pub(super) temp_id: Uuid,
    pub(super) path: PathBuf,
    pub(super) cleanup: TempFileCleanup,
    /// Buffered writer for the temporary object body.
    pub writer: BufWriter<File>,
    #[allow(dead_code)]
    pub(super) bucket: BucketName,
    #[allow(dead_code)]
    pub(super) key: ObjectKey,
}

impl TempObjectWriter {
    /// Flushes and closes the writer, returning a staged object file.
    pub async fn finish(mut self) -> Result<StagedObject, StoreError> {
        self.writer.flush().await?;
        let Self {
            temp_id,
            path,
            mut cleanup,
            writer,
            bucket: _,
            key: _,
        } = self;
        drop(writer);
        cleanup.disarm();
        Ok(StagedObject {
            temp_id,
            cleanup: TempFileCleanup::new(path.clone()),
            path,
        })
    }

    /// Discards the temporary object body.
    pub async fn discard(self) -> Result<(), StoreError> {
        let Self {
            path,
            writer,
            mut cleanup,
            ..
        } = self;
        drop(writer);
        cleanup.disarm();
        remove_file_if_exists(path).await
    }
}

/// Fully written temporary object file ready for middleware or commit.
pub struct StagedObject {
    pub(super) temp_id: Uuid,
    pub(super) path: PathBuf,
    pub(super) cleanup: TempFileCleanup,
}

impl StagedObject {
    /// Returns the path to the current staged bytes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a unique replacement path in the same temporary directory.
    pub fn replacement_path(&self, replacement_id: Uuid) -> PathBuf {
        self.path
            .parent()
            .map(|parent| parent.join(format!("{replacement_id}.replace")))
            .unwrap_or_else(|| PathBuf::from(format!("{replacement_id}.replace")))
    }

    /// Replaces staged bytes with a processor-produced replacement file.
    pub async fn replace_with(&mut self, replacement_path: PathBuf) -> Result<(), StoreError> {
        match fs::metadata(&replacement_path).await {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => return Err(StoreError::InvalidPath(replacement_path)),
            Err(error) => return Err(StoreError::Io(error)),
        }
        remove_file_if_exists(self.path.clone()).await?;
        fs::rename(&replacement_path, &self.path).await?;
        Ok(())
    }

    /// Deletes staged bytes.
    pub async fn discard(self) -> Result<(), StoreError> {
        let Self {
            path, mut cleanup, ..
        } = self;
        cleanup.disarm();
        remove_file_if_exists(path).await
    }

    /// Disarms cleanup and returns the staged object ID and file path for commit.
    pub(super) fn into_parts(self) -> (Uuid, PathBuf) {
        let Self {
            temp_id,
            path,
            mut cleanup,
        } = self;
        cleanup.disarm();
        (temp_id, path)
    }
}

/// Temporary part writer returned by [`crate::storage::FileMultipartStore::create_temp_part`].
pub struct TempPartWriter {
    pub(super) path: PathBuf,
    pub(super) cleanup: TempFileCleanup,
    /// Buffered writer for the temporary part body.
    pub writer: BufWriter<File>,
}

impl TempPartWriter {
    /// Discards the temporary part body.
    pub async fn discard(self) -> Result<(), StoreError> {
        let Self {
            path,
            writer,
            mut cleanup,
        } = self;
        drop(writer);
        cleanup.disarm();
        remove_file_if_exists(path).await
    }

    /// Disarms cleanup and returns the part path and writer for commit.
    pub(super) fn into_parts(self) -> (PathBuf, BufWriter<File>) {
        let Self {
            path,
            writer,
            mut cleanup,
        } = self;
        cleanup.disarm();
        (path, writer)
    }
}

pub(super) struct TempFileCleanup {
    path: Option<PathBuf>,
}

impl TempFileCleanup {
    /// Arms best-effort cleanup for a temporary file path.
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileCleanup {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else {
            return;
        };
        if let Ok(handle) = Handle::try_current() {
            handle.spawn(async move {
                let _ = remove_file_if_exists(path).await;
            });
        } else {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Discards a temporary object and logs cleanup failure at debug level.
pub(super) async fn discard_temp_object(temp: TempObjectWriter, reason: &'static str) {
    if let Err(error) = temp.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard temporary object after storage failure"
        );
    }
}

/// Discards a staged object and logs cleanup failure at debug level.
pub(super) async fn discard_staged_object(staged: StagedObject, reason: &'static str) {
    if let Err(error) = staged.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard staged object after storage failure"
        );
    }
}
