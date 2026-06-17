use std::path::{Path, PathBuf};

use tokio::{
    fs::{self, File},
    io::{AsyncWriteExt, BufWriter},
};
use uuid::Uuid;

use super::{StoreError, fs_util::remove_file_if_exists};
use crate::s3::types::{BucketName, ObjectKey};

/// Temporary object writer returned by [`crate::storage::FileObjectStore::create_temp_object`].
pub struct TempObjectWriter {
    pub(super) temp_id: Uuid,
    pub(super) path: PathBuf,
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
            writer,
            bucket: _,
            key: _,
        } = self;
        drop(writer);
        Ok(StagedObject { temp_id, path })
    }

    /// Discards the temporary object body.
    pub async fn discard(self) -> Result<(), StoreError> {
        let Self { path, writer, .. } = self;
        drop(writer);
        remove_file_if_exists(path).await
    }
}

/// Fully written temporary object file ready for middleware or commit.
pub struct StagedObject {
    pub(super) temp_id: Uuid,
    pub(super) path: PathBuf,
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
        remove_file_if_exists(self.path).await
    }
}

/// Temporary part writer returned by [`crate::storage::FileMultipartStore::create_temp_part`].
pub struct TempPartWriter {
    pub(super) path: PathBuf,
    /// Buffered writer for the temporary part body.
    pub writer: BufWriter<File>,
}

impl TempPartWriter {
    /// Discards the temporary part body.
    pub async fn discard(self) -> Result<(), StoreError> {
        let Self { path, writer } = self;
        drop(writer);
        remove_file_if_exists(path).await
    }
}

pub(super) async fn discard_temp_object(temp: TempObjectWriter, reason: &'static str) {
    if let Err(error) = temp.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard temporary object after storage failure"
        );
    }
}

pub(super) async fn discard_staged_object(staged: StagedObject, reason: &'static str) {
    if let Err(error) = staged.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard staged object after storage failure"
        );
    }
}
