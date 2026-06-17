use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use chrono::Utc;
use dashmap::DashMap;
use md5::Digest as _;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
};
use uuid::Uuid;

use super::{
    CommittedPart, CompletedPart, FileObjectStore, ObjectMetadata, PartMetadata, StoreError,
    TempPartWriter, UploadId, UploadMetadata, UploadProcessing, UploadSession, UploadState,
    complete_checksum::MultipartCompleteChecksumState,
    fs_util::{create_parent_dir, remove_file_if_exists},
    temp::{discard_staged_object, discard_temp_object},
};
use crate::{
    body::{checksum::ChecksumRequest, upload::summarize_staged_upload},
    config::{AccessKeyId, UploadLimits},
    middleware::{
        UploadProcessorContext, UploadProcessorOperation, process_staged_upload,
        processors_are_empty,
    },
    s3::types::{BucketName, ContentLength, ETag, ObjectKey, PartNumber},
};

/// Filesystem-backed multipart upload store.
#[derive(Debug)]
pub struct FileMultipartStore {
    pub(super) root: Arc<PathBuf>,
    pub(super) sessions: DashMap<UploadId, UploadSession>,
}

impl FileMultipartStore {
    /// Opens or creates a multipart store rooted at `root`.
    ///
    /// Loads open sessions from disk, removes terminal sessions, and removes
    /// stale temporary files. Returns an error for filesystem or JSON failures.
    pub async fn new(root: PathBuf) -> Result<Self, StoreError> {
        fs::create_dir_all(root.join("multipart")).await?;
        let store = Self {
            root: Arc::new(root),
            sessions: DashMap::new(),
        };
        store.load_sessions().await?;
        store.cleanup_stale_temp_files().await?;
        Ok(store)
    }

    /// Creates and persists a new multipart upload session.
    pub async fn create_upload(
        &self,
        bucket: BucketName,
        key: ObjectKey,
        owner_access_key_id: Option<AccessKeyId>,
        metadata: UploadMetadata,
    ) -> Result<UploadSession, StoreError> {
        let upload_id = UploadId::new();
        let session = UploadSession {
            upload_id: upload_id.clone(),
            bucket,
            key,
            initiated: Utc::now(),
            state: UploadState::Open,
            owner_access_key_id,
            metadata,
            parts: BTreeMap::new(),
        };
        fs::create_dir_all(self.parts_dir(&upload_id)).await?;
        self.persist_session(&session).await?;
        self.sessions.insert(upload_id, session.clone());
        Ok(session)
    }

    /// Returns a snapshot of an upload session.
    pub fn get_upload(&self, upload_id: &UploadId) -> Option<UploadSession> {
        self.sessions.get(upload_id).map(|entry| entry.clone())
    }

    fn get_open_upload(&self, upload_id: &UploadId) -> Result<UploadSession, StoreError> {
        let session = self
            .sessions
            .get(upload_id)
            .ok_or(StoreError::NoSuchUpload)?
            .clone();
        session.ensure_open()?;
        Ok(session)
    }

    /// Writes and commits a complete part from an in-memory byte slice.
    ///
    /// This is primarily used by tests and small helper paths. Streaming upload
    /// handlers should use [`Self::create_temp_part`] and [`Self::commit_part`].
    pub async fn write_part(
        &self,
        upload_id: &UploadId,
        part_number: PartNumber,
        bytes: &[u8],
        md5: Vec<u8>,
        etag: ETag,
        checksums: BTreeMap<String, String>,
    ) -> Result<PartMetadata, StoreError> {
        self.get_open_upload(upload_id)?;

        let path = self.part_path(upload_id, part_number);
        create_parent_dir(&path).await?;
        fs::write(path, bytes).await?;

        let part = PartMetadata {
            part_number,
            size: bytes.len() as u64,
            etag,
            md5,
            checksums,
            last_modified: Utc::now(),
        };

        let session_snapshot = {
            let Some(mut session) = self.sessions.get_mut(upload_id) else {
                return Err(StoreError::NoSuchUpload);
            };
            session.ensure_open()?;
            session.parts.insert(part_number, part.clone());
            session.clone()
        };
        self.persist_session(&session_snapshot).await?;
        Ok(part)
    }

    /// Creates a temporary part writer for an open upload.
    pub async fn create_temp_part(
        &self,
        upload_id: &UploadId,
        part_number: PartNumber,
    ) -> Result<TempPartWriter, StoreError> {
        self.get_open_upload(upload_id)?;

        let temp_id = Uuid::new_v4();
        let path = self
            .upload_dir(upload_id)
            .join(format!("{:05}.{temp_id}.tmp", part_number.get()));
        create_parent_dir(&path).await?;
        let file = File::create(&path).await?;

        Ok(TempPartWriter {
            path,
            writer: BufWriter::new(file),
        })
    }

    /// Atomically publishes a temporary part.
    ///
    /// Re-uploading the same part number replaces the previous part. If session
    /// persistence fails after publishing, the previous part file and in-memory
    /// session entry are restored where possible.
    pub async fn commit_part(
        &self,
        upload_id: &UploadId,
        part_number: PartNumber,
        temp: TempPartWriter,
        part: CommittedPart,
    ) -> Result<PartMetadata, StoreError> {
        let TempPartWriter {
            path: temp_path,
            writer,
        } = temp;
        drop(writer);

        let session = self.get_open_upload(upload_id)?;
        let final_path = self.part_path(upload_id, part_number);
        let previous_part = session.parts.get(&part_number).cloned();
        let backup_path = previous_part.as_ref().map(|_| {
            self.upload_dir(upload_id).join(format!(
                "{:05}.{}.rollback.tmp",
                part_number.get(),
                Uuid::new_v4()
            ))
        });

        let publish_result = async {
            create_parent_dir(&final_path).await?;
            if let Some(backup_path) = &backup_path {
                fs::hard_link(&final_path, backup_path).await?;
            }
            fs::rename(&temp_path, final_path.clone()).await?;
            Ok(())
        }
        .await;
        if let Err(error) = publish_result {
            let _ = remove_file_if_exists(temp_path).await;
            if let Some(backup_path) = backup_path {
                let _ = remove_file_if_exists(backup_path).await;
            }
            return Err(error);
        }

        let part = PartMetadata {
            part_number,
            size: part.size,
            etag: part.etag,
            md5: part.md5,
            checksums: part.checksums,
            last_modified: Utc::now(),
        };

        let session_snapshot = {
            let Some(mut session) = self.sessions.get_mut(upload_id) else {
                return Err(StoreError::NoSuchUpload);
            };
            session.ensure_open()?;
            session.parts.insert(part_number, part.clone());
            session.clone()
        };
        if let Err(error) = self.persist_session(&session_snapshot).await {
            let _ = remove_file_if_exists(final_path.clone()).await;
            if let Some(backup_path) = backup_path {
                let _ = fs::rename(backup_path, final_path).await;
            }
            if let Some(previous_part) = previous_part
                && let Some(mut session) = self.sessions.get_mut(upload_id)
            {
                session.parts.insert(part_number, previous_part);
            } else if let Some(mut session) = self.sessions.get_mut(upload_id) {
                session.parts.remove(&part_number);
            }
            return Err(error);
        }
        if let Some(backup_path) = backup_path {
            remove_file_if_exists(backup_path).await?;
        }
        Ok(part)
    }

    /// Aborts an open upload and deletes its temporary storage.
    ///
    /// Returns [`StoreError::NoSuchUpload`] when the upload is missing or not
    /// open. If filesystem deletion fails, the session remains marked aborted.
    pub async fn abort_upload(&self, upload_id: &UploadId) -> Result<(), StoreError> {
        let mut session = self.get_open_upload(upload_id)?;
        session.state = UploadState::Aborted;
        self.persist_session(&session).await?;
        self.sessions.insert(upload_id.clone(), session);

        let dir = self.upload_dir(upload_id);
        match fs::remove_dir_all(dir).await {
            Ok(()) => {
                self.sessions.remove(upload_id);
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.sessions.remove(upload_id);
                Ok(())
            }
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Completes an open multipart upload into a committed object.
    ///
    /// Validates requested part existence, ETags, non-final part size, object
    /// size, and full-object checksums before committing the final object.
    /// Temporary object data is discarded on validation or I/O failure.
    pub async fn complete_upload(
        &self,
        object_store: &FileObjectStore,
        upload_id: &UploadId,
        requested_parts: &[CompletedPart],
        checksum_request: &ChecksumRequest,
        upload_limits: &UploadLimits,
        processing: UploadProcessing<'_>,
    ) -> Result<ObjectMetadata, StoreError> {
        let session = self.begin_completion(upload_id).await?;
        let result = self
            .complete_upload_after_transition(
                session,
                MultipartCompletion {
                    object_store,
                    upload_id,
                    requested_parts,
                    checksum_request,
                    upload_limits,
                    processing,
                },
            )
            .await;
        if result.is_err() {
            self.restore_open_upload(upload_id).await;
        }
        result
    }

    async fn complete_upload_after_transition(
        &self,
        session: UploadSession,
        completion: MultipartCompletion<'_>,
    ) -> Result<ObjectMetadata, StoreError> {
        let MultipartCompletion {
            object_store,
            upload_id,
            requested_parts,
            checksum_request,
            upload_limits,
            processing,
        } = completion;
        let mut validated_parts = Vec::with_capacity(requested_parts.len());
        for (index, requested) in requested_parts.iter().enumerate() {
            let part = session
                .parts
                .get(&requested.part_number)
                .ok_or(StoreError::InvalidPart)?;
            if part.etag != requested.etag {
                return Err(StoreError::InvalidPart);
            }
            if index + 1 < requested_parts.len()
                && part.size < upload_limits.min_non_final_part_size
            {
                return Err(StoreError::EntityTooSmall);
            }
            validated_parts.push(part);
        }

        let mut temp = object_store
            .create_temp_object(&session.bucket, &session.key)
            .await?;
        let mut multipart_md5 = md5::Md5::new();
        let mut checksum_state = MultipartCompleteChecksumState::new(checksum_request);
        let mut total_size = 0_u64;

        for part in validated_parts {
            let mut file = match File::open(self.part_path(upload_id, part.part_number)).await {
                Ok(file) => file,
                Err(error) => {
                    discard_temp_object(temp, "multipart complete part open failure").await;
                    return Err(StoreError::Io(error));
                }
            };
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = match file.read(&mut buffer).await {
                    Ok(read) => read,
                    Err(error) => {
                        discard_temp_object(temp, "multipart complete part read failure").await;
                        return Err(StoreError::Io(error));
                    }
                };
                if read == 0 {
                    break;
                }
                if let Err(error) = temp.writer.write_all(&buffer[..read]).await {
                    discard_temp_object(temp, "multipart complete temp object write failure").await;
                    return Err(StoreError::Io(error));
                }
                checksum_state.update(&buffer[..read]);
            }
            multipart_md5.update(&part.md5);
            total_size += part.size;
            if total_size > upload_limits.max_object_size {
                discard_temp_object(temp, "multipart complete object size validation failure")
                    .await;
                return Err(StoreError::EntityTooLarge);
            }
        }

        if let Err(error) = checksum_request.validate(&checksum_state.finalize()) {
            discard_temp_object(temp, "multipart complete checksum validation failure").await;
            return Err(StoreError::Checksum(error));
        }
        if let Err(error) = temp.writer.flush().await {
            discard_temp_object(temp, "multipart complete temp object flush failure").await;
            return Err(StoreError::Io(error));
        }
        let staged = temp.finish().await?;
        let context = UploadProcessorContext {
            request_id: processing.request_id.clone(),
            bucket: session.bucket.clone(),
            key: session.key.clone(),
            operation: UploadProcessorOperation::CompleteMultipartUpload,
            original_size: ContentLength::new(total_size),
            content_type: session.metadata.content_type.clone(),
            user_metadata: session.metadata.user_metadata.clone(),
        };
        let staged = process_staged_upload(processing.upload_processors, staged, context)
            .await
            .map_err(StoreError::Processor)?;
        let final_body = match summarize_staged_upload(staged.path()).await {
            Ok(final_body) => final_body,
            Err(error) => {
                discard_staged_object(staged, "multipart complete final summary failure").await;
                return Err(StoreError::Processor(error));
            }
        };
        if final_body.size.get() > upload_limits.max_object_size {
            discard_staged_object(
                staged,
                "multipart complete processed object size validation failure",
            )
            .await;
            return Err(StoreError::EntityTooLarge);
        }
        let etag = if processors_are_empty(processing.upload_processors) {
            ETag::from_multipart_md5(hex::encode(multipart_md5.finalize()), requested_parts.len())
        } else {
            ETag::from_hex_md5(hex::encode(&final_body.digests.md5))
        };
        let checksums = if processors_are_empty(processing.upload_processors) {
            checksum_request.checksum_values()
        } else {
            checksum_request.checksum_values_for_digests(&final_body.digests)
        };
        let metadata = ObjectMetadata {
            bucket: session.bucket.clone(),
            key: session.key.clone(),
            size: final_body.size.get(),
            etag,
            content_type: session.metadata.content_type,
            content_encoding: session.metadata.content_encoding,
            content_disposition: session.metadata.content_disposition,
            content_language: session.metadata.content_language,
            cache_control: session.metadata.cache_control,
            expires: session.metadata.expires,
            tagging: session.metadata.tagging,
            user_metadata: session.metadata.user_metadata,
            checksums,
            last_modified: Utc::now(),
        };

        object_store
            .commit_staged_object(staged, metadata.clone())
            .await?;
        if let Some(completed_session) = self.mark_upload_state(upload_id, UploadState::Completed)
            && let Err(error) = self.persist_session(&completed_session).await
        {
            tracing::warn!(
                upload_id = %upload_id.as_str(),
                error = %error,
                "completed multipart upload state persistence failed"
            );
        }
        if let Err(error) = remove_file_if_exists(self.session_path(upload_id)).await {
            tracing::warn!(
                upload_id = %upload_id.as_str(),
                error = %error,
                "completed multipart upload session cleanup failed"
            );
        }
        self.sessions.remove(upload_id);
        if let Err(error) = fs::remove_dir_all(self.upload_dir(upload_id)).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                upload_id = %upload_id.as_str(),
                error = %error,
                "completed multipart upload cleanup failed"
            );
        }
        Ok(metadata)
    }

    async fn begin_completion(&self, upload_id: &UploadId) -> Result<UploadSession, StoreError> {
        let session_snapshot = {
            let Some(mut session) = self.sessions.get_mut(upload_id) else {
                return Err(StoreError::NoSuchUpload);
            };
            session.ensure_open()?;
            session.state = UploadState::Completing;
            session.clone()
        };
        if let Err(error) = self.persist_session(&session_snapshot).await {
            tracing::warn!(
                upload_id = %upload_id.as_str(),
                error = %error,
                "failed to persist multipart upload completion state"
            );
        }
        Ok(session_snapshot)
    }

    async fn restore_open_upload(&self, upload_id: &UploadId) {
        let Some(session_snapshot) = self.mark_upload_state(upload_id, UploadState::Open) else {
            return;
        };
        if let Err(error) = self.persist_session(&session_snapshot).await {
            tracing::warn!(
                upload_id = %upload_id.as_str(),
                error = %error,
                "failed to restore multipart upload to open state after completion failure"
            );
        }
    }

    fn mark_upload_state(&self, upload_id: &UploadId, state: UploadState) -> Option<UploadSession> {
        let mut session = self.sessions.get_mut(upload_id)?;
        session.state = state;
        Some(session.clone())
    }

    fn upload_dir(&self, upload_id: &UploadId) -> PathBuf {
        self.root.join("multipart").join(upload_id.as_str())
    }

    fn parts_dir(&self, upload_id: &UploadId) -> PathBuf {
        self.upload_dir(upload_id).join("parts")
    }

    fn part_path(&self, upload_id: &UploadId, part_number: PartNumber) -> PathBuf {
        self.parts_dir(upload_id)
            .join(format!("{:05}.part", part_number.get()))
    }

    fn session_path(&self, upload_id: &UploadId) -> PathBuf {
        self.upload_dir(upload_id).join("session.json")
    }

    async fn persist_session(&self, session: &UploadSession) -> Result<(), StoreError> {
        let session_path = self.session_path(&session.upload_id);
        create_parent_dir(&session_path).await?;
        let tmp_path = self
            .upload_dir(&session.upload_id)
            .join(format!("session.{}.tmp", Uuid::new_v4()));
        let json = serde_json::to_vec_pretty(session)?;
        let result = async {
            fs::write(&tmp_path, json).await?;
            fs::rename(&tmp_path, session_path).await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = remove_file_if_exists(tmp_path).await;
        }
        result
    }

    async fn load_sessions(&self) -> Result<(), StoreError> {
        let multipart_root = self.root.join("multipart");
        let mut entries = fs::read_dir(multipart_root).await?;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let session_path = entry.path().join("session.json");
            match fs::read(&session_path).await {
                Ok(bytes) => {
                    let session: UploadSession = serde_json::from_slice(&bytes)?;
                    if !session.is_open() {
                        if let Err(error) = fs::remove_dir_all(entry.path()).await
                            && error.kind() != std::io::ErrorKind::NotFound
                        {
                            tracing::warn!(
                                upload_id = %session.upload_id.as_str(),
                                error = %error,
                                "terminal multipart upload cleanup failed on startup"
                            );
                        }
                        continue;
                    }
                    self.sessions.insert(session.upload_id.clone(), session);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
        Ok(())
    }

    async fn cleanup_stale_temp_files(&self) -> Result<(), StoreError> {
        let multipart_root = self.root.join("multipart");
        let mut uploads = fs::read_dir(multipart_root).await?;
        while let Some(upload) = uploads.next_entry().await? {
            if !upload.file_type().await?.is_dir() {
                continue;
            }

            let mut entries = fs::read_dir(upload.path()).await?;
            while let Some(entry) = entries.next_entry().await? {
                if !entry.file_type().await?.is_file() {
                    continue;
                }

                let file_name = entry.file_name();
                if file_name
                    .to_str()
                    .is_some_and(|name| name.ends_with(".tmp"))
                {
                    remove_file_if_exists(entry.path()).await?;
                }
            }
        }
        Ok(())
    }
}

struct MultipartCompletion<'a> {
    object_store: &'a FileObjectStore,
    upload_id: &'a UploadId,
    requested_parts: &'a [CompletedPart],
    checksum_request: &'a ChecksumRequest,
    upload_limits: &'a UploadLimits,
    processing: UploadProcessing<'a>,
}
