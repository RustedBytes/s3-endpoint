use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use chrono::{DateTime, Utc};
use crc::{CRC_32_ISCSI, CRC_32_ISO_HDLC, Crc};
use dashmap::DashMap;
use md5::{Digest as Md5Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt, BufWriter},
};
use uuid::Uuid;

use crate::{
    body::{
        checksum::{ChecksumDigests, ChecksumRequest},
        upload::summarize_staged_upload,
    },
    config::{AccessKeyId, UploadLimits},
    error::S3Error,
    middleware::{
        SharedUploadProcessor, UploadProcessorContext, UploadProcessorOperation,
        process_staged_upload, processors_are_empty,
    },
    s3::types::{BucketName, ContentLength, ETag, ObjectKey, PartNumber, RequestId},
};

pub use crate::s3::types::UploadId;

static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

/// Persisted metadata for a committed object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    /// Bucket that owns the object.
    pub bucket: BucketName,
    /// Object key.
    pub key: ObjectKey,
    /// Object size in bytes.
    pub size: u64,
    /// Object ETag.
    pub etag: ETag,
    /// Optional `Content-Type` metadata.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Optional `Content-Encoding` metadata, excluding transport-only `aws-chunked`.
    #[serde(default)]
    pub content_encoding: Option<String>,
    /// Optional `Content-Disposition` metadata.
    #[serde(default)]
    pub content_disposition: Option<String>,
    /// Optional `Content-Language` metadata.
    #[serde(default)]
    pub content_language: Option<String>,
    /// Optional `Cache-Control` metadata.
    #[serde(default)]
    pub cache_control: Option<String>,
    /// Optional `Expires` metadata.
    #[serde(default)]
    pub expires: Option<String>,
    /// Optional raw `x-amz-tagging` value.
    #[serde(default)]
    pub tagging: Option<String>,
    /// User metadata keyed by lowercase `x-amz-meta-*` header names.
    #[serde(default)]
    pub user_metadata: BTreeMap<String, String>,
    /// Stored checksum headers such as `x-amz-checksum-crc32`.
    #[serde(default)]
    pub checksums: BTreeMap<String, String>,
    /// Object modification timestamp.
    pub last_modified: DateTime<Utc>,
}

/// Metadata captured when an upload is initiated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UploadMetadata {
    /// Optional `Content-Type` metadata.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Optional `Content-Encoding` metadata.
    #[serde(default)]
    pub content_encoding: Option<String>,
    /// Optional `Content-Disposition` metadata.
    #[serde(default)]
    pub content_disposition: Option<String>,
    /// Optional `Content-Language` metadata.
    #[serde(default)]
    pub content_language: Option<String>,
    /// Optional `Cache-Control` metadata.
    #[serde(default)]
    pub cache_control: Option<String>,
    /// Optional `Expires` metadata.
    #[serde(default)]
    pub expires: Option<String>,
    /// Optional raw `x-amz-tagging` value.
    #[serde(default)]
    pub tagging: Option<String>,
    /// Negotiated checksum algorithm for multipart uploads.
    #[serde(default)]
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    /// Negotiated checksum type for multipart uploads.
    #[serde(default)]
    pub checksum_type: Option<ChecksumType>,
    /// User metadata keyed by lowercase `x-amz-meta-*` header names.
    #[serde(default)]
    pub user_metadata: BTreeMap<String, String>,
}

/// Supported S3 checksum algorithms.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChecksumAlgorithm {
    /// CRC32 checksum.
    #[serde(rename = "CRC32")]
    Crc32,
    /// CRC32C checksum.
    #[serde(rename = "CRC32C")]
    Crc32c,
    /// SHA1 checksum.
    #[serde(rename = "SHA1")]
    Sha1,
    /// SHA256 checksum.
    #[serde(rename = "SHA256")]
    Sha256,
    /// SHA512 checksum.
    #[serde(rename = "SHA512")]
    Sha512,
}

/// S3 multipart checksum type.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChecksumType {
    /// Per-part checksum composition.
    #[serde(rename = "COMPOSITE")]
    Composite,
    /// Full-object checksum.
    #[serde(rename = "FULL_OBJECT")]
    FullObject,
}

/// Filesystem-backed object store.
#[derive(Clone, Debug)]
pub struct FileObjectStore {
    root: Arc<PathBuf>,
}

impl FileObjectStore {
    /// Opens or creates a filesystem object store rooted at `root`.
    ///
    /// Creates required directories and removes stale temporary/orphaned files.
    /// Returns an error when directory creation, cleanup, or metadata parsing fails.
    pub async fn new(root: PathBuf) -> Result<Self, StoreError> {
        fs::create_dir_all(root.join("objects")).await?;
        fs::create_dir_all(root.join("metadata")).await?;
        fs::create_dir_all(root.join("tmp")).await?;
        let store = Self {
            root: Arc::new(root),
        };
        store.cleanup_stale_temp_files().await?;
        store.cleanup_orphaned_object_files().await?;
        store.cleanup_orphaned_metadata_files().await?;
        Ok(store)
    }

    /// Creates a temporary object writer for a bucket/key.
    ///
    /// The caller must write the full object body and then pass the writer to
    /// [`Self::commit_object`] or [`TempObjectWriter::discard`].
    pub async fn create_temp_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<TempObjectWriter, StoreError> {
        let temp_id = Uuid::new_v4();
        let path = self.root.join("tmp").join(format!("{temp_id}.part"));
        let file = File::create(&path).await?;

        Ok(TempObjectWriter {
            temp_id,
            path,
            writer: BufWriter::new(file),
            bucket: bucket.clone(),
            key: key.clone(),
        })
    }

    /// Atomically publishes a temporary object and metadata.
    ///
    /// On failure, best-effort rollback restores the previous object/metadata
    /// pair when one existed and removes temporary files. Returns an error for
    /// filesystem or serialization failures.
    pub async fn commit_object(
        &self,
        temp: TempObjectWriter,
        metadata: ObjectMetadata,
    ) -> Result<(), StoreError> {
        self.commit_staged_object(temp.finish().await?, metadata)
            .await
    }

    /// Atomically publishes a staged object and metadata.
    ///
    /// This is used by upload middleware paths that need filesystem access to a
    /// fully decoded temporary object before it is committed.
    pub async fn commit_staged_object(
        &self,
        staged: StagedObject,
        metadata: ObjectMetadata,
    ) -> Result<(), StoreError> {
        let StagedObject {
            temp_id,
            path: temp_path,
        } = staged;

        let object_path = self.object_path(&metadata.bucket, &metadata.key);
        let metadata_path = self.metadata_path(&metadata.bucket, &metadata.key);
        let metadata_tmp = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.metadata.json"));
        let object_backup = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.object.rollback.tmp"));
        let metadata_backup = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.metadata.rollback.tmp"));

        let result = async {
            create_parent_dir(&object_path).await?;
            create_parent_dir(&metadata_path).await?;

            let json = serde_json::to_vec_pretty(&metadata)?;
            fs::write(&metadata_tmp, json).await?;
            let had_object = backup_existing_file(&object_path, &object_backup).await?;
            let had_metadata = backup_existing_file(&metadata_path, &metadata_backup).await?;

            fs::rename(&temp_path, &object_path).await?;
            if let Err(error) = fs::rename(&metadata_tmp, &metadata_path).await {
                rollback_published_file(&object_path, &object_backup, had_object).await;
                rollback_published_file(&metadata_path, &metadata_backup, had_metadata).await;
                return Err(StoreError::Io(error));
            }

            remove_backup_file(&object_backup, had_object).await?;
            remove_backup_file(&metadata_backup, had_metadata).await?;
            Ok(())
        }
        .await;

        if result.is_err() {
            let _ = remove_file_if_exists(temp_path).await;
            let _ = remove_file_if_exists(metadata_tmp).await;
            let _ = remove_file_if_exists(object_backup).await;
            let _ = remove_file_if_exists(metadata_backup).await;
        }

        result
    }

    /// Reads committed object metadata.
    ///
    /// Returns `Ok(None)` when either metadata or object bytes are missing, so
    /// orphaned metadata/data files are not exposed as objects.
    pub async fn head_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<Option<ObjectMetadata>, StoreError> {
        let metadata_path = self.metadata_path(bucket, key);
        let object_path = self.object_path(bucket, key);
        let metadata = match fs::read(metadata_path).await {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };

        match fs::metadata(object_path).await {
            Ok(object) if object.is_file() => Ok(Some(metadata)),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Opens a committed object for streaming.
    ///
    /// Returns `Ok(None)` when the object is missing or disappears between
    /// metadata lookup and file open.
    pub async fn open_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<Option<(ObjectMetadata, File)>, StoreError> {
        let Some(metadata) = self.head_object(bucket, key).await? else {
            return Ok(None);
        };
        match File::open(self.object_path(bucket, key)).await {
            Ok(file) => Ok(Some((metadata, file))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Deletes object metadata and bytes.
    ///
    /// Missing objects are treated as success, matching S3 delete semantics.
    pub async fn delete_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<(), StoreError> {
        let metadata_path = self.metadata_path(bucket, key);
        let object_path = self.object_path(bucket, key);

        match fs::remove_file(&metadata_path).await {
            Ok(()) => remove_file_if_exists(object_path).await,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn object_path(&self, bucket: &BucketName, key: &ObjectKey) -> PathBuf {
        let digest = object_digest(bucket, key);
        self.root
            .join("objects")
            .join(&digest[..2])
            .join(format!("{digest}.data"))
    }

    fn metadata_path(&self, bucket: &BucketName, key: &ObjectKey) -> PathBuf {
        let digest = object_digest(bucket, key);
        self.root
            .join("metadata")
            .join(&digest[..2])
            .join(format!("{digest}.json"))
    }

    async fn cleanup_stale_temp_files(&self) -> Result<(), StoreError> {
        let mut entries = fs::read_dir(self.root.join("tmp")).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                remove_file_if_exists(entry.path()).await?;
            }
        }
        Ok(())
    }

    async fn cleanup_orphaned_object_files(&self) -> Result<(), StoreError> {
        let mut prefixes = fs::read_dir(self.root.join("objects")).await?;
        while let Some(prefix_entry) = prefixes.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }

            let mut objects = fs::read_dir(prefix_entry.path()).await?;
            while let Some(object_entry) = objects.next_entry().await? {
                if !object_entry.file_type().await?.is_file() {
                    continue;
                }

                let Some(file_name) = object_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(digest) = file_name.strip_suffix(".data") else {
                    continue;
                };

                let metadata_path = if digest.len() >= 2 {
                    self.root
                        .join("metadata")
                        .join(&digest[..2])
                        .join(format!("{digest}.json"))
                } else {
                    self.root.join("metadata").join(format!("{digest}.json"))
                };

                match fs::metadata(metadata_path).await {
                    Ok(metadata) if metadata.is_file() => {}
                    Ok(_) => remove_file_if_exists(object_entry.path()).await?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        remove_file_if_exists(object_entry.path()).await?;
                    }
                    Err(error) => return Err(StoreError::Io(error)),
                }
            }
        }
        Ok(())
    }

    async fn cleanup_orphaned_metadata_files(&self) -> Result<(), StoreError> {
        let mut prefixes = fs::read_dir(self.root.join("metadata")).await?;
        while let Some(prefix_entry) = prefixes.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }

            let mut metadata_files = fs::read_dir(prefix_entry.path()).await?;
            while let Some(metadata_entry) = metadata_files.next_entry().await? {
                if !metadata_entry.file_type().await?.is_file() {
                    continue;
                }

                let Some(file_name) = metadata_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(digest) = file_name.strip_suffix(".json") else {
                    continue;
                };

                let object_path = if digest.len() >= 2 {
                    self.root
                        .join("objects")
                        .join(&digest[..2])
                        .join(format!("{digest}.data"))
                } else {
                    self.root.join("objects").join(format!("{digest}.data"))
                };

                match fs::metadata(object_path).await {
                    Ok(object) if object.is_file() => {}
                    Ok(_) => remove_file_if_exists(metadata_entry.path()).await?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        remove_file_if_exists(metadata_entry.path()).await?;
                    }
                    Err(error) => return Err(StoreError::Io(error)),
                }
            }
        }
        Ok(())
    }
}

/// Persisted multipart upload session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadSession {
    /// Upload ID.
    pub upload_id: UploadId,
    /// Target bucket.
    pub bucket: BucketName,
    /// Target object key.
    pub key: ObjectKey,
    /// Upload initiation timestamp.
    pub initiated: DateTime<Utc>,
    /// Upload lifecycle state.
    #[serde(default)]
    pub state: UploadState,
    /// Access key that initiated a signed upload, if any.
    #[serde(default)]
    pub owner_access_key_id: Option<AccessKeyId>,
    /// Metadata captured at create-multipart-upload time.
    #[serde(default)]
    pub metadata: UploadMetadata,
    /// Uploaded parts keyed by part number.
    pub parts: BTreeMap<PartNumber, PartMetadata>,
}

/// Multipart upload lifecycle state.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum UploadState {
    /// Upload accepts new parts and control operations.
    #[default]
    Open,
    /// Completion has started.
    Completing,
    /// Upload completed and should not be resumed.
    Completed,
    /// Upload was aborted and should not be resumed.
    Aborted,
}

impl UploadSession {
    /// Returns whether the session is open.
    pub fn is_open(&self) -> bool {
        self.state == UploadState::Open
    }

    fn ensure_open(&self) -> Result<(), StoreError> {
        if self.is_open() {
            Ok(())
        } else {
            Err(StoreError::NoSuchUpload)
        }
    }
}

/// Metadata for a committed multipart part.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartMetadata {
    /// Part number.
    pub part_number: PartNumber,
    /// Part size in bytes.
    pub size: u64,
    /// Part ETag.
    pub etag: ETag,
    /// Raw MD5 digest bytes used for multipart ETag calculation.
    pub md5: Vec<u8>,
    /// Stored checksum headers such as `x-amz-checksum-crc32`.
    #[serde(default)]
    pub checksums: BTreeMap<String, String>,
    /// Part commit timestamp.
    pub last_modified: DateTime<Utc>,
}

/// Filesystem-backed multipart upload store.
#[derive(Debug)]
pub struct FileMultipartStore {
    root: Arc<PathBuf>,
    sessions: DashMap<UploadId, UploadSession>,
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
        let session = self.get_open_upload(upload_id)?;
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

/// Part requested in a `CompleteMultipartUpload` call.
#[derive(Clone, Debug)]
pub struct CompletedPart {
    /// Requested part number.
    pub part_number: PartNumber,
    /// ETag supplied by the client.
    pub etag: ETag,
}

/// Upload middleware inputs for multipart completion.
pub struct UploadProcessing<'a> {
    /// Request ID associated with the completing request.
    pub request_id: &'a RequestId,
    /// Registered upload processors.
    pub upload_processors: &'a [SharedUploadProcessor],
}

/// Temporary object writer returned by [`FileObjectStore::create_temp_object`].
pub struct TempObjectWriter {
    temp_id: Uuid,
    path: PathBuf,
    /// Buffered writer for the temporary object body.
    pub writer: BufWriter<File>,
    #[allow(dead_code)]
    bucket: BucketName,
    #[allow(dead_code)]
    key: ObjectKey,
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
    temp_id: Uuid,
    path: PathBuf,
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

async fn discard_temp_object(temp: TempObjectWriter, reason: &'static str) {
    if let Err(error) = temp.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard temporary object after storage failure"
        );
    }
}

async fn discard_staged_object(staged: StagedObject, reason: &'static str) {
    if let Err(error) = staged.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard staged object after storage failure"
        );
    }
}

/// Temporary part writer returned by [`FileMultipartStore::create_temp_part`].
pub struct TempPartWriter {
    path: PathBuf,
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

/// Validated part data ready to commit.
pub struct CommittedPart {
    /// Part size in bytes.
    pub size: u64,
    /// Raw MD5 digest bytes.
    pub md5: Vec<u8>,
    /// Part ETag.
    pub etag: ETag,
    /// Stored checksum headers such as `x-amz-checksum-crc32`.
    pub checksums: BTreeMap<String, String>,
}

struct MultipartCompleteChecksumState<'a> {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
    crc32: Option<crc::Digest<'a, u32>>,
    crc32c: Option<crc::Digest<'a, u32>>,
}

impl MultipartCompleteChecksumState<'static> {
    fn new(checksum_request: &ChecksumRequest) -> Self {
        Self {
            md5: checksum_request.requires_md5().then(Md5::new),
            sha1: checksum_request.requires_sha1().then(Sha1::new),
            sha256: checksum_request.requires_sha256().then(Sha256::new),
            sha512: checksum_request.requires_sha512().then(Sha512::new),
            crc32: checksum_request.requires_crc32().then(|| CRC32.digest()),
            crc32c: checksum_request.requires_crc32c().then(|| CRC32C.digest()),
        }
    }
}

impl MultipartCompleteChecksumState<'_> {
    fn update(&mut self, bytes: &[u8]) {
        if let Some(md5) = &mut self.md5 {
            md5.update(bytes);
        }
        if let Some(sha1) = &mut self.sha1 {
            sha1.update(bytes);
        }
        if let Some(sha256) = &mut self.sha256 {
            sha256.update(bytes);
        }
        if let Some(sha512) = &mut self.sha512 {
            sha512.update(bytes);
        }
        if let Some(crc32) = &mut self.crc32 {
            crc32.update(bytes);
        }
        if let Some(crc32c) = &mut self.crc32c {
            crc32c.update(bytes);
        }
    }

    fn finalize(self) -> ChecksumDigests {
        ChecksumDigests {
            md5: self
                .md5
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha1: self
                .sha1
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha256: self
                .sha256
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha512: self
                .sha512
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            crc32: self
                .crc32
                .map(|digest| digest.finalize())
                .unwrap_or_default(),
            crc32c: self
                .crc32c
                .map(|digest| digest.finalize())
                .unwrap_or_default(),
        }
    }
}

fn object_digest(bucket: &BucketName, key: &ObjectKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bucket.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(key.as_str().as_bytes());
    hex::encode(hasher.finalize())
}

async fn create_parent_dir(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path.parent() else {
        return Err(StoreError::InvalidPath(path.to_path_buf()));
    };
    fs::create_dir_all(parent).await?;
    Ok(())
}

async fn remove_file_if_exists(path: PathBuf) -> Result<(), StoreError> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StoreError::Io(error)),
    }
}

async fn backup_existing_file(source: &Path, backup: &Path) -> Result<bool, StoreError> {
    match fs::hard_link(source, backup).await {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(StoreError::Io(error)),
    }
}

async fn remove_backup_file(path: &Path, exists: bool) -> Result<(), StoreError> {
    if exists {
        remove_file_if_exists(path.to_path_buf()).await?;
    }
    Ok(())
}

async fn rollback_published_file(path: &Path, backup: &Path, had_previous: bool) {
    let _ = remove_file_if_exists(path.to_path_buf()).await;
    if had_previous {
        let _ = fs::rename(backup, path).await;
    }
}

#[derive(Debug, Error)]
/// Errors returned by filesystem object and multipart stores.
pub enum StoreError {
    /// Filesystem I/O failed.
    #[error("storage I/O failed")]
    Io(#[from] std::io::Error),

    /// Persisted JSON metadata could not be encoded or decoded.
    #[error("failed to encode or decode storage metadata")]
    Json(#[from] serde_json::Error),

    /// A persisted file path did not match the expected storage layout.
    #[error("invalid storage path: {0}")]
    InvalidPath(PathBuf),

    /// An upload ID was not a canonical UUID path segment.
    #[error("invalid upload ID")]
    InvalidUploadId,

    /// The requested multipart upload does not exist or is no longer open.
    #[error("multipart upload does not exist")]
    NoSuchUpload,

    /// The requested multipart part is missing, duplicated, or inconsistent.
    #[error("multipart upload part is invalid")]
    InvalidPart,

    /// A non-final multipart part is below the configured minimum size.
    #[error("multipart upload part is smaller than the minimum allowed size")]
    EntityTooSmall,

    /// An object, part, or completed multipart object exceeds configured limits.
    #[error("entity is larger than the maximum allowed size")]
    EntityTooLarge,

    /// Final object checksum validation failed.
    #[error("checksum validation failed")]
    Checksum(S3Error),

    /// Upload middleware rejected or failed a staged object.
    #[error("upload processor failed")]
    Processor(S3Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    #[test]
    fn upload_session_deserialization_defaults_missing_state_to_open() {
        let upload_id = UploadId::new();
        let upload_id_value = upload_id.as_str();
        let json = format!(
            r#"{{
              "upload_id": "{upload_id_value}",
              "bucket": "test-bucket",
              "key": "key.txt",
              "initiated": "2026-06-16T00:00:00Z",
              "metadata": {{}},
              "parts": {{}}
            }}"#
        );

        let session = serde_json::from_str::<UploadSession>(&json).expect("session");

        assert_eq!(session.state, UploadState::Open);
        assert!(session.owner_access_key_id.is_none());
        assert!(session.is_open());
    }

    #[test]
    fn upload_metadata_serializes_checksum_enums_as_s3_values() {
        let metadata = UploadMetadata {
            checksum_algorithm: Some(ChecksumAlgorithm::Crc32c),
            checksum_type: Some(ChecksumType::FullObject),
            ..UploadMetadata::default()
        };

        let json = serde_json::to_value(&metadata).expect("serialize metadata");

        assert_eq!(json["checksum_algorithm"], "CRC32C");
        assert_eq!(json["checksum_type"], "FULL_OBJECT");
        assert_eq!(
            serde_json::from_value::<UploadMetadata>(json)
                .expect("deserialize metadata")
                .checksum_algorithm,
            Some(ChecksumAlgorithm::Crc32c)
        );
    }

    #[tokio::test]
    async fn multipart_store_rejects_part_creation_for_non_open_upload() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileMultipartStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("store");
        let upload_id = UploadId::new();
        let session = UploadSession {
            upload_id: upload_id.clone(),
            bucket: BucketName::parse("test-bucket").expect("bucket"),
            key: ObjectKey::parse("key.txt").expect("key"),
            initiated: Utc::now(),
            state: UploadState::Completing,
            owner_access_key_id: None,
            metadata: UploadMetadata::default(),
            parts: BTreeMap::new(),
        };
        store.sessions.insert(upload_id.clone(), session);

        let result = store
            .create_temp_part(&upload_id, PartNumber::parse(1).expect("part number"))
            .await;

        assert!(matches!(result, Err(StoreError::NoSuchUpload)));
    }

    #[tokio::test]
    async fn multipart_store_startup_removes_terminal_upload_sessions() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let open_upload_id = UploadId::new();
        let completed_upload_id = UploadId::new();
        let aborted_upload_id = UploadId::new();

        for (upload_id, state) in [
            (open_upload_id.clone(), UploadState::Open),
            (completed_upload_id.clone(), UploadState::Completed),
            (aborted_upload_id.clone(), UploadState::Aborted),
        ] {
            let upload_dir = temp_dir.path().join("multipart").join(upload_id.as_str());
            std::fs::create_dir_all(upload_dir.join("parts")).expect("create upload dir");
            let session = UploadSession {
                upload_id,
                bucket: BucketName::parse("test-bucket").expect("bucket"),
                key: ObjectKey::parse("key.txt").expect("key"),
                initiated: Utc::now(),
                state,
                owner_access_key_id: None,
                metadata: UploadMetadata::default(),
                parts: BTreeMap::new(),
            };
            std::fs::write(
                upload_dir.join("session.json"),
                serde_json::to_vec_pretty(&session).expect("session json"),
            )
            .expect("write session");
        }

        let store = FileMultipartStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("store");

        assert!(store.get_upload(&open_upload_id).is_some());
        assert!(store.get_upload(&completed_upload_id).is_none());
        assert!(store.get_upload(&aborted_upload_id).is_none());
        assert!(
            temp_dir
                .path()
                .join("multipart")
                .join(open_upload_id.as_str())
                .exists()
        );
        assert!(
            !temp_dir
                .path()
                .join("multipart")
                .join(completed_upload_id.as_str())
                .exists()
        );
        assert!(
            !temp_dir
                .path()
                .join("multipart")
                .join(aborted_upload_id.as_str())
                .exists()
        );
    }

    #[test]
    fn multipart_complete_checksum_state_is_empty_without_requested_checksums() {
        let headers = HeaderMap::new();
        let request = ChecksumRequest::from_headers(&headers).expect("checksum request");

        let state = MultipartCompleteChecksumState::new(&request);

        assert!(state.md5.is_none());
        assert!(state.sha1.is_none());
        assert!(state.sha256.is_none());
        assert!(state.sha512.is_none());
        assert!(state.crc32.is_none());
        assert!(state.crc32c.is_none());
    }

    #[test]
    fn multipart_complete_checksum_state_enables_requested_digests() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "content-md5",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
        );
        headers.insert(
            "x-amz-checksum-crc32c",
            HeaderValue::from_static("AAAAAA=="),
        );
        headers.insert(
            "x-amz-checksum-sha1",
            HeaderValue::from_str(&BASE64.encode([0_u8; 20])).expect("header"),
        );
        let request = ChecksumRequest::from_headers(&headers).expect("checksum request");

        let state = MultipartCompleteChecksumState::new(&request);

        assert!(state.md5.is_some());
        assert!(state.sha1.is_some());
        assert!(state.sha256.is_none());
        assert!(state.sha512.is_none());
        assert!(state.crc32.is_none());
        assert!(state.crc32c.is_some());
    }
}
