use std::{path::PathBuf, sync::Arc};

use futures_util::future::BoxFuture;
use thiserror::Error;
use tokio::fs::File;

mod checksum;
mod complete_checksum;
mod fs_util;
mod model;
mod multipart;
mod object;
mod temp;

use crate::error::S3Error;
use crate::{
    body::checksum::ChecksumRequest,
    config::{AccessKeyId, IoTuning, UploadLimits},
    s3::types::{BucketName, ObjectKey, PartNumber},
};

pub use crate::s3::types::UploadId;
pub use checksum::{ChecksumAlgorithm, ChecksumType};
pub use model::{
    CommittedPart, CompletedPart, ObjectMetadata, PartMetadata, UploadMetadata, UploadProcessing,
    UploadSession, UploadState,
};
pub use multipart::FileMultipartStore;
pub use object::FileObjectStore;
pub use temp::{StagedObject, TempObjectWriter, TempPartWriter};

/// Shared object store implementation.
pub type SharedObjectStore = Arc<dyn ObjectStore>;
/// Shared multipart store implementation.
pub type SharedMultipartStore = Arc<dyn MultipartStore>;

/// Object storage boundary used by request handlers.
///
/// The default implementation is [`FileObjectStore`]. Custom implementations
/// can wrap the filesystem store or provide alternate persistence while
/// preserving the same S3-visible behavior.
pub trait ObjectStore: Send + Sync + 'static {
    /// Creates a temporary object writer for a bucket/key.
    fn create_temp_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<TempObjectWriter, StoreError>>;

    /// Atomically publishes a staged object and metadata.
    fn commit_staged_object<'a>(
        &'a self,
        staged: StagedObject,
        metadata: ObjectMetadata,
    ) -> BoxFuture<'a, Result<(), StoreError>>;

    /// Reads committed object metadata.
    fn head_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<Option<ObjectMetadata>, StoreError>>;

    /// Opens a committed object for streaming.
    fn open_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<Option<(ObjectMetadata, File)>, StoreError>>;

    /// Deletes object metadata and bytes.
    fn delete_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<(), StoreError>>;
}

impl ObjectStore for FileObjectStore {
    fn create_temp_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<TempObjectWriter, StoreError>> {
        Box::pin(FileObjectStore::create_temp_object(self, bucket, key))
    }

    fn commit_staged_object<'a>(
        &'a self,
        staged: StagedObject,
        metadata: ObjectMetadata,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(FileObjectStore::commit_staged_object(
            self, staged, metadata,
        ))
    }

    fn head_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<Option<ObjectMetadata>, StoreError>> {
        Box::pin(FileObjectStore::head_object(self, bucket, key))
    }

    fn open_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<Option<(ObjectMetadata, File)>, StoreError>> {
        Box::pin(FileObjectStore::open_object(self, bucket, key))
    }

    fn delete_object<'a>(
        &'a self,
        bucket: &'a BucketName,
        key: &'a ObjectKey,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(FileObjectStore::delete_object(self, bucket, key))
    }
}

/// Inputs for completing a multipart upload.
pub struct CompleteUploadRequest<'a> {
    /// Object store that receives the completed object.
    pub object_store: &'a dyn ObjectStore,
    /// Multipart upload ID.
    pub upload_id: &'a UploadId,
    /// Client-requested parts in completion order.
    pub requested_parts: &'a [CompletedPart],
    /// Requested checksum validation.
    pub checksum_request: &'a ChecksumRequest,
    /// Upload size limits.
    pub upload_limits: &'a UploadLimits,
    /// I/O buffer tuning.
    pub io_tuning: &'a IoTuning,
    /// Upload processing context.
    pub processing: UploadProcessing<'a>,
}

/// Multipart storage boundary used by request handlers.
pub trait MultipartStore: Send + Sync + 'static {
    /// Creates and persists a new multipart upload session.
    fn create_upload<'a>(
        &'a self,
        bucket: BucketName,
        key: ObjectKey,
        owner_access_key_id: Option<AccessKeyId>,
        metadata: UploadMetadata,
    ) -> BoxFuture<'a, Result<UploadSession, StoreError>>;

    /// Returns a snapshot of an upload session.
    fn get_upload(&self, upload_id: &UploadId) -> Option<UploadSession>;

    /// Creates a temporary part writer for an open upload.
    fn create_temp_part<'a>(
        &'a self,
        upload_id: &'a UploadId,
        part_number: PartNumber,
    ) -> BoxFuture<'a, Result<TempPartWriter, StoreError>>;

    /// Atomically publishes a temporary part.
    fn commit_part<'a>(
        &'a self,
        upload_id: &'a UploadId,
        part_number: PartNumber,
        temp: TempPartWriter,
        part: CommittedPart,
    ) -> BoxFuture<'a, Result<PartMetadata, StoreError>>;

    /// Aborts an open upload and deletes its temporary storage.
    fn abort_upload<'a>(&'a self, upload_id: &'a UploadId)
    -> BoxFuture<'a, Result<(), StoreError>>;

    /// Completes an open multipart upload into a committed object.
    fn complete_upload<'a>(
        &'a self,
        request: CompleteUploadRequest<'a>,
    ) -> BoxFuture<'a, Result<ObjectMetadata, StoreError>>;
}

impl MultipartStore for FileMultipartStore {
    fn create_upload<'a>(
        &'a self,
        bucket: BucketName,
        key: ObjectKey,
        owner_access_key_id: Option<AccessKeyId>,
        metadata: UploadMetadata,
    ) -> BoxFuture<'a, Result<UploadSession, StoreError>> {
        Box::pin(FileMultipartStore::create_upload(
            self,
            bucket,
            key,
            owner_access_key_id,
            metadata,
        ))
    }

    fn get_upload(&self, upload_id: &UploadId) -> Option<UploadSession> {
        FileMultipartStore::get_upload(self, upload_id)
    }

    fn create_temp_part<'a>(
        &'a self,
        upload_id: &'a UploadId,
        part_number: PartNumber,
    ) -> BoxFuture<'a, Result<TempPartWriter, StoreError>> {
        Box::pin(FileMultipartStore::create_temp_part(
            self,
            upload_id,
            part_number,
        ))
    }

    fn commit_part<'a>(
        &'a self,
        upload_id: &'a UploadId,
        part_number: PartNumber,
        temp: TempPartWriter,
        part: CommittedPart,
    ) -> BoxFuture<'a, Result<PartMetadata, StoreError>> {
        Box::pin(FileMultipartStore::commit_part(
            self,
            upload_id,
            part_number,
            temp,
            part,
        ))
    }

    fn abort_upload<'a>(
        &'a self,
        upload_id: &'a UploadId,
    ) -> BoxFuture<'a, Result<(), StoreError>> {
        Box::pin(FileMultipartStore::abort_upload(self, upload_id))
    }

    fn complete_upload<'a>(
        &'a self,
        request: CompleteUploadRequest<'a>,
    ) -> BoxFuture<'a, Result<ObjectMetadata, StoreError>> {
        Box::pin(FileMultipartStore::complete_upload(self, request))
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
    use crate::{
        body::checksum::ChecksumRequest,
        config::UploadLimits,
        s3::types::{BucketName, ETag, ObjectKey, PartNumber, RequestId},
        storage::complete_checksum::MultipartCompleteChecksumState,
    };
    use axum::http::{HeaderMap, HeaderValue};
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use chrono::{TimeZone, Utc};
    use std::{collections::BTreeMap, sync::Arc, time::Duration};

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
    async fn multipart_completion_failure_restores_upload_to_open() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let object_store = FileObjectStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("object store");
        let multipart_store = FileMultipartStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("multipart store");
        let upload = multipart_store
            .create_upload(
                BucketName::parse("test-bucket").expect("bucket"),
                ObjectKey::parse("key.txt").expect("key"),
                None,
                UploadMetadata::default(),
            )
            .await
            .expect("create upload");
        let checksum_request =
            ChecksumRequest::from_headers(&HeaderMap::new()).expect("empty checksum request");

        let result = multipart_store
            .complete_upload(CompleteUploadRequest {
                object_store: &object_store,
                upload_id: &upload.upload_id,
                requested_parts: &[CompletedPart {
                    part_number: PartNumber::parse(1).expect("part number"),
                    etag: ETag::parse("\"missing\"").expect("etag"),
                }],
                checksum_request: &checksum_request,
                upload_limits: &UploadLimits::default(),
                io_tuning: &crate::config::IoTuning::default(),
                processing: UploadProcessing {
                    request_id: &RequestId::new(),
                    upload_processors: &[],
                },
            })
            .await;

        assert!(matches!(result, Err(StoreError::InvalidPart)));
        let upload = multipart_store
            .get_upload(&upload.upload_id)
            .expect("upload remains");
        assert_eq!(upload.state, UploadState::Open);
        multipart_store
            .create_temp_part(
                &upload.upload_id,
                PartNumber::parse(1).expect("part number"),
            )
            .await
            .expect("part creation after failed completion");
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

    #[tokio::test]
    async fn multipart_store_startup_removes_expired_open_upload_sessions() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let upload_id = UploadId::new();
        let upload_dir = temp_dir.path().join("multipart").join(upload_id.as_str());
        std::fs::create_dir_all(upload_dir.join("parts")).expect("create upload dir");
        let now = Utc
            .with_ymd_and_hms(2026, 6, 17, 12, 0, 0)
            .single()
            .expect("current time");
        let session = UploadSession {
            upload_id: upload_id.clone(),
            bucket: BucketName::parse("test-bucket").expect("bucket"),
            key: ObjectKey::parse("key.txt").expect("key"),
            initiated: now - chrono::Duration::hours(2),
            state: UploadState::Open,
            owner_access_key_id: None,
            metadata: UploadMetadata::default(),
            parts: BTreeMap::new(),
        };
        std::fs::write(
            upload_dir.join("session.json"),
            serde_json::to_vec_pretty(&session).expect("session json"),
        )
        .expect("write session");

        let store = FileMultipartStore::new_with_options(
            temp_dir.path().to_path_buf(),
            crate::config::MultipartLifecycle::builder()
                .abort_incomplete_after(Duration::from_secs(60 * 60))
                .build(),
            Arc::new(move || now),
        )
        .await
        .expect("store");

        assert!(store.get_upload(&upload_id).is_none());
        assert!(!upload_dir.exists());
    }

    #[test]
    fn multipart_complete_checksum_state_is_empty_without_requested_checksums() {
        let headers = HeaderMap::new();
        let request = ChecksumRequest::from_headers(&headers).expect("checksum request");

        let state = MultipartCompleteChecksumState::new(&request);
        let enabled = state.enabled_digests();

        assert!(!enabled.md5);
        assert!(!enabled.sha1);
        assert!(!enabled.sha256);
        assert!(!enabled.sha512);
        assert!(!enabled.crc32);
        assert!(!enabled.crc32c);
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
        let enabled = state.enabled_digests();

        assert!(enabled.md5);
        assert!(enabled.sha1);
        assert!(!enabled.sha256);
        assert!(!enabled.sha512);
        assert!(!enabled.crc32);
        assert!(enabled.crc32c);
    }
}
