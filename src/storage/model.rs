use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{ChecksumAlgorithm, ChecksumType, StoreError, UploadId};
use crate::{
    config::AccessKeyId,
    middleware::SharedUploadProcessor,
    s3::types::{BucketName, ETag, ObjectKey, PartNumber, RequestId},
};

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

    pub(super) fn ensure_open(&self) -> Result<(), StoreError> {
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
