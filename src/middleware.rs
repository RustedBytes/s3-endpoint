//! Typed S3-aware upload middleware.
//!
//! Upload processors run after S3 request authentication, payload decoding, and
//! client checksum validation, but before object bytes are committed to storage.
//! They are intended for decoded-object workflows such as antivirus scanning or
//! media normalization that cannot safely operate as generic HTTP body
//! middleware.

use std::{collections::BTreeMap, fmt, path::Path, sync::Arc};

use futures_util::future::BoxFuture;
use uuid::Uuid;

use crate::{
    error::S3Error,
    s3::types::{BucketName, ContentLength, ObjectKey, RequestId},
    storage::{StagedObject, StoreError},
};

/// Shared upload processor object.
pub type SharedUploadProcessor = Arc<dyn UploadProcessor>;

/// Operation that produced a staged object for processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadProcessorOperation {
    /// A single-request `PutObject` upload.
    PutObject,
    /// A completed multipart upload after parts have been assembled.
    CompleteMultipartUpload,
}

/// Stable upload metadata available to processors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadProcessorContext {
    /// Request ID returned to the client for this S3 request.
    pub request_id: RequestId,
    /// Bucket being written.
    pub bucket: BucketName,
    /// Object key being written.
    pub key: ObjectKey,
    /// S3 operation that produced the staged object.
    pub operation: UploadProcessorOperation,
    /// Decoded client-upload size before processors run.
    pub original_size: ContentLength,
    /// Optional `Content-Type` metadata supplied by the client.
    pub content_type: Option<String>,
    /// User metadata headers keyed by lowercase `x-amz-meta-*` names.
    pub user_metadata: BTreeMap<String, String>,
}

/// Per-processor file paths.
pub struct UploadProcessorRequest<'a> {
    /// Upload metadata and target identity.
    pub context: &'a UploadProcessorContext,
    /// Path to the current staged object bytes.
    pub current_path: &'a Path,
    /// Reserved path where a processor may write replacement bytes.
    pub replacement_path: &'a Path,
}

/// Processor decision for a staged upload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadProcessorAction {
    /// Keep the current staged bytes unchanged.
    Keep,
    /// Replace current staged bytes with the file written to `replacement_path`.
    Replace,
}

/// Error returned by an upload processor.
#[derive(Debug)]
pub enum UploadProcessorError {
    /// The upload is intentionally rejected, for example because a scanner found
    /// unsafe content.
    Rejected(String),
    /// The processor failed internally and the upload result is unknown.
    Failed(String),
}

impl fmt::Display for UploadProcessorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(message) | Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UploadProcessorError {}

/// In-process processor for decoded S3 uploads.
pub trait UploadProcessor: Send + Sync + 'static {
    /// Inspect or replace a staged upload file.
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>>;
}

pub(crate) async fn process_staged_upload(
    processors: &[SharedUploadProcessor],
    mut staged: StagedObject,
    context: UploadProcessorContext,
) -> Result<StagedObject, S3Error> {
    for processor in processors {
        let replacement_path = staged.replacement_path(Uuid::new_v4());
        let action = match processor
            .process(UploadProcessorRequest {
                context: &context,
                current_path: staged.path(),
                replacement_path: &replacement_path,
            })
            .await
        {
            Ok(action) => action,
            Err(error) => {
                remove_unused_replacement(&replacement_path).await?;
                let _ = staged.discard().await;
                return Err(map_processor_error(error));
            }
        };

        match action {
            UploadProcessorAction::Keep => remove_unused_replacement(&replacement_path).await?,
            UploadProcessorAction::Replace => {
                match staged.replace_with(replacement_path).await {
                    Ok(()) => {}
                    Err(error) => {
                        let _ = staged.discard().await;
                        return Err(S3Error::internal(format!(
                            "failed to replace staged upload: {error}"
                        )));
                    }
                };
            }
        }
    }

    Ok(staged)
}

fn map_processor_error(error: UploadProcessorError) -> S3Error {
    match error {
        UploadProcessorError::Rejected(message) => S3Error::access_denied(message),
        UploadProcessorError::Failed(message) => {
            S3Error::internal(format!("upload processor failed: {message}"))
        }
    }
}

async fn remove_unused_replacement(path: &Path) -> Result<(), S3Error> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(S3Error::internal(format!(
            "failed to remove unused upload processor replacement file: {error}"
        ))),
    }
}

impl From<StoreError> for UploadProcessorError {
    fn from(error: StoreError) -> Self {
        Self::Failed(error.to_string())
    }
}

pub(crate) fn processors_are_empty(processors: &[SharedUploadProcessor]) -> bool {
    processors.is_empty()
}
