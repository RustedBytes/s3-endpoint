//! Typed S3-aware upload middleware.
//!
//! Upload processors run after S3 request authentication, payload decoding, and
//! client checksum validation, but before object bytes are committed to storage.
//! They are intended for decoded-object workflows such as antivirus scanning or
//! media normalization that cannot safely operate as generic HTTP body
//! middleware.

use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
};

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

/// Owned convenience handle passed to closure-based upload processors.
#[derive(Clone, Debug)]
pub struct UploadProcessorHandle {
    context: UploadProcessorContext,
    current_path: PathBuf,
    replacement_path: PathBuf,
}

impl UploadProcessorHandle {
    fn from_request(request: UploadProcessorRequest<'_>) -> Self {
        Self {
            context: request.context.clone(),
            current_path: request.current_path.to_path_buf(),
            replacement_path: request.replacement_path.to_path_buf(),
        }
    }

    /// Upload metadata and target identity.
    pub fn context(&self) -> &UploadProcessorContext {
        &self.context
    }

    /// Path to the current staged object bytes.
    pub fn current_path(&self) -> &Path {
        &self.current_path
    }

    /// Reserved path where replacement bytes may be written.
    pub fn replacement_path(&self) -> &Path {
        &self.replacement_path
    }

    /// Reads the current staged object into memory.
    ///
    /// This helper is intended for simple processors. Large-object processors
    /// can stream directly from [`Self::current_path`].
    pub async fn read_current(&self) -> Result<Vec<u8>, UploadProcessorError> {
        tokio::fs::read(&self.current_path)
            .await
            .map_err(UploadProcessorError::from)
    }

    /// Writes replacement bytes to the reserved replacement path.
    pub async fn write_replacement(
        &self,
        bytes: impl AsRef<[u8]>,
    ) -> Result<(), UploadProcessorError> {
        tokio::fs::write(&self.replacement_path, bytes)
            .await
            .map_err(UploadProcessorError::from)
    }

    /// Keeps the current staged bytes unchanged.
    pub fn keep(&self) -> UploadProcessorAction {
        UploadProcessorAction::Keep
    }

    /// Replaces current staged bytes with the file written to the replacement path.
    pub fn replace(&self) -> UploadProcessorAction {
        UploadProcessorAction::Replace
    }

    /// Rejects the upload with an S3 `AccessDenied` response.
    pub fn reject(
        &self,
        message: impl Into<String>,
    ) -> Result<UploadProcessorAction, UploadProcessorError> {
        Err(UploadProcessorError::Rejected(message.into()))
    }

    /// Fails the upload with an S3 `InternalError` response.
    pub fn fail(
        &self,
        message: impl Into<String>,
    ) -> Result<UploadProcessorAction, UploadProcessorError> {
        Err(UploadProcessorError::Failed(message.into()))
    }
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

/// Closure-backed upload processor adapter.
pub struct UploadProcessorFn<F> {
    name: String,
    handler: F,
}

impl<F> UploadProcessorFn<F> {
    /// Creates a closure-backed upload processor.
    pub fn new(name: impl Into<String>, handler: F) -> Self {
        Self {
            name: name.into(),
            handler,
        }
    }

    /// Returns the diagnostic processor name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl<F, Fut> UploadProcessor for UploadProcessorFn<F>
where
    F: Fn(UploadProcessorHandle) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<UploadProcessorAction, UploadProcessorError>> + Send + 'static,
{
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        let handle = UploadProcessorHandle::from_request(request);
        Box::pin((self.handler)(handle))
    }
}

/// Runs upload processors sequentially against staged object bytes.
///
/// Each processor may keep the current bytes or replace them with its reserved
/// replacement file. On rejection or failure, staged bytes are discarded.
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

impl From<std::io::Error> for UploadProcessorError {
    fn from(error: std::io::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

/// Returns whether no upload processors are configured.
pub(crate) fn processors_are_empty(processors: &[SharedUploadProcessor]) -> bool {
    processors.is_empty()
}
