//! Developer tuning hooks for embedded S3 endpoint applications.

use std::{fmt, future::Future, sync::Arc};

use axum::http::Method;
use futures_util::future::BoxFuture;

use crate::{
    config::{AccessKeyId, S3Action},
    error::S3Error,
    s3::types::{BucketName, ObjectKey, PartNumber, RequestId, UploadId},
};

/// Shared request observer object.
pub type SharedRequestObserver = Arc<dyn RequestObserver>;
/// Shared error mapper object.
pub type SharedErrorMapper = Arc<dyn ErrorMapper>;
/// Shared request ID factory object.
pub type SharedRequestIdFactory = Arc<dyn RequestIdFactory>;
/// Shared authorization policy object.
pub type SharedAuthorizationPolicy = Arc<dyn AuthorizationPolicy>;

/// Authenticated principal visible to tuning hooks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestPrincipal {
    /// Anonymous request accepted by configuration.
    Anonymous,
    /// Signed request authenticated as an access key.
    AccessKey {
        /// Access key ID used by the request.
        access_key_id: AccessKeyId,
    },
}

/// Read-only S3 request metadata passed to request observers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3RequestContext {
    /// Request ID attached to this request.
    pub request_id: RequestId,
    /// HTTP method.
    pub method: Method,
    /// Detected S3 operation name or `InvalidRequest`.
    pub operation: String,
    /// Parsed bucket when target parsing succeeded.
    pub bucket: Option<BucketName>,
    /// Parsed object key when target parsing succeeded.
    pub key: Option<ObjectKey>,
    /// Multipart upload ID when present in the request query.
    pub upload_id: Option<UploadId>,
    /// Multipart part number when present in the request query.
    pub part_number: Option<PartNumber>,
    /// Raw request content length when provided.
    pub content_length: Option<u64>,
}

/// Error mapping context passed before an S3 XML error response is built.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3ErrorContext {
    /// Request ID attached to this request.
    pub request_id: RequestId,
    /// Detected S3 operation name or `InvalidRequest`.
    pub operation: String,
}

/// Authorization context passed to custom authorization policies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    /// Authenticated principal.
    pub principal: RequestPrincipal,
    /// Bucket being authorized.
    pub bucket: BucketName,
    /// Object key being authorized when the operation targets an object.
    pub key: Option<ObjectKey>,
    /// S3 action being authorized.
    pub action: S3Action,
}

/// Read-only observer for parsed S3 requests.
pub trait RequestObserver: Send + Sync + 'static {
    /// Observes a request. Returning normally must not change request handling.
    fn observe<'a>(&'a self, context: S3RequestContext) -> BoxFuture<'a, ()>;
}

impl<F, Fut> RequestObserver for F
where
    F: Fn(S3RequestContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn observe<'a>(&'a self, context: S3RequestContext) -> BoxFuture<'a, ()> {
        Box::pin((self)(context))
    }
}

/// Maps or logs S3 errors before they are converted to XML responses.
pub trait ErrorMapper: Send + Sync + 'static {
    /// Returns the error that should be rendered.
    fn map_error<'a>(&'a self, context: S3ErrorContext, error: S3Error) -> BoxFuture<'a, S3Error>;
}

impl<F, Fut> ErrorMapper for F
where
    F: Fn(S3ErrorContext, S3Error) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = S3Error> + Send + 'static,
{
    fn map_error<'a>(&'a self, context: S3ErrorContext, error: S3Error) -> BoxFuture<'a, S3Error> {
        Box::pin((self)(context, error))
    }
}

/// Creates request IDs for S3 responses and hooks.
pub trait RequestIdFactory: Send + Sync + 'static {
    /// Creates a request ID.
    fn request_id(&self) -> RequestId;
}

impl<F> RequestIdFactory for F
where
    F: Fn() -> RequestId + Send + Sync + 'static,
{
    fn request_id(&self) -> RequestId {
        (self)()
    }
}

/// Additional authorization policy evaluated after static allow-lists.
pub trait AuthorizationPolicy: Send + Sync + 'static {
    /// Returns `Ok(())` to allow the request or an S3 error to deny it.
    fn authorize(&self, context: AuthorizationContext) -> Result<(), S3Error>;
}

impl<F> AuthorizationPolicy for F
where
    F: Fn(AuthorizationContext) -> Result<(), S3Error> + Send + Sync + 'static,
{
    fn authorize(&self, context: AuthorizationContext) -> Result<(), S3Error> {
        (self)(context)
    }
}

impl fmt::Display for RequestPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => formatter.write_str("anonymous"),
            Self::AccessKey { access_key_id } => write!(formatter, "{access_key_id}"),
        }
    }
}
