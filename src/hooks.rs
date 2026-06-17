//! Developer tuning hooks for embedded S3 endpoint applications.

use std::{fmt, future::Future, sync::Arc};

use axum::{
    http::{HeaderMap, Method, Uri},
    response::Response,
};
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;

use crate::{
    config::{AccessKeyId, S3Action},
    error::S3Error,
    s3::types::{BucketName, ObjectKey, PartNumber, RequestId, S3Operation, UploadId},
};

/// Shared request observer object.
pub type SharedRequestObserver = Arc<dyn RequestObserver>;
/// Shared error mapper object.
pub type SharedErrorMapper = Arc<dyn ErrorMapper>;
/// Shared request ID factory object.
pub type SharedRequestIdFactory = Arc<dyn RequestIdFactory>;
/// Shared authorization policy object.
pub type SharedAuthorizationPolicy = Arc<dyn AuthorizationPolicy>;
/// Shared authentication provider object.
pub type SharedAuthenticationProvider = Arc<dyn AuthenticationProvider>;
/// Shared operation policy object.
pub type SharedOperationPolicy = Arc<dyn OperationPolicy>;
/// Shared target policy object.
pub type SharedTargetPolicy = Arc<dyn TargetPolicy>;
/// Shared upload policy object.
pub type SharedUploadPolicy = Arc<dyn UploadPolicy>;
/// Shared response mapper object.
pub type SharedResponseMapper = Arc<dyn ResponseMapper>;
/// Shared clock object.
pub type SharedClock = Arc<dyn Clock>;

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
    /// Application-defined authenticated principal.
    Custom {
        /// Stable principal identifier.
        id: String,
    },
}

/// Request data passed to a custom authentication provider.
#[derive(Clone, Debug)]
pub struct AuthenticationRequest {
    /// HTTP method.
    pub method: Method,
    /// Full request URI.
    pub uri: Uri,
    /// Request headers.
    pub headers: HeaderMap,
}

/// Authentication result returned by a custom provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationResult {
    principal: RequestPrincipal,
    access_key_id: Option<AccessKeyId>,
}

impl AuthenticationResult {
    /// Authenticates the request as an anonymous principal.
    pub fn anonymous() -> Self {
        Self {
            principal: RequestPrincipal::Anonymous,
            access_key_id: None,
        }
    }

    /// Authenticates the request as an access-key principal.
    pub fn access_key(access_key_id: AccessKeyId) -> Self {
        Self {
            principal: RequestPrincipal::AccessKey {
                access_key_id: access_key_id.clone(),
            },
            access_key_id: Some(access_key_id),
        }
    }

    /// Authenticates the request as an application-defined principal.
    pub fn custom(id: impl Into<String>) -> Self {
        Self {
            principal: RequestPrincipal::Custom { id: id.into() },
            access_key_id: None,
        }
    }

    /// Returns the authenticated principal.
    pub fn principal(&self) -> &RequestPrincipal {
        &self.principal
    }

    pub(crate) fn into_parts(self) -> (RequestPrincipal, Option<AccessKeyId>) {
        (self.principal, self.access_key_id)
    }
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

/// Response mapping context passed before an HTTP response is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S3ResponseContext {
    /// Request ID attached to this request.
    pub request_id: RequestId,
    /// Detected S3 operation name or `InvalidRequest`.
    pub operation: String,
    /// Parsed bucket when target parsing succeeded.
    pub bucket: Option<BucketName>,
    /// Parsed object key when target parsing succeeded.
    pub key: Option<ObjectKey>,
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

/// Operation policy context passed before an implemented operation is dispatched.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationContext {
    /// Parsed S3 operation.
    pub operation: S3Operation,
    /// IAM-style action for this operation.
    pub action: S3Action,
}

/// Target policy context passed after bucket/key parsing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetContext {
    /// Bucket being accessed.
    pub bucket: BucketName,
    /// Object key when the request targets an object.
    pub key: Option<ObjectKey>,
    /// S3 action being performed.
    pub action: S3Action,
}

/// Upload policy context passed before an upload body is accepted.
#[derive(Clone, Debug)]
pub struct UploadPolicyContext {
    /// Request ID attached to this request.
    pub request_id: RequestId,
    /// Bucket being written.
    pub bucket: BucketName,
    /// Object key being written.
    pub key: ObjectKey,
    /// S3 action being performed.
    pub action: S3Action,
    /// Request headers.
    pub headers: HeaderMap,
}

/// Read-only observer for parsed S3 requests.
pub trait RequestObserver: Send + Sync + 'static {
    /// Observes a request. Returning normally must not change request handling.
    fn observe<'a>(&'a self, context: S3RequestContext) -> BoxFuture<'a, ()>;
}

/// Custom authentication provider for embedded applications.
pub trait AuthenticationProvider: Send + Sync + 'static {
    /// Authenticates the request or returns an S3 error to reject it.
    fn authenticate<'a>(
        &'a self,
        request: AuthenticationRequest,
    ) -> BoxFuture<'a, Result<AuthenticationResult, S3Error>>;
}

impl<F, Fut> AuthenticationProvider for F
where
    F: Fn(AuthenticationRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<AuthenticationResult, S3Error>> + Send + 'static,
{
    fn authenticate<'a>(
        &'a self,
        request: AuthenticationRequest,
    ) -> BoxFuture<'a, Result<AuthenticationResult, S3Error>> {
        Box::pin((self)(request))
    }
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

/// Maps successful or error HTTP responses before they are returned.
pub trait ResponseMapper: Send + Sync + 'static {
    /// Returns the response that should be sent to the caller.
    fn map_response<'a>(
        &'a self,
        context: S3ResponseContext,
        response: Response,
    ) -> BoxFuture<'a, Response>;
}

impl<F, Fut> ResponseMapper for F
where
    F: Fn(S3ResponseContext, Response) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    fn map_response<'a>(
        &'a self,
        context: S3ResponseContext,
        response: Response,
    ) -> BoxFuture<'a, Response> {
        Box::pin((self)(context, response))
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

/// Additional operation policy evaluated before dispatch.
pub trait OperationPolicy: Send + Sync + 'static {
    /// Returns `Ok(())` to allow dispatch or an S3 error to reject it.
    fn allow_operation(&self, context: OperationContext) -> Result<(), S3Error>;
}

impl<F> OperationPolicy for F
where
    F: Fn(OperationContext) -> Result<(), S3Error> + Send + Sync + 'static,
{
    fn allow_operation(&self, context: OperationContext) -> Result<(), S3Error> {
        (self)(context)
    }
}

/// Additional bucket/key policy evaluated after target parsing.
pub trait TargetPolicy: Send + Sync + 'static {
    /// Returns `Ok(())` to allow the target or an S3 error to reject it.
    fn allow_target(&self, context: TargetContext) -> Result<(), S3Error>;
}

impl<F> TargetPolicy for F
where
    F: Fn(TargetContext) -> Result<(), S3Error> + Send + Sync + 'static,
{
    fn allow_target(&self, context: TargetContext) -> Result<(), S3Error> {
        (self)(context)
    }
}

/// Additional upload policy evaluated before upload bytes are read.
pub trait UploadPolicy: Send + Sync + 'static {
    /// Returns `Ok(())` to allow the upload or an S3 error to reject it.
    fn allow_upload(&self, context: UploadPolicyContext) -> Result<(), S3Error>;
}

impl<F> UploadPolicy for F
where
    F: Fn(UploadPolicyContext) -> Result<(), S3Error> + Send + Sync + 'static,
{
    fn allow_upload(&self, context: UploadPolicyContext) -> Result<(), S3Error> {
        (self)(context)
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

/// Clock used for object and multipart timestamps.
pub trait Clock: Send + Sync + 'static {
    /// Returns the current UTC timestamp.
    fn now(&self) -> DateTime<Utc>;
}

impl<F> Clock for F
where
    F: Fn() -> DateTime<Utc> + Send + Sync + 'static,
{
    fn now(&self) -> DateTime<Utc> {
        (self)()
    }
}

/// System UTC clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

impl fmt::Display for RequestPrincipal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => formatter.write_str("anonymous"),
            Self::AccessKey { access_key_id } => write!(formatter, "{access_key_id}"),
            Self::Custom { id } => formatter.write_str(id),
        }
    }
}
