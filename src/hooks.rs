//! Developer tuning hooks for embedded S3 endpoint applications.

use std::{fmt, future::Future, sync::Arc, time::Duration};

use axum::{
    http::{self, HeaderMap, HeaderValue, Method, StatusCode, Uri},
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
/// Shared tenant limits provider object.
pub type SharedTenantLimitsProvider = Arc<dyn TenantLimitsProvider>;

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

const MAX_TENANT_ID_LEN: usize = 256;

/// Stable tenant identifier used by tenant limit hooks.
///
/// Tenant IDs are security-relevant stable identifiers used for quota keys,
/// metrics, logs, and application-owned limit stores. Prefer [`TenantId::parse`]
/// when accepting IDs from custom authentication systems.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Creates a tenant ID without validation.
    ///
    /// This constructor is retained for source compatibility. New code should
    /// prefer [`TenantId::parse`] so empty, control-character, or oversized IDs
    /// are rejected before they reach quota keys, logs, or external stores.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Parses a tenant ID from an application-provided value.
    pub fn parse(value: impl Into<String>) -> Result<Self, TenantIdError> {
        let value = value.into();
        validate_tenant_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the tenant ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_principal(principal: &RequestPrincipal) -> Result<Self, TenantIdError> {
        match principal {
            RequestPrincipal::Anonymous => Self::parse("anonymous"),
            RequestPrincipal::AccessKey { access_key_id } => Self::parse(access_key_id.as_str()),
            RequestPrincipal::Custom { id } => Self::parse(id.clone()),
        }
    }
}

impl From<&RequestPrincipal> for TenantId {
    fn from(principal: &RequestPrincipal) -> Self {
        match principal {
            RequestPrincipal::Anonymous => Self::new("anonymous"),
            RequestPrincipal::AccessKey { access_key_id } => {
                Self::new(access_key_id.as_str().to_owned())
            }
            RequestPrincipal::Custom { id } => Self::new(id.clone()),
        }
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Tenant ID validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TenantIdError {
    /// Tenant ID is empty.
    Empty,
    /// Tenant ID is longer than the supported maximum.
    TooLong {
        /// Maximum accepted tenant ID length in bytes.
        max_len: usize,
    },
    /// Tenant ID contains an ASCII control character.
    ControlCharacter,
}

impl fmt::Display for TenantIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("tenant ID must not be empty"),
            Self::TooLong { max_len } => {
                write!(formatter, "tenant ID must be at most {max_len} bytes")
            }
            Self::ControlCharacter => {
                formatter.write_str("tenant ID must not contain control characters")
            }
        }
    }
}

impl std::error::Error for TenantIdError {}

fn validate_tenant_id(value: &str) -> Result<(), TenantIdError> {
    if value.is_empty() {
        return Err(TenantIdError::Empty);
    }
    if value.len() > MAX_TENANT_ID_LEN {
        return Err(TenantIdError::TooLong {
            max_len: MAX_TENANT_ID_LEN,
        });
    }
    if value.chars().any(char::is_control) {
        return Err(TenantIdError::ControlCharacter);
    }
    Ok(())
}

/// Request data passed to a custom authentication provider.
///
/// Headers can include credentials such as `Authorization`,
/// `x-amz-security-token`, signed headers, and application tokens. Avoid
/// logging them directly; use [`redacted_headers`] when diagnostic logging needs
/// header names and non-sensitive values.
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
    ///
    /// This constructor is retained for compatibility. Prefer
    /// [`AuthenticationResult::try_custom`] for user-supplied IDs so invalid
    /// tenant identifiers are rejected at the authentication boundary.
    pub fn custom(id: impl Into<String>) -> Self {
        Self {
            principal: RequestPrincipal::Custom { id: id.into() },
            access_key_id: None,
        }
    }

    /// Authenticates the request as a validated application-defined principal.
    pub fn try_custom(id: impl Into<String>) -> Result<Self, TenantIdError> {
        let tenant = TenantId::parse(id)?;
        Ok(Self::custom(tenant.as_str().to_owned()))
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
///
/// Headers can include signed request data, metadata, and application-provided
/// values. Avoid logging them directly; use [`redacted_headers`] for diagnostic
/// output.
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

/// Returns a copy of headers with security-sensitive values replaced.
///
/// This helper is intended for application hook diagnostics. It redacts common
/// S3 and HTTP credential headers while preserving other names and values.
pub fn redacted_headers(headers: &HeaderMap) -> HeaderMap {
    let mut redacted = headers.clone();
    for name in [
        http::header::AUTHORIZATION.as_str(),
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-amz-security-token",
        "x-amz-server-side-encryption-customer-key",
        "x-amz-server-side-encryption-customer-key-md5",
        "x-amz-server-side-encryption-context",
    ] {
        if redacted.contains_key(name) {
            redacted.insert(name, HeaderValue::from_static("<redacted>"));
        }
    }
    redacted
}

/// Per-tenant operation limit context passed before and after request handling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantLimitContext {
    /// Request ID attached to this request.
    pub request_id: RequestId,
    /// Derived tenant ID.
    pub tenant: TenantId,
    /// Authenticated principal.
    pub principal: RequestPrincipal,
    /// HTTP method.
    pub method: Method,
    /// Parsed S3 operation.
    pub operation: S3Operation,
    /// IAM-style action for this operation.
    pub action: S3Action,
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

/// Outcome passed to tenant limit providers after an operation finishes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantOperationOutcome {
    /// Final HTTP status before response mapping.
    pub status: StatusCode,
    /// Whether the operation failed because its timeout elapsed.
    pub timed_out: bool,
    /// S3 error code for failed operations.
    pub error_code: Option<String>,
    /// S3 error message for failed operations.
    pub error_message: Option<String>,
    /// Decoded bytes observed for completed uploads when known.
    pub decoded_bytes: Option<u64>,
}

impl TenantOperationOutcome {
    /// Builds a successful operation outcome from a response.
    pub fn success(status: StatusCode, decoded_bytes: Option<u64>) -> Self {
        Self {
            status,
            timed_out: false,
            error_code: None,
            error_message: None,
            decoded_bytes,
        }
    }

    /// Builds a failed operation outcome from an S3 error.
    pub fn error(error: &S3Error, decoded_bytes: Option<u64>) -> Self {
        Self {
            status: error.status(),
            timed_out: false,
            error_code: Some(error.code().to_owned()),
            error_message: Some(error.message().to_owned()),
            decoded_bytes,
        }
    }

    /// Builds an operation timeout outcome.
    pub fn timed_out(error: &S3Error) -> Self {
        Self {
            status: error.status(),
            timed_out: true,
            error_code: Some(error.code().to_owned()),
            error_message: Some(error.message().to_owned()),
            decoded_bytes: None,
        }
    }
}

/// Lease returned by tenant limit providers for an admitted operation.
pub struct TenantOperationLease {
    timeout: Option<Duration>,
    _permit: Option<Box<dyn Send + Sync>>,
}

impl TenantOperationLease {
    /// Creates a lease with no timeout or external permit.
    pub fn new() -> Self {
        Self {
            timeout: None,
            _permit: None,
        }
    }

    /// Creates a lease with an operation timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self::new().timeout(timeout)
    }

    /// Sets the operation timeout for this lease.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Adds an application-owned permit guard to this lease.
    pub fn permit<P>(mut self, permit: P) -> Self
    where
        P: Send + Sync + 'static,
    {
        self._permit = Some(Box::new(permit));
        self
    }

    /// Returns the configured timeout.
    pub fn timeout_duration(&self) -> Option<Duration> {
        self.timeout
    }
}

impl Default for TenantOperationLease {
    fn default() -> Self {
        Self::new()
    }
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

/// Per-tenant operation limits and quota hook.
pub trait TenantLimitsProvider: Send + Sync + 'static {
    /// Begins an operation or rejects it with an S3 error.
    fn begin_operation<'a>(
        &'a self,
        context: TenantLimitContext,
    ) -> BoxFuture<'a, Result<TenantOperationLease, S3Error>>;

    /// Observes the final operation outcome.
    fn finish_operation<'a>(
        &'a self,
        context: TenantLimitContext,
        outcome: TenantOperationOutcome,
    ) -> BoxFuture<'a, ()>;
}

/// No-op tenant limits provider used when no provider is configured.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTenantLimitsProvider;

impl TenantLimitsProvider for NoopTenantLimitsProvider {
    fn begin_operation<'a>(
        &'a self,
        _context: TenantLimitContext,
    ) -> BoxFuture<'a, Result<TenantOperationLease, S3Error>> {
        Box::pin(async { Ok(TenantOperationLease::new()) })
    }

    fn finish_operation<'a>(
        &'a self,
        _context: TenantLimitContext,
        _outcome: TenantOperationOutcome,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AccessKeyId;

    #[test]
    fn tenant_id_is_derived_from_request_principal() {
        assert_eq!(
            TenantId::from(&RequestPrincipal::Anonymous).as_str(),
            "anonymous"
        );
        assert_eq!(
            TenantId::from(&RequestPrincipal::AccessKey {
                access_key_id: AccessKeyId::parse("client-a").expect("access key")
            })
            .as_str(),
            "client-a"
        );
        assert_eq!(
            TenantId::from(&RequestPrincipal::Custom {
                id: "tenant-a".to_owned()
            })
            .as_str(),
            "tenant-a"
        );
    }

    #[test]
    fn tenant_id_parse_rejects_unsafe_values() {
        assert_eq!(TenantId::parse("").unwrap_err(), TenantIdError::Empty);
        assert_eq!(
            TenantId::parse("tenant\nid").unwrap_err(),
            TenantIdError::ControlCharacter
        );
        assert_eq!(
            TenantId::parse("x".repeat(MAX_TENANT_ID_LEN + 1)).unwrap_err(),
            TenantIdError::TooLong {
                max_len: MAX_TENANT_ID_LEN
            }
        );
    }

    #[test]
    fn authentication_result_try_custom_validates_id() {
        let result = AuthenticationResult::try_custom("tenant-a").expect("custom auth");
        assert_eq!(
            result.principal(),
            &RequestPrincipal::Custom {
                id: "tenant-a".to_owned()
            }
        );

        assert_eq!(
            AuthenticationResult::try_custom("tenant\rid").unwrap_err(),
            TenantIdError::ControlCharacter
        );
    }

    #[test]
    fn redacted_headers_masks_sensitive_values() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("secret"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("api-secret"));
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );

        let redacted = redacted_headers(&headers);
        assert_eq!(
            redacted.get(http::header::AUTHORIZATION),
            Some(&HeaderValue::from_static("<redacted>"))
        );
        assert_eq!(
            redacted.get("x-api-key"),
            Some(&HeaderValue::from_static("<redacted>"))
        );
        assert_eq!(
            redacted.get(http::header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/plain"))
        );
    }
}
