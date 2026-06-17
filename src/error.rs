use axum::{
    http::{
        HeaderName, HeaderValue, StatusCode,
        header::{ALLOW, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
};

use crate::s3::types::RequestId;

/// S3 XML error response.
///
/// `S3Error` keeps the HTTP status, S3 error code, user-facing message,
/// optional resource, and extra response headers together until the HTTP
/// boundary converts it to an XML response. Constructors are named after the
/// S3 error code or behavior they represent.
#[derive(Clone, Debug)]
pub struct S3Error {
    status: StatusCode,
    code: &'static str,
    message: String,
    resource: Option<String>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl S3Error {
    /// Returns a `400 InvalidRequest` error.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidRequest", message)
    }

    /// Returns a `400 InvalidArgument` error.
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidArgument", message)
    }

    /// Returns a `400 MalformedXML` error.
    pub fn malformed_xml(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "MalformedXML", message)
    }

    /// Returns a `404 NoSuchBucket` error for a bucket name.
    pub fn no_such_bucket(bucket: impl Into<String>) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            format!("The specified bucket does not exist: {}", bucket.into()),
        )
    }

    /// Returns a `404 NoSuchKey` error.
    pub fn no_such_key() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "The specified key does not exist.",
        )
    }

    /// Returns a `403 AccessDenied` error.
    pub fn access_denied(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "AccessDenied", message)
    }

    /// Returns a `400 AuthorizationHeaderMalformed` error.
    pub fn authorization_header_malformed(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "AuthorizationHeaderMalformed",
            message,
        )
    }

    /// Returns a `403 SignatureDoesNotMatch` error.
    pub fn signature_does_not_match() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        )
    }

    /// Returns a `403 RequestTimeTooSkewed` error.
    pub fn request_time_too_skewed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "RequestTimeTooSkewed",
            "The difference between the request time and the server's time is too large.",
        )
    }

    /// Returns a `411 MissingContentLength` error.
    pub fn missing_content_length() -> Self {
        Self::new(
            StatusCode::LENGTH_REQUIRED,
            "MissingContentLength",
            "You must provide the Content-Length HTTP header.",
        )
    }

    /// Returns a `400 BadDigest` error.
    pub fn bad_digest(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BadDigest", message)
    }

    /// Returns a `404 NoSuchUpload` error.
    pub fn no_such_upload() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "The specified multipart upload does not exist.",
        )
    }

    /// Returns a `400 InvalidPart` error.
    pub fn invalid_part(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "InvalidPart", message)
    }

    /// Returns a `400 EntityTooSmall` error.
    pub fn entity_too_small(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "EntityTooSmall", message)
    }

    /// Returns a `413 EntityTooLarge` error.
    pub fn entity_too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "EntityTooLarge", message)
    }

    /// Returns a `503 SlowDown` error.
    pub fn slow_down(message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "SlowDown", message)
    }

    /// Returns a `416 InvalidRange` error.
    pub fn invalid_range(message: impl Into<String>) -> Self {
        Self::new(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", message)
    }

    /// Returns a `412 PreconditionFailed` error.
    pub fn precondition_failed(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "PreconditionFailed",
            message,
        )
    }

    /// Returns a `405 MethodNotAllowed` error with the endpoint's `Allow` header.
    pub fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
            "The specified method is not allowed against this resource.",
        )
        .with_header(
            ALLOW,
            HeaderValue::from_static("DELETE, GET, HEAD, POST, PUT"),
        )
    }

    /// Returns a `501 NotImplemented` error.
    pub fn not_implemented(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "NotImplemented", message)
    }

    /// Returns a `500 InternalError` error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", message)
    }

    /// Attaches the S3 resource path included in the XML error body.
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Attaches an HTTP response header to the eventual error response.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Converts the error into an S3 XML response using a known request ID.
    pub fn into_response_with_request_id(self, request_id: &RequestId) -> Response {
        let mut response = (self.status, self.to_xml(request_id)).into_response();
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        for (name, value) in self.headers {
            response.headers_mut().insert(name, value);
        }
        if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
            response.headers_mut().insert("x-amz-request-id", value);
        }
        response
    }

    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            resource: None,
            headers: Vec::new(),
        }
    }

    fn to_xml(&self, request_id: &RequestId) -> String {
        let resource = self
            .resource
            .as_ref()
            .map(|resource| format!("  <Resource>{}</Resource>\n", escape_xml(resource)))
            .unwrap_or_default();

        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error>\n\
             \x20 <Code>{}</Code>\n\
             \x20 <Message>{}</Message>\n\
             {}\
             \x20 <RequestId>{}</RequestId>\n\
             </Error>\n",
            self.code,
            escape_xml(&self.message),
            resource,
            request_id.as_str()
        )
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let request_id = RequestId::new();
        self.into_response_with_request_id(&request_id)
    }
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
