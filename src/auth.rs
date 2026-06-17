use std::collections::BTreeMap;

use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use http::{HeaderMap, Method, Uri};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    body::upload::payload_hash_mode,
    config::{AccessKeyId, AuthState, S3Action},
    error::S3Error,
    hooks::RequestPrincipal,
    s3::types::BucketName,
};

type HmacSha256 = Hmac<Sha256>;
const PRESIGNED_AUTH_FIELDS: &[&str] = &[
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-SignedHeaders",
    "X-Amz-Signature",
    "X-Amz-Security-Token",
];

/// Authenticates a request using SigV4 header auth, SigV4 presigned URL auth,
/// or explicitly enabled anonymous access.
///
/// Returns an [`AuthContext`] that identifies the authentication mode, access
/// key, and streaming signing state needed by aws-chunked body verification.
/// Recoverable authentication failures are mapped to S3 XML errors; malformed
/// signatures, invalid timestamps, unsupported algorithms, missing signed
/// headers, invalid session tokens, and unknown credentials never panic.
pub fn authenticate(
    config: &AuthState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<AuthContext, S3Error> {
    let authorization_values = headers
        .get_all(http::header::AUTHORIZATION)
        .iter()
        .collect::<Vec<_>>();
    if authorization_values.len() > 1 {
        return Err(S3Error::access_denied(
            "Authorization header must not appear more than once",
        ));
    }

    if let Some(value) = authorization_values.first() {
        let value = value
            .to_str()
            .map_err(|_| S3Error::access_denied("invalid Authorization header"))?;
        verify_header_auth(config, method, uri, headers, value)
            .map_err(map_auth_error)
            .map(|header_auth| AuthContext {
                mode: AuthMode::HeaderSigV4,
                principal: RequestPrincipal::AccessKey {
                    access_key_id: header_auth.access_key_id.clone(),
                },
                access_key_id: Some(header_auth.access_key_id),
                streaming_signing: Some(header_auth.streaming_signing),
            })
    } else if uri.query().is_some_and(is_presigned_query) {
        verify_presigned_url(config, method, uri, headers)
            .map_err(map_auth_error)
            .map(|access_key_id| AuthContext {
                mode: AuthMode::PresignedUrl,
                principal: RequestPrincipal::AccessKey {
                    access_key_id: access_key_id.clone(),
                },
                access_key_id: Some(access_key_id),
                streaming_signing: None,
            })
    } else if config.allow_anonymous() {
        Ok(AuthContext {
            mode: AuthMode::Anonymous,
            principal: RequestPrincipal::Anonymous,
            access_key_id: None,
            streaming_signing: None,
        })
    } else {
        Err(S3Error::access_denied("Access Denied"))
    }
}

/// Authorizes an authenticated request for a bucket/action pair.
///
/// Anonymous requests are accepted only when anonymous access is enabled and
/// the configured bucket allow-list permits the bucket. Signed requests must
/// use an active credential whose bucket and action allow-lists permit the
/// requested operation.
pub fn authorize(
    config: &AuthState,
    auth: &AuthContext,
    bucket: &BucketName,
    action: S3Action,
) -> Result<(), S3Error> {
    if auth.mode == AuthMode::Custom {
        return Ok(());
    }
    if auth.mode == AuthMode::Anonymous {
        if config.permits_anonymous_bucket(bucket) {
            return Ok(());
        }
        return Err(S3Error::access_denied(format!(
            "Anonymous access is not authorized for bucket {}",
            bucket.as_str()
        )));
    }

    let Some(access_key_id) = auth.access_key_id.as_ref() else {
        return Err(S3Error::access_denied("Access Denied"));
    };

    if config.permits_credential(access_key_id.as_str(), bucket, action) {
        Ok(())
    } else {
        Err(S3Error::access_denied(format!(
            "Access key is not authorized for {} on bucket {}",
            action.as_str(),
            bucket.as_str()
        )))
    }
}

fn verify_header_auth(
    config: &AuthState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    authorization: &str,
) -> Result<HeaderAuth, AuthError> {
    let parsed = ParsedAuthorization::parse(authorization)?;
    let credential = CredentialScope::parse(&parsed.credential)?;
    let access_key = config
        .credential(&credential.access_key_id)
        .ok_or(AuthError::UnknownAccessKey)?;

    if !access_key.active {
        return Err(AuthError::InactiveAccessKey);
    }
    if credential.region != config.region() {
        return Err(AuthError::RegionMismatch);
    }
    if credential.service != "s3" || credential.terminal != "aws4_request" {
        return Err(AuthError::InvalidCredentialScope);
    }

    let amz_date = header_str(headers, "x-amz-date")?;
    if !amz_date.starts_with(&credential.date) {
        return Err(AuthError::CredentialDateMismatch);
    }
    validate_timestamp(amz_date, config.max_skew_seconds())?;
    validate_header_session_token(access_key.session_token, headers)?;

    let canonical_request = canonical_request(
        method,
        uri,
        headers,
        &parsed.signed_headers,
        CanonicalQueryMode::IncludeAll,
        PayloadHashSource::Header,
    )?;
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        amz_date, credential.date, credential.region, canonical_request_hash
    );

    let signing_key = signing_key(
        access_key.secret_key.as_str(),
        &credential.date,
        &credential.region,
    )?;
    let expected = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    if subtle_constant_time_eq(expected.as_bytes(), parsed.signature.as_bytes()) {
        let credential_scope = format!("{}/{}/s3/aws4_request", credential.date, credential.region);
        Ok(HeaderAuth {
            access_key_id: access_key.access_key_id,
            streaming_signing: StreamingSigningContext {
                signing_key,
                seed_signature: parsed.signature,
                amz_date: amz_date.to_owned(),
                credential_scope,
            },
        })
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

fn verify_presigned_url(
    config: &AuthState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<AccessKeyId, AuthError> {
    let query = query_fields(
        uri.query()
            .ok_or(AuthError::MissingPresignedField("X-Amz-Algorithm"))?,
    )?;

    let algorithm = required_query(&query, "X-Amz-Algorithm")?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(AuthError::UnsupportedAlgorithm);
    }

    let credential = CredentialScope::parse(required_query(&query, "X-Amz-Credential")?)?;
    let access_key = config
        .credential(&credential.access_key_id)
        .ok_or(AuthError::UnknownAccessKey)?;
    if !access_key.active {
        return Err(AuthError::InactiveAccessKey);
    }
    if credential.region != config.region() {
        return Err(AuthError::RegionMismatch);
    }
    if credential.service != "s3" || credential.terminal != "aws4_request" {
        return Err(AuthError::InvalidCredentialScope);
    }

    let amz_date = required_query(&query, "X-Amz-Date")?;
    if !amz_date.starts_with(&credential.date) {
        return Err(AuthError::CredentialDateMismatch);
    }
    let request_time = parse_amz_date(amz_date)?;
    validate_presigned_session_token(access_key.session_token, &query)?;

    let expires = required_query(&query, "X-Amz-Expires")?
        .parse::<u32>()
        .map_err(|_| AuthError::InvalidExpires)?;
    if !(1..=604_800).contains(&expires) {
        return Err(AuthError::InvalidExpires);
    }
    validate_presigned_expiry(request_time, expires, config.max_skew_seconds())?;

    let signed_headers = required_query(&query, "X-Amz-SignedHeaders")?;
    let provided_signature = required_query(&query, "X-Amz-Signature")?;
    validate_signature(provided_signature)?;

    let canonical_request = canonical_request(
        method,
        uri,
        headers,
        signed_headers,
        CanonicalQueryMode::ExcludePresignedSignature,
        PayloadHashSource::UnsignedPayload,
    )?;
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        amz_date, credential.date, credential.region, canonical_request_hash
    );

    let signing_key = signing_key(
        access_key.secret_key.as_str(),
        &credential.date,
        &credential.region,
    )?;
    let expected = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

    if subtle_constant_time_eq(expected.as_bytes(), provided_signature.as_bytes()) {
        Ok(access_key.access_key_id)
    } else {
        Err(AuthError::SignatureMismatch)
    }
}

fn canonical_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    signed_headers: &str,
    query_mode: CanonicalQueryMode,
    payload_hash_source: PayloadHashSource,
) -> Result<String, AuthError> {
    let canonical_uri = canonical_uri(uri.path());
    let canonical_query = canonical_query(uri.query().unwrap_or(""), query_mode)?;
    let signed_header_names = signed_headers.split(';').collect::<Vec<_>>();
    validate_signed_headers(&signed_header_names)?;
    validate_amz_headers_are_signed(headers, &signed_header_names)?;
    validate_singleton_auth_headers(headers)?;
    let canonical_headers = canonical_headers(headers, &signed_header_names)?;
    let payload_hash = match payload_hash_source {
        PayloadHashSource::Header => {
            let mode = payload_hash_mode(headers).map_err(|_| AuthError::InvalidPayloadHashMode)?;
            mode.canonical_value()
                .ok_or_else(|| AuthError::MissingSignedHeader("x-amz-content-sha256".to_owned()))?
                .to_owned()
        }
        PayloadHashSource::UnsignedPayload => "UNSIGNED-PAYLOAD".to_owned(),
    };

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    ))
}

fn validate_signed_headers(signed_headers: &[&str]) -> Result<(), AuthError> {
    if signed_headers.is_empty() || signed_headers.iter().any(|name| name.is_empty()) {
        return Err(AuthError::InvalidSignedHeaders);
    }
    let mut previous = None;
    for name in signed_headers {
        if name
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || byte.is_ascii_control())
        {
            return Err(AuthError::InvalidSignedHeaders);
        }
        if let Some(previous) = previous
            && previous >= *name
        {
            return Err(AuthError::InvalidSignedHeaders);
        }
        previous = Some(*name);
    }
    if !signed_headers.contains(&"host") {
        return Err(AuthError::MissingSignedHeader("host".to_owned()));
    }
    Ok(())
}

fn validate_amz_headers_are_signed(
    headers: &HeaderMap,
    signed_headers: &[&str],
) -> Result<(), AuthError> {
    for name in headers.keys().map(|name| name.as_str()) {
        if name.starts_with("x-amz-") && !signed_headers.contains(&name) {
            return Err(AuthError::MissingSignedHeader(name.to_owned()));
        }
    }
    Ok(())
}

fn validate_singleton_auth_headers(headers: &HeaderMap) -> Result<(), AuthError> {
    for name in ["x-amz-date", "x-amz-content-sha256", "x-amz-security-token"] {
        if headers.get_all(name).iter().count() > 1 {
            return Err(AuthError::DuplicateHeader(name.to_owned()));
        }
    }
    Ok(())
}

fn canonical_uri(path: &str) -> String {
    aws_uri_encode(path.as_bytes(), true)
}

fn canonical_query(query: &str, mode: CanonicalQueryMode) -> Result<String, AuthError> {
    if query.is_empty() {
        return Ok(String::new());
    }

    let mut params = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name)?;
        if mode == CanonicalQueryMode::ExcludePresignedSignature && name == "X-Amz-Signature" {
            continue;
        }
        let value = percent_decode(value)?;
        params.push((
            aws_uri_encode(name.as_bytes(), false),
            aws_uri_encode(value.as_bytes(), false),
        ));
    }
    params.sort();
    Ok(params
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&"))
}

fn canonical_headers(headers: &HeaderMap, signed: &[&str]) -> Result<String, AuthError> {
    let mut values = BTreeMap::new();

    for name in signed {
        let header_values = headers.get_all(*name).iter().collect::<Vec<_>>();
        if header_values.is_empty() {
            return Err(AuthError::MissingSignedHeader((*name).to_owned()));
        }
        let value = header_values
            .into_iter()
            .map(|value| {
                value
                    .to_str()
                    .map(normalize_header_value)
                    .map_err(|_| AuthError::InvalidHeaderValue((*name).to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        values.insert((*name).to_owned(), value);
    }

    Ok(values
        .into_iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect())
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .ok_or_else(|| AuthError::MissingSignedHeader(name.to_owned()))?
        .to_str()
        .map_err(|_| AuthError::InvalidHeaderValue(name.to_owned()))
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_header_session_token(
    expected: Option<&str>,
    headers: &HeaderMap,
) -> Result<(), AuthError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = header_str(headers, "x-amz-security-token")?;
    if actual == expected {
        Ok(())
    } else {
        Err(AuthError::InvalidSessionToken)
    }
}

fn validate_presigned_session_token(
    expected: Option<&str>,
    query: &BTreeMap<String, String>,
) -> Result<(), AuthError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = required_query(query, "X-Amz-Security-Token")?;
    if actual == expected {
        Ok(())
    } else {
        Err(AuthError::InvalidSessionToken)
    }
}

fn validate_timestamp(amz_date: &str, max_skew_seconds: i64) -> Result<(), AuthError> {
    let request_time = parse_amz_date(amz_date)?;
    let now = Utc::now();
    let skew = if request_time > now {
        request_time - now
    } else {
        now - request_time
    };

    if skew > Duration::seconds(max_skew_seconds) {
        return Err(AuthError::RequestTimeTooSkewed);
    }
    Ok(())
}

fn validate_presigned_expiry(
    request_time: DateTime<Utc>,
    expires: u32,
    max_skew_seconds: i64,
) -> Result<(), AuthError> {
    let now = Utc::now();
    if now + Duration::seconds(max_skew_seconds) < request_time {
        return Err(AuthError::RequestTimeTooSkewed);
    }
    if now > request_time + Duration::seconds(i64::from(expires)) {
        return Err(AuthError::ExpiredPresignedUrl);
    }
    Ok(())
}

fn parse_amz_date(value: &str) -> Result<DateTime<Utc>, AuthError> {
    NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%SZ")
        .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
        .map_err(|_| AuthError::InvalidTimestamp)
}

fn query_fields(query: &str) -> Result<BTreeMap<String, String>, AuthError> {
    let mut fields = BTreeMap::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = percent_decode(name)?;
        if PRESIGNED_AUTH_FIELDS.contains(&name.as_str()) && fields.contains_key(&name) {
            return Err(AuthError::DuplicatePresignedField(name));
        }
        fields.insert(name, percent_decode(value)?);
    }
    Ok(fields)
}

fn is_presigned_query(query: &str) -> bool {
    query.split('&').any(|pair| {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        percent_decode_str(name)
            .decode_utf8()
            .is_ok_and(|name| name == "X-Amz-Algorithm")
    })
}

fn required_query<'a>(
    query: &'a BTreeMap<String, String>,
    name: &'static str,
) -> Result<&'a str, AuthError> {
    query
        .get(name)
        .map(String::as_str)
        .ok_or(AuthError::MissingPresignedField(name))
}

fn percent_decode(value: &str) -> Result<String, AuthError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| AuthError::InvalidQueryEncoding)
}

fn aws_uri_encode(bytes: &[u8], preserve_slash: bool) -> String {
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            b'/' if preserve_slash => encoded.push('/'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn signing_key(secret_key: &str, date: &str, region: &str) -> Result<Vec<u8>, AuthError> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, b"s3")?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| AuthError::Crypto)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn subtle_constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.ct_eq(right).into()
}

fn validate_signature(value: &str) -> Result<(), AuthError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(AuthError::InvalidSignature)
    }
}

fn map_auth_error(error: AuthError) -> S3Error {
    match error {
        AuthError::SignatureMismatch => S3Error::signature_does_not_match(),
        AuthError::Crypto => S3Error::internal("failed to compute authentication HMAC"),
        AuthError::RequestTimeTooSkewed => S3Error::request_time_too_skewed(),
        AuthError::ExpiredPresignedUrl => S3Error::access_denied("Request has expired"),
        AuthError::InvalidCredentialScope
        | AuthError::RegionMismatch
        | AuthError::CredentialDateMismatch => {
            S3Error::authorization_header_malformed(error.to_string())
        }
        other => S3Error::access_denied(other.to_string()),
    }
}

/// Authentication result for a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthContext {
    /// Authentication mode used for the request.
    pub mode: AuthMode,
    /// Authenticated principal.
    pub principal: RequestPrincipal,
    /// Access key ID for signed requests, or `None` for anonymous requests.
    pub access_key_id: Option<AccessKeyId>,
    /// Streaming signing data for signed aws-chunked uploads.
    pub streaming_signing: Option<StreamingSigningContext>,
}

struct HeaderAuth {
    access_key_id: AccessKeyId,
    streaming_signing: StreamingSigningContext,
}

/// SigV4 streaming signing state derived from the request signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamingSigningContext {
    /// Derived SigV4 signing key for chunk and trailer signatures.
    pub signing_key: Vec<u8>,
    /// Seed signature from the Authorization header.
    pub seed_signature: String,
    /// Request timestamp from `x-amz-date`.
    pub amz_date: String,
    /// Credential scope in `date/region/s3/aws4_request` form.
    pub credential_scope: String,
}

/// Authentication mode selected for a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthMode {
    /// `Authorization: AWS4-HMAC-SHA256 ...` header authentication.
    HeaderSigV4,
    /// Query-string SigV4 presigned URL authentication.
    PresignedUrl,
    /// Anonymous access allowed by configuration.
    Anonymous,
    /// Application-defined custom authentication.
    Custom,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CanonicalQueryMode {
    IncludeAll,
    ExcludePresignedSignature,
}

#[derive(Clone, Copy)]
enum PayloadHashSource {
    Header,
    UnsignedPayload,
}

struct ParsedAuthorization {
    credential: String,
    signed_headers: String,
    signature: String,
}

impl ParsedAuthorization {
    fn parse(value: &str) -> Result<Self, AuthError> {
        let Some(rest) = value.strip_prefix("AWS4-HMAC-SHA256 ") else {
            return Err(AuthError::UnsupportedAlgorithm);
        };

        let mut fields = BTreeMap::new();
        for part in rest.split(',') {
            let part = part.trim();
            let Some((name, value)) = part.split_once('=') else {
                return Err(AuthError::MalformedAuthorization);
            };
            if fields.contains_key(name) {
                return Err(AuthError::DuplicateAuthorizationField(name.to_owned()));
            }
            fields.insert(name, value);
        }

        let signature = required_field(&fields, "Signature")?;
        validate_signature(signature)?;

        Ok(Self {
            credential: required_field(&fields, "Credential")?.to_owned(),
            signed_headers: required_field(&fields, "SignedHeaders")?.to_owned(),
            signature: signature.to_owned(),
        })
    }
}

fn required_field<'a>(
    fields: &'a BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<&'a str, AuthError> {
    fields
        .get(name)
        .copied()
        .ok_or(AuthError::MissingAuthorizationField(name))
}

struct CredentialScope {
    access_key_id: String,
    date: String,
    region: String,
    service: String,
    terminal: String,
}

impl CredentialScope {
    fn parse(value: &str) -> Result<Self, AuthError> {
        let parts = value.split('/').collect::<Vec<_>>();
        if parts.len() != 5 || parts.iter().any(|part| part.is_empty()) {
            return Err(AuthError::InvalidCredentialScope);
        }
        if parts[1].len() != 8 || !parts[1].bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(AuthError::InvalidCredentialScope);
        }

        Ok(Self {
            access_key_id: parts[0].to_owned(),
            date: parts[1].to_owned(),
            region: parts[2].to_owned(),
            service: parts[3].to_owned(),
            terminal: parts[4].to_owned(),
        })
    }
}

#[derive(Debug, Error)]
enum AuthError {
    #[error("unsupported authorization algorithm")]
    UnsupportedAlgorithm,

    #[error("malformed authorization header")]
    MalformedAuthorization,

    #[error("authorization header is missing {0}")]
    MissingAuthorizationField(&'static str),

    #[error("authorization header field {0} must not appear more than once")]
    DuplicateAuthorizationField(String),

    #[error("invalid credential scope")]
    InvalidCredentialScope,

    #[error("unknown access key")]
    UnknownAccessKey,

    #[error("inactive access key")]
    InactiveAccessKey,

    #[error("credential region is not configured")]
    RegionMismatch,

    #[error("credential date does not match x-amz-date")]
    CredentialDateMismatch,

    #[error("request timestamp is invalid")]
    InvalidTimestamp,

    #[error("request time is too skewed")]
    RequestTimeTooSkewed,

    #[error("presigned URL has expired")]
    ExpiredPresignedUrl,

    #[error("session token is missing or invalid")]
    InvalidSessionToken,

    #[error("missing signed header {0}")]
    MissingSignedHeader(String),

    #[error("signed headers are invalid")]
    InvalidSignedHeaders,

    #[error("presigned URL is missing {0}")]
    MissingPresignedField(&'static str),

    #[error("presigned URL field {0} must not appear more than once")]
    DuplicatePresignedField(String),

    #[error("presigned URL expiration is invalid")]
    InvalidExpires,

    #[error("query string contains invalid percent-encoded UTF-8")]
    InvalidQueryEncoding,

    #[error("invalid signed header value for {0}")]
    InvalidHeaderValue(String),

    #[error("unsupported x-amz-content-sha256 payload mode")]
    InvalidPayloadHashMode,

    #[error("{0} must not appear more than once")]
    DuplicateHeader(String),

    #[error("signature mismatch")]
    SignatureMismatch,

    #[error("signature must be lowercase 64-character hex")]
    InvalidSignature,

    #[error("failed to compute authentication HMAC")]
    Crypto,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn canonical_query_preserves_empty_values_and_sorts_after_encoding() {
        assert_eq!(
            canonical_query("uploads&z=last&a=one%20two", CanonicalQueryMode::IncludeAll)
                .expect("query"),
            "a=one%20two&uploads=&z=last"
        );
    }

    #[test]
    fn canonical_query_includes_signature_param_for_header_auth() {
        assert_eq!(
            canonical_query(
                "X-Amz-Signature=not-auth&x-id=PutObject",
                CanonicalQueryMode::IncludeAll,
            )
            .expect("query"),
            "X-Amz-Signature=not-auth&x-id=PutObject"
        );
    }

    #[test]
    fn canonical_query_excludes_decoded_signature_param_for_presigned_auth() {
        assert_eq!(
            canonical_query(
                "X-Amz%2DSignature=abc&x-id=PutObject",
                CanonicalQueryMode::ExcludePresignedSignature,
            )
            .expect("query"),
            "x-id=PutObject"
        );
    }

    #[test]
    fn presigned_query_detection_decodes_query_field_names() {
        assert!(is_presigned_query("X-Amz%2DAlgorithm=AWS4-HMAC-SHA256"));
        assert!(!is_presigned_query("x-id=PutObject"));
    }

    #[test]
    fn canonical_headers_trim_and_compress_spaces() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("x-amz-date", HeaderValue::from_static("  a   b  "));

        let got = canonical_headers(&headers, &["x-amz-date", "host"]).expect("headers");

        assert_eq!(got, "host:example.com\nx-amz-date:a b\n");
    }

    #[test]
    fn canonical_headers_join_repeated_values() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert(
            "x-amz-meta-owner",
            HeaderValue::from_static("  first   value "),
        );
        headers.append("x-amz-meta-owner", HeaderValue::from_static("second"));

        let got = canonical_headers(&headers, &["host", "x-amz-meta-owner"]).expect("headers");

        assert_eq!(
            got,
            "host:example.com\nx-amz-meta-owner:first value,second\n"
        );
    }

    #[test]
    fn signed_headers_must_be_lowercase_sorted_unique_and_include_host() {
        assert!(validate_signed_headers(&["host", "x-amz-date"]).is_ok());
        assert!(matches!(
            validate_signed_headers(&["Host", "x-amz-date"]),
            Err(AuthError::InvalidSignedHeaders)
        ));
        assert!(matches!(
            validate_signed_headers(&["x-amz-date"]),
            Err(AuthError::MissingSignedHeader(name)) if name == "host"
        ));
        assert!(matches!(
            validate_signed_headers(&["x-amz-date", "host"]),
            Err(AuthError::InvalidSignedHeaders)
        ));
        assert!(matches!(
            validate_signed_headers(&["host", "host"]),
            Err(AuthError::InvalidSignedHeaders)
        ));
    }

    #[test]
    fn all_x_amz_request_headers_must_be_signed() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("example.com"));
        headers.insert("x-amz-date", HeaderValue::from_static("20260616T120000Z"));
        headers.insert("x-amz-meta-owner", HeaderValue::from_static("rust"));

        assert!(matches!(
            validate_amz_headers_are_signed(&headers, &["host", "x-amz-date"]),
            Err(AuthError::MissingSignedHeader(name)) if name == "x-amz-meta-owner"
        ));
        assert!(
            validate_amz_headers_are_signed(&headers, &["host", "x-amz-date", "x-amz-meta-owner"])
                .is_ok()
        );
    }

    #[test]
    fn authorization_header_rejects_duplicate_fields() {
        let header = format!(
            "AWS4-HMAC-SHA256 Credential=test/20260616/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature={}, Signature={}",
            "0".repeat(64),
            "1".repeat(64)
        );

        assert!(matches!(
            ParsedAuthorization::parse(&header),
            Err(AuthError::DuplicateAuthorizationField(name)) if name == "Signature"
        ));
    }

    #[test]
    fn credential_scope_rejects_empty_segments() {
        assert!(matches!(
            CredentialScope::parse("test//us-east-1/s3/aws4_request"),
            Err(AuthError::InvalidCredentialScope)
        ));
        assert!(matches!(
            CredentialScope::parse("test/20260616//s3/aws4_request"),
            Err(AuthError::InvalidCredentialScope)
        ));
    }

    #[test]
    fn credential_scope_rejects_malformed_dates() {
        assert!(matches!(
            CredentialScope::parse("test/2026/us-east-1/s3/aws4_request"),
            Err(AuthError::InvalidCredentialScope)
        ));
        assert!(matches!(
            CredentialScope::parse("test/2026061a/us-east-1/s3/aws4_request"),
            Err(AuthError::InvalidCredentialScope)
        ));
    }
}
