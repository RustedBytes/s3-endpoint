use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, NaiveDateTime, Utc};

use crate::{
    AppState,
    config::S3Action,
    error::S3Error,
    handlers::request::{authenticate_and_authorize_target, validate_empty_payload_hash},
    s3::types::RequestId,
    storage::ObjectMetadata,
};

pub(crate) async fn head_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let (_, target) =
        authenticate_and_authorize_target(&state, &request, S3Action::HeadObject).await?;
    validate_empty_payload_hash(&request)?;

    let metadata = state
        .object_store
        .head_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to read object metadata: {err}")))?
        .ok_or_else(S3Error::no_such_key)?;

    if let Some(response) = conditional_response(request.headers(), &metadata, request_id)? {
        return Ok(response);
    }

    metadata_response(metadata, request_id)
}

pub(crate) fn conditional_response(
    headers: &HeaderMap,
    metadata: &ObjectMetadata,
    request_id: &RequestId,
) -> Result<Option<Response>, S3Error> {
    if let Some(value) = headers.get(header::IF_MATCH) {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_request("If-Match must be valid ASCII"))?;
        if !strong_etag_condition_matches(value, metadata.etag.as_str()) {
            return Err(S3Error::precondition_failed(
                "At least one of the preconditions you specified did not hold.",
            ));
        }
    }

    if let Some(value) = headers.get(header::IF_NONE_MATCH) {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_request("If-None-Match must be valid ASCII"))?;
        if weak_etag_condition_matches(value, metadata.etag.as_str()) {
            let response = object_metadata_response_builder_with_status_and_length(
                metadata,
                request_id,
                StatusCode::NOT_MODIFIED,
                0,
            )
            .body(Body::empty())
            .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;
            return Ok(Some(response));
        }
    }

    if !headers.contains_key(header::IF_MATCH)
        && let Some(value) = headers.get(header::IF_UNMODIFIED_SINCE)
    {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_request("If-Unmodified-Since must be valid ASCII"))?;
        let since = parse_http_datetime(value, "If-Unmodified-Since")?;
        if metadata.last_modified.timestamp() > since.timestamp() {
            return Err(S3Error::precondition_failed(
                "At least one of the preconditions you specified did not hold.",
            ));
        }
    }

    if !headers.contains_key(header::IF_NONE_MATCH)
        && let Some(value) = headers.get(header::IF_MODIFIED_SINCE)
    {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_request("If-Modified-Since must be valid ASCII"))?;
        let since = parse_http_datetime(value, "If-Modified-Since")?;
        if metadata.last_modified.timestamp() <= since.timestamp() {
            let response = object_metadata_response_builder_with_status_and_length(
                metadata,
                request_id,
                StatusCode::NOT_MODIFIED,
                0,
            )
            .body(Body::empty())
            .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;
            return Ok(Some(response));
        }
    }

    Ok(None)
}

fn strong_etag_condition_matches(value: &str, etag: &str) -> bool {
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || candidate == etag
    })
}

fn weak_etag_condition_matches(value: &str, etag: &str) -> bool {
    let etag = weak_etag_value(etag);
    value.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || weak_etag_value(candidate) == etag
    })
}

fn weak_etag_value(value: &str) -> &str {
    value.strip_prefix("W/").unwrap_or(value)
}

fn parse_http_datetime(value: &str, header_name: &'static str) -> Result<DateTime<Utc>, S3Error> {
    DateTime::parse_from_rfc2822(value)
        .map(|value| value.with_timezone(&Utc))
        .or_else(|_| {
            NaiveDateTime::parse_from_str(value, "%A, %d-%b-%y %H:%M:%S GMT")
                .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
        })
        .or_else(|_| {
            NaiveDateTime::parse_from_str(value, "%a %b %e %H:%M:%S %Y")
                .map(|value| DateTime::from_naive_utc_and_offset(value, Utc))
        })
        .map_err(|_| S3Error::invalid_argument(format!("{header_name} must be an HTTP-date")))
}

pub(crate) fn object_metadata_response_builder(
    metadata: &ObjectMetadata,
    request_id: &RequestId,
) -> http::response::Builder {
    object_metadata_response_builder_with_status_and_length(
        metadata,
        request_id,
        StatusCode::OK,
        metadata.size,
    )
}

pub(crate) fn object_metadata_response_builder_with_status_and_length(
    metadata: &ObjectMetadata,
    request_id: &RequestId,
    status: StatusCode,
    content_length: u64,
) -> http::response::Builder {
    let mut response = Response::builder()
        .status(status)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, content_length.to_string())
        .header(header::ETAG, metadata.etag.as_str())
        .header(
            header::LAST_MODIFIED,
            format_http_datetime(metadata.last_modified),
        );

    if let Some(value) = &metadata.content_type {
        response = response.header(header::CONTENT_TYPE, value);
    }
    if let Some(value) = &metadata.content_encoding {
        response = response.header(header::CONTENT_ENCODING, value);
    }
    if let Some(value) = &metadata.content_disposition {
        response = response.header(header::CONTENT_DISPOSITION, value);
    }
    if let Some(value) = &metadata.content_language {
        response = response.header(header::CONTENT_LANGUAGE, value);
    }
    if let Some(value) = &metadata.cache_control {
        response = response.header(header::CACHE_CONTROL, value);
    }
    if let Some(value) = &metadata.expires {
        response = response.header(header::EXPIRES, value);
    }
    if let Some(value) = &metadata.tagging {
        response = response.header("x-amz-tagging", value);
    }
    for (name, value) in &metadata.user_metadata {
        response = response.header(name, value);
    }
    if !metadata.checksums.is_empty() {
        response = response.header("x-amz-checksum-type", "FULL_OBJECT");
    }
    for (name, value) in &metadata.checksums {
        response = response.header(name, value);
    }

    response
}

fn metadata_response(
    metadata: ObjectMetadata,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    object_metadata_response_builder(&metadata, request_id)
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}

fn format_http_datetime(value: DateTime<Utc>) -> String {
    value.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_datetime_accepts_all_http_date_forms() {
        let expected = 784_111_777;

        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            let parsed = parse_http_datetime(value, "If-Modified-Since").expect("http-date");
            assert_eq!(parsed.timestamp(), expected);
        }
    }

    #[test]
    fn parse_http_datetime_rejects_invalid_dates() {
        let error = parse_http_datetime("2026-06-16T12:00:00Z", "If-Modified-Since")
            .expect_err("non HTTP-date should fail");

        assert!(format!("{error:?}").contains("If-Modified-Since must be an HTTP-date"));
    }
}
