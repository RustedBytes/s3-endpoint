use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, header},
    response::Response,
};
use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};
use std::time::Instant;

use crate::{
    AppState,
    error::S3Error,
    s3::{
        target::{has_virtual_hosted_bucket, resolve_s3_target},
        types::{PartNumber, RequestId, S3Operation, UploadId},
    },
};

pub async fn handle_s3_request(State(state): State<AppState>, request: Request<Body>) -> Response {
    let method = request.method().clone();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let detected_operation = detect_operation(
        &request,
        state.config.virtual_host_base_domain.as_deref(),
        &query,
    );
    let operation = detected_operation
        .as_ref()
        .map(DetectedOperation::name)
        .unwrap_or("InvalidRequest");
    let mut log_context = request_log_context(
        &request,
        state.config.virtual_host_base_domain.as_deref(),
        &query,
    );
    let content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    let request_id = RequestId::new();
    let started_at = Instant::now();

    let response = match state.try_acquire_s3_request() {
        Ok(_permit) => match dispatch(state, request, detected_operation, &request_id).await {
            Ok(response) => response,
            Err(error) => error.into_response_with_request_id(&request_id),
        },
        Err(error) => error.into_response_with_request_id(&request_id),
    };
    let response = if method == Method::HEAD {
        without_head_response_body(response)
    } else {
        response
    };
    if let Some(decoded_bytes) = response.extensions().get::<DecodedBodyBytes>() {
        log_context.decoded_bytes = Some(decoded_bytes.0);
    }
    tracing::info!(
        request_id = %request_id,
        operation,
        status = response.status().as_u16(),
        duration_ms = started_at.elapsed().as_millis(),
        bucket = log_context.bucket.as_deref().unwrap_or(""),
        key_sha256 = log_context.key_sha256.as_deref().unwrap_or(""),
        upload_id = log_context.upload_id.as_deref().unwrap_or(""),
        part_number = log_context.part_number.map(PartNumber::get).unwrap_or_default(),
        request_content_length = content_length.unwrap_or_default(),
        decoded_bytes = log_context.decoded_bytes.unwrap_or_default(),
        "s3 request completed"
    );
    response
}

fn without_head_response_body(mut response: Response) -> Response {
    if !response.status().is_success() {
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, http::HeaderValue::from_static("0"));
    }
    let (parts, _) = response.into_parts();
    Response::from_parts(parts, Body::empty())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RequestLogContext {
    bucket: Option<String>,
    key_sha256: Option<String>,
    upload_id: Option<String>,
    part_number: Option<PartNumber>,
    decoded_bytes: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct DecodedBodyBytes(u64);

pub(crate) fn record_decoded_body_bytes(mut response: Response, bytes: u64) -> Response {
    response.extensions_mut().insert(DecodedBodyBytes(bytes));
    response
}

fn request_log_context(
    request: &Request<Body>,
    virtual_host_base_domain: Option<&str>,
    query: &str,
) -> RequestLogContext {
    let mut context = RequestLogContext {
        upload_id: query_param(query, "uploadId"),
        part_number: query_param(query, "partNumber")
            .and_then(|value| value.parse::<PartNumber>().ok()),
        ..RequestLogContext::default()
    };

    if let Ok(target) = resolve_s3_target(
        request.uri().path(),
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        virtual_host_base_domain,
    ) {
        context.bucket = Some(target.bucket.as_str().to_owned());
        context.key_sha256 = Some(hex::encode(Sha256::digest(target.key.as_str().as_bytes())));
    }

    context
}

async fn dispatch(
    state: AppState,
    request: Request<Body>,
    detected_operation: Result<DetectedOperation, S3Error>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    match detected_operation? {
        DetectedOperation::Implemented(S3Operation::HeadObject) => {
            return crate::handlers::head_object::head_object(state, request, request_id).await;
        }
        DetectedOperation::Implemented(S3Operation::HeadBucket) => {
            return crate::handlers::head_bucket::head_bucket(state, request, request_id).await;
        }
        DetectedOperation::Implemented(S3Operation::CreateMultipartUpload) => {
            return crate::handlers::multipart::create_multipart_upload(state, request, request_id)
                .await;
        }
        DetectedOperation::Implemented(S3Operation::UploadPart {
            upload_id,
            part_number,
        }) => {
            return crate::handlers::multipart::upload_part(
                state,
                request,
                request_id,
                upload_id,
                part_number,
            )
            .await;
        }
        DetectedOperation::Implemented(S3Operation::PutObject) => {
            return crate::handlers::put_object::handle_put_object(state, request, request_id)
                .await;
        }
        DetectedOperation::Implemented(S3Operation::CompleteMultipartUpload { upload_id }) => {
            return crate::handlers::multipart::complete_multipart_upload(
                state, request, request_id, upload_id,
            )
            .await;
        }
        DetectedOperation::Implemented(S3Operation::AbortMultipartUpload { upload_id }) => {
            return crate::handlers::multipart::abort_multipart_upload(
                state, request, request_id, upload_id,
            )
            .await;
        }
        DetectedOperation::Implemented(S3Operation::DeleteObject) => {
            return crate::handlers::delete_object::delete_object(state, request, request_id).await;
        }
        DetectedOperation::Implemented(S3Operation::ListParts { upload_id }) => {
            return crate::handlers::multipart::list_parts(state, request, request_id, upload_id)
                .await;
        }
        DetectedOperation::Implemented(S3Operation::GetObject) => {
            return crate::handlers::get_object::get_object(state, request, request_id).await;
        }
        DetectedOperation::ListObjectsV2 => {
            Err(S3Error::not_implemented("ListObjectsV2 is not implemented"))
        }
        DetectedOperation::Unsupported => Err(S3Error::invalid_argument("list-type must be 2")),
        DetectedOperation::MethodNotAllowed => Err(S3Error::method_not_allowed()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DetectedOperation {
    Implemented(S3Operation),
    ListObjectsV2,
    Unsupported,
    MethodNotAllowed,
}

impl DetectedOperation {
    fn name(&self) -> &'static str {
        match self {
            Self::Implemented(operation) => operation.name(),
            Self::ListObjectsV2 => "ListObjectsV2",
            Self::Unsupported => "Unsupported",
            Self::MethodNotAllowed => "MethodNotAllowed",
        }
    }
}

fn detect_operation(
    request: &Request<Body>,
    virtual_host_base_domain: Option<&str>,
    query: &str,
) -> Result<DetectedOperation, S3Error> {
    let method = request.method();
    if method == Method::HEAD {
        if has_object_route(request, virtual_host_base_domain) {
            return Ok(DetectedOperation::Implemented(S3Operation::HeadObject));
        }
        return Ok(DetectedOperation::Implemented(S3Operation::HeadBucket));
    }

    if method == Method::POST {
        let has_uploads = unique_query_flag(query, "uploads")?;
        let upload_id = unique_query_param(query, "uploadId")?;
        if has_uploads && upload_id.is_some() {
            return Err(S3Error::invalid_request(
                "multipart operation query is ambiguous",
            ));
        }
        if has_uploads {
            return Ok(DetectedOperation::Implemented(
                S3Operation::CreateMultipartUpload,
            ));
        }
        if let Some(upload_id) = upload_id {
            return Ok(DetectedOperation::Implemented(
                S3Operation::CompleteMultipartUpload {
                    upload_id: parse_upload_id_value(upload_id)?,
                },
            ));
        }
    }

    let part_number = unique_query_param(query, "partNumber")?;
    let upload_id = unique_query_param(query, "uploadId")?;

    if method == Method::PUT && upload_id.is_some() && part_number.is_none() {
        return Err(S3Error::invalid_request("partNumber is required"));
    }

    if method == Method::PUT && part_number.is_some() && upload_id.is_none() {
        return Err(S3Error::invalid_request("uploadId is required"));
    }

    if method == Method::PUT
        && let Some(part_number) = part_number
    {
        return Ok(DetectedOperation::Implemented(S3Operation::UploadPart {
            upload_id: parse_upload_id_value(upload_id.expect("checked uploadId"))?,
            part_number: parse_part_number_value(part_number)?,
        }));
    }

    if method == Method::PUT {
        return Ok(DetectedOperation::Implemented(S3Operation::PutObject));
    }
    if method == Method::DELETE
        && let Some(upload_id) = upload_id
    {
        return Ok(DetectedOperation::Implemented(
            S3Operation::AbortMultipartUpload {
                upload_id: parse_upload_id_value(upload_id)?,
            },
        ));
    }
    if method == Method::DELETE {
        if has_object_route(request, virtual_host_base_domain) {
            return Ok(DetectedOperation::Implemented(S3Operation::DeleteObject));
        }
        return Ok(DetectedOperation::MethodNotAllowed);
    }
    if method == Method::GET
        && let Some(upload_id) = upload_id
    {
        return Ok(DetectedOperation::Implemented(S3Operation::ListParts {
            upload_id: parse_upload_id_value(upload_id)?,
        }));
    }
    if method == Method::GET
        && let Some(list_type) = unique_query_param(query, "list-type")?
    {
        if list_type == "2" {
            return Ok(DetectedOperation::ListObjectsV2);
        }
        return Ok(DetectedOperation::Unsupported);
    }
    if method == Method::GET {
        if has_object_route(request, virtual_host_base_domain) {
            return Ok(DetectedOperation::Implemented(S3Operation::GetObject));
        }
        return Ok(DetectedOperation::MethodNotAllowed);
    }

    Ok(DetectedOperation::MethodNotAllowed)
}

fn parse_upload_id_value(value: String) -> Result<UploadId, S3Error> {
    UploadId::parse(value).map_err(|_| S3Error::invalid_request("invalid upload ID"))
}

fn parse_part_number_value(value: String) -> Result<PartNumber, S3Error> {
    let value = value
        .parse::<u16>()
        .map_err(|_| S3Error::invalid_request("partNumber must be an integer"))?;
    PartNumber::parse(value)
        .map_err(|_| S3Error::invalid_request("partNumber must be in 1..=10000"))
}

fn has_object_route(request: &Request<Body>, virtual_host_base_domain: Option<&str>) -> bool {
    let path = request
        .uri()
        .path()
        .strip_prefix('/')
        .unwrap_or(request.uri().path());
    if let (Some(host), Some(base_domain)) = (
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        virtual_host_base_domain,
    ) && has_virtual_hosted_bucket(host, base_domain)
    {
        return !path.is_empty();
    }

    match path.split_once('/') {
        Some((bucket, key)) => !bucket.is_empty() && !key.is_empty(),
        None => false,
    }
}

pub(crate) fn query_param(query: &str, name: &str) -> Option<String> {
    query_param_values(query, name).into_iter().next()
}

pub(crate) fn unique_query_param(query: &str, name: &str) -> Result<Option<String>, S3Error> {
    let mut values = query_param_values_checked(query, name)?;
    if values.len() > 1 {
        return Err(S3Error::invalid_request(format!(
            "{name} must not appear more than once"
        )));
    }
    Ok(values.pop())
}

fn query_param_values_checked(query: &str, name: &str) -> Result<Vec<String>, S3Error> {
    query
        .split('&')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode_checked(key);
            (key, value)
        })
        .filter_map(|(key, value)| match key {
            Ok(key) if key == name => Some(percent_decode_checked(value).map(Some)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.into_iter().flatten().collect())
}

fn query_param_values(query: &str, name: &str) -> Vec<String> {
    query
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let key = percent_decode(key)?;
            (key == name).then(|| percent_decode(value)).flatten()
        })
        .collect()
}

fn unique_query_flag(query: &str, name: &str) -> Result<bool, S3Error> {
    let mut count = 0;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match percent_decode_checked(key) {
            Ok(key) if key == name && (value.is_empty() || pair.split_once('=').is_none()) => {
                count += 1;
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
    if count > 1 {
        return Err(S3Error::invalid_request(format!(
            "{name} must not appear more than once"
        )));
    }
    Ok(count == 1)
}

fn percent_decode(value: &str) -> Option<String> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .ok()
}

fn percent_decode_checked(value: &str) -> Result<String, S3Error> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|value| value.into_owned())
        .map_err(|_| {
            S3Error::invalid_request("query string contains invalid percent-encoded UTF-8")
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_log_context_hashes_key_and_keeps_multipart_ids() {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/test-bucket/path/to/object.txt?partNumber=7&uploadId=upload-123")
            .body(Body::empty())
            .expect("request");

        let context = request_log_context(&request, None, request.uri().query().expect("query"));

        assert_eq!(context.bucket.as_deref(), Some("test-bucket"));
        let expected_key_hash = hex::encode(Sha256::digest(b"path/to/object.txt"));
        assert_eq!(
            context.key_sha256.as_deref(),
            Some(expected_key_hash.as_str())
        );
        assert_eq!(context.upload_id.as_deref(), Some("upload-123"));
        assert_eq!(
            context.part_number,
            Some(PartNumber::parse(7).expect("part number"))
        );
    }

    #[test]
    fn request_log_context_supports_virtual_hosted_bucket() {
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/key.txt")
            .header(header::HOST, "test-bucket.s3.local:9000")
            .body(Body::empty())
            .expect("request");

        let context = request_log_context(&request, Some("s3.local"), "");

        assert_eq!(context.bucket.as_deref(), Some("test-bucket"));
        let expected_key_hash = hex::encode(Sha256::digest(b"key.txt"));
        assert_eq!(
            context.key_sha256.as_deref(),
            Some(expected_key_hash.as_str())
        );
    }

    #[test]
    fn detect_operation_parses_upload_part() {
        let upload_id = UploadId::new();
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/test-bucket/object.txt?partNumber=1&uploadId={upload_id}"
            ))
            .body(Body::empty())
            .expect("request");

        let operation = detect_operation(&request, None, request.uri().query().expect("query"))
            .expect("operation");

        assert_eq!(
            operation,
            DetectedOperation::Implemented(S3Operation::UploadPart {
                upload_id,
                part_number: PartNumber::parse(1).expect("part number")
            })
        );
    }

    #[test]
    fn detect_operation_reports_list_objects_v2() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket?list-type=2")
            .body(Body::empty())
            .expect("request");

        let operation = detect_operation(&request, None, request.uri().query().expect("query"))
            .expect("operation");

        assert_eq!(operation, DetectedOperation::ListObjectsV2);
    }

    #[test]
    fn detect_operation_does_not_report_invalid_list_type_as_v2() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket?list-type=1")
            .body(Body::empty())
            .expect("request");

        let operation = detect_operation(&request, None, request.uri().query().expect("query"))
            .expect("operation");

        assert_eq!(operation, DetectedOperation::Unsupported);
    }

    #[test]
    fn detect_operation_reports_object_operation_for_invalid_object_key() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket/bad%0Akey.txt")
            .body(Body::empty())
            .expect("request");

        let operation = detect_operation(&request, None, "").expect("operation");

        assert_eq!(
            operation,
            DetectedOperation::Implemented(S3Operation::GetObject)
        );
    }

    #[test]
    fn detect_operation_rejects_invalid_query_utf8() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test-bucket/object.txt?upload%FFId=upload-123")
            .body(Body::empty())
            .expect("request");

        let result = detect_operation(&request, None, request.uri().query().expect("query"));

        assert!(result.is_err());
    }

    #[test]
    fn detect_operation_rejects_ambiguous_multipart_queries() {
        let upload_id = UploadId::new();
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "/test-bucket/object.txt?uploads&uploadId={upload_id}"
            ))
            .body(Body::empty())
            .expect("request");

        let result = detect_operation(&request, None, request.uri().query().expect("query"));

        assert!(result.is_err());
    }

    #[test]
    fn detect_operation_rejects_duplicate_multipart_query_params() {
        let upload_id = UploadId::new();
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!(
                "/test-bucket/object.txt?partNumber=1&partNumber=2&uploadId={upload_id}"
            ))
            .body(Body::empty())
            .expect("request");

        let result = detect_operation(&request, None, request.uri().query().expect("query"));

        assert!(result.is_err());
    }

    #[test]
    fn detect_operation_requires_upload_id_and_part_number_together() {
        let upload_id = UploadId::new();
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/test-bucket/object.txt?uploadId={upload_id}"))
            .body(Body::empty())
            .expect("request");

        let missing_part = detect_operation(&request, None, request.uri().query().expect("query"));
        assert!(missing_part.is_err());

        let request = Request::builder()
            .method(Method::PUT)
            .uri("/test-bucket/object.txt?partNumber=1")
            .body(Body::empty())
            .expect("request");

        let missing_upload_id =
            detect_operation(&request, None, request.uri().query().expect("query"));
        assert!(missing_upload_id.is_err());
    }

    #[test]
    fn record_decoded_body_bytes_adds_response_extension() {
        let response = Response::builder().body(Body::empty()).expect("response");

        let response = record_decoded_body_bytes(response, 42);

        assert_eq!(
            response
                .extensions()
                .get::<DecodedBodyBytes>()
                .map(|bytes| bytes.0),
            Some(42)
        );
    }
}
