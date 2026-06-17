use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::Response,
};
use futures_util::stream;
use std::io::SeekFrom;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::{
    AppState, auth,
    config::S3Action,
    error::S3Error,
    handlers::{
        request::{authorize_request, resolve_request_target, validate_empty_payload_hash},
        s3::unique_query_param,
    },
    s3::types::RequestId,
};

/// Handles `GetObject`, including conditional requests, single ranges, and response overrides.
pub(crate) async fn get_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    auth_context: auth::AuthContext,
) -> Result<Response, S3Error> {
    let target = resolve_request_target(&state, &request)?;
    let key_sha256 = crate::handlers::s3::object_key_sha256(&target.key);
    authorize_request(
        &state,
        &auth_context,
        &target.bucket,
        Some(&target.key),
        S3Action::GetObject,
    )?;
    validate_empty_payload_hash(&request)?;

    let (metadata, mut file) = state
        .object_store
        .open_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to open object: {err}")))?
        .ok_or_else(S3Error::no_such_key)?;
    log::info!(
        "object opened request_id={} bucket={} key_sha256={} size={}",
        request_id,
        target.bucket.as_str(),
        key_sha256,
        metadata.size
    );

    if let Some(response) = crate::handlers::head_object::conditional_response(
        request.headers(),
        &metadata,
        request_id,
    )? {
        return Ok(response);
    }

    let range = parse_range_header(request.headers(), metadata.size)?;
    let query = request.uri().query().unwrap_or_default();
    let response = match range {
        Some(range) => {
            file.seek(SeekFrom::Start(range.start))
                .await
                .map_err(|err| S3Error::internal(format!("failed to seek object: {err}")))?;
            let response =
                crate::handlers::head_object::object_metadata_response_builder_with_status_and_length(
                    &metadata,
                    request_id,
                    StatusCode::PARTIAL_CONTENT,
                    range.len(),
                )
                .header(
                    header::CONTENT_RANGE,
                    format!("bytes {}-{}/{}", range.start, range.end, metadata.size),
                );
            apply_response_overrides(response, query)?.body(Body::from_stream(file_stream_limited(
                file,
                range.len(),
                state.io_tuning.object_stream_buffer_size,
            )))
        }
        None => {
            let response = crate::handlers::head_object::object_metadata_response_builder(
                &metadata, request_id,
            );
            apply_response_overrides(response, query)?.body(Body::from_stream(file_stream(
                file,
                state.io_tuning.object_stream_buffer_size,
            )))
        }
    };

    response.map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}

fn apply_response_overrides(
    mut response: http::response::Builder,
    query: &str,
) -> Result<http::response::Builder, S3Error> {
    const OVERRIDES: &[(&str, header::HeaderName)] = &[
        ("response-cache-control", header::CACHE_CONTROL),
        ("response-content-disposition", header::CONTENT_DISPOSITION),
        ("response-content-encoding", header::CONTENT_ENCODING),
        ("response-content-language", header::CONTENT_LANGUAGE),
        ("response-content-type", header::CONTENT_TYPE),
        ("response-expires", header::EXPIRES),
    ];

    for (query_name, header_name) in OVERRIDES {
        if let Some(value) = unique_query_param(query, query_name)? {
            let value = HeaderValue::from_str(&value).map_err(|_| {
                S3Error::invalid_request(format!("{query_name} is not a valid header value"))
            })?;
            let Some(headers) = response.headers_mut() else {
                return Err(S3Error::internal(
                    "failed to apply response header override",
                ));
            };
            headers.insert(header_name.clone(), value);
        }
    }

    Ok(response)
}

fn file_stream(
    file: File,
    buffer_size: usize,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    stream::try_unfold((file, buffer_size), |(mut file, buffer_size)| async move {
        let mut buffer = vec![0_u8; buffer_size];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), (file, buffer_size))))
    })
}

fn file_stream_limited(
    file: File,
    bytes: u64,
    buffer_size: usize,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    stream::try_unfold(
        (file, bytes, buffer_size),
        |(mut file, remaining, buffer_size)| async move {
            if remaining == 0 {
                return Ok(None);
            }
            let read_limit = remaining.min(buffer_size as u64) as usize;
            let mut buffer = vec![0_u8; read_limit];
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                return Ok(None);
            }
            buffer.truncate(read);
            Ok(Some((
                Bytes::from(buffer),
                (file, remaining - read as u64, buffer_size),
            )))
        },
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    fn len(self) -> u64 {
        self.end - self.start + 1
    }
}

fn parse_range_header(headers: &HeaderMap, object_size: u64) -> Result<Option<ByteRange>, S3Error> {
    let Some(value) = headers.get(header::RANGE) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| S3Error::invalid_range("Range must be valid ASCII"))?;
    let Some(range) = value.strip_prefix("bytes=") else {
        return Err(S3Error::invalid_range("Only bytes ranges are supported"));
    };
    if range.contains(',') {
        return Err(S3Error::invalid_range(
            "Multiple byte ranges are not supported",
        ));
    }
    let Some((start, end)) = range.split_once('-') else {
        return Err(S3Error::invalid_range(
            "Range must use bytes=start-end syntax",
        ));
    };
    if object_size == 0 {
        return Err(unsatisfiable_range_error(object_size));
    }

    match (start.is_empty(), end.is_empty()) {
        (false, false) => {
            let start = parse_range_number(start)?;
            let end = parse_range_number(end)?;
            if start > end || start >= object_size {
                return Err(unsatisfiable_range_error(object_size));
            }
            Ok(Some(ByteRange {
                start,
                end: end.min(object_size - 1),
            }))
        }
        (false, true) => {
            let start = parse_range_number(start)?;
            if start >= object_size {
                return Err(unsatisfiable_range_error(object_size));
            }
            Ok(Some(ByteRange {
                start,
                end: object_size - 1,
            }))
        }
        (true, false) => {
            let suffix_len = parse_range_number(end)?;
            if suffix_len == 0 {
                return Err(unsatisfiable_range_error(object_size));
            }
            let start = object_size.saturating_sub(suffix_len);
            Ok(Some(ByteRange {
                start,
                end: object_size - 1,
            }))
        }
        (true, true) => Err(unsatisfiable_range_error(object_size)),
    }
}

fn parse_range_number(value: &str) -> Result<u64, S3Error> {
    value
        .parse::<u64>()
        .map_err(|_| S3Error::invalid_range("Range contains an invalid byte position"))
}

fn unsatisfiable_range_error(object_size: u64) -> S3Error {
    let error = S3Error::invalid_range("Range is not satisfiable");
    match HeaderValue::from_str(&format!("bytes */{object_size}")) {
        Ok(value) => error.with_header(header::CONTENT_RANGE, value),
        Err(_) => error,
    }
}
