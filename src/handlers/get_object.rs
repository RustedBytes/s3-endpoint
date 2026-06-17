use axum::{
    body::{Body, Bytes},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    response::Response,
};
use futures_util::stream;
use sha2::Digest as Sha2Digest;
use std::io::SeekFrom;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
};

use crate::{
    AppState, auth,
    body::upload::validate_fixed_sha256_payload_hash,
    config::S3Action,
    error::S3Error,
    handlers::s3::unique_query_param,
    s3::{target::resolve_s3_target, types::RequestId},
};

pub(crate) async fn get_object(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let auth_context = auth::authenticate(
        &state.auth,
        request.method(),
        request.uri(),
        request.headers(),
    )?;
    let path = request.uri().path().to_owned();
    let target = resolve_s3_target(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path))?;
    auth::authorize(
        &state.auth,
        &auth_context,
        &target.bucket,
        S3Action::GetObject,
    )?;
    let empty_payload_digest = sha2::Sha256::digest([]);
    validate_fixed_sha256_payload_hash(request.headers(), empty_payload_digest.as_ref())?;

    let (metadata, mut file) = state
        .object_store
        .open_object(&target.bucket, &target.key)
        .await
        .map_err(|err| S3Error::internal(format!("failed to open object: {err}")))?
        .ok_or_else(S3Error::no_such_key)?;

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
            apply_response_overrides(response, query)?
                .body(Body::from_stream(file_stream_limited(file, range.len())))
        }
        None => {
            let response = crate::handlers::head_object::object_metadata_response_builder(
                &metadata, request_id,
            );
            apply_response_overrides(response, query)?.body(Body::from_stream(file_stream(file)))
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

fn file_stream(file: File) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    stream::try_unfold(file, |mut file| async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), file)))
    })
}

fn file_stream_limited(
    file: File,
    bytes: u64,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    stream::try_unfold((file, bytes), |(mut file, remaining)| async move {
        if remaining == 0 {
            return Ok(None);
        }
        let read_limit = remaining.min(64 * 1024) as usize;
        let mut buffer = vec![0_u8; read_limit];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.truncate(read);
        Ok(Some((Bytes::from(buffer), (file, remaining - read as u64))))
    })
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
