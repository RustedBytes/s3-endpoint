use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use sha2::Digest as Sha2Digest;
use tokio::io::AsyncWriteExt;

use crate::{
    AppState, auth,
    body::{
        checksum::{ChecksumName, ChecksumRequest},
        upload::{validate_fixed_sha256_payload_hash, write_upload_body},
    },
    config::S3Action,
    error::S3Error,
    handlers::put_object::validate_upload_headers,
    handlers::{
        request::{
            authenticate_request, authorize_request, resolve_request_target,
            validate_empty_payload_hash,
        },
        s3::unique_query_param,
        upload_metadata::collect_upload_metadata,
        validate_empty_request_body_headers, validate_supported_request_body_length,
    },
    s3::types::{ETag, PartNumber, RequestId, UploadId},
    storage::{CompletedPart, StoreError, UploadProcessing, UploadSession},
};

const COMPLETE_MULTIPART_XML_LIMIT: usize = 8 * 1024 * 1024;

pub(crate) async fn create_multipart_upload(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    validate_empty_request_body_headers(request.headers(), "CreateMultipartUpload")?;
    validate_upload_headers(request.headers())?;
    validate_empty_payload_hash(&request)?;
    let target = resolve_request_target(&state, &request)?;
    authorize_request(
        &state,
        &auth_context,
        &target.bucket,
        Some(&target.key),
        S3Action::CreateMultipartUpload,
    )?;
    let session = state
        .multipart_store
        .create_upload(
            target.bucket,
            target.key,
            auth_context.access_key_id.clone(),
            collect_upload_metadata(request.headers())?,
        )
        .await
        .map_err(map_store_error)?;
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n\
         \x20 <Bucket>{}</Bucket>\n\
         \x20 <Key>{}</Key>\n\
         \x20 <UploadId>{}</UploadId>\n\
         </InitiateMultipartUploadResult>\n",
        escape_xml(session.bucket.as_str()),
        escape_xml(session.key.as_str()),
        escape_xml(session.upload_id.as_str())
    );

    xml_response(StatusCode::OK, request_id, body)
}

pub(crate) async fn upload_part(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    upload_id: UploadId,
    part_number: PartNumber,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    validate_supported_request_body_length(request.headers())?;
    validate_upload_headers(request.headers())?;
    let headers = request.headers().clone();
    let session = validate_upload_session_target(&state, &request, &auth_context, &upload_id)?;
    authorize_request(
        &state,
        &auth_context,
        &session.bucket,
        Some(&session.key),
        S3Action::UploadPart,
    )?;

    let _part_writer_permit = state.try_acquire_multipart_part_writer()?;
    let _aws_chunked_decoder_permit = state.try_acquire_aws_chunked_decoder(&headers)?;

    let mut temp = state
        .multipart_store
        .create_temp_part(&upload_id, part_number)
        .await
        .map_err(map_store_error)?;
    let uploaded_body = match write_upload_body(
        &headers,
        request.into_body(),
        &mut temp.writer,
        "part body",
        auth_context.streaming_signing.as_ref(),
        state.config.upload_limits.max_part_size,
    )
    .await
    {
        Ok(uploaded_body) => uploaded_body,
        Err(error) => {
            discard_temp_part(temp, "part body upload failure").await;
            return Err(error);
        }
    };
    if let Err(err) = temp.writer.flush().await {
        discard_temp_part(temp, "part body flush failure").await;
        return Err(S3Error::internal(format!(
            "failed to flush part body: {err}"
        )));
    }

    let etag = ETag::from_hex_md5(hex::encode(&uploaded_body.md5_digest));
    let response_checksums = uploaded_body.checksums.clone();
    let uploaded_size = uploaded_body.size.get();
    state
        .multipart_store
        .commit_part(
            &upload_id,
            part_number,
            temp,
            crate::storage::CommittedPart {
                size: uploaded_size,
                md5: uploaded_body.md5_digest,
                etag: etag.clone(),
                checksums: uploaded_body.checksums,
            },
        )
        .await
        .map_err(map_store_error)?;

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::ETAG, etag.as_str())
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0");
    for (name, value) in response_checksums {
        response = response.header(name, value);
    }
    let response = response
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;

    Ok(crate::handlers::s3::record_decoded_body_bytes(
        response,
        uploaded_size,
    ))
}

pub(crate) async fn list_parts(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    upload_id: UploadId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    let query = request.uri().query().unwrap_or_default();
    let page = ListPartsPageRequest::parse(query)?;
    let session = validate_upload_session_target(&state, &request, &auth_context, &upload_id)?;
    authorize_request(
        &state,
        &auth_context,
        &session.bucket,
        Some(&session.key),
        S3Action::ListMultipartUploadParts,
    )?;
    validate_empty_payload_hash(&request)?;

    let matching_parts: Vec<_> = session
        .parts
        .values()
        .filter(|part| part.part_number.get() > page.part_number_marker)
        .take(page.max_parts + 1)
        .collect();
    let is_truncated = matching_parts.len() > page.max_parts;
    let listed_parts = matching_parts
        .iter()
        .take(page.max_parts)
        .copied()
        .collect::<Vec<_>>();
    let next_marker = is_truncated
        .then(|| listed_parts.last().map(|part| part.part_number))
        .flatten();

    let mut parts = String::new();
    for part in &listed_parts {
        let mut checksum_xml = String::new();
        for (name, value) in &part.checksums {
            if let Some(element_name) = checksum_xml_element_name(name) {
                checksum_xml.push_str(&format!(
                    "    <{}>{}</{}>\n",
                    element_name,
                    escape_xml(value),
                    element_name
                ));
            }
        }
        parts.push_str(&format!(
            "  <Part>\n    <PartNumber>{}</PartNumber>\n    <LastModified>{}</LastModified>\n    <ETag>{}</ETag>\n    <Size>{}</Size>\n{}  </Part>\n",
            part.part_number.get(),
            format_s3_datetime(part.last_modified),
            escape_xml(part.etag.as_str()),
            part.size,
            checksum_xml
        ));
    }

    let next_marker_xml = next_marker
        .map(|marker| {
            format!(
                "  <NextPartNumberMarker>{}</NextPartNumberMarker>\n",
                marker.get()
            )
        })
        .unwrap_or_default();

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n\
         \x20 <Bucket>{}</Bucket>\n\
         \x20 <Key>{}</Key>\n\
         \x20 <UploadId>{}</UploadId>\n\
         \x20 <PartNumberMarker>{}</PartNumberMarker>\n\
         \x20 <MaxParts>{}</MaxParts>\n\
         \x20 <IsTruncated>{}</IsTruncated>\n\
         {}\
         {}\
         </ListPartsResult>\n",
        escape_xml(session.bucket.as_str()),
        escape_xml(session.key.as_str()),
        escape_xml(session.upload_id.as_str()),
        page.part_number_marker,
        page.max_parts,
        is_truncated,
        next_marker_xml,
        parts,
    );

    xml_response(StatusCode::OK, request_id, body)
}

fn checksum_xml_element_name(header_name: &str) -> Option<&'static str> {
    ChecksumName::from_header_name(header_name).map(ChecksumName::xml_element_name)
}

pub(crate) async fn abort_multipart_upload(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    upload_id: UploadId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    validate_empty_request_body_headers(request.headers(), "AbortMultipartUpload")?;
    let session = validate_upload_session_target(&state, &request, &auth_context, &upload_id)?;
    authorize_request(
        &state,
        &auth_context,
        &session.bucket,
        Some(&session.key),
        S3Action::AbortMultipartUpload,
    )?;
    validate_empty_payload_hash(&request)?;
    state
        .multipart_store
        .abort_upload(&upload_id)
        .await
        .map_err(map_store_error)?;

    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("x-amz-request-id", request_id.as_str())
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}

pub(crate) async fn complete_multipart_upload(
    state: AppState,
    request: Request<Body>,
    request_id: &RequestId,
    upload_id: UploadId,
) -> Result<Response, S3Error> {
    let auth_context = authenticate_request(&state, &request)?;
    let headers = request.headers().clone();
    let location = completion_location(&request);
    let session = validate_upload_session_target(&state, &request, &auth_context, &upload_id)?;
    authorize_request(
        &state,
        &auth_context,
        &session.bucket,
        Some(&session.key),
        S3Action::CompleteMultipartUpload,
    )?;
    let body = axum::body::to_bytes(request.into_body(), COMPLETE_MULTIPART_XML_LIMIT)
        .await
        .map_err(|err| S3Error::invalid_request(format!("failed to read completion XML: {err}")))?;
    let completion_payload_digest = sha2::Sha256::digest(&body);
    validate_fixed_sha256_payload_hash(&headers, completion_payload_digest.as_ref())?;
    let parts = parse_completed_parts(std::str::from_utf8(&body).map_err(|_| {
        S3Error::invalid_request("CompleteMultipartUpload XML must be valid UTF-8")
    })?)?;
    if parts.is_empty() {
        return Err(S3Error::invalid_part(
            "CompleteMultipartUpload must include at least one part",
        ));
    }
    validate_ascending_parts(&parts)?;
    let checksum_request = ChecksumRequest::from_headers(&headers)?;

    let metadata = state
        .multipart_store
        .complete_upload(
            &state.object_store,
            &upload_id,
            &parts,
            &checksum_request,
            &state.config.upload_limits,
            UploadProcessing {
                request_id,
                upload_processors: state.upload_processors(),
            },
        )
        .await
        .map_err(map_store_error)?;

    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n\
         \x20 <Location>{}</Location>\n\
         \x20 <Bucket>{}</Bucket>\n\
         \x20 <Key>{}</Key>\n\
         \x20 <ETag>{}</ETag>\n\
         </CompleteMultipartUploadResult>\n",
        escape_xml(&location),
        escape_xml(metadata.bucket.as_str()),
        escape_xml(metadata.key.as_str()),
        escape_xml(metadata.etag.as_str())
    );

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("x-amz-request-id", request_id.as_str());
    if !metadata.checksums.is_empty() {
        response = response.header("x-amz-checksum-type", "FULL_OBJECT");
    }
    for (name, value) in &metadata.checksums {
        response = response.header(name, value);
    }
    let response = response
        .body(Body::from(body))
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))?;

    Ok(crate::handlers::s3::record_decoded_body_bytes(
        response,
        metadata.size,
    ))
}

fn validate_upload_session_target(
    state: &AppState,
    request: &Request<Body>,
    auth_context: &auth::AuthContext,
    upload_id: &UploadId,
) -> Result<UploadSession, S3Error> {
    let session = state
        .multipart_store
        .get_upload(upload_id)
        .ok_or_else(S3Error::no_such_upload)?;
    if !session.is_open() {
        return Err(S3Error::no_such_upload());
    }
    let target = resolve_request_target(state, request)?;

    if target.bucket != session.bucket || target.key != session.key {
        return Err(S3Error::no_such_upload());
    }
    if session
        .owner_access_key_id
        .as_ref()
        .is_some_and(|owner| auth_context.access_key_id.as_ref() != Some(owner))
    {
        return Err(S3Error::no_such_upload());
    }

    Ok(session)
}

fn completion_location(request: &Request<Body>) -> String {
    let path = request.uri().path();
    request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| path.to_owned(), |host| format!("http://{host}{path}"))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct ListPartsPageRequest {
    max_parts: usize,
    part_number_marker: u16,
}

impl ListPartsPageRequest {
    const DEFAULT_MAX_PARTS: usize = 1000;
    const MAX_PARTS_LIMIT: usize = 1000;

    fn parse(query: &str) -> Result<Self, S3Error> {
        let max_parts = match unique_query_param(query, "max-parts")? {
            Some(value) => {
                let max_parts = value
                    .parse::<usize>()
                    .map_err(|_| S3Error::invalid_argument("max-parts must be an integer"))?;
                if max_parts == 0 {
                    return Err(S3Error::invalid_argument("max-parts must be in 1..=1000"));
                }
                max_parts.min(Self::MAX_PARTS_LIMIT)
            }
            None => Self::DEFAULT_MAX_PARTS,
        };
        let part_number_marker = match unique_query_param(query, "part-number-marker")? {
            Some(value) => {
                let marker = value.parse::<u16>().map_err(|_| {
                    S3Error::invalid_argument("part-number-marker must be an integer")
                })?;
                if marker > 10_000 {
                    return Err(S3Error::invalid_argument(
                        "part-number-marker must be in 0..=10000",
                    ));
                }
                marker
            }
            None => 0,
        };

        Ok(Self {
            max_parts,
            part_number_marker,
        })
    }
}

fn parse_completed_parts(xml: &str) -> Result<Vec<CompletedPart>, S3Error> {
    let request: CompleteMultipartUploadXml =
        quick_xml::de::from_str(xml).map_err(|err| S3Error::malformed_xml(err.to_string()))?;

    request
        .parts
        .into_iter()
        .map(|part| {
            let part_number = part
                .part_number
                .ok_or_else(|| S3Error::malformed_xml("PartNumber is required"))?;
            let part_number = PartNumber::parse(part_number)
                .map_err(|_| S3Error::invalid_part("PartNumber must be in 1..=10000"))?;
            let etag = part
                .etag
                .ok_or_else(|| S3Error::malformed_xml("ETag is required"))?;
            let etag = ETag::parse(etag).map_err(|_| S3Error::invalid_part("ETag is invalid"))?;
            Ok(CompletedPart { part_number, etag })
        })
        .collect()
}

fn validate_ascending_parts(parts: &[CompletedPart]) -> Result<(), S3Error> {
    if parts
        .windows(2)
        .any(|window| window[0].part_number >= window[1].part_number)
    {
        return Err(S3Error::invalid_part(
            "Parts must be specified in ascending PartNumber order.",
        ));
    }
    Ok(())
}

fn map_store_error(error: StoreError) -> S3Error {
    match error {
        StoreError::NoSuchUpload => S3Error::no_such_upload(),
        StoreError::InvalidPart => {
            S3Error::invalid_part("One or more parts could not be found or the ETag did not match.")
        }
        StoreError::EntityTooSmall => S3Error::entity_too_small(
            "Your proposed upload is smaller than the minimum allowed object size.",
        ),
        StoreError::EntityTooLarge => {
            S3Error::entity_too_large("Your proposed upload exceeds the maximum allowed size.")
        }
        StoreError::Checksum(error) => error,
        StoreError::Processor(error) => error,
        other => S3Error::internal(format!("storage operation failed: {other}")),
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename = "CompleteMultipartUpload")]
struct CompleteMultipartUploadXml {
    #[serde(rename = "Part", default)]
    parts: Vec<CompletedPartXml>,
}

#[derive(Debug, Deserialize)]
struct CompletedPartXml {
    #[serde(rename = "PartNumber")]
    part_number: Option<u16>,
    #[serde(rename = "ETag")]
    etag: Option<String>,
}

fn xml_response(
    status: StatusCode,
    request_id: &RequestId,
    body: String,
) -> Result<Response, S3Error> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .header("x-amz-request-id", request_id.as_str())
        .body(Body::from(body))
        .map_err(|err| S3Error::internal(format!("failed to build response: {err}")))
}

fn format_s3_datetime(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

async fn discard_temp_part(temp: crate::storage::TempPartWriter, reason: &'static str) {
    if let Err(error) = temp.discard().await {
        tracing::debug!(
            reason,
            error = %error,
            "failed to discard temporary multipart part after upload failure"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_multipart_parser_accepts_maximum_part_count_with_formatted_xml() {
        let mut xml = String::from("<CompleteMultipartUpload>\n");
        for part_number in 1..=10_000 {
            xml.push_str(&format!(
                "                                <Part>\n\
                 \x20                                 <PartNumber>{part_number}</PartNumber>\n\
                 \x20                                 <ETag>\"{:032x}\"</ETag>\n\
                 \x20                               </Part>\n",
                part_number
            ));
        }
        xml.push_str("</CompleteMultipartUpload>");

        assert!(xml.len() > 1024 * 1024);
        assert!(xml.len() < COMPLETE_MULTIPART_XML_LIMIT);

        let parts = parse_completed_parts(&xml).expect("parse completion xml");
        assert_eq!(parts.len(), 10_000);
        assert_eq!(parts.first().expect("first part").part_number.get(), 1);
        assert_eq!(parts.last().expect("last part").part_number.get(), 10_000);
        validate_ascending_parts(&parts).expect("ascending parts");
    }
}
