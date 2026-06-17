pub mod delete_object;
pub mod get_object;
pub mod head_bucket;
pub mod head_object;
pub mod health;
pub mod multipart;
pub mod put_object;
pub mod request;
pub mod s3;
pub mod upload_metadata;

use axum::http::{HeaderMap, header};

use crate::{body::upload::is_aws_chunked_request, error::S3Error, s3::types::ContentLength};

pub(crate) fn validate_supported_request_body_length(headers: &HeaderMap) -> Result<(), S3Error> {
    let content_length = validate_content_length(headers)?;
    let transfer_encoding = validate_transfer_encoding(headers)?;

    if transfer_encoding.has_chunked {
        if content_length.is_some() && !is_aws_chunked_request(headers) {
            return Err(S3Error::invalid_request(
                "Content-Length must not be used with Transfer-Encoding for non aws-chunked uploads",
            ));
        }
        return Ok(());
    }

    if content_length.is_some() {
        Ok(())
    } else {
        Err(S3Error::missing_content_length())
    }
}

pub(crate) fn validate_empty_request_body_headers(
    headers: &HeaderMap,
    operation: &str,
) -> Result<(), S3Error> {
    let content_length = validate_content_length(headers)?;
    let transfer_encoding = validate_transfer_encoding(headers)?;

    if transfer_encoding.has_any {
        return Err(S3Error::invalid_request(format!(
            "{operation} does not support Transfer-Encoding"
        )));
    }
    if content_length.is_some_and(|content_length| content_length.get() != 0) {
        return Err(S3Error::invalid_request(format!(
            "{operation} requires Content-Length: 0"
        )));
    }
    Ok(())
}

fn validate_content_length(headers: &HeaderMap) -> Result<Option<ContentLength>, S3Error> {
    let values = headers
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(S3Error::invalid_request(
            "Content-Length must not appear more than once",
        ));
    }
    let Some(content_length) = values.first() else {
        return Ok(None);
    };
    let content_length = content_length
        .to_str()
        .map_err(|_| S3Error::invalid_request("Content-Length must be valid ASCII"))?;
    content_length
        .parse::<ContentLength>()
        .map(Some)
        .map_err(|_| S3Error::invalid_request("Content-Length must be an integer"))
}

#[derive(Debug, Default)]
struct TransferEncodingValidation {
    has_any: bool,
    has_chunked: bool,
}

fn validate_transfer_encoding(headers: &HeaderMap) -> Result<TransferEncodingValidation, S3Error> {
    let values = headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(TransferEncodingValidation::default());
    }

    let mut has_chunked = false;
    let mut has_any = false;
    for value in values {
        let value = value
            .to_str()
            .map_err(|_| S3Error::invalid_request("Transfer-Encoding must be valid ASCII"))?;
        for encoding in value.split(',').map(str::trim) {
            if encoding.is_empty() {
                return Err(S3Error::invalid_request(
                    "Transfer-Encoding must not contain empty values",
                ));
            }
            has_any = true;
            if !encoding.eq_ignore_ascii_case("chunked") {
                return Err(S3Error::invalid_request(
                    "Unsupported Transfer-Encoding; only chunked is supported",
                ));
            }
            has_chunked = true;
        }
    }

    Ok(TransferEncodingValidation {
        has_any,
        has_chunked,
    })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn empty_request_body_headers_accept_absent_or_zero_content_length() {
        let headers = HeaderMap::new();
        validate_empty_request_body_headers(&headers, "ListParts").expect("no body headers");

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        validate_empty_request_body_headers(&headers, "ListParts").expect("zero length");
    }

    #[test]
    fn empty_request_body_headers_reject_non_zero_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));

        let error = validate_empty_request_body_headers(&headers, "ListParts")
            .expect_err("non-empty body should fail");

        assert!(format!("{error:?}").contains("ListParts requires Content-Length: 0"));
    }

    #[test]
    fn empty_request_body_headers_reject_transfer_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );

        let error = validate_empty_request_body_headers(&headers, "ListParts")
            .expect_err("transfer encoding should fail");

        assert!(format!("{error:?}").contains("ListParts does not support Transfer-Encoding"));
    }
}
