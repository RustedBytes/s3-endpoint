use std::collections::BTreeMap;

use thiserror::Error;

/// Fully decoded aws-chunked body used by protocol tests and helpers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodedAwsChunkedBody {
    /// Decoded payload bytes with aws-chunked framing removed.
    pub data: Vec<u8>,
    /// Trailer headers keyed by lowercase trailer name.
    pub trailers: BTreeMap<String, String>,
}

/// Decodes an aws-chunked byte buffer into payload bytes and trailers.
///
/// This helper is intended for bounded buffers in tests and protocol utilities;
/// request handling uses the streaming upload parser so object bytes are not
/// buffered in memory. Returns an error for malformed control lines, invalid
/// chunk sizes, missing chunk terminators, malformed trailers, or duplicate
/// trailer names.
pub fn decode_aws_chunked_body(encoded: &[u8]) -> Result<DecodedAwsChunkedBody, AwsChunkedError> {
    let mut cursor = 0;
    let mut data = Vec::new();

    loop {
        let line = read_crlf_line(encoded, &mut cursor)?;
        let size_token = line
            .split_once(';')
            .map_or(line.as_str(), |(size, _)| size)
            .trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|_| AwsChunkedError::InvalidChunkSize(size_token.to_owned()))?;

        if size == 0 {
            let trailers = read_trailers(encoded, &mut cursor)?;
            return Ok(DecodedAwsChunkedBody { data, trailers });
        }

        if encoded.len().saturating_sub(cursor) < size + 2 {
            return Err(AwsChunkedError::UnexpectedEndOfBody);
        }
        data.extend_from_slice(&encoded[cursor..cursor + size]);
        cursor += size;

        if encoded.get(cursor..cursor + 2) != Some(b"\r\n") {
            return Err(AwsChunkedError::MissingChunkTerminator);
        }
        cursor += 2;
    }
}

fn read_trailers(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<BTreeMap<String, String>, AwsChunkedError> {
    let mut trailers = BTreeMap::new();
    loop {
        let line = read_crlf_line(encoded, cursor)?;
        if line.is_empty() {
            return Ok(trailers);
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(AwsChunkedError::MalformedTrailer(line));
        };
        let name = name.trim().to_ascii_lowercase();
        if trailers.contains_key(&name) {
            return Err(AwsChunkedError::DuplicateTrailer(name));
        }
        trailers.insert(name, value.trim().to_owned());
    }
}

fn read_crlf_line(encoded: &[u8], cursor: &mut usize) -> Result<String, AwsChunkedError> {
    let remaining = encoded
        .get(*cursor..)
        .ok_or(AwsChunkedError::UnexpectedEndOfBody)?;
    let Some(offset) = remaining.windows(2).position(|window| window == b"\r\n") else {
        return Err(AwsChunkedError::UnexpectedEndOfBody);
    };
    let line = std::str::from_utf8(&remaining[..offset])
        .map_err(|_| AwsChunkedError::NonUtf8ControlLine)?
        .to_owned();
    *cursor += offset + 2;
    Ok(line)
}

#[derive(Debug, Error)]
/// Errors returned by [`decode_aws_chunked_body`].
pub enum AwsChunkedError {
    /// The body ended before a complete chunk, control line, or trailer block.
    #[error("aws-chunked body ended unexpectedly")]
    UnexpectedEndOfBody,

    /// A chunk-size token was not valid hexadecimal.
    #[error("aws-chunked chunk size is invalid: {0}")]
    InvalidChunkSize(String),

    /// A non-final chunk was not followed by `\r\n`.
    #[error("aws-chunked chunk is missing trailing CRLF")]
    MissingChunkTerminator,

    /// A chunk control line or trailer line was not valid UTF-8.
    #[error("aws-chunked control line is not UTF-8")]
    NonUtf8ControlLine,

    /// A trailer line did not contain a `name: value` pair.
    #[error("aws-chunked trailer is malformed: {0}")]
    MalformedTrailer(String),

    /// A trailer name appeared more than once after case normalization.
    #[error("aws-chunked trailer appears more than once: {0}")]
    DuplicateTrailer(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_chunks_and_trailers() {
        let got = decode_aws_chunked_body(
            b"5;chunk-signature=ignored\r\nhello\r\n0\r\nx-amz-checksum-crc32: abcd\r\n\r\n",
        )
        .expect("decode");

        assert_eq!(got.data, b"hello");
        assert_eq!(
            got.trailers.get("x-amz-checksum-crc32"),
            Some(&"abcd".to_owned())
        );
    }

    #[test]
    fn rejects_missing_chunk_terminator() {
        let got = decode_aws_chunked_body(b"5\r\nhello0\r\n\r\n");

        assert!(matches!(got, Err(AwsChunkedError::MissingChunkTerminator)));
    }

    #[test]
    fn rejects_duplicate_trailer_names_case_insensitively() {
        let got = decode_aws_chunked_body(
            b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32: abcd\r\nX-Amz-Checksum-Crc32: efgh\r\n\r\n",
        );

        assert!(matches!(
            got,
            Err(AwsChunkedError::DuplicateTrailer(name)) if name == "x-amz-checksum-crc32"
        ));
    }
}
