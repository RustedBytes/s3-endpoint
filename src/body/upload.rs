use std::{collections::BTreeMap, path::Path};

use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, header},
};
use crc::{CRC_32_ISCSI, CRC_32_ISO_HDLC, Crc};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::{fs::File, io::AsyncReadExt};

use crate::{
    auth::StreamingSigningContext,
    body::checksum::{ChecksumDigests, ChecksumRequest},
    error::S3Error,
    s3::types::{ContentLength, PayloadHashMode},
};

const MAX_AWS_CHUNKED_CONTROL_LINE_BYTES: usize = 16 * 1024;
static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UploadedBody {
    pub size: ContentLength,
    pub md5_digest: Vec<u8>,
    pub checksums: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FinalUploadBody {
    pub size: ContentLength,
    pub digests: ChecksumDigests,
}

/// Re-reads a staged upload and computes the final size and checksum digests.
///
/// This is used after upload processors may have replaced the originally
/// uploaded bytes.
pub(crate) async fn summarize_staged_upload(
    path: &Path,
    buffer_size: usize,
) -> Result<FinalUploadBody, S3Error> {
    let mut file = File::open(path)
        .await
        .map_err(|err| S3Error::internal(format!("failed to open staged upload: {err}")))?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut sha512 = Sha512::new();
    let mut crc32 = CRC32.digest();
    let mut crc32c = CRC32C.digest();
    let mut size = 0_u64;
    let mut buffer = vec![0_u8; buffer_size];

    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|err| S3Error::internal(format!("failed to read staged upload: {err}")))?;
        if read == 0 {
            break;
        }
        let chunk = &buffer[..read];
        size = size.saturating_add(read as u64);
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        sha512.update(chunk);
        crc32.update(chunk);
        crc32c.update(chunk);
    }

    Ok(FinalUploadBody {
        size: ContentLength::new(size),
        digests: ChecksumDigests {
            md5: md5.finalize().to_vec(),
            sha1: sha1.finalize().to_vec(),
            sha256: sha256.finalize().to_vec(),
            sha512: sha512.finalize().to_vec(),
            crc32: crc32.finalize(),
            crc32c: crc32c.finalize(),
        },
    })
}

/// Streams an HTTP request body to `writer` while validating S3 payload integrity.
///
/// Supports plain bodies and aws-chunked bodies, enforces decoded size limits,
/// validates SigV4 streaming chunk signatures when present, and returns the
/// decoded body size plus checksums to echo in the response.
pub async fn write_upload_body<W>(
    headers: &HeaderMap,
    body: Body,
    writer: &mut W,
    write_target: &str,
    streaming_signing: Option<&StreamingSigningContext>,
    max_decoded_size: u64,
) -> Result<UploadedBody, S3Error>
where
    W: AsyncWrite + Unpin,
{
    validate_payload_hash_mode(headers)?;

    let mut state = UploadBodyState::new(headers);

    let trailers = if is_aws_chunked_request(headers) {
        write_aws_chunked_upload_body(
            headers,
            body,
            writer,
            &mut state,
            write_target,
            streaming_signing,
            max_decoded_size,
        )
        .await?
    } else {
        let expected_content_length = content_length(headers)?;
        let mut body = body.into_data_stream();

        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|err| {
                S3Error::invalid_request(format!("failed to read request body: {err}"))
            })?;
            validate_plain_body_chunk_length(expected_content_length, state.size, chunk.len())?;
            validate_decoded_size_limit(state.size, chunk.len(), max_decoded_size)?;
            write_body_chunk(writer, &chunk, &mut state, write_target).await?;
        }
        validate_plain_content_length(expected_content_length, state.size)?;
        BTreeMap::new()
    };

    let size = ContentLength::new(state.size);
    let md5_digest = state.md5.finalize().to_vec();
    let sha1_digest = state
        .sha1
        .map(|digest| digest.finalize().to_vec())
        .unwrap_or_default();
    let sha256_digest = state
        .sha256
        .map(|digest| digest.finalize().to_vec())
        .unwrap_or_default();
    let sha512_digest = state
        .sha512
        .map(|digest| digest.finalize().to_vec())
        .unwrap_or_default();
    validate_actual_sha256_payload_hash(headers, &sha256_digest)?;
    let checksum_request = ChecksumRequest::from_headers_and_trailers(headers, &trailers)?;
    checksum_request.validate(&ChecksumDigests {
        md5: md5_digest.clone(),
        sha1: sha1_digest,
        sha256: sha256_digest,
        sha512: sha512_digest,
        crc32: state
            .crc32
            .map(|digest| digest.finalize())
            .unwrap_or_default(),
        crc32c: state
            .crc32c
            .map(|digest| digest.finalize())
            .unwrap_or_default(),
    })?;

    Ok(UploadedBody {
        size,
        md5_digest,
        checksums: checksum_request.checksum_values(),
    })
}

/// Parses the `x-amz-content-sha256` payload mode from request headers.
pub(crate) fn payload_hash_mode(headers: &HeaderMap) -> Result<PayloadHashMode, S3Error> {
    let value = optional_singleton_header(headers, "x-amz-content-sha256")?
        .map(|value| value.to_str())
        .transpose()
        .map_err(|_| S3Error::invalid_request("x-amz-content-sha256 must be valid ASCII"))?;

    PayloadHashMode::parse(value)
        .map_err(|_| S3Error::invalid_request("Unsupported x-amz-content-sha256 payload mode"))
}

fn validate_payload_hash_mode(headers: &HeaderMap) -> Result<(), S3Error> {
    let mode = payload_hash_mode(headers)?;
    if is_aws_chunked_request(headers) {
        match mode {
            PayloadHashMode::StreamingSignedPayload
            | PayloadHashMode::StreamingSignedPayloadTrailer
            | PayloadHashMode::StreamingUnsignedPayloadTrailer => Ok(()),
            _ => Err(S3Error::invalid_request(
                "Unsupported x-amz-content-sha256 payload mode for aws-chunked upload",
            )),
        }
    } else {
        match mode {
            PayloadHashMode::Missing
            | PayloadHashMode::UnsignedPayload
            | PayloadHashMode::FixedSha256 { .. } => Ok(()),
            _ => Err(S3Error::invalid_request(
                "Unsupported x-amz-content-sha256 payload mode",
            )),
        }
    }
}

/// Validates an actual SHA-256 payload hash for ordinary non-aws-chunked bodies.
pub(crate) fn validate_actual_sha256_payload_hash(
    headers: &HeaderMap,
    actual_digest: &[u8],
) -> Result<(), S3Error> {
    if is_aws_chunked_request(headers) {
        return Ok(());
    }

    match payload_hash_mode(headers)? {
        PayloadHashMode::Missing | PayloadHashMode::UnsignedPayload => Ok(()),
        PayloadHashMode::FixedSha256 { digest, .. } => {
            if digest.as_slice() != actual_digest {
                return Err(S3Error::bad_digest(
                    "The provided x-amz-content-sha256 header does not match what was computed.",
                ));
            }
            Ok(())
        }
        _ => Err(S3Error::invalid_request(
            "Unsupported x-amz-content-sha256 payload mode",
        )),
    }
}

/// Validates a fixed SHA-256 payload hash for operations with a known digest.
pub(crate) fn validate_fixed_sha256_payload_hash(
    headers: &HeaderMap,
    actual_digest: &[u8],
) -> Result<(), S3Error> {
    match payload_hash_mode(headers)? {
        PayloadHashMode::Missing | PayloadHashMode::UnsignedPayload => Ok(()),
        PayloadHashMode::FixedSha256 { digest, .. } => {
            if digest.as_slice() != actual_digest {
                return Err(S3Error::bad_digest(
                    "The provided x-amz-content-sha256 header does not match what was computed.",
                ));
            }
            Ok(())
        }
        _ => Err(S3Error::invalid_request(
            "Unsupported x-amz-content-sha256 payload mode",
        )),
    }
}

async fn write_aws_chunked_upload_body<W>(
    headers: &HeaderMap,
    body: Body,
    writer: &mut W,
    state: &mut UploadBodyState<'_>,
    write_target: &str,
    streaming_signing: Option<&StreamingSigningContext>,
    max_decoded_size: u64,
) -> Result<BTreeMap<String, String>, S3Error>
where
    W: AsyncWrite + Unpin,
{
    let mut parser =
        AwsChunkedUploadParser::new(streaming_signature_verifier(headers, streaming_signing)?);
    let mut body = body.into_data_stream();

    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|err| {
            S3Error::invalid_request(format!("failed to read aws-chunked body: {err}"))
        })?;
        if let Some(trailers) = parser
            .push_and_write(&chunk, writer, state, write_target, max_decoded_size)
            .await?
        {
            validate_decoded_content_length(headers, state.size)?;
            return Ok(trailers);
        }
    }

    if let Some(trailers) = parser.finish() {
        validate_decoded_content_length(headers, state.size)?;
        return Ok(trailers);
    }

    Err(S3Error::invalid_request(
        "aws-chunked body ended unexpectedly",
    ))
}

fn validate_decoded_content_length(headers: &HeaderMap, actual_length: u64) -> Result<(), S3Error> {
    let expected_length = decoded_content_length(headers)?.ok_or_else(|| {
        S3Error::invalid_request("x-amz-decoded-content-length is required for aws-chunked uploads")
    })?;
    if expected_length.get() != actual_length {
        return Err(S3Error::invalid_request(
            "x-amz-decoded-content-length does not match decoded body length",
        ));
    }
    Ok(())
}

fn validate_decoded_size_limit(
    bytes_read: u64,
    next_chunk_len: usize,
    max_decoded_size: u64,
) -> Result<(), S3Error> {
    if bytes_read.saturating_add(next_chunk_len as u64) > max_decoded_size {
        return Err(S3Error::entity_too_large(
            "Your proposed upload exceeds the maximum allowed size.",
        ));
    }
    Ok(())
}

fn validate_plain_body_chunk_length(
    expected_length: Option<ContentLength>,
    bytes_read: u64,
    next_chunk_len: usize,
) -> Result<(), S3Error> {
    if let Some(expected_length) = expected_length
        && bytes_read.saturating_add(next_chunk_len as u64) > expected_length.get()
    {
        return Err(S3Error::invalid_request(
            "Content-Length does not match request body length",
        ));
    }
    Ok(())
}

fn validate_plain_content_length(
    expected_length: Option<ContentLength>,
    actual_length: u64,
) -> Result<(), S3Error> {
    if let Some(expected_length) = expected_length
        && expected_length.get() != actual_length
    {
        return Err(S3Error::invalid_request(
            "Content-Length does not match request body length",
        ));
    }
    Ok(())
}

struct UploadBodyState<'a> {
    md5: Md5,
    sha256: Option<Sha256>,
    sha1: Option<Sha1>,
    sha512: Option<Sha512>,
    crc32: Option<crc::Digest<'a, u32>>,
    crc32c: Option<crc::Digest<'a, u32>>,
    size: u64,
}

impl UploadBodyState<'_> {
    fn new(headers: &HeaderMap) -> Self {
        Self {
            md5: Md5::new(),
            sha256: (requires_actual_sha256_payload_hash(headers)
                || checksum_header_or_declared_trailer(headers, "x-amz-checksum-sha256"))
            .then(Sha256::new),
            sha1: checksum_header_or_declared_trailer(headers, "x-amz-checksum-sha1")
                .then(Sha1::new),
            sha512: checksum_header_or_declared_trailer(headers, "x-amz-checksum-sha512")
                .then(Sha512::new),
            crc32: checksum_header_or_declared_trailer(headers, "x-amz-checksum-crc32")
                .then(|| CRC32.digest()),
            crc32c: checksum_header_or_declared_trailer(headers, "x-amz-checksum-crc32c")
                .then(|| CRC32C.digest()),
            size: 0,
        }
    }
}

async fn write_body_chunk<W>(
    writer: &mut W,
    chunk: &[u8],
    state: &mut UploadBodyState<'_>,
    write_target: &str,
) -> Result<(), S3Error>
where
    W: AsyncWrite + Unpin,
{
    state.size += chunk.len() as u64;
    state.md5.update(chunk);
    if let Some(sha256) = &mut state.sha256 {
        sha256.update(chunk);
    }
    if let Some(sha1) = &mut state.sha1 {
        sha1.update(chunk);
    }
    if let Some(sha512) = &mut state.sha512 {
        sha512.update(chunk);
    }
    if let Some(crc32) = &mut state.crc32 {
        crc32.update(chunk);
    }
    if let Some(crc32c) = &mut state.crc32c {
        crc32c.update(chunk);
    }
    writer
        .write_all(chunk)
        .await
        .map_err(|err| S3Error::internal(format!("failed to write {write_target}: {err}")))?;
    Ok(())
}

fn requires_actual_sha256_payload_hash(headers: &HeaderMap) -> bool {
    if is_aws_chunked_request(headers) {
        return false;
    }
    matches!(
        payload_hash_mode(headers),
        Ok(PayloadHashMode::FixedSha256 { .. })
    )
}

fn checksum_header_or_declared_trailer(headers: &HeaderMap, name: &str) -> bool {
    headers.contains_key(name) || checksum_trailer_declares(headers, name)
}

fn checksum_trailer_declares(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get("x-amz-trailer")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|declared| declared.trim().eq_ignore_ascii_case(name))
        })
}

struct AwsChunkedUploadParser {
    buffer: Vec<u8>,
    state: AwsChunkedParserState,
    trailers: BTreeMap<String, String>,
    signature_verifier: Option<AwsChunkSignatureVerifier>,
}

impl AwsChunkedUploadParser {
    fn new(signature_verifier: Option<AwsChunkSignatureVerifier>) -> Self {
        Self {
            buffer: Vec::new(),
            state: AwsChunkedParserState::ChunkHeader,
            trailers: BTreeMap::new(),
            signature_verifier,
        }
    }

    async fn push_and_write<W>(
        &mut self,
        bytes: &[u8],
        writer: &mut W,
        body_state: &mut UploadBodyState<'_>,
        write_target: &str,
        max_decoded_size: u64,
    ) -> Result<Option<BTreeMap<String, String>>, S3Error>
    where
        W: AsyncWrite + Unpin,
    {
        if matches!(self.state, AwsChunkedParserState::Done) {
            if bytes.is_empty() {
                return Ok(Some(std::mem::take(&mut self.trailers)));
            }
            return Err(S3Error::invalid_request(
                "aws-chunked body has data after final trailer",
            ));
        }

        self.buffer.extend_from_slice(bytes);

        loop {
            match self.state {
                AwsChunkedParserState::ChunkHeader => {
                    let Some(line) = self.read_line()? else {
                        return Ok(None);
                    };
                    let header = parse_aws_chunk_header(&line)?;
                    if header.size == 0 {
                        self.verify_chunk_signature(header.signature.as_deref(), b"")?;
                        self.state = AwsChunkedParserState::Trailer;
                    } else {
                        self.state = AwsChunkedParserState::ChunkData {
                            size: header.size,
                            signature: header.signature,
                        };
                    }
                }
                AwsChunkedParserState::ChunkData {
                    size,
                    ref signature,
                } => {
                    if self.buffer.len() < size + 2 {
                        return Ok(None);
                    }
                    if self.buffer.get(size..size + 2) != Some(b"\r\n") {
                        return Err(S3Error::invalid_request(
                            "aws-chunked chunk is missing trailing CRLF",
                        ));
                    }
                    let data = self.buffer.drain(..size).collect::<Vec<_>>();
                    self.buffer.drain(..2);
                    let signature = signature.clone();
                    self.verify_chunk_signature(signature.as_deref(), &data)?;
                    validate_decoded_size_limit(body_state.size, data.len(), max_decoded_size)?;
                    write_body_chunk(writer, &data, body_state, write_target).await?;
                    self.state = AwsChunkedParserState::ChunkHeader;
                }
                AwsChunkedParserState::Trailer => {
                    let Some(line) = self.read_line()? else {
                        return Ok(None);
                    };
                    if line.is_empty() {
                        self.verify_trailer_signature()?;
                        self.state = AwsChunkedParserState::Done;
                        if !self.buffer.is_empty() {
                            return Err(S3Error::invalid_request(
                                "aws-chunked body has data after final trailer",
                            ));
                        }
                        return Ok(Some(std::mem::take(&mut self.trailers)));
                    }
                    let Some((name, value)) = line.split_once(':') else {
                        return Err(S3Error::invalid_request(format!(
                            "aws-chunked trailer is malformed: {line}"
                        )));
                    };
                    let name = name.trim().to_ascii_lowercase();
                    if self.trailers.contains_key(&name) {
                        return Err(S3Error::invalid_request(format!(
                            "aws-chunked trailer appears more than once: {name}"
                        )));
                    }
                    self.trailers.insert(name, value.trim().to_owned());
                }
                AwsChunkedParserState::Done => unreachable!("done state handled before loop"),
            }
        }
    }

    fn finish(self) -> Option<BTreeMap<String, String>> {
        matches!(self.state, AwsChunkedParserState::Done).then_some(self.trailers)
    }

    fn verify_chunk_signature(
        &mut self,
        provided_signature: Option<&str>,
        chunk_data: &[u8],
    ) -> Result<(), S3Error> {
        let Some(verifier) = &mut self.signature_verifier else {
            return Ok(());
        };
        verifier.verify(provided_signature, chunk_data)
    }

    fn verify_trailer_signature(&mut self) -> Result<(), S3Error> {
        let Some(verifier) = &mut self.signature_verifier else {
            return Ok(());
        };
        verifier.verify_trailer(&self.trailers)
    }

    fn read_line(&mut self) -> Result<Option<String>, S3Error> {
        let Some(offset) = self.buffer.windows(2).position(|window| window == b"\r\n") else {
            if self.buffer.len() > MAX_AWS_CHUNKED_CONTROL_LINE_BYTES {
                return Err(S3Error::invalid_request(
                    "aws-chunked control line is too large",
                ));
            }
            return Ok(None);
        };
        let line = self.buffer.drain(..offset).collect::<Vec<_>>();
        self.buffer.drain(..2);
        String::from_utf8(line)
            .map(Some)
            .map_err(|_| S3Error::invalid_request("aws-chunked control line is not UTF-8"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AwsChunkedParserState {
    ChunkHeader,
    ChunkData {
        size: usize,
        signature: Option<String>,
    },
    Trailer,
    Done,
}

#[derive(Debug)]
struct AwsChunkHeader {
    size: usize,
    signature: Option<String>,
}

fn parse_aws_chunk_header(line: &str) -> Result<AwsChunkHeader, S3Error> {
    let (size_token, extensions) = line
        .split_once(';')
        .map_or((line.trim(), ""), |(size, extensions)| {
            (size.trim(), extensions)
        });
    let size = usize::from_str_radix(size_token, 16).map_err(|_| {
        S3Error::invalid_request(format!("aws-chunked chunk size is invalid: {size_token}"))
    })?;
    let mut signature = None;
    for extension in extensions
        .split(';')
        .filter(|extension| !extension.trim().is_empty())
    {
        let Some((name, value)) = extension.split_once('=') else {
            return Err(S3Error::invalid_request(format!(
                "aws-chunked chunk extension is malformed: {extension}"
            )));
        };
        if !name.trim().eq_ignore_ascii_case("chunk-signature") {
            continue;
        }
        if signature.is_some() {
            return Err(S3Error::invalid_request(
                "aws-chunked chunk-signature appears more than once",
            ));
        }
        let value = value.trim();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(S3Error::invalid_request(
                "aws-chunked chunk-signature must be lowercase 64-character hex",
            ));
        }
        signature = Some(value.to_owned());
    }

    Ok(AwsChunkHeader { size, signature })
}

fn streaming_signature_verifier(
    headers: &HeaderMap,
    streaming_signing: Option<&StreamingSigningContext>,
) -> Result<Option<AwsChunkSignatureVerifier>, S3Error> {
    let mode = match payload_hash_mode(headers)? {
        PayloadHashMode::StreamingSignedPayload => StreamingSignatureMode::Payload,
        PayloadHashMode::StreamingSignedPayloadTrailer => StreamingSignatureMode::PayloadTrailer,
        _ => return Ok(None),
    };

    let Some(streaming_signing) = streaming_signing else {
        return Err(S3Error::signature_does_not_match());
    };

    Ok(Some(AwsChunkSignatureVerifier::new(
        streaming_signing,
        mode,
    )))
}

struct AwsChunkSignatureVerifier {
    signing_key: Vec<u8>,
    previous_signature: String,
    amz_date: String,
    credential_scope: String,
    mode: StreamingSignatureMode,
}

impl AwsChunkSignatureVerifier {
    fn new(context: &StreamingSigningContext, mode: StreamingSignatureMode) -> Self {
        Self {
            signing_key: context.signing_key.clone(),
            previous_signature: context.seed_signature.clone(),
            amz_date: context.amz_date.clone(),
            credential_scope: context.credential_scope.clone(),
            mode,
        }
    }

    fn verify(
        &mut self,
        provided_signature: Option<&str>,
        chunk_data: &[u8],
    ) -> Result<(), S3Error> {
        let Some(provided_signature) = provided_signature else {
            return Err(S3Error::signature_does_not_match());
        };
        let empty_hash = hex::encode(Sha256::digest([]));
        let chunk_hash = hex::encode(Sha256::digest(chunk_data));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
            self.amz_date, self.credential_scope, self.previous_signature, empty_hash, chunk_hash
        );
        let expected = hex::encode(hmac_sha256(&self.signing_key, string_to_sign.as_bytes())?);
        if !subtle_constant_time_eq(expected.as_bytes(), provided_signature.as_bytes()) {
            return Err(S3Error::signature_does_not_match());
        }
        self.previous_signature = provided_signature.to_owned();
        Ok(())
    }

    fn verify_trailer(&mut self, trailers: &BTreeMap<String, String>) -> Result<(), S3Error> {
        if self.mode != StreamingSignatureMode::PayloadTrailer {
            return Ok(());
        }
        let provided_signature = trailers
            .get("x-amz-trailer-signature")
            .ok_or_else(S3Error::signature_does_not_match)?;
        let canonical_trailers = trailers
            .iter()
            .filter(|(name, _)| name.as_str() != "x-amz-trailer-signature")
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect::<String>();
        let trailer_hash = hex::encode(Sha256::digest(canonical_trailers.as_bytes()));
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.amz_date, self.credential_scope, self.previous_signature, trailer_hash
        );
        let expected = hex::encode(hmac_sha256(&self.signing_key, string_to_sign.as_bytes())?);
        if !subtle_constant_time_eq(expected.as_bytes(), provided_signature.as_bytes()) {
            return Err(S3Error::signature_does_not_match());
        }
        self.previous_signature = provided_signature.to_owned();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamingSignatureMode {
    Payload,
    PayloadTrailer,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, S3Error> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| S3Error::internal("failed to compute aws-chunked HMAC"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn subtle_constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.ct_eq(right).into()
}

/// Returns whether the request declares S3 `aws-chunked` content encoding.
pub(crate) fn is_aws_chunked_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("aws-chunked"))
        })
}

fn decoded_content_length(headers: &HeaderMap) -> Result<Option<ContentLength>, S3Error> {
    let Some(value) = optional_singleton_header(headers, "x-amz-decoded-content-length")? else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        S3Error::invalid_request("x-amz-decoded-content-length must be valid ASCII")
    })?;
    value
        .parse::<ContentLength>()
        .map(Some)
        .map_err(|_| S3Error::invalid_request("x-amz-decoded-content-length must be an integer"))
}

fn content_length(headers: &HeaderMap) -> Result<Option<ContentLength>, S3Error> {
    let Some(value) = headers.get(header::CONTENT_LENGTH) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| S3Error::invalid_request("Content-Length must be valid ASCII"))?;
    value
        .parse::<ContentLength>()
        .map(Some)
        .map_err(|_| S3Error::invalid_request("Content-Length must be an integer"))
}

fn optional_singleton_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a HeaderValue>, S3Error> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(S3Error::invalid_request(format!(
            "{name} must not appear more than once"
        )));
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn aws_chunk_header_accepts_valid_signature_and_ignored_extensions() {
        let header =
            parse_aws_chunk_header(&format!("a;foo=bar;chunk-signature={}", "0".repeat(64)))
                .expect("chunk header");

        assert_eq!(header.size, 10);
        assert_eq!(header.signature.as_deref(), Some("0".repeat(64).as_str()));
    }

    #[test]
    fn aws_chunk_header_rejects_duplicate_signature_extension() {
        let error = parse_aws_chunk_header(&format!(
            "1;chunk-signature={};chunk-signature={}",
            "0".repeat(64),
            "1".repeat(64)
        ))
        .expect_err("duplicate signature should fail");

        assert!(format!("{error:?}").contains("chunk-signature appears more than once"));
    }

    #[test]
    fn aws_chunk_header_rejects_malformed_signature_extension() {
        let error = parse_aws_chunk_header("1;chunk-signature=ABC")
            .expect_err("malformed signature should fail");

        assert!(format!("{error:?}").contains("lowercase 64-character hex"));
    }

    #[test]
    fn aws_chunk_header_rejects_malformed_extension() {
        let error =
            parse_aws_chunk_header("1;malformed").expect_err("malformed extension should fail");

        assert!(format!("{error:?}").contains("chunk extension is malformed"));
    }

    #[test]
    fn upload_body_state_only_enables_md5_by_default() {
        let headers = HeaderMap::new();

        let state = UploadBodyState::new(&headers);

        assert!(state.sha1.is_none());
        assert!(state.sha256.is_none());
        assert!(state.sha512.is_none());
        assert!(state.crc32.is_none());
        assert!(state.crc32c.is_none());
    }

    #[test]
    fn upload_body_state_enables_requested_checksum_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-checksum-crc32c",
            HeaderValue::from_static("AAAAAA=="),
        );
        headers.insert(
            "x-amz-checksum-sha512",
            HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="),
        );

        let state = UploadBodyState::new(&headers);

        assert!(state.sha1.is_none());
        assert!(state.sha256.is_none());
        assert!(state.sha512.is_some());
        assert!(state.crc32.is_none());
        assert!(state.crc32c.is_some());
    }

    #[test]
    fn upload_body_state_enables_declared_checksum_trailers_case_insensitively() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-trailer",
            HeaderValue::from_static("X-Amz-Checksum-Crc32, x-amz-checksum-sha1"),
        );

        let state = UploadBodyState::new(&headers);

        assert!(state.sha1.is_some());
        assert!(state.sha256.is_none());
        assert!(state.sha512.is_none());
        assert!(state.crc32.is_some());
        assert!(state.crc32c.is_none());
    }

    #[test]
    fn upload_body_state_enables_sha256_for_actual_payload_hash() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(&"0".repeat(64)).expect("header"),
        );

        let state = UploadBodyState::new(&headers);

        assert!(state.sha256.is_some());
    }

    #[test]
    fn payload_hash_mode_from_headers_accepts_supported_modes() {
        let cases = [
            ("UNSIGNED-PAYLOAD", PayloadHashMode::UnsignedPayload),
            (
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                PayloadHashMode::StreamingSignedPayload,
            ),
            (
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                PayloadHashMode::StreamingSignedPayloadTrailer,
            ),
            (
                "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                PayloadHashMode::StreamingUnsignedPayloadTrailer,
            ),
        ];

        for (value, expected) in cases {
            let mut headers = HeaderMap::new();
            headers.insert("x-amz-content-sha256", HeaderValue::from_static(value));

            assert_eq!(payload_hash_mode(&headers).expect("payload mode"), expected);
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-amz-content-sha256",
            HeaderValue::from_str(&"0".repeat(64)).expect("header"),
        );
        assert!(matches!(
            payload_hash_mode(&headers).expect("fixed sha256"),
            PayloadHashMode::FixedSha256 { .. }
        ));
    }

    #[test]
    fn payload_hash_mode_from_headers_accepts_missing_header() {
        let headers = HeaderMap::new();

        assert_eq!(
            payload_hash_mode(&headers).expect("payload mode"),
            PayloadHashMode::Missing
        );
    }

    #[test]
    fn payload_hash_mode_from_headers_rejects_invalid_values() {
        for value in ["not-supported".to_owned(), "A".repeat(64)] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-amz-content-sha256",
                HeaderValue::from_str(&value).expect("header"),
            );

            let error = payload_hash_mode(&headers).expect_err("invalid payload mode");

            assert!(format!("{error:?}").contains("Unsupported x-amz-content-sha256 payload mode"));
        }
    }

    #[test]
    fn payload_hash_mode_from_headers_rejects_duplicate_header() {
        let mut headers = HeaderMap::new();
        headers.append(
            "x-amz-content-sha256",
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
        headers.append(
            "x-amz-content-sha256",
            HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );

        let error = payload_hash_mode(&headers).expect_err("duplicate payload hash");

        assert!(
            format!("{error:?}").contains("x-amz-content-sha256 must not appear more than once")
        );
    }
}
