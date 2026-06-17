# Specification: AWS-SDK-compatible S3 upload endpoint in Rust

This spec targets a **general-purpose S3-compatible upload subset**, enough for AWS SDKs, AWS CLI, `boto3`, Java SDK, Go SDK, JS SDK, and presigned PUT uploads when clients are configured to use your endpoint.

It does **not** attempt to implement all of S3. It focuses on:

```text
PutObject
CreateMultipartUpload
UploadPart
CompleteMultipartUpload
AbortMultipartUpload
ListParts
SigV4 header auth
SigV4 presigned URLs
aws-chunked streaming bodies
checksum headers and checksum trailers
```

AWS SDK compatibility depends heavily on **SigV4**, **multipart upload**, and **checksum/trailer behavior**. S3 authenticates REST API requests with Signature Version 4, and the canonical request format is strict. The S3 canonical request includes method, canonical URI, canonical query string, canonical headers, signed headers, and hashed payload. ([AWS Documentation][1])

---

## 0. Rust toolchain target

This implementation targets:

```text
Rust: 1.95.0
Edition: 2024
Minimum supported Rust version (MSRV): 1.95.0
Nightly features: forbidden
```

Cargo manifest baseline:

```toml
[package]
name = "s3-endpoint"
version = "0.1.0"
edition = "2024"
rust-version = "1.95"
```

Rust 1.95 stabilized `cfg_select!`, which is a standard-library alternative to the common `cfg-if` crate for compile-time platform selection. Use it for platform-specific storage, filesystem, and socket code instead of adding `cfg-if` unless a dependency already requires it. ([Rust Blog][20])

Example:

```rust
cfg_select! {
    unix => {
        mod platform_fs;
    }
    windows => {
        mod platform_fs;
    }
    _ => {
        mod platform_fs;
    }
}
```

Rust 1.95 also stabilized `if let` guards in `match` arms. Use them where they make request parsing clearer, especially for routing, auth-mode detection, and checksum/trailer validation. ([Rust Blog][20])

Example:

```rust
match operation {
    Operation::UploadPart(params)
        if let (Some(upload_id), Some(part_number)) = (params.upload_id, params.part_number) =>
    {
        route_upload_part(upload_id, part_number).await
    }
    _ => Err(S3Error::invalid_request("invalid multipart upload request")),
}
```

Use Rust 1.95 stabilized APIs when they simplify hot-path code:

```text
Vec::push_mut / Vec::insert_mut:
  useful when building canonical header/query vectors and then filling derived fields.

Atomic*::update / Atomic*::try_update:
  useful for request counters, in-flight writer counters, and simple admission-control metrics.

core::hint::cold_path:
  useful for rare XML error construction or signature mismatch diagnostics.

bool::try_from(integer):
  useful for strict config/env parsing where integer booleans are accepted.
```

Avoid these Rust 1.95 areas for v1:

```text
Do not use custom JSON target specs on stable.
Do not introduce unsafe MaybeUninit/raw-pointer optimizations.
Do not rely on inline assembly.
Do not optimize with cold_path until correctness tests are in place.
```

Cargo in Rust 1.95 parses TOML v1.1 for manifests and config files. Keep `Cargo.toml` simple unless TOML v1.1 syntax clearly improves readability, because using newer manifest syntax raises the development MSRV. ([Rust Release Notes][21])

## 0.1 Project engineering rules

This specification must be implemented according to the local project guidance in `AGENTS.md`.

Implementation rules:

```text
Prefer simple, idiomatic, maintainable Rust over clever abstractions.
Prefer explicit behavior over hidden framework magic.
Make invalid protocol states unrepresentable where practical.
Use narrow modules with clear domain names; do not create vague utils/common modules.
Use traits only for real boundaries such as storage, credentials, clock, or ID generation.
Keep dependency choices conservative and wrap risky dependencies behind small modules.
Keep one authoritative implementation for each protocol rule; do not duplicate SigV4, checksum, multipart, or storage validation logic in handlers and tests.
Keep storage, HTTP extraction, auth, checksum, and S3 domain logic orthogonal; framework types should not leak into pure protocol modules unless they are the natural boundary type.
Do not use panic/unwrap/expect for normal request, auth, parsing, storage, or network failures.
Do not log secrets, access keys, secret keys, session tokens, Authorization headers, presigned signatures, or raw request dumps.
Do not use unsafe in v1 application code.
Every spawned task must have an owner, cancellation path, and shutdown behavior.
Never hold blocking locks across .await.
Every behavior-changing implementation step must include focused tests.
Avoid hidden global mutable state; prefer explicit ownership through AppState and request-scoped values.
Keep refactors small and behavior-preserving unless the spec intentionally changes behavior.
Document non-obvious protocol decisions in module-level docs, Rustdoc, or comments close to the code.
```

Domain modeling requirements:

```text
Use newtypes for bucket names, object keys, upload IDs, request IDs, part numbers, ETags, content lengths, credential IDs, and secret values.
Use enums for finite protocol states such as operation, auth mode, upload state, checksum algorithm, and payload hash mode.
Use NonZero* integer types where zero is invalid, for example multipart part numbers and configured positive limits.
Expose smart constructors for values that require validation; keep fields private unless the value is already trusted internal state.
Accept raw strings and headers only at extraction/parsing boundaries; pass validated domain values to auth, storage, and handlers.
```

Public API and module contract requirements:

```text
Public Rust APIs MUST use precise argument and return types.
Public functions and types MUST document purpose, error cases, and any panics.
Panics in public APIs are allowed only for programmer errors and must be documented.
Module names MUST describe the domain or capability, for example auth, body, checksum, storage, handlers, and s3.
Do not create vague modules such as utils, common, misc, or helpers for production code.
If a module depends on axum, http, tokio, filesystem APIs, or a third-party parser, keep that boundary explicit.
```

Error and observability requirements from `AGENTS.md`:

```text
Use Result for every recoverable failure.
Convert internal errors to S3 XML responses only at the HTTP boundary.
Preserve source errors where useful with thiserror #[source].
Add operation context before crossing module boundaries.
Use tracing spans/events for request_id, operation, status, duration, and byte counts.
Do not emit verbose Debug output for request contexts that may include credentials, signatures, or raw headers.
Do not swallow errors. If cleanup, logging, or best-effort deletion intentionally ignores an error, document why and emit a safe trace/debug event.
Startup failures MUST be clear and fail fast when config, credentials, storage root, or permissions are invalid.
```

Async and concurrency requirements:

```text
Prefer request-scoped work over background tasks.
Prefer a single streaming upload loop until profiling proves task splitting is useful.
Use tokio::sync primitives only when async coordination is required.
Use std::sync primitives only for short synchronous critical sections and never across .await.
Never keep DashMap guards, mutex guards, or filesystem handles alive longer than the state transition they protect.
Bound all queues, semaphores, caches, and background cleanup work.
```

Testing requirements from `AGENTS.md`:

```text
Test observable behavior, not implementation details.
Tests MUST be deterministic, isolated, and independent of execution order.
Use unit tests for pure protocol rules such as canonicalization, checksum validation, and operation parsing.
Use integration tests for real HTTP routing, auth, storage, XML errors, and SDK compatibility flows.
Do not mock so aggressively that tests stop proving S3-compatible behavior.
Every bug fix MUST add a regression test unless the behavior is already covered by an equivalent test.
Before refactoring risky code, add tests first when coverage is weak.
```

Preferred verification before calling work complete:

```sh
cargo fmt
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Completion review checklist:

```text
Code is formatted.
Relevant tests pass.
Clippy warnings are handled without blanket silencing.
Names and module boundaries are clear.
Recoverable errors include context and do not panic.
Clones and allocations in upload hot paths are intentional.
Async tasks are owned, cancellable, and bounded.
Locks and DashMap guards are not held across .await.
Logs and errors do not expose secrets or raw signatures.
Public APIs are documented.
Edge cases from the acceptance matrix are covered or explicitly deferred.
```

---

## 1. Compatibility target

### 1.1 Required client scenarios

The server **MUST** support these client flows:

```bash
aws s3api put-object --bucket b --key k --body file.bin --endpoint-url http://localhost:9000

aws s3 cp file.bin s3://b/k --endpoint-url http://localhost:9000

boto3.client("s3", endpoint_url="http://localhost:9000").put_object(...)

AWS SDK Java/Go/JS/Python PutObject

AWS SDK multipart upload helpers / transfer managers

presigned PUT URL uploads from browsers or curl
```

### 1.2 Required S3 addressing styles

Support both:

```text
Path-style:
PUT /bucket/key
Host: s3.example.com

Virtual-hosted-style:
PUT /key
Host: bucket.s3.example.com
```

Amazon S3 supports both path-style and virtual-hosted-style URL forms, although AWS recommends the standard virtual-hosted endpoint style. ([AWS Documentation][2])

For local/dev endpoints, path-style support is essential because many custom S3-compatible services use:

```text
http://localhost:9000/bucket/key
```

---

## 2. Non-goals for v1

Do **not** implement these in the first upload-compatible version unless your product needs them:

```text
ACL enforcement
Bucket policies
Object Lock
Versioning
Lifecycle
Replication
SSE-KMS
SSE-C
S3 Express directory bucket semantics
Object tagging APIs
ListObjectsV2
CopyObject
UploadPartCopy
```

However, your upload endpoint **MUST either accept-and-ignore or reject clearly** unsupported upload headers. AWS SDKs may send headers such as `x-amz-storage-class`, `x-amz-acl`, `x-amz-meta-*`, `x-amz-tagging`, or checksum headers.

---

# 3. HTTP server requirements

## 3.1 Protocol

The server **MUST** support HTTP/1.1.

For production, terminate TLS at:

```text
nginx
Caddy
Envoy
HAProxy
custom TLS wrapper
```

AWS SDKs work best with HTTPS in production, especially when streaming checksum trailers are used.

## 3.2 Request body modes

The body reader **MUST** support:

```text
Content-Length: N

Transfer-Encoding: chunked

Content-Encoding: aws-chunked
```

For AWS SigV4 streaming uploads, S3 requires `x-amz-decoded-content-length` to specify the real object length, and the request may use either `Content-Length` for encoded length or `Transfer-Encoding` instead. ([AWS Documentation][3])

---

# 4. Routing

## 4.1 Operation detection

Route by HTTP method and query string:

```text
PUT    /bucket/key                         -> PutObject
POST   /bucket/key?uploads                 -> CreateMultipartUpload
PUT    /bucket/key?partNumber=N&uploadId=U -> UploadPart
POST   /bucket/key?uploadId=U              -> CompleteMultipartUpload
DELETE /bucket/key?uploadId=U              -> AbortMultipartUpload
GET    /bucket/key?uploadId=U              -> ListParts
HEAD   /bucket                             -> HeadBucket, recommended for SDK/CLI compatibility
```

Multipart upload is a sequence of normal signed requests: initiate, upload parts, then complete; each request is signed independently. ([AWS Documentation][4])

## 4.2 Bucket/key extraction

Implement this resolver:

```rust
pub struct BucketName(String);
pub struct ObjectKey(String);

pub struct S3Target {
    pub bucket: BucketName,
    pub key: ObjectKey,
    pub virtual_hosted: bool,
}
```

`BucketName` and `ObjectKey` MUST be validated newtypes with private fields and smart constructors. Keep raw request path bytes separately for SigV4 canonicalization; validated target types are for post-auth routing and storage.

Rules:

```text
If Host starts with "<bucket>." before your configured base domain:
    bucket = host prefix
    key = absolute request path without leading "/"

Else:
    bucket = first path segment
    key = remaining path after "/bucket/"
```

Important: for **SigV4 verification**, do not normalize the URI path before canonicalization. S3 explicitly warns not to normalize paths because object keys may contain repeated slashes, and normalizing would change the object name. ([AWS Documentation][5])

That means these are different keys:

```text
a/b.txt
a//b.txt
a/./b.txt
```

After signature verification, you may validate keys for your storage backend, but do not change the canonical path used for signing.

---

# 5. Authentication: SigV4

## 5.1 Supported auth modes

The server **MUST** support:

```text
Authorization header SigV4
Presigned URL SigV4
Optional anonymous uploads, only if explicitly enabled per bucket
```

Reject unsupported auth with:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/xml

<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>...</RequestId>
</Error>
```

## 5.2 Credential store

Store credentials like:

```rust
use std::collections::BTreeSet;

pub struct AccessKeyId(String);
pub struct SecretKey(String);

pub struct AccessKey {
    pub access_key_id: AccessKeyId,
    pub secret_key: SecretKey,
    pub session_token: Option<String>,
    pub active: bool,
    pub allowed_buckets: BTreeSet<BucketName>,
    pub allowed_actions: BTreeSet<S3Action>,
}
```

`SecretKey` MUST have a redacted `Debug` implementation and MUST NOT be logged or exposed through error messages.

Required upload actions:

```text
s3:PutObject
s3:CreateMultipartUpload
s3:UploadPart
s3:CompleteMultipartUpload
s3:AbortMultipartUpload
s3:ListMultipartUploadParts
```

Implemented object read/delete compatibility actions:

```text
s3:GetObject
s3:HeadObject
s3:DeleteObject
s3:HeadBucket
```

The same SigV4 verifier is used for header-signed and presigned requests. Presigned URLs are required for `PutObject` and are supported for implemented object read/delete operations when the signing credential is authorized for the corresponding action.

You do not need real IAM policy syntax in v1. A simple internal allow-list is enough.

---

## 5.3 Header-based SigV4

The request will look like:

```http
PUT /bucket/key HTTP/1.1
Host: s3.example.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../20260616/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=...
x-amz-date: 20260616T120000Z
x-amz-content-sha256: UNSIGNED-PAYLOAD
```

Parse:

```text
Algorithm      = AWS4-HMAC-SHA256
Credential     = <access-key>/<date>/<region>/s3/aws4_request
SignedHeaders  = semicolon-separated lowercase header names
Signature      = lowercase hex HMAC-SHA256
```

Reject if:

```text
algorithm != AWS4-HMAC-SHA256
service != s3
credential date does not match x-amz-date date
region is not one of the regions you configured
access key is unknown or inactive
session token is required but missing or wrong
timestamp skew exceeds your configured tolerance
signature mismatch
```

`x-amz-content-sha256` is required for S3 SigV4 requests. It identifies the payload signing mode. ([AWS Documentation][6])

---

## 5.4 Canonical request

Build exactly:

```text
<HTTPMethod>\n
<CanonicalURI>\n
<CanonicalQueryString>\n
<CanonicalHeaders>\n
<SignedHeaders>\n
<HashedPayload>
```

AWS documents this exact S3 canonical request structure. ([AWS Documentation][5])

### Canonical URI

Rules:

```text
Use the raw absolute path.
URI-encode according to AWS rules.
Do not path-normalize.
Do not collapse slashes.
Do not decode and re-encode inconsistently.
```

AWS’s S3 SigV4 docs specify custom URI encoding rules and warn that platform encoders may not match the required behavior. ([AWS Documentation][5])

Required URI-encoding behavior:

```text
Encode every byte except:
A-Z a-z 0-9 - . _ ~

Encode space as %20, never +

Use uppercase hex digits

Do not encode "/" inside the object key portion
```

For presigned URL canonicalization, AWS specifically says to encode `/` everywhere except inside the object key name. ([AWS Documentation][7])

### Canonical query string

Rules:

```text
Split query params by &
Preserve empty values: ?uploads -> uploads=
URI-encode names and values individually
Sort by encoded name, then encoded value
Join with &
For presigned URLs, exclude X-Amz-Signature from canonical query string
```

S3 requires query parameters to be URI-encoded individually and sorted alphabetically after encoding. ([AWS Documentation][5])

### Canonical headers

Rules:

```text
Lowercase header names
Trim leading/trailing whitespace
Compress sequential internal spaces to one space
Sort by header name
Format as: name:value\n
Include exactly the headers listed in SignedHeaders
```

At minimum, `host` must be signed. Any `x-amz-*` header included in the request should be signed, and presigned URLs require host plus any `x-amz-*` headers that the client plans to send. ([AWS Documentation][7])

### Hashed payload

Use the literal value of `x-amz-content-sha256` when it is one of:

```text
UNSIGNED-PAYLOAD
STREAMING-AWS4-HMAC-SHA256-PAYLOAD
STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
STREAMING-UNSIGNED-PAYLOAD-TRAILER
```

Use the real lowercase hex SHA256 digest when `x-amz-content-sha256` is a 64-character SHA256 value.

S3 recognizes actual payload checksums, unsigned single-chunk payloads, signed streaming payloads, and streaming payloads with trailers through the `x-amz-content-sha256` value. ([AWS Documentation][8])

---

## 5.5 String to sign

Build:

```text
AWS4-HMAC-SHA256\n
<yyyymmdd'T'HHMMSS'Z'>\n
<yyyymmdd>/<region>/s3/aws4_request\n
hex_sha256(canonical_request)
```

Then derive signing key:

```text
kDate    = HMAC-SHA256("AWS4" + secret, yyyymmdd)
kRegion  = HMAC-SHA256(kDate, region)
kService = HMAC-SHA256(kRegion, "s3")
kSigning = HMAC-SHA256(kService, "aws4_request")
signature = hex(HMAC-SHA256(kSigning, string_to_sign))
```

AWS’s SigV4 process signs by creating a canonical request, creating a string to sign, deriving a signing key, and calculating an HMAC-SHA256 signature. ([AWS Documentation][9])

Use constant-time comparison for signatures.

---

## 5.6 Presigned URL auth

Support query parameters:

```text
X-Amz-Algorithm
X-Amz-Credential
X-Amz-Date
X-Amz-Expires
X-Amz-SignedHeaders
X-Amz-Signature
X-Amz-Security-Token, optional
```

For presigned URLs, S3 uses query parameters to authenticate the request, and the canonical request uses `UNSIGNED-PAYLOAD` because the presigner may not know the upload body at signing time. ([AWS Documentation][7])

Validation:

```text
X-Amz-Algorithm MUST equal AWS4-HMAC-SHA256
X-Amz-Expires MUST be integer 1..604800
now MUST be <= X-Amz-Date + X-Amz-Expires
X-Amz-Signature MUST be excluded from canonical query string
X-Amz-Security-Token MUST be included if session credentials are used
```

AWS documents a maximum presigned URL expiration of `604800` seconds, or seven days. ([AWS Documentation][7])

---

# 6. Payload handling

Implement a single async streaming abstraction:

```rust
use bytes::Bytes;
use futures_util::Stream;
use std::collections::BTreeMap;

pub type TrailerMap = BTreeMap<String, String>;
pub type BodyChunkResult = Result<Bytes, BodyReadError>;

pub trait DecodedBodyReader: Stream<Item = BodyChunkResult> + Unpin {
    fn decoded_bytes_read(&self) -> u64;
    fn trailers(&self) -> &TrailerMap;
}
```

Concrete readers:

```text
ContentLengthBodyReader
HttpChunkedBodyReader
AwsChunkedSignedBodyReader
AwsChunkedUnsignedTrailerBodyReader
```

## 6.1 Plain Content-Length body

Used for:

```text
x-amz-content-sha256: <actual sha256>
x-amz-content-sha256: UNSIGNED-PAYLOAD
```

Requirements:

```text
Read exactly Content-Length bytes.
If actual SHA256 mode: compute SHA256 while streaming and compare.
If UNSIGNED-PAYLOAD: do not use body bytes in SigV4 verification.
Still compute object checksums requested by checksum headers.
```

## 6.2 HTTP chunked body

If request has:

```http
Transfer-Encoding: chunked
```

decode standard HTTP chunks first.

Then apply SigV4 payload handling according to `x-amz-content-sha256`.

## 6.3 aws-chunked signed streaming

When:

```http
Content-Encoding: aws-chunked
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
```

body format:

```text
<chunk-size-hex>;chunk-signature=<signature>\r\n
<chunk-data>\r\n
...
0;chunk-signature=<signature>\r\n
\r\n
```

Requirements:

```text
Compute seed signature from normal SigV4 header auth.
For each chunk:
    parse chunk size
    parse chunk-signature
    calculate expected chunk signature using previous signature
    compare constant-time
    stream decoded chunk data to storage/checksum engine
Final chunk MUST have size 0.
```

S3’s streaming SigV4 uses chained signatures: the first chunk uses a seed signature, and every subsequent chunk signature includes the previous chunk signature. ([AWS Documentation][3])

## 6.4 aws-chunked with trailing checksum

When:

```http
Content-Encoding: aws-chunked
x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
x-amz-trailer: x-amz-checksum-crc32
```

or:

```http
Content-Encoding: aws-chunked
x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
x-amz-trailer: x-amz-checksum-crc32
```

Requirements:

```text
Decode data chunks.
Read final 0-byte chunk.
Then read trailing header chunk.
Parse trailers listed by x-amz-trailer.
Validate checksum trailer values.
Store checksum metadata.
```

When trailing headers are used, S3 requires `x-amz-trailer` in the initial request and sends trailing headers after the final 0-byte chunk. ([AWS Documentation][10])

Recent AWS SDKs can calculate checksums automatically and append them as trailing checksums for chunked uploads. ([AWS Documentation][11])

---

# 7. Checksum requirements

## 7.1 Supported checksum inputs

Support these request headers:

```text
Content-MD5
x-amz-checksum-crc32
x-amz-checksum-crc32c
x-amz-checksum-sha1
x-amz-checksum-sha256
x-amz-checksum-sha512
x-amz-sdk-checksum-algorithm
x-amz-trailer
```

AWS S3 supports checksum algorithms including CRC32, CRC32C, SHA1, SHA256, SHA512, MD5, CRC64NVME, and newer XXHash variants; v1 of your server can support a subset, but it must reject unsupported algorithms clearly. ([AWS Documentation][11])

Recommended v1 subset:

```text
MD5
CRC32
CRC32C
SHA1
SHA256
SHA512
```

If you do not support:

```text
CRC64NVME
XXHASH64
XXHASH3
XXHASH128
```

return:

```xml
<Error>
  <Code>InvalidRequest</Code>
  <Message>Checksum algorithm not supported</Message>
</Error>
```

## 7.2 Validation rules

For `PutObject`:

```text
If Content-MD5 is present:
    compute MD5 over decoded object bytes
    compare to Base64 128-bit MD5

If x-amz-checksum-* header is present:
    compute that checksum over decoded object bytes
    compare Base64 value

If x-amz-trailer is present:
    read checksum value from trailers
    compute over decoded object bytes
    compare

If x-amz-sdk-checksum-algorithm is present:
    require either matching x-amz-checksum-* header or x-amz-trailer
```

AWS’s PutObject docs state that `Content-MD5` is checked against the object and that checksum headers are data-integrity checks. The PutObject docs also state that when `x-amz-sdk-checksum-algorithm` is sent, a corresponding checksum header or trailer must be sent, otherwise S3 fails the request with `400 Bad Request`. ([AWS Documentation][12])

On mismatch:

```http
HTTP/1.1 400 Bad Request
Content-Type: application/xml

<Error>
  <Code>BadDigest</Code>
  <Message>The Content-MD5 you specified did not match what we received.</Message>
</Error>
```

For non-MD5 checksum mismatch, use:

```xml
<Code>BadDigest</Code>
<Message>The provided x-amz-checksum header does not match what was computed.</Message>
```

---

# 8. PutObject

## 8.1 Request

```http
PUT /bucket/key HTTP/1.1
Host: s3.example.com
Authorization: ...
x-amz-date: ...
x-amz-content-sha256: ...
Content-Length: ...
Content-Type: application/octet-stream
x-amz-meta-user-key: user-value

<body>
```

## 8.2 Processing

Order:

```text
1. Parse request line, headers, and query.
2. Resolve bucket and key.
3. Verify SigV4 or presigned auth.
4. Authorize s3:PutObject.
5. Send 100 Continue if client sent Expect: 100-continue and auth passed.
6. Create temporary object writer.
7. Stream decoded body to temporary storage.
8. Compute ETag and requested checksums while streaming.
9. Validate Content-MD5/checksum headers/trailers.
10. Atomically commit object.
11. Return 200 OK with ETag and checksum headers.
```

AWS’s PutObject success response returns HTTP 200 and includes an `ETag` header for the uploaded object. ([AWS Documentation][12])

## 8.3 Response

```http
HTTP/1.1 200 OK
ETag: "d41d8cd98f00b204e9800998ecf8427e"
x-amz-request-id: <request-id>
Content-Length: 0
```

If you validated additional checksums, return matching checksum response headers when possible:

```text
x-amz-checksum-crc32
x-amz-checksum-crc32c
x-amz-checksum-sha1
x-amz-checksum-sha256
x-amz-checksum-sha512
x-amz-checksum-type: FULL_OBJECT
```

S3’s PutObject response may include checksum headers if checksum data was uploaded with the object, and for PutObject the checksum type is `FULL_OBJECT`. ([AWS Documentation][12])

## 8.4 ETag behavior

For v1:

```text
Single-part unencrypted object:
    ETag = quoted lowercase hex MD5 of decoded object bytes

Multipart object:
    ETag = quoted lowercase hex MD5(concat(binary_part_md5s)) + "-" + part_count
```

Be careful: S3’s `ETag` is not always a plain MD5 digest, especially for multipart uploads and some encryption modes. AWS explicitly documents that ETag may or may not be an MD5 digest. ([AWS Documentation][13])

## 8.5 Conditional object reads

For implemented `GetObject` and `HeadObject` compatibility:

```text
If-Match MUST fail with 412 PreconditionFailed when no supplied ETag matches the object ETag.
If-None-Match MUST return 304 NotModified when any supplied ETag or * matches the object ETag.
If-Unmodified-Since MUST fail with 412 PreconditionFailed when the object was modified after the supplied HTTP-date.
If-Modified-Since MUST return 304 NotModified when the object was not modified after the supplied HTTP-date.
ETag conditions take precedence over date conditions.
```

## 8.6 GetObject response header overrides

For `GetObject`, support the standard S3 response header override query parameters:

```text
response-cache-control        -> Cache-Control
response-content-disposition  -> Content-Disposition
response-content-encoding     -> Content-Encoding
response-content-language     -> Content-Language
response-content-type         -> Content-Type
response-expires              -> Expires
```

Override values MUST be percent-decoded as UTF-8, MUST reject duplicate override parameters, and MUST apply to both full-object and single-range `GetObject` responses.

---

# 9. Multipart upload

## 9.1 CreateMultipartUpload

Request:

```http
POST /bucket/key?uploads HTTP/1.1
Host: s3.example.com
Authorization: ...
x-amz-date: ...
x-amz-content-sha256: UNSIGNED-PAYLOAD
```

Processing:

```text
1. Verify auth.
2. Authorize s3:CreateMultipartUpload.
3. Generate uploadId.
4. Persist upload session:
    bucket
    key
    uploadId
    owner/accessKey
    initiated timestamp
    metadata from request
    checksum algorithm/type
    state = open
5. Return XML with UploadId.
```

Response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>bucket</Bucket>
  <Key>key</Key>
  <UploadId>upload-id</UploadId>
</InitiateMultipartUploadResult>
```

`CreateMultipartUpload` initiates a multipart upload and returns an upload ID used by later part, complete, or abort requests. ([AWS Documentation][4])

---

## 9.2 UploadPart

Request:

```http
PUT /bucket/key?partNumber=1&uploadId=abc HTTP/1.1
Host: s3.example.com
Authorization: ...
Content-Length: ...
x-amz-content-sha256: ...
```

Validation:

```text
uploadId exists
upload is open
bucket/key match upload session
authenticated access key matches upload session owner when an owner was recorded
partNumber is integer 1..10000
body checksum is valid
part size is valid
```

S3 part numbers range from 1 to 10,000, and uploading the same part number again overwrites the previous part. ([AWS Documentation][14])

Processing:

```text
1. Verify auth.
2. Validate upload session exists, is open, matches bucket/key, and is owned by the authenticated access key when an owner was recorded.
3. Authorize s3:UploadPart.
4. Stream decoded body to temp part file.
5. Compute part MD5 and requested checksums.
6. Commit part as uploads/<uploadId>/parts/<partNumber>.
7. Record:
    partNumber
    size
    etag
    checksums
    lastModified
8. Return 200 OK with ETag.
```

Response:

```http
HTTP/1.1 200 OK
ETag: "part-md5-hex"
x-amz-request-id: ...
Content-Length: 0
```

---

## 9.3 CompleteMultipartUpload

Request:

```http
POST /bucket/key?uploadId=abc HTTP/1.1
Host: s3.example.com
Authorization: ...
Content-Type: application/xml

<CompleteMultipartUpload>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"etag1"</ETag>
  </Part>
  <Part>
    <PartNumber>2</PartNumber>
    <ETag>"etag2"</ETag>
  </Part>
</CompleteMultipartUpload>
```

Processing:

```text
1. Verify auth.
2. Validate upload session exists, is open, matches bucket/key, and is owned by the authenticated access key when an owner was recorded.
3. Authorize s3:CompleteMultipartUpload.
4. Parse XML.
5. Validate all listed parts exist.
6. Validate ETags match uploaded part ETags.
7. Validate parts are in ascending order.
8. Validate all non-final parts meet minimum part size.
9. Concatenate parts in ascending PartNumber order.
10. Validate full-object checksum if provided.
11. Atomically commit final object.
12. Mark upload complete.
13. Delete temporary parts.
14. Return CompleteMultipartUploadResult XML.
```

S3 completes multipart upload by concatenating uploaded parts in ascending part-number order, and the complete request must include each part number and ETag returned by `UploadPart`. ([AWS Documentation][15])

Response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>http://s3.example.com/bucket/key</Location>
  <Bucket>bucket</Bucket>
  <Key>key</Key>
  <ETag>"multipart-etag-2"</ETag>
</CompleteMultipartUploadResult>
```

Important: AWS notes that `CompleteMultipartUpload` can initially return `200 OK` and still embed an error in the response body; AWS SDKs handle that case. You can avoid this complexity in v1 by doing all validation before sending headers. ([AWS Documentation][15])

---

## 9.4 AbortMultipartUpload

Request:

```http
DELETE /bucket/key?uploadId=abc HTTP/1.1
```

Processing:

```text
1. Verify auth.
2. Validate upload session exists, is open, matches bucket/key, and is owned by the authenticated access key when an owner was recorded.
3. Authorize s3:AbortMultipartUpload.
4. Mark upload aborted.
5. Delete temporary uploaded parts.
6. Return 204 No Content.
```

S3 aborts multipart uploads by preventing additional part uploads and freeing storage consumed by uploaded parts. ([AWS Documentation][16])

Response:

```http
HTTP/1.1 204 No Content
Content-Length: 0
```

---

## 9.5 ListParts

Request:

```http
GET /bucket/key?uploadId=abc&max-parts=1000&part-number-marker=0 HTTP/1.1
```

Processing:

```text
1. Verify auth.
2. Validate upload session exists, is open, matches bucket/key, and is owned by the authenticated access key when an owner was recorded.
3. Authorize s3:ListMultipartUploadParts.
4. Return uploaded parts sorted by part number.
5. Respect max-parts, default/max 1000.
6. Support pagination via NextPartNumberMarker.
```

S3 `ListParts` returns uploaded parts for a given upload ID and returns a maximum of 1,000 parts per response. ([AWS Documentation][17])

Response:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>bucket</Bucket>
  <Key>key</Key>
  <UploadId>abc</UploadId>
  <PartNumberMarker>0</PartNumberMarker>
  <NextPartNumberMarker>2</NextPartNumberMarker>
  <MaxParts>1000</MaxParts>
  <IsTruncated>false</IsTruncated>
  <Part>
    <PartNumber>1</PartNumber>
    <LastModified>2026-06-16T12:00:00.000Z</LastModified>
    <ETag>"etag1"</ETag>
    <Size>5242880</Size>
  </Part>
</ListPartsResult>
```

---

## 9.6 Multipart limits

Use these defaults:

```text
Maximum object size: 48.8 TiB
Maximum parts per upload: 10,000
Part number range: 1..10,000
Part size: 5 MiB..5 GiB
Last part may be smaller than 5 MiB
ListParts page size: max 1000
ListMultipartUploads page size: max 1000
```

These are the current S3 multipart upload limits documented by AWS. ([AWS Documentation][18])

Make them configurable because many S3-compatible stores intentionally use lower limits.

---

# 10. Metadata storage

Store per object:

```rust
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

pub struct ObjectMetadata {
    pub bucket: BucketName,
    pub key: ObjectKey,
    pub size: u64,
    pub etag: ETag,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub content_disposition: Option<String>,
    pub content_language: Option<String>,
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub user_metadata: BTreeMap<String, String>, // x-amz-meta-*
    pub checksums: BTreeMap<String, String>,
    pub last_modified: DateTime<Utc>,
}
```

For `PutObject`, persist:

```text
Content-Type
Content-Encoding
Content-Disposition
Content-Language
Cache-Control
Expires
x-amz-meta-*
x-amz-tagging, optional
checksum metadata
ETag
size
last modified
```

S3 supports user-defined metadata through `x-amz-meta-*`, and the PutObject docs show metadata such as `x-amz-meta-author` in upload requests. ([AWS Documentation][12])

---

# 11. Error format

All errors should be XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>SignatureDoesNotMatch</Code>
  <Message>The request signature we calculated does not match the signature you provided.</Message>
  <Resource>/bucket/key</Resource>
  <RequestId>...</RequestId>
</Error>
```

S3 error codes are program-readable strings, and S3 REST errors are returned as structured XML-style error responses. ([AWS Documentation][19])

Minimum errors:

```text
304 NotModified
400 BadDigest
400 InvalidArgument
400 InvalidRequest
400 MalformedXML
400 MissingContentLength
400 AuthorizationHeaderMalformed
403 AccessDenied
403 SignatureDoesNotMatch
403 RequestTimeTooSkewed
404 NoSuchBucket
404 NoSuchKey
404 NoSuchUpload
405 MethodNotAllowed
409 BucketAlreadyExists, optional
409 ConditionalRequestConflict
411 LengthRequired
412 PreconditionFailed
413 EntityTooLarge
501 NotImplemented
503 SlowDown
```

Rust error handling requirements:

```text
Use structured error enums with thiserror for protocol, auth, body, checksum, and storage failures.
Map internal errors to S3 XML errors at the HTTP boundary only.
Add operation context when propagating errors across module boundaries.
If anyhow is added, use it only in application startup, CLI glue, tests, or one-shot tooling.
Never use unwrap/expect/panic for recoverable request failures.
Use debug_assert! only for internal invariants already enforced by types.
```

Example shape:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("signature mismatch")]
    SignatureMismatch,

    #[error("unknown access key")]
    UnknownAccessKey,

    #[error("failed to parse authorization header")]
    MalformedAuthorizationHeader {
        #[source]
        source: AuthorizationParseError,
    },
}
```

Logging and tracing requirements:

```text
Trace request_id, operation, bucket, key hash or redacted key, upload_id, part_number, status, latency, and byte counts.
Do not log Authorization headers, secret keys, session tokens, presigned signatures, or full raw canonical requests by default.
Expose signature debugging only behind an explicit development-only feature or config flag, and redact credentials.
```

---

# 12. Storage backend requirements

The storage layer should expose:

```rust
pub trait ObjectStore: Send + Sync {
    async fn create_temp_object(&self, bucket: &str, key: &str) -> Result<TempWriter, StoreError>;
    async fn commit_object(
        &self,
        temp_id: TempId,
        bucket: &str,
        key: &str,
        metadata: ObjectMetadata,
    ) -> Result<(), StoreError>;
    async fn head_object(&self, bucket: &str, key: &str) -> Result<Option<ObjectMetadata>, StoreError>;
    async fn get_object(&self, bucket: &str, key: &str) -> Result<ObjectReader, StoreError>; // optional for upload-only v1
    async fn delete_object(&self, bucket: &str, key: &str) -> Result<(), StoreError>; // optional
}

pub trait MultipartStore: Send + Sync {
    async fn create_upload(
        &self,
        bucket: &str,
        key: &str,
        metadata: InitiateMetadata,
    ) -> Result<UploadId, StoreError>;
    async fn get_upload(&self, upload_id: &UploadId) -> Result<UploadSession, StoreError>;
    async fn create_temp_part(
        &self,
        upload_id: &UploadId,
        part_number: u16,
    ) -> Result<TempWriter, StoreError>;
    async fn commit_part(
        &self,
        upload_id: &UploadId,
        part_number: u16,
        metadata: PartMetadata,
    ) -> Result<(), StoreError>;
    async fn list_parts(
        &self,
        upload_id: &UploadId,
        marker: Option<u16>,
        limit: usize,
    ) -> Result<Vec<PartMetadata>, StoreError>;
    async fn complete_upload(
        &self,
        upload_id: &UploadId,
        final_object_metadata: ObjectMetadata,
    ) -> Result<(), StoreError>;
    async fn abort_upload(&self, upload_id: &UploadId) -> Result<(), StoreError>;
}
```

These traits use native Rust async functions in traits and are intended for static dispatch or concrete application state. If dynamic trait objects become necessary, document that boundary before adding `async-trait` or an object-safe adapter.

Implementation requirements:

```text
Writes MUST be atomic.
Part commits MUST be idempotent for the same uploadId + partNumber.
CompleteMultipartUpload MUST be atomic.
Aborted uploads MUST not become visible as objects.
Overwriting an object MUST be atomic from readers' perspective.
Startup MUST remove stale temp files and object data or metadata files that no longer have a matching peer.
```

For filesystem storage:

```text
root/
  buckets/
    bucket/
      objects/
        sha256-key-path-or-tree
      metadata/
        sha256-key.json
  multipart/
    upload-id/
      session.json
      parts/
        00001.part
        00001.json
```

Do **not** map raw object keys directly to filesystem paths without escaping. S3 keys can contain slashes and unusual characters.

---

# 13. Rust crate baseline, modules, and data structures

Recommended module split:

```text
src/
  main.rs
  config.rs
  error.rs
  http/
    mod.rs
    server.rs
    extract.rs
    chunked.rs
  s3/
    mod.rs
    router.rs
    target.rs
    xml.rs
    errors.rs
  auth/
    mod.rs
    sigv4_parser.rs
    canonical.rs
    verifier.rs
    presign.rs
  body/
    mod.rs
    decoded.rs
    plain.rs
    http_chunked.rs
    aws_chunked.rs
    trailers.rs
  checksum/
    mod.rs
    md5.rs
    crc.rs
    sha.rs
    verifier.rs
  storage/
    mod.rs
    object_store.rs
    multipart_store.rs
    file_store.rs
  handlers/
    mod.rs
    put_object.rs
    create_multipart_upload.rs
    upload_part.rs
    complete_multipart_upload.rs
    abort_multipart_upload.rs
    list_parts.rs
    head_bucket.rs
```

## 13.1 Crate policy

Use the current `Cargo.toml` as the dependency source of truth. The initial implementation should stay on a conservative crate set and add dependencies only when they remove real complexity or provide well-maintained protocol, crypto, async, parsing, or testing behavior.

Required baseline crates:

```text
HTTP runtime/server:
  tokio
  axum
  tower
  http

HTTP body streaming:
  bytes
  futures-util

SigV4 and crypto:
  hmac
  sha2
  sha1
  md-5
  subtle
  percent-encoding

Encoding and wire formats:
  base64
  hex
  quick-xml
  serde
  serde_json

Checksums:
  crc
  md-5
  sha1
  sha2

Storage, IDs, and time:
  tempfile
  uuid
  chrono

Configuration:
  clap

Observability:
  tracing
  tracing-subscriber

Errors:
  thiserror

Concurrency:
  dashmap

Integration tests:
  tower with util feature
```

Dependency policy:

```text
Every dependency is a maintenance decision.
Before adding a crate, check whether the standard library or an existing dependency is sufficient.
Prefer small, focused crates over broad frameworks.
Review maintenance status, license, transitive dependency size, security history, compile-time cost, and ease of replacement.
Wrap dependencies that touch core protocol behavior, storage, crypto adapters, or external systems behind small local modules.
Do not add crates for trivial tasks.
Do not add async-trait for v1 unless trait object safety is actually required; prefer native async functions, concrete types, or generic trait bounds.
Do not add parking_lot for request-path locks; prefer lock-free ownership, DashMap for hot mutable maps, or tokio synchronization primitives when async coordination is required.
```

Current manifest baseline:

```toml
[dependencies]
axum = "0.8"
base64 = "0.22"
bytes = "1"
chrono = { version = "0.4", default-features = false, features = ["clock", "serde"] }
clap = { version = "4", features = ["derive", "env"] }
crc = "3"
dashmap = "6"
hex = "0.4"
http = "1"
futures-util = "0.3"
hmac = "0.12"
md-5 = "0.10"
percent-encoding = "2"
quick-xml = { version = "0.38", features = ["serialize"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha1 = "0.10"
sha2 = "0.10"
subtle = "2"
tempfile = "3"
thiserror = "2"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
uuid = { version = "1", features = ["v4", "serde"] }

[dev-dependencies]
tower = { version = "0.5", features = ["util"] }
```

Do not write crypto primitives yourself. Use audited RustCrypto crates or another maintained crypto implementation. Treat `unsafe` as forbidden for v1 unless a dependency requires it internally.

Optional crates that need a short justification before being added:

```text
http-body-util:
  only if handler or test body plumbing becomes meaningfully simpler than the current axum/tower APIs.

tokio-util:
  only if streaming IO adapters are needed for a real storage path.

tower-http:
  only if built-in trace/request-id layers replace local code without weakening S3 request-id behavior.

smallvec:
  useful for canonical query/header vectors if profiling or code clarity shows Vec allocation is meaningful.

arc-swap:
  useful for live-reloaded read-mostly credential/config maps.

moka:
  useful for a bounded object metadata cache with size and TTL limits.

aws-config and aws-sdk-s3:
  integration tests against real AWS SDK request behavior.

reqwest:
  black-box HTTP integration tests where tower service tests are insufficient.

proptest:
  canonical URI/query/header fuzzing once deterministic examples pass.

insta:
  XML snapshot tests if response fixtures become hard to review inline.

aws-sigv4
scratchstack-aws-signature
```

Use SigV4 helper crates only as references, test oracles, or carefully evaluated helpers. The server still needs explicit S3 canonicalization control because this endpoint verifies inbound requests and must preserve S3-specific path, query, and payload-signing behavior exactly.

Every added dependency must be compatible with Rust 1.95 and edition 2024. Keep manifest syntax simple even though Cargo in Rust 1.95 supports TOML v1.1.

## 13.2 Data structure guidance for high-volume uploads

Primary rule:

```text
Object bytes MUST never be buffered as a complete in-memory object.
Payload data MUST flow through bounded chunks into temporary storage while checksums are updated incrementally.
```

Request context:

```rust
use bytes::Bytes;
use http::{HeaderMap, Method};

pub struct RequestContext {
    request_id: RequestId,
    method: Method,
    raw_path: Bytes,
    raw_query: Option<Bytes>,
    headers: HeaderMap,
    target: S3Target,
    auth: AuthContext,
}
```

`RequestContext` is request-scoped. Do not store it in shared global state. Values that may contain secrets, signatures, or raw Authorization headers must not implement verbose logging.

Use domain newtypes and enums for protocol concepts instead of raw strings and booleans:

```rust
pub struct RequestId(String);
pub struct UploadId(String);
pub struct PartNumber(std::num::NonZeroU16);
pub struct ContentLength(u64);
pub struct ETag(String);

pub enum S3Action {
    PutObject,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
    ListMultipartUploadParts,
}

pub enum UploadState {
    Open,
    Completing,
    Completed,
    Aborted,
}

pub enum AuthMode {
    HeaderSigV4,
    PresignedUrl,
    Anonymous,
}

pub enum S3Operation {
    PutObject,
    CreateMultipartUpload,
    UploadPart { upload_id: UploadId, part_number: PartNumber },
    CompleteMultipartUpload { upload_id: UploadId },
    AbortMultipartUpload { upload_id: UploadId },
    ListParts { upload_id: UploadId },
    HeadBucket,
}
```

These types MUST have private fields and smart constructors when validation can fail. Types used as map or set keys should derive or implement `Eq`, `PartialEq`, `Ord`, `PartialOrd`, `Hash`, and `Clone` as appropriate. Internal code should receive validated domain types, not loosely structured request strings.

Use these containers:

```text
Headers: http::HeaderMap
Raw path/query/body chunks: bytes::Bytes
Mutable parser buffers: bytes::BytesMut
Canonical query params: Vec<CanonicalQueryParam> sorted by encoded name/value
Canonical headers: Vec<CanonicalHeader> sorted by header name
Metadata maps requiring deterministic order: std::collections::BTreeMap
Unordered credential/action lookups: std::collections::HashMap or HashSet
Deterministic allow-lists and persisted metadata: std::collections::BTreeSet or BTreeMap
```

Do not use `HashMap` for canonical query parameters, canonical headers, multipart part ordering, or any data where duplicate preservation or deterministic ordering is required.

Body pipeline:

```text
HTTP body chunks
  -> optional HTTP chunk decoder
  -> optional aws-chunked decoder
  -> checksum fanout
  -> temporary object or part writer
```

The normal upload loop should read one chunk, update all active checksum states, write that chunk, then read the next chunk. That creates natural backpressure from the storage layer to the client.

Checksum state should be incremental:

```rust
pub struct ChecksumState {
    pub md5: Option<Md5>,
    pub crc32: Option<Crc32Hasher>,
    pub crc32c: Option<Crc32cHasher>,
    pub sha1: Option<Sha1>,
    pub sha256: Option<Sha256>,
    pub sha512: Option<Sha512>,
}
```

Each decoded body chunk must update only the enabled checksum states.

Credential storage:

```text
Initial v1:
  immutable Arc<HashMap<AccessKeyId, AccessKey>> inside AppState

Frequently mutated credentials:
  dashmap::DashMap<String, AccessKey>

Live-reloaded read-mostly credentials:
  arc_swap::ArcSwap<HashMap<AccessKeyId, AccessKey>>, only if arc-swap is added
```

Avoid a global `Mutex<HashMap<...>>` on the request path.

Active multipart uploads:

```rust
pub type UploadMap = dashmap::DashMap<UploadId, UploadSession>;

pub struct UploadSession {
    pub upload_id: UploadId,
    pub bucket: BucketName,
    pub key: ObjectKey,
    pub owner_access_key_id: Option<AccessKeyId>,
    pub parts: std::collections::BTreeMap<PartNumber, PartMetadata>,
    pub state: UploadState,
}
```

Use `DashMap` for concurrent lookup by `uploadId`. Store the initiating `AccessKeyId` on signed upload sessions and require the same authenticated access key for `UploadPart`, `ListParts`, `CompleteMultipartUpload`, and `AbortMultipartUpload`; return `NoSuchUpload` on mismatches so upload IDs are not disclosed across clients. Anonymous upload sessions have no recorded owner and rely on normal bucket/action authorization. Use `BTreeMap<PartNumber, PartMetadata>` inside an upload session because parts must be listed and completed in ascending part-number order. Never hold a `DashMap` entry guard across filesystem I/O or another `.await`; clone the validated session metadata needed for the async step, perform I/O, then reacquire the entry for a short state transition.

Object metadata lookup:

```text
Source of truth:
  filesystem or database metadata keyed by escaped/hash bucket + key

Optional hot cache:
  moka::future::Cache<(BucketName, ObjectKey), Arc<ObjectMetadata>>, only if moka is added
```

Do not keep all object metadata in one unbounded in-memory map unless the deployment has a hard object-count limit.

Temporary writers:

```rust
pub struct TempObjectWrite {
    pub temp_id: TempId,
    pub path: std::path::PathBuf,
    pub writer: tokio::io::BufWriter<tokio::fs::File>,
    pub bytes_written: u64,
    pub checksums: ChecksumState,
}
```

Use `tokio::io::BufWriter` for filesystem-backed temp files. Keep object commit metadata separate from the writer until checksum and length validation have succeeded.

Backpressure and limits:

```text
Use tokio::sync::Semaphore for:
  maximum concurrent requests
  maximum active object writers
  maximum active multipart part writers
  maximum active aws-chunked decoders

Use bounded tokio::sync::mpsc channels only when read and write work are split across tasks.
Keep channel capacity small, such as 4..16 body chunks.
```

Prefer a single-task streaming loop for v1 unless profiling proves that split read/write tasks improve throughput.

String and key storage:

```text
Use String/newtypes for request-specific values.
Use Arc<str> only for repeated long-lived bucket names, access key IDs, regions, and action names when it reduces cloning in shared state.
Use String for request-specific object keys.
Keep the raw URI/path bytes unchanged for SigV4 canonicalization.
Never convert raw object keys directly into PathBuf.
```

Concurrency model:

```text
Shared application state: Arc<AppState>
Read-heavy immutable maps: Arc<HashMap<...>>
Hot mutable maps: DashMap
Per-upload ordered parts: BTreeMap
Caches with size/TTL limits: moka, only if added
Per-request buffers: Bytes, BytesMut, Vec
Large payloads: streaming only
```

Async task lifecycle:

```text
Prefer request-scoped async work that completes before the handler returns.
If background cleanup or multipart garbage collection is needed, own JoinHandles in AppState.
Use cancellation tokens or shutdown channels for every background task.
Do not spawn unbounded per-chunk or per-part tasks.
Do not hold std::sync or parking_lot locks across .await.
Use tokio locks only when lock ownership across .await is intentional and documented.
```

---

# 14. AWS SDK configuration for tests

## AWS CLI

```bash
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key testsecret
aws configure set default.region us-east-1

aws s3api put-object \
  --bucket test-bucket \
  --key hello.txt \
  --body ./hello.txt \
  --endpoint-url http://127.0.0.1:9000
```

## Python boto3

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id="test",
    aws_secret_access_key="testsecret",
    region_name="us-east-1",
    config=Config(
        signature_version="s3v4",
        s3={"addressing_style": "path"},
    ),
)

s3.put_object(
    Bucket="test-bucket",
    Key="hello.txt",
    Body=b"hello",
)
```

## Java SDK v2

```java
S3Client s3 = S3Client.builder()
    .endpointOverride(URI.create("http://127.0.0.1:9000"))
    .region(Region.US_EAST_1)
    .credentialsProvider(
        StaticCredentialsProvider.create(
            AwsBasicCredentials.create("test", "testsecret")))
    .serviceConfiguration(
        S3Configuration.builder()
            .pathStyleAccessEnabled(true)
            .build())
    .build();

s3.putObject(
    PutObjectRequest.builder()
        .bucket("test-bucket")
        .key("hello.txt")
        .build(),
    RequestBody.fromBytes("hello".getBytes(StandardCharsets.UTF_8))
);
```

## Go SDK v2

```go
cfg, err := config.LoadDefaultConfig(
    context.Background(),
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(
        credentials.NewStaticCredentialsProvider("test", "testsecret", "")),
)
if err != nil {
    return err
}

s3Client := s3.NewFromConfig(cfg, func(options *s3.Options) {
    options.BaseEndpoint = aws.String("http://127.0.0.1:9000")
    options.UsePathStyle = true
})

_, err = s3Client.PutObject(context.Background(), &s3.PutObjectInput{
    Bucket: aws.String("test-bucket"),
    Key:    aws.String("hello.txt"),
    Body:   bytes.NewReader([]byte("hello")),
})
```

## JavaScript SDK v3

```javascript
const s3 = new S3Client({
  endpoint: "http://127.0.0.1:9000",
  forcePathStyle: true,
  region: "us-east-1",
  credentials: {
    accessKeyId: "test",
    secretAccessKey: "testsecret",
  },
});

await s3.send(new PutObjectCommand({
  Bucket: "test-bucket",
  Key: "hello.txt",
  Body: Buffer.from("hello"),
}));
```

The repository CI SHOULD run SDK smoke tests for AWS CLI, Python boto3, Go SDK v2, Java SDK v2, JavaScript SDK v3, and presigned PUT uploads.

---

# 15. Acceptance test matrix

Your developer should not call the endpoint “AWS SDK compatible” until these pass.

```text
A. PutObject, small file, Content-Length
B. PutObject, key with spaces
C. PutObject, key with unicode
D. PutObject, key with repeated slashes: a//b.txt
E. PutObject with x-amz-meta-*
F. PutObject with Content-Type
G. PutObject with Content-MD5 success
H. PutObject with Content-MD5 mismatch -> BadDigest
I. PutObject with x-amz-checksum-crc32
J. PutObject with x-amz-checksum-crc32c
K. PutObject with x-amz-checksum-sha256
L. PutObject using UNSIGNED-PAYLOAD
M. PutObject using actual SHA256 payload hash
N. PutObject using Expect: 100-continue
O. Presigned PUT URL
P. Presigned PUT URL expired -> AccessDenied or SignatureDoesNotMatch
Q. Multipart: create, upload 2 parts, complete
R. Multipart: upload same part twice, later part wins
S. Multipart: complete with wrong ETag -> InvalidPart
T. Multipart: abort then upload part -> NoSuchUpload
U. Multipart: list parts pagination
V. aws-chunked signed streaming
W. aws-chunked checksum trailer
X. STREAMING-UNSIGNED-PAYLOAD-TRAILER with checksum trailer
Y. Signature mismatch with changed path
Z. Signature mismatch with changed signed header
```

---

# 16. Implementation order

Build this as tracer bullets first: each stage should create a thin end-to-end path with real routing, storage, observable errors, and tests before expanding edge cases.

Implementation rules for every stage:

```text
Add or update focused tests with the behavior change.
Keep modules cohesive and independently testable.
Refactor small inconsistencies in touched code when safe.
Avoid speculative abstractions; add traits only when a boundary is real.
Run cargo fmt, cargo test, and cargo clippy --all-targets --all-features -- -D warnings when available.
```

Build it in this order:

```text
1. Minimal AppState, config loading, request IDs, XML error boundary, and health/startup checks.
2. HTTP route for Content-Length PutObject using path-style bucket/key resolution and filesystem temp commit.
3. Focused S3 XML responses and structured Rust error mapping.
4. Validated domain newtypes for bucket, key, upload ID, part number, content length, ETag, and operation detection.
5. SigV4 header auth with canonicalization unit tests from AWS examples.
6. PutObject ETag, metadata persistence, and overwrite atomicity.
7. Content-MD5 and x-amz-checksum-sha256 streaming validation.
8. Presigned URL auth.
9. Multipart create/upload/complete/abort with ordered part state.
10. ListParts.
11. Virtual-hosted-style routing.
12. HTTP chunked decoder.
13. aws-chunked signed streaming.
14. aws-chunked checksum trailers.
15. CRC32 / CRC32C support.
16. SDK test matrix in CI.
```

The most common failure points will be:

```text
URI canonicalization
not preserving repeated slashes
incorrect query sorting
not signing Host with port
incorrect handling of UNSIGNED-PAYLOAD
not supporting aws-chunked
not supporting checksum trailers from newer SDKs
returning JSON instead of XML errors
sending 100 Continue before authentication
```

For a Rust implementation, the riskiest parts are **SigV4 canonicalization** and **aws-chunked trailer decoding**. Implement those with AWS’s official example requests as unit tests before integrating storage, and keep them covered by deterministic unit tests before wiring them into async storage paths.

[1]: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html?utm_source=chatgpt.com "Authenticating Requests (AWS Signature Version 4)"
[2]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html?utm_source=chatgpt.com "Virtual hosting of general purpose buckets"
[3]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html "Signature Calculations for the Authorization Header: Transferring Payload in Multiple Chunks (Chunked Upload) (AWS Signature Version 4) - Amazon Simple Storage Service"
[4]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html "CreateMultipartUpload - Amazon Simple Storage Service"
[5]: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html "Signature Calculations for the Authorization Header: Transferring Payload in a Single Chunk (AWS Signature Version 4) - Amazon Simple Storage Service"
[6]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html?utm_source=chatgpt.com "Create a signed AWS API request"
[7]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html "Authenticating Requests: Using Query Parameters (AWS Signature Version 4) - Amazon Simple Storage Service"
[8]: https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-auth-using-authorization-header.html "Authenticating Requests: Using the Authorization Header (AWS Signature Version 4) - Amazon Simple Storage Service"
[9]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html?utm_source=chatgpt.com "AWS Signature Version 4 for API requests"
[10]: https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html "Signature calculations for trailing headers (chunked uploads) (AWS Signature Version 4) - Amazon Simple Storage Service"
[11]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html "Checking object integrity for data uploads in Amazon S3 - Amazon Simple Storage Service"
[12]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html "PutObject - Amazon Simple Storage Service"
[13]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Object.html?utm_source=chatgpt.com "Object - Amazon Simple Storage Service"
[14]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html "UploadPart - Amazon Simple Storage Service"
[15]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html "CompleteMultipartUpload - Amazon Simple Storage Service"
[16]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html "AbortMultipartUpload - Amazon Simple Storage Service"
[17]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html "ListParts - Amazon Simple Storage Service"
[18]: https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html "Amazon S3 multipart upload limits - Amazon Simple Storage Service"
[19]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_Error.html?utm_source=chatgpt.com "Error - Amazon S3"
[20]: https://blog.rust-lang.org/2026/04/16/Rust-1.95.0/ "Announcing Rust 1.95.0"
[21]: https://doc.rust-lang.org/beta/releases.html#version-1950-2026-04-16 "Rust Release Notes: Version 1.95.0"
