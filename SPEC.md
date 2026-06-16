# Specification: AWS-SDK-compatible S3 upload endpoint in C++

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

```cpp
struct S3Target {
    std::string bucket;
    std::string key;
    bool virtual_hosted;
};
```

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

```cpp
struct AccessKey {
    std::string access_key_id;
    std::string secret_key;
    std::optional<std::string> session_token;
    bool active;
    std::set<std::string> allowed_buckets;
    std::set<std::string> allowed_actions;
};
```

Required upload actions:

```text
s3:PutObject
s3:CreateMultipartUpload
s3:UploadPart
s3:CompleteMultipartUpload
s3:AbortMultipartUpload
s3:ListMultipartUploadParts
```

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

Implement a single abstraction:

```cpp
class DecodedBodyReader {
public:
    virtual ReadResult read(uint8_t* dst, size_t max) = 0;
    virtual uint64_t decoded_bytes_read() const = 0;
    virtual TrailerMap trailers() const = 0;
};
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
partNumber is integer 1..10000
body checksum is valid
part size is valid
```

S3 part numbers range from 1 to 10,000, and uploading the same part number again overwrites the previous part. ([AWS Documentation][14])

Processing:

```text
1. Verify auth.
2. Authorize s3:UploadPart.
3. Stream decoded body to temp part file.
4. Compute part MD5 and requested checksums.
5. Commit part as uploads/<uploadId>/parts/<partNumber>.
6. Record:
    partNumber
    size
    etag
    checksums
    lastModified
7. Return 200 OK with ETag.
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
2. Authorize s3:CompleteMultipartUpload.
3. Parse XML.
4. Validate upload session exists and is open.
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
2. Authorize s3:AbortMultipartUpload.
3. Mark upload aborted.
4. Delete temporary uploaded parts.
5. Return 204 No Content.
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
2. Authorize s3:ListMultipartUploadParts.
3. Return uploaded parts sorted by part number.
4. Respect max-parts, default/max 1000.
5. Support pagination via NextPartNumberMarker.
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

```cpp
struct ObjectMetadata {
    std::string bucket;
    std::string key;
    uint64_t size;
    std::string etag;
    std::string content_type;
    std::string content_encoding;
    std::string content_disposition;
    std::string cache_control;
    std::string expires;
    std::map<std::string, std::string> user_metadata; // x-amz-meta-*
    std::map<std::string, std::string> checksums;
    std::chrono::system_clock::time_point last_modified;
};
```

For `PutObject`, persist:

```text
Content-Type
Content-Encoding
Content-Disposition
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
413 EntityTooLarge
501 NotImplemented
503 SlowDown
```

---

# 12. Storage backend requirements

The storage layer should expose:

```cpp
class ObjectStore {
public:
    TempWriter create_temp_object(bucket, key);
    void commit_object(temp_id, bucket, key, ObjectMetadata metadata);
    std::optional<ObjectMetadata> head_object(bucket, key);
    Reader get_object(bucket, key); // optional for upload-only v1
    void delete_object(bucket, key); // optional
};

class MultipartStore {
public:
    UploadId create_upload(bucket, key, InitiateMetadata metadata);
    UploadSession get_upload(uploadId);
    TempWriter create_temp_part(uploadId, partNumber);
    void commit_part(uploadId, partNumber, PartMetadata metadata);
    std::vector<PartMetadata> list_parts(uploadId, marker, limit);
    void complete_upload(uploadId, final_object_metadata);
    void abort_upload(uploadId);
};
```

Implementation requirements:

```text
Writes MUST be atomic.
Part commits MUST be idempotent for the same uploadId + partNumber.
CompleteMultipartUpload MUST be atomic.
Aborted uploads MUST not become visible as objects.
Overwriting an object MUST be atomic from readers' perspective.
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

# 13. Required C++ modules

Recommended module split:

```text
http/
  HttpServer
  HttpRequest
  HttpResponse
  HeaderMap
  ChunkedDecoder

s3/
  S3Router
  S3TargetResolver
  S3Xml
  S3Errors

auth/
  SigV4Parser
  SigV4Canonicalizer
  SigV4Verifier
  HmacSha256
  Sha256
  ConstantTimeCompare

body/
  DecodedBodyReader
  PlainBodyReader
  HttpChunkedBodyReader
  AwsChunkedReader
  TrailerParser

checksum/
  Md5
  Crc32
  Crc32c
  Sha1
  Sha256Checksum
  Sha512Checksum
  ChecksumVerifier

storage/
  ObjectStore
  MultipartStore
  FileObjectStore or RocksDbObjectStore

handlers/
  PutObjectHandler
  CreateMultipartUploadHandler
  UploadPartHandler
  CompleteMultipartUploadHandler
  AbortMultipartUploadHandler
  ListPartsHandler
  HeadBucketHandler
```

Use OpenSSL or another crypto library for:

```text
HMAC-SHA256
SHA256
SHA1
SHA512
MD5, if you support Content-MD5/ETag compatibility
```

You can write the HTTP server without Boost, but do not write crypto yourself.

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
    .forcePathStyle(true)
    .build();

s3.putObject(
    PutObjectRequest.builder()
        .bucket("test-bucket")
        .key("hello.txt")
        .build(),
    RequestBody.fromBytes("hello".getBytes(StandardCharsets.UTF_8))
);
```

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

Build it in this order:

```text
1. HTTP parser + Content-Length PUT
2. XML responses and S3-style errors
3. Bucket/key resolver, path-style only
4. SigV4 header auth
5. PutObject with ETag
6. Content-MD5 and x-amz-checksum-sha256
7. Presigned URL auth
8. Multipart create/upload/complete/abort
9. ListParts
10. Virtual-hosted-style routing
11. HTTP chunked decoder
12. aws-chunked signed streaming
13. aws-chunked checksum trailers
14. CRC32 / CRC32C support
15. SDK test matrix in CI
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

For a C++ implementation, the riskiest parts are **SigV4 canonicalization** and **aws-chunked trailer decoding**. Implement those with AWS’s official example requests as unit tests before integrating storage.

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
