# s3-endpoint

[![CI](https://github.com/RustedBytes/s3-endpoint/actions/workflows/ci.yml/badge.svg)](https://github.com/RustedBytes/s3-endpoint/actions/workflows/ci.yml)

Rust S3-compatible endpoint focused on upload and object-access workflows used by AWS SDKs and the AWS CLI.

The implementation targets Rust 1.95, edition 2024, and forbids unsafe code in application modules.

## Supported Scope

Implemented operations:

```text
PutObject
CreateMultipartUpload
UploadPart
ListParts
CompleteMultipartUpload
AbortMultipartUpload
HeadBucket
HeadObject
GetObject
DeleteObject
```

Implemented compatibility features:

```text
Path-style and virtual-hosted-style addressing
SigV4 Authorization header authentication
SigV4 presigned URLs
UNSIGNED-PAYLOAD and fixed SHA256 payload hashes
HTTP chunked request bodies
Content-Encoding: aws-chunked
Signed aws-chunked payloads and trailer signatures
Content-MD5
x-amz-checksum-crc32, crc32c, sha1, sha256, sha512
Checksum trailers
Multipart ownership checks
Conditional GET/HEAD
Single-range GET
GetObject response header overrides
Filesystem-backed object and multipart persistence
```

Explicit non-goals for this version include bucket listing, bucket creation, ACLs, IAM policy syntax, object lock, versioning, server-side encryption, CopyObject, UploadPartCopy, and full S3 account semantics.

## Run

```bash
cargo run -- \
  --addr 127.0.0.1:9000 \
  --storage-root ./data \
  --access-key-id test \
  --secret-key testsecret \
  --region us-east-1
```

Useful environment variables mirror the CLI flags:

```text
S3_ENDPOINT_ADDR
S3_ENDPOINT_STORAGE_ROOT
S3_ENDPOINT_ALLOW_ANONYMOUS
S3_ENDPOINT_ACCESS_KEY_ID
S3_ENDPOINT_SECRET_KEY
S3_ENDPOINT_SESSION_TOKEN
S3_ENDPOINT_CREDENTIALS_FILE
S3_ENDPOINT_REGION
S3_ENDPOINT_ALLOWED_BUCKETS
S3_ENDPOINT_ALLOWED_ACTIONS
S3_ENDPOINT_VIRTUAL_HOST_BASE_DOMAIN
S3_ENDPOINT_MAX_OBJECT_SIZE
S3_ENDPOINT_MAX_PART_SIZE
S3_ENDPOINT_MIN_NON_FINAL_PART_SIZE
S3_ENDPOINT_MAX_CONCURRENT_S3_REQUESTS
S3_ENDPOINT_MAX_ACTIVE_OBJECT_WRITERS
S3_ENDPOINT_MAX_ACTIVE_MULTIPART_PART_WRITERS
S3_ENDPOINT_MAX_ACTIVE_AWS_CHUNKED_DECODERS
```

The health endpoint is:

```bash
curl -i http://127.0.0.1:9000/health
```

## Credentials File

`--credentials-file` accepts a JSON array of additional credentials:

```json
[
  {
    "access_key_id": "client-a",
    "secret_key": "client-secret",
    "session_token": "optional-session-token",
    "active": true,
    "allowed_buckets": ["test-bucket"],
    "allowed_actions": ["s3:PutObject", "s3:CreateMultipartUpload", "s3:UploadPart"]
  }
]
```

Empty `allowed_buckets` or `allowed_actions` means the credential is unrestricted for that dimension.

## AWS CLI Example

```bash
printf 'hello\n' > hello.txt

AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=testsecret \
AWS_DEFAULT_REGION=us-east-1 \
aws s3api put-object \
  --bucket test-bucket \
  --key hello.txt \
  --body ./hello.txt \
  --endpoint-url http://127.0.0.1:9000
```

## boto3 Example

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://127.0.0.1:9000",
    aws_access_key_id="test",
    aws_secret_access_key="testsecret",
    region_name="us-east-1",
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)

s3.put_object(Bucket="test-bucket", Key="hello.txt", Body=b"hello")
print(s3.get_object(Bucket="test-bucket", Key="hello.txt")["Body"].read())
```

## Verify

Run the normal project gates:

```bash
cargo fmt --check
RUSTDOCFLAGS="-D missing_docs" cargo doc --no-deps
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Run the SDK smoke tests locally:

```bash
python3 -m venv .venv-sdk
.venv-sdk/bin/python -m pip install --upgrade pip boto3 awscli

cargo build --locked
target/debug/s3-endpoint \
  --addr 127.0.0.1:9000 \
  --storage-root ./data-sdk-smoke \
  --access-key-id test \
  --secret-key testsecret \
  --region us-east-1
```

In another shell:

```bash
.venv-sdk/bin/python tests/sdk/boto3_smoke.py
.venv-sdk/bin/python tests/sdk/presigned_curl_smoke.py
AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=testsecret \
AWS_DEFAULT_REGION=us-east-1 \
tests/sdk/aws_cli_smoke.sh
(cd tests/sdk/go-smoke && go run .)
(cd tests/sdk/java-smoke && mvn --batch-mode --no-transfer-progress compile exec:java)
(cd tests/sdk/js-smoke && npm ci && npm run smoke)
```

The GitHub Actions workflow runs the Rust gates plus AWS CLI, boto3, presigned curl, Go SDK v2, Java SDK v2, and JavaScript SDK v3 smoke flows against the built binary.
