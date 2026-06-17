#!/usr/bin/env bash
set -euo pipefail

AWS_BIN="${AWS_BIN:-aws}"
ENDPOINT_URL="${S3_ENDPOINT_URL:-http://127.0.0.1:9000}"
BUCKET="${S3_TEST_BUCKET:-cli-bucket}"
TMP_DIR="$(mktemp -d)"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-testsecret}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

printf 'hello from aws cli\n' > "$TMP_DIR/s3api.txt"
"$AWS_BIN" s3api put-object \
  --bucket "$BUCKET" \
  --key s3api.txt \
  --body "$TMP_DIR/s3api.txt" \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null

"$AWS_BIN" s3api head-object \
  --bucket "$BUCKET" \
  --key s3api.txt \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null

"$AWS_BIN" s3api get-object \
  --bucket "$BUCKET" \
  --key s3api.txt \
  --endpoint-url "$ENDPOINT_URL" \
  "$TMP_DIR/s3api.out" \
  >/dev/null
cmp "$TMP_DIR/s3api.txt" "$TMP_DIR/s3api.out"

printf 'hello from aws s3 cp\n' > "$TMP_DIR/cp.txt"
"$AWS_BIN" s3 cp \
  "$TMP_DIR/cp.txt" \
  "s3://$BUCKET/cp.txt" \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null

"$AWS_BIN" s3 cp \
  "s3://$BUCKET/cp.txt" \
  "$TMP_DIR/cp.out" \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null
cmp "$TMP_DIR/cp.txt" "$TMP_DIR/cp.out"

"$AWS_BIN" s3api delete-object \
  --bucket "$BUCKET" \
  --key s3api.txt \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null
"$AWS_BIN" s3api delete-object \
  --bucket "$BUCKET" \
  --key cp.txt \
  --endpoint-url "$ENDPOINT_URL" \
  >/dev/null
