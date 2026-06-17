# S3 Middleware Server Example

This crate exposes an Axum router plus S3-aware upload processors. Use upload
processors when code needs to inspect or transform decoded S3 object bytes, such
as antivirus scanning, media validation, or audio cleaning.

Processors run after request authentication, payload decoding, upload size
checks, and client checksum validation. They run before the object is committed
to storage.

## Embed The Router

Use the fluent config builders when embedding the endpoint in an Axum server.
`AppBuilder::build_router()` builds `AppState` and returns a ready-to-serve
router.

```rust
use std::{net::SocketAddr, time::Duration};

use s3_endpoint::{
    AppState,
    config::{AuthConfig, Config, IoTuning, MultipartLifecycle, S3Action},
    error::S3Error,
};
use axum::http::{self, HeaderValue};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder("./data")
        .auth(
            AuthConfig::builder()
                .allow_anonymous(true)
                .region("us-east-1")
                .build(),
        )
        .build();

    let app = AppState::builder(config)
        .health_path("/ready")
        .io_tuning(
            IoTuning::builder()
                .object_stream_buffer_size(128 * 1024)
                .multipart_complete_buffer_size(128 * 1024)
                .build(),
        )
        .multipart_lifecycle(
            MultipartLifecycle::builder()
                .abort_incomplete_after(Duration::from_secs(7 * 24 * 60 * 60))
                .build(),
        )
        .disable_operation(S3Action::DeleteObject)
        .authentication_provider(|request| async move {
            if request
                .headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                == Some("let-me-in")
            {
                return Ok(s3_endpoint::hooks::AuthenticationResult::custom("tenant-a"));
            }
            Err(S3Error::access_denied("invalid api key"))
        })
        .target_policy(|request| {
            if request
                .key
                .as_ref()
                .is_some_and(|key| key.as_str().starts_with("internal/"))
            {
                return Err(S3Error::access_denied("internal prefix is reserved"));
            }
            Ok(())
        })
        .upload_policy(|request| {
            if request
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                == Some("application/x-msdownload")
            {
                return Err(S3Error::access_denied("content type is blocked"));
            }
            Ok(())
        })
        .upload_processor_fn("antivirus", |upload| async move {
            let bytes = upload.read_current().await?;
            if bytes.windows(b"EICAR".len()).any(|window| window == b"EICAR") {
                return upload.reject("upload failed antivirus scan");
            }
            Ok(upload.keep())
        })
        .authorization_policy(|request| {
            if request.bucket.as_str() == "blocked-bucket" {
                return Err(S3Error::access_denied("bucket is blocked by application policy"));
            }
            Ok(())
        })
        .on_response(|_context, mut response| async move {
            response
                .headers_mut()
                .insert("x-service", HeaderValue::from_static("embedded-s3"));
            response
        })
        .on_error(|context, error| async move {
            tracing::warn!(
                request_id = %context.request_id,
                operation = %context.operation,
                code = %error.code(),
                message = %error.message(),
                "S3 request failed"
            );
            error
        })
        .build_router()
        .await?;

    let addr: SocketAddr = "127.0.0.1:9000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

`AppState::new(config)` and `router(state)` still work and create a server with
the default `/health` route and no upload processors.

When `authentication_provider` is configured, it replaces the built-in static
SigV4/anonymous authentication path. Leave it unset to keep the default S3
SigV4 behavior, including signed aws-chunked upload verification.

## Developer Tuning Hooks

The embedded API exposes several additive controls:

- `disable_operation` and `operation_policy` gate implemented S3 operations
  before handlers run.
- `target_policy` applies app-specific bucket/key rules after S3 target parsing.
- `upload_policy` rejects uploads before the body is read or staged.
- `on_response` can add or adjust HTTP headers on successful or error
  responses.
- `clock` supplies deterministic timestamps for tests or coordinated runtime
  clocks.
- `io_tuning` adjusts object stream, staged upload summary, and multipart
  completion buffer sizes.
- `multipart_lifecycle` controls startup cleanup and incomplete upload expiry.
- `object_store` and `multipart_store` replace the default filesystem stores
  with implementations of the public storage traits.
- `tenant_limits_provider` lets applications enforce per-tenant quotas,
  concurrency permits, and operation timeouts. Tenants are derived from the
  authenticated principal: anonymous requests use `anonymous`, access-key
  requests use the access key ID, and custom auth uses the custom principal ID.

Tenant limits are hook-based. The crate calls `begin_operation` after
authentication and before handler execution; providers may return an S3 error,
an operation timeout, and/or an owned permit guard. The crate calls
`finish_operation` once for every begun operation with the final status, S3
error details when present, timeout flag, and decoded upload bytes when known.

## Register Processors

Register processors in the order they should run. For simple processors, prefer
`upload_processor_fn`. The closure receives an owned handle with helpers for
reading the staged file, writing a replacement, keeping bytes unchanged,
rejecting the upload, or failing the request.

## Inspect And Reject Uploads

Return `UploadProcessorAction::Keep` to leave the staged object unchanged.
Return `UploadProcessorError::Rejected` to reject the upload with an S3
`AccessDenied` response.

```rust
let state = AppState::builder(config)
    .upload_processor_fn("antivirus", |upload| async move {
        let bytes = upload.read_current().await?;
        if bytes.windows(b"EICAR".len()).any(|window| window == b"EICAR") {
            return upload.reject("upload failed antivirus scan");
        }
        Ok(upload.keep())
    })
    .build()
    .await?;
```

## Transform Uploads

To replace the object bytes, write the new object to `request.replacement_path`
and return `UploadProcessorAction::Replace`.

```rust
use futures_util::future::BoxFuture;
use s3_endpoint::middleware::{
    UploadProcessor, UploadProcessorAction, UploadProcessorError,
    UploadProcessorRequest,
};

struct AudioCleanerProcessor;

impl UploadProcessor for AudioCleanerProcessor {
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async move {
            let Some(content_type) = request.context.content_type.as_deref() else {
                return Ok(UploadProcessorAction::Keep);
            };
            if !content_type.starts_with("audio/") {
                return Ok(UploadProcessorAction::Keep);
            }

            // Replace this with real audio cleanup, such as running ffmpeg or
            // calling an in-process DSP pipeline. The replacement file must be
            // fully written before returning Replace.
            let input = tokio::fs::read(request.current_path)
                .await
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;
            let cleaned = normalize_audio_bytes(input)?;
            tokio::fs::write(request.replacement_path, cleaned)
                .await
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;

            Ok(UploadProcessorAction::Replace)
        })
    }
}

fn normalize_audio_bytes(bytes: Vec<u8>) -> Result<Vec<u8>, UploadProcessorError> {
    // Demo placeholder. Real code should preserve or intentionally rewrite the
    // media container format.
    Ok(bytes)
}
```

The trait form remains useful for reusable processor types and processors that
want direct streaming access to staged file paths.

## Behavior Notes

- Processors are trusted in-process Rust code.
- Processors run sequentially in registration order.
- `PutObject` processors run after the decoded client body has been validated.
- Multipart processors run once during `CompleteMultipartUpload`, after parts
  have been assembled and validated.
- If a processor replaces bytes, the stored object size, ETag, and returned
  checksum headers are recalculated from the final bytes.
- Processor failures use `UploadProcessorError::Failed` and return S3
  `InternalError`.
- Processor rejections use `UploadProcessorError::Rejected` and return S3
  `AccessDenied`.
