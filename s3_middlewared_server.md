# S3 Middleware Server Example

This crate exposes an Axum router plus S3-aware upload processors. Use upload
processors when code needs to inspect or transform decoded S3 object bytes, such
as antivirus scanning, media validation, or audio cleaning.

Processors run after request authentication, payload decoding, upload size
checks, and client checksum validation. They run before the object is committed
to storage.

## Register Processors

Build `AppState` with `AppState::builder(config)` and register processors in the
order they should run.

```rust
use std::net::SocketAddr;

use s3_endpoint::{
    AppState,
    config::{AuthConfig, Config},
    router,
};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        storage_root: "./data".into(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    };

    let state = AppState::builder(config)
        .upload_processor(AntivirusProcessor)
        .upload_processor(AudioCleanerProcessor)
        .build()
        .await?;

    let addr: SocketAddr = "127.0.0.1:9000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await?;

    Ok(())
}
```

`AppState::new(config)` still works and creates a server with no upload
processors.

## Inspect And Reject Uploads

Return `UploadProcessorAction::Keep` to leave the staged object unchanged.
Return `UploadProcessorError::Rejected` to reject the upload with an S3
`AccessDenied` response.

```rust
use futures_util::future::BoxFuture;
use s3_endpoint::middleware::{
    UploadProcessor, UploadProcessorAction, UploadProcessorError,
    UploadProcessorRequest,
};

struct AntivirusProcessor;

impl UploadProcessor for AntivirusProcessor {
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async move {
            let bytes = tokio::fs::read(request.current_path)
                .await
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;

            if bytes.windows(b"EICAR".len()).any(|window| window == b"EICAR") {
                return Err(UploadProcessorError::Rejected(
                    "upload failed antivirus scan".to_owned(),
                ));
            }

            Ok(UploadProcessorAction::Keep)
        })
    }
}
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

