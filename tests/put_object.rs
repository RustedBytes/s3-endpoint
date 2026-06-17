use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use crc::{CRC_32_ISCSI, CRC_32_ISO_HDLC, Crc};
use futures_util::future::BoxFuture;
use futures_util::stream;
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use s3_endpoint::{
    AppState,
    config::{AccessKeyConfig, AuthConfig, Config, S3Action, UploadLimits},
    middleware::{
        UploadProcessor, UploadProcessorAction, UploadProcessorError, UploadProcessorRequest,
    },
    router,
    s3::types::{BucketName, ObjectKey},
};
use tower::ServiceExt;

async fn test_state() -> (AppState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    (state, temp_dir)
}

async fn test_state_with_processor<P>(processor: P) -> (AppState, tempfile::TempDir)
where
    P: UploadProcessor,
{
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::builder(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .upload_processor(processor)
    .build()
    .await
    .expect("create app state");
    (state, temp_dir)
}

async fn test_state_with_virtual_hosting() -> (AppState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: Some("s3.local".to_owned()),
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    (state, temp_dir)
}

fn permissive_auth_config() -> AuthConfig {
    AuthConfig {
        max_skew_seconds: 10 * 365 * 24 * 60 * 60,
        ..AuthConfig::default()
    }
}

#[tokio::test]
async fn health_returns_no_content() {
    let (state, _temp_dir) = test_state().await;
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn unsupported_object_method_returns_s3_method_not_allowed() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/test-bucket/object.txt")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::ALLOW),
        Some(&HeaderValue::from_static("DELETE, GET, HEAD, POST, PUT"))
    );
    let body = response_text(response).await;
    assert!(body.contains("<Code>MethodNotAllowed</Code>"));
    assert!(body.contains("The specified method is not allowed against this resource."));
}

#[tokio::test]
async fn put_object_streams_to_storage_and_returns_etag() {
    let (state, _temp_dir) = test_state().await;
    let body = b"hello s3";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/hello.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_ENCODING, "gzip")
                .header(
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"hello.txt\"",
                )
                .header(header::CONTENT_LANGUAGE, "en-US")
                .header(header::CACHE_CONTROL, "max-age=60")
                .header(header::EXPIRES, "Wed, 21 Oct 2026 07:28:00 GMT")
                .header("x-amz-tagging", "project=rust&kind=test")
                .header("x-amz-meta-owner", "rust")
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::ETAG).expect("etag"),
        expected_etag.as_str()
    );
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("hello.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");

    assert_eq!(metadata.size, body.len() as u64);
    assert_eq!(metadata.etag.as_str(), expected_etag);
    assert_eq!(metadata.content_type.as_deref(), Some("text/plain"));
    assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(
        metadata.content_disposition.as_deref(),
        Some("attachment; filename=\"hello.txt\"")
    );
    assert_eq!(metadata.content_language.as_deref(), Some("en-US"));
    assert_eq!(metadata.cache_control.as_deref(), Some("max-age=60"));
    assert_eq!(
        metadata.expires.as_deref(),
        Some("Wed, 21 Oct 2026 07:28:00 GMT")
    );
    assert_eq!(metadata.tagging.as_deref(), Some("project=rust&kind=test"));
    assert_eq!(
        metadata.user_metadata,
        BTreeMap::from([("x-amz-meta-owner".to_owned(), "rust".to_owned())])
    );
}

#[tokio::test]
async fn put_object_processor_rejection_returns_access_denied_without_commit() {
    let (state, _temp_dir) = test_state_with_processor(RejectProcessor).await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/rejected.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("upload rejected by test processor"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("rejected.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_processor_transform_commits_recalculated_object() {
    let (state, _temp_dir) = test_state_with_processor(ReplaceProcessor {
        replacement: b"clean audio".to_vec(),
    })
    .await;
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(b"clean audio")));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/audio.wav")
                .header(header::CONTENT_LENGTH, "5")
                .header(header::CONTENT_TYPE, "audio/wav")
                .body(Body::from("dirty"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::ETAG).expect("etag"),
        expected_etag.as_str()
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("audio.wav").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, "clean audio".len() as u64);
    assert_eq!(metadata.etag.as_str(), expected_etag);
    assert_eq!(metadata.content_type.as_deref(), Some("audio/wav"));

    let object_path = stored_object_path(
        state.config.storage_root.as_path(),
        "test-bucket",
        "audio.wav",
    );
    let stored = std::fs::read(object_path).expect("read stored object");
    assert_eq!(stored, b"clean audio");
}

#[tokio::test]
async fn put_object_processors_run_in_registration_order() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::builder(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .upload_processor(AppendProcessor { suffix: b"-one" })
    .upload_processor(AppendProcessor { suffix: b"-two" })
    .build()
    .await
    .expect("create app state");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/chained.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("base"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let object_path = stored_object_path(
        state.config.storage_root.as_path(),
        "test-bucket",
        "chained.txt",
    );
    let stored = std::fs::read(object_path).expect("read stored object");
    assert_eq!(stored, b"base-one-two");
}

#[tokio::test]
async fn put_object_stores_user_metadata_as_deterministic_map() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/metadata-map.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-meta-zeta", "last")
                .header("x-amz-meta-alpha", "first")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("metadata-map.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");

    assert_eq!(
        metadata.user_metadata,
        BTreeMap::from([
            ("x-amz-meta-alpha".to_owned(), "first".to_owned()),
            ("x-amz-meta-zeta".to_owned(), "last".to_owned()),
        ])
    );
}

#[tokio::test]
async fn put_object_rejects_duplicate_persisted_metadata_headers() {
    let (state, _temp_dir) = test_state().await;
    let mut request = Request::builder()
        .method("PUT")
        .uri("/test-bucket/duplicate-content-type.txt")
        .header(header::CONTENT_LENGTH, "4")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("body"))
        .expect("build request");
    request.headers_mut().append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("content-type must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-content-type.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_duplicate_user_metadata_headers() {
    let (state, _temp_dir) = test_state().await;
    let mut request = Request::builder()
        .method("PUT")
        .uri("/test-bucket/duplicate-user-metadata.txt")
        .header(header::CONTENT_LENGTH, "4")
        .header("x-amz-meta-owner", "rust")
        .body(Body::from("body"))
        .expect("build request");
    request
        .headers_mut()
        .append("x-amz-meta-owner", HeaderValue::from_static("duplicate"));

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-meta-owner must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-user-metadata.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_non_ascii_user_metadata_value() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/non-ascii-metadata.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header(
                    "x-amz-meta-owner",
                    HeaderValue::from_bytes(b"\xFF").expect("header value"),
                )
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-meta-owner must be valid ASCII"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("non-ascii-metadata.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_sse_header() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/sse.txt")
                .header(header::CONTENT_LENGTH, "3")
                .header("x-amz-server-side-encryption", "aws:kms")
                .body(Body::from("sse"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported upload header"));
}

#[tokio::test]
async fn put_object_rejects_copy_object_header() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/copied.txt")
                .header(header::CONTENT_LENGTH, "0")
                .header("x-amz-copy-source", "/test-bucket/source.txt")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported upload header: x-amz-copy-source"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("copied.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_common_ignored_upload_headers() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/ignored-headers.txt")
                .header(header::CONTENT_LENGTH, "7")
                .header("x-amz-acl", "private")
                .header("x-amz-storage-class", "STANDARD")
                .body(Body::from("ignored"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_object_preserves_repeated_slashes_in_key() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/a//b.txt")
                .header(header::CONTENT_LENGTH, "1")
                .body(Body::from("x"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("a//b.txt").expect("key"),
        )
        .await
        .expect("read metadata");

    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_supports_percent_encoded_space_and_unicode_keys() {
    let (state, _temp_dir) = test_state().await;
    let app = router(state.clone());
    let body = "encoded key body";

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/folder%20name/unicod%C3%A9-%E2%9C%93.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("folder name/unicodé-✓.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, body.len() as u64);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/folder%20name/unicod%C3%A9-%E2%9C%93.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(get.status(), StatusCode::OK);
    let downloaded = to_bytes(get.into_body(), usize::MAX)
        .await
        .expect("read get body");
    assert_eq!(&downloaded[..], body.as_bytes());
}

#[tokio::test]
async fn put_object_accepts_expect_100_continue_header() {
    let (state, _temp_dir) = test_state().await;
    let body = "continue";

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/expect-continue.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header(header::EXPECT, "100-continue")
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("expect-continue.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, body.len() as u64);
}

#[tokio::test]
async fn put_object_rejects_percent_decoded_control_character_in_key() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad%0Akey.txt")
                .header(header::CONTENT_LENGTH, "1")
                .body(Body::from("x"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("object key contains invalid characters"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("bad-key.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_supports_virtual_hosted_style() {
    let (state, _temp_dir) = test_state_with_virtual_hosting().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/virtual.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .header(header::CONTENT_LENGTH, "7")
                .body(Body::from("virtual"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("virtual.txt").expect("key"),
        )
        .await
        .expect("read metadata");

    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_matches_virtual_host_base_domain_case_insensitively() {
    let (state, _temp_dir) = test_state_with_virtual_hosting().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/case-host.txt")
                .header(header::HOST, "test-bucket.S3.Local")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("case-host.txt").expect("key"),
        )
        .await
        .expect("read metadata");

    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_without_content_length_returns_s3_xml_error() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/hello.txt")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::LENGTH_REQUIRED);
    assert_has_request_id(&response);
    let request_id = response
        .headers()
        .get("x-amz-request-id")
        .expect("request id header")
        .to_str()
        .expect("request id ascii")
        .to_owned();
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .expect("content-type"),
        "application/xml; charset=utf-8"
    );

    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");

    assert!(body.contains("<Code>MissingContentLength</Code>"));
    assert!(body.contains("<Resource>/test-bucket/hello.txt</Resource>"));
    assert!(body.contains(&format!("<RequestId>{request_id}</RequestId>")));
}

#[tokio::test]
async fn put_object_rejects_short_content_length_body() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/short-body.txt")
                .header(header::CONTENT_LENGTH, "10")
                .body(Body::from("short"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length does not match request body length"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("short-body.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_long_content_length_body() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/long-body.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("too long"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length does not match request body length"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("long-body.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_invalid_content_length_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-content-length.txt")
                .header(header::CONTENT_LENGTH, "not-a-number")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length must be an integer"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("bad-content-length.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_duplicate_content_length_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/duplicate-content-length.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Content-Length must not appear more than once"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-content-length.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_transfer_encoding_before_creating_temp_file() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/unsupported-transfer-encoding.txt")
                .header(header::TRANSFER_ENCODING, "gzip")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported Transfer-Encoding; only chunked is supported"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("unsupported-transfer-encoding.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_plain_content_length_with_transfer_encoding() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/content-length-with-transfer-encoding.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header(header::TRANSFER_ENCODING, "chunked")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains(
        "Content-Length must not be used with Transfer-Encoding for non aws-chunked uploads"
    ));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("content-length-with-transfer-encoding.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_body_larger_than_configured_object_limit() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: UploadLimits {
            max_object_size: 4,
            ..UploadLimits::default()
        },
    })
    .await
    .expect("create app state");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/too-large.txt")
                .header(header::CONTENT_LENGTH, "5")
                .body(Body::from("12345"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = response_text(response).await;
    assert!(body.contains("<Code>EntityTooLarge</Code>"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("too-large.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_cleans_temp_file_when_commit_fails_before_publish() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let metadata_dir = temp_dir.path().join("metadata");
    std::fs::remove_dir_all(&metadata_dir).expect("remove metadata dir");
    std::fs::write(&metadata_dir, b"not a directory").expect("replace metadata dir with file");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/commit-fails.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_tmp_dir_is_empty(temp_dir.path());
}

#[tokio::test]
async fn put_object_startup_removes_stale_temp_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let tmp_dir = temp_dir.path().join("tmp");
    std::fs::create_dir_all(&tmp_dir).expect("create tmp dir");
    std::fs::write(tmp_dir.join("stale-object.part"), b"object").expect("write stale object temp");
    std::fs::write(tmp_dir.join("stale-metadata.json"), b"metadata")
        .expect("write stale metadata temp");
    std::fs::write(tmp_dir.join("stale.rollback.tmp"), b"rollback")
        .expect("write stale rollback temp");
    std::fs::create_dir(tmp_dir.join("ignored-dir")).expect("create tmp subdirectory");

    let _state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let entries = std::fs::read_dir(&tmp_dir)
        .expect("read tmp dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("read tmp entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name(), "ignored-dir");
}

#[tokio::test]
async fn put_object_startup_removes_orphaned_object_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let object_path = stored_object_path(temp_dir.path(), "test-bucket", "orphan.txt");
    std::fs::create_dir_all(object_path.parent().expect("object parent"))
        .expect("create object dir");
    std::fs::write(&object_path, b"orphaned bytes").expect("write orphaned object file");

    let _state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    assert!(!object_path.exists());
}

#[tokio::test]
async fn put_object_startup_removes_orphaned_metadata_files() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let metadata_path = stored_metadata_path(temp_dir.path(), "test-bucket", "orphan-metadata.txt");
    std::fs::create_dir_all(metadata_path.parent().expect("metadata parent"))
        .expect("create metadata dir");
    std::fs::write(
        &metadata_path,
        br#"{
  "bucket": "test-bucket",
  "key": "orphan-metadata.txt",
  "size": 5,
  "etag": "\"5d41402abc4b2a76b9719d911017c592\"",
  "user_metadata": {},
  "checksums": {},
  "last_modified": "2026-06-16T00:00:00Z"
}"#,
    )
    .expect("write orphaned metadata file");

    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    assert!(!metadata_path.exists());
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("orphan-metadata.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[cfg(unix)]
#[tokio::test]
async fn put_object_overwrite_restores_previous_metadata_when_commit_fails_after_publish() {
    use std::os::unix::fs::PermissionsExt;

    let (state, temp_dir) = test_state().await;
    let app = router(state.clone());

    let create = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/overwrite-rollback.txt")
                .header(header::CONTENT_LENGTH, "8")
                .body(Body::from("old-body"))
                .expect("build request"),
        )
        .await
        .expect("send create request");
    assert_eq!(create.status(), StatusCode::OK);

    let metadata_path =
        stored_metadata_path(temp_dir.path(), "test-bucket", "overwrite-rollback.txt");
    let metadata_dir = metadata_path.parent().expect("metadata parent");
    let original_permissions = std::fs::metadata(metadata_dir)
        .expect("metadata dir permissions")
        .permissions();
    std::fs::set_permissions(metadata_dir, std::fs::Permissions::from_mode(0o555))
        .expect("make metadata dir read-only");

    let overwrite = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/overwrite-rollback.txt")
                .header(header::CONTENT_LENGTH, "8")
                .body(Body::from("new-body"))
                .expect("build request"),
        )
        .await
        .expect("send overwrite request");
    std::fs::set_permissions(metadata_dir, original_permissions).expect("restore permissions");

    assert_eq!(overwrite.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("overwrite-rollback.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, "old-body".len() as u64);
}

#[tokio::test]
async fn put_object_accepts_decoded_http_chunked_body() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/chunked.txt")
                .header(header::TRANSFER_ENCODING, "chunked")
                .body(Body::from("chunked-body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("chunked.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, "chunked-body".len() as u64);
}

#[tokio::test]
async fn put_object_accepts_aws_chunked_unsigned_payload_trailer_crc32() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"hello trailer";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("aws-chunked.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, decoded.len() as u64);
    assert_eq!(metadata.content_encoding, None);
}

#[tokio::test]
async fn put_object_accepts_aws_chunked_with_transfer_encoding_chunked() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"aws chunked over transfer chunked";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);
    let expected_checksum = expected_crc32_checksum(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-transfer-encoding.txt")
                .header(header::TRANSFER_ENCODING, "chunked")
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum header"),
        expected_checksum.as_str()
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("aws-chunked-transfer-encoding.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, decoded.len() as u64);
}

#[tokio::test]
async fn put_object_preserves_non_transport_content_encoding_for_aws_chunked() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"gzip encoded metadata";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-gzip.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked, gzip")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("aws-chunked-gzip.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.content_encoding.as_deref(), Some("gzip"));
}

#[tokio::test]
async fn put_object_rejects_aws_chunked_without_decoded_content_length() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"missing decoded length";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-missing-decoded-length.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-decoded-content-length is required"));
}

#[tokio::test]
async fn put_object_rejects_aws_chunked_decoded_content_length_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"decoded length mismatch";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-bad-decoded-length.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header(
                    "x-amz-decoded-content-length",
                    (decoded.len() + 1).to_string(),
                )
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("does not match decoded body length"));
}

#[tokio::test]
async fn put_object_streams_split_aws_chunked_body() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"split hello trailer";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-split.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(split_body(encoded, 3))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("aws-chunked-split.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, decoded.len() as u64);
}

#[tokio::test]
async fn put_object_accepts_signed_aws_chunked_payload() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed-aws-chunked.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
    let decoded = b"signed aws chunked";
    let decoded_len = decoded.len().to_string();
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[("x-amz-decoded-content-length", &decoded_len)],
    });
    let seed_signature = authorization_signature(&authorization);
    let signing_key = signing_key("testsecret", &amz_date[..8], "us-east-1");
    let encoded = signed_aws_chunked_body(
        decoded,
        &signing_key,
        seed_signature,
        amz_date,
        "20260616/us-east-1/s3/aws4_request",
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-decoded-content-length", decoded_len)
                .header(header::AUTHORIZATION, authorization)
                .body(split_body(encoded, 5))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("signed-aws-chunked.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, decoded.len() as u64);
}

#[tokio::test]
async fn put_object_accepts_signed_aws_chunked_payload_trailer() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed-aws-chunked-trailer.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-sdk-checksum-algorithm;x-amz-trailer";
    let decoded = b"signed aws chunked trailer";
    let decoded_len = decoded.len().to_string();
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[
            ("x-amz-decoded-content-length", &decoded_len),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
    });
    let seed_signature = authorization_signature(&authorization);
    let signing_key = signing_key("testsecret", &amz_date[..8], "us-east-1");
    let (encoded, checksum) = signed_aws_chunked_body_with_crc32_trailer(
        decoded,
        &signing_key,
        seed_signature,
        amz_date,
        "20260616/us-east-1/s3/aws4_request",
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-decoded-content-length", decoded_len)
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header(header::AUTHORIZATION, authorization)
                .body(split_body(encoded, 4))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum header"),
        checksum.as_str()
    );
}

#[tokio::test]
async fn put_object_rejects_signed_aws_chunked_payload_trailer_signature_mismatch() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed-aws-chunked-trailer-bad.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-sdk-checksum-algorithm;x-amz-trailer";
    let decoded = b"signed aws chunked trailer";
    let decoded_len = decoded.len().to_string();
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[
            ("x-amz-decoded-content-length", &decoded_len),
            ("x-amz-sdk-checksum-algorithm", "CRC32"),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
    });
    let seed_signature = authorization_signature(&authorization);
    let signing_key = signing_key("testsecret", &amz_date[..8], "us-east-1");
    let (mut encoded, _checksum) = signed_aws_chunked_body_with_crc32_trailer(
        decoded,
        &signing_key,
        seed_signature,
        amz_date,
        "20260616/us-east-1/s3/aws4_request",
    );
    let last = encoded
        .iter()
        .rposition(|byte| byte.is_ascii_hexdigit())
        .expect("hex digit");
    encoded[last] = if encoded[last] == b'0' { b'1' } else { b'0' };

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-decoded-content-length", decoded_len)
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

#[tokio::test]
async fn put_object_rejects_signed_aws_chunked_payload_signature_mismatch() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed-aws-chunked-bad.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
    let decoded = b"signed aws chunked";
    let decoded_len = decoded.len().to_string();
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[("x-amz-decoded-content-length", &decoded_len)],
    });
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        format!("{:x};chunk-signature={}\r\n", decoded.len(), "0".repeat(64)).as_bytes(),
    );
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0;chunk-signature=");
    encoded.extend_from_slice("0".repeat(64).as_bytes());
    encoded.extend_from_slice(b"\r\n\r\n");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-decoded-content-length", decoded_len)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
}

#[tokio::test]
async fn put_object_rejects_duplicate_signed_aws_chunked_chunk_signature() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed-aws-chunked-duplicate-signature.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length";
    let decoded = b"signed aws chunked";
    let decoded_len = decoded.len().to_string();
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[("x-amz-decoded-content-length", &decoded_len)],
    });
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        format!(
            "{:x};chunk-signature={};chunk-signature={}\r\n",
            decoded.len(),
            "0".repeat(64),
            "1".repeat(64)
        )
        .as_bytes(),
    );
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0;chunk-signature=");
    encoded.extend_from_slice("0".repeat(64).as_bytes());
    encoded.extend_from_slice(b"\r\n\r\n");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-decoded-content-length", decoded_len)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("chunk-signature appears more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("signed-aws-chunked-duplicate-signature.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_aws_chunked_trailer_checksum_mismatch() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"hello trailer";
    let encoded = aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc32", "AAAAAA==");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/aws-chunked-bad.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
}

#[tokio::test]
async fn put_object_rejects_checksum_supplied_as_header_and_trailer() {
    let (state, temp_dir) = test_state().await;
    let decoded = b"duplicate checksum source";
    let header_checksum = expected_crc32_checksum(decoded);
    let encoded = aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc32", "AAAAAA==");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/duplicate-checksum-source.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-checksum-crc32", header_checksum)
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-checksum-crc32 must not be supplied as both header and trailer"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-checksum-source.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_duplicate_aws_chunked_trailer_name() {
    let (state, temp_dir) = test_state().await;
    let decoded = b"duplicate trailer";
    let checksum = expected_crc32_checksum(decoded);
    let mut encoded = Vec::new();
    encoded.extend_from_slice(format!("{:x}\r\n", decoded.len()).as_bytes());
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0\r\n");
    encoded.extend_from_slice(format!("x-amz-checksum-crc32: {checksum}\r\n").as_bytes());
    encoded.extend_from_slice(b"x-amz-checksum-crc32: AAAAAA==\r\n\r\n");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/duplicate-trailer-name.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("aws-chunked trailer appears more than once"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-trailer-name.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_undeclared_checksum_trailer() {
    let (state, temp_dir) = test_state().await;
    let decoded = b"undeclared checksum trailer";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/undeclared-checksum-trailer.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum trailer was not declared: x-amz-checksum-crc32"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("undeclared-checksum-trailer.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_duplicate_declared_checksum_trailer() {
    let (state, temp_dir) = test_state().await;
    let decoded = b"duplicate declared trailer";
    let encoded = aws_chunked_body_with_crc32_trailer(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/duplicate-declared-trailer.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header(
                    "x-amz-trailer",
                    "x-amz-checksum-crc32, X-Amz-Checksum-Crc32",
                )
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-trailer declares trailer more than once"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-declared-trailer.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_checksum_header() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/unsupported-checksum.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-checksum-crc64nvme", BASE64.encode([0_u8; 8]))
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum algorithm not supported"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("unsupported-checksum.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_non_ascii_sdk_checksum_algorithm() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/non-ascii-sdk-checksum.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header(
                    "x-amz-sdk-checksum-algorithm",
                    HeaderValue::from_bytes(b"\xFF").expect("header value"),
                )
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-sdk-checksum-algorithm must be valid ASCII"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("non-ascii-sdk-checksum.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_sdk_checksum_algorithm_without_checksum_source() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/missing-sdk-checksum-source.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-sdk-checksum-algorithm", "CRC32")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(
        body.contains(
            "x-amz-sdk-checksum-algorithm requires a matching checksum header or trailer"
        )
    );
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("missing-sdk-checksum-source.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_checksum_trailer() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"unsupported trailer checksum";
    let encoded =
        aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc64nvme", "AAAAAAAAAAA=");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/unsupported-checksum-trailer.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc64nvme")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Checksum algorithm not supported"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("unsupported-checksum-trailer.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_missing_declared_checksum_trailer() {
    let (state, _temp_dir) = test_state().await;
    let decoded = b"missing declared trailer";
    let encoded = aws_chunked_body_without_trailers(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/missing-checksum-trailer.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-checksum-crc32")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Declared checksum trailer was not received"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("missing-checksum-trailer.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_declared_trailer_name() {
    let (state, temp_dir) = test_state().await;
    let decoded = b"unsupported declared trailer";
    let encoded = aws_chunked_body_without_trailers(decoded);

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/unsupported-declared-trailer.txt")
                .header(header::CONTENT_LENGTH, encoded.len().to_string())
                .header(header::CONTENT_ENCODING, "aws-chunked")
                .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
                .header("x-amz-decoded-content-length", decoded.len().to_string())
                .header("x-amz-trailer", "x-amz-meta-owner")
                .body(Body::from(encoded))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-trailer contains unsupported trailer name"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("unsupported-declared-trailer.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_matching_content_md5() {
    let (state, _temp_dir) = test_state().await;
    let body = b"md5 checked";
    let content_md5 = BASE64.encode(Md5::digest(body));

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/md5.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("content-md5", content_md5)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_object_rejects_content_md5_mismatch() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-md5.txt")
                .header(header::CONTENT_LENGTH, "5")
                .header("content-md5", BASE64.encode([0_u8; 16]))
                .body(Body::from("wrong"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("<Code>BadDigest</Code>"));
}

#[tokio::test]
async fn put_object_rejects_duplicate_checksum_header_without_committing() {
    let (state, _temp_dir) = test_state().await;
    let content_md5 = BASE64.encode(Md5::digest(b"body"));
    let mut request = Request::builder()
        .method("PUT")
        .uri("/test-bucket/duplicate-md5.txt")
        .header(header::CONTENT_LENGTH, "4")
        .header("content-md5", &content_md5)
        .body(Body::from("body"))
        .expect("build request");
    request.headers_mut().append(
        "content-md5",
        HeaderValue::from_str(&content_md5).expect("content md5"),
    );

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("content-md5 must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-md5.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_duplicate_sdk_checksum_algorithm_header_without_committing() {
    let (state, _temp_dir) = test_state().await;
    let body = b"body";
    let checksum = BASE64.encode(sha2::Sha256::digest(body));
    let mut request = Request::builder()
        .method("PUT")
        .uri("/test-bucket/duplicate-sdk-checksum-algorithm.txt")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .header("x-amz-sdk-checksum-algorithm", "SHA256")
        .header("x-amz-checksum-sha256", checksum)
        .body(Body::from(&body[..]))
        .expect("build request");
    request.headers_mut().append(
        "x-amz-sdk-checksum-algorithm",
        HeaderValue::from_static("SHA256"),
    );

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("x-amz-sdk-checksum-algorithm must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-sdk-checksum-algorithm.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_unsupported_payload_hash_mode() {
    let (state, _temp_dir) = test_state().await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/unsupported-payload-mode.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-content-sha256", "NOT-A-SUPPORTED-PAYLOAD-MODE")
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));
}

#[tokio::test]
async fn put_object_rejects_duplicate_payload_hash_header_without_auth() {
    let (state, _temp_dir) = test_state().await;
    let mut request = Request::builder()
        .method("PUT")
        .uri("/test-bucket/duplicate-payload-hash.txt")
        .header(header::HOST, "localhost:9000")
        .header(header::CONTENT_LENGTH, "4")
        .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
        .body(Body::from("body"))
        .expect("build request");
    request.headers_mut().append(
        "x-amz-content-sha256",
        HeaderValue::from_static(
            "0000000000000000000000000000000000000000000000000000000000000000",
        ),
    );

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("x-amz-content-sha256 must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-payload-hash.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_matching_actual_sha256_payload_hash() {
    let (state, _temp_dir) = test_state().await;
    let body = b"actual sha256 payload";
    let payload_hash = hex::encode(sha2::Sha256::digest(body));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/actual-sha256.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("actual-sha256.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(metadata.size, body.len() as u64);
}

#[tokio::test]
async fn put_object_rejects_uppercase_actual_sha256_payload_hash() {
    let (state, _temp_dir) = test_state().await;
    let body = b"actual sha256 uppercase payload";
    let payload_hash = hex::encode(sha2::Sha256::digest(body)).to_ascii_uppercase();

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/uppercase-actual-sha256.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", payload_hash)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("Unsupported x-amz-content-sha256 payload mode"));

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("uppercase-actual-sha256.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_actual_sha256_payload_hash_mismatch() {
    let (state, temp_dir) = test_state().await;
    let body = b"actual sha256 mismatch";

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-actual-sha256.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", "0".repeat(64))
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>BadDigest</Code>"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("bad-actual-sha256.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_matching_sha256_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let body = b"sha256 checked";
    let checksum = BASE64.encode(sha2::Sha256::digest(body));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/sha256.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-sha256", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-sha256")
            .expect("checksum header"),
        checksum.as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("sha256.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-sha256"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn put_object_accepts_matching_sha1_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let body = b"sha1 checked";
    let checksum = BASE64.encode(sha1::Sha1::digest(body));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/sha1.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-sha1", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-sha1")
            .expect("checksum header"),
        checksum.as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("sha1.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-sha1"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn put_object_accepts_matching_sha512_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let body = b"sha512 checked";
    let checksum = BASE64.encode(sha2::Sha512::digest(body));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/sha512.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-sha512", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-sha512")
            .expect("checksum header"),
        checksum.as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("sha512.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-sha512"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn put_object_accepts_matching_crc32_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let body = b"crc32 checked";
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(body);
    let checksum = BASE64.encode(crc.to_be_bytes());

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/crc32.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32")
            .expect("checksum header"),
        checksum.as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("crc32.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-crc32"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn put_object_rejects_checksum_header_with_wrong_decoded_length() {
    let (state, temp_dir) = test_state().await;

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-checksum-length.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-checksum-crc32", BASE64.encode([0_u8; 1]))
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("x-amz-checksum-crc32 must decode to 4 bytes"));
    assert_tmp_dir_is_empty(temp_dir.path());

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("bad-checksum-length.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_matching_crc32c_checksum_header() {
    let (state, _temp_dir) = test_state().await;
    let body = b"crc32c checked";
    let crc = Crc::<u32>::new(&CRC_32_ISCSI).checksum(body);
    let checksum = BASE64.encode(crc.to_be_bytes());

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/crc32c.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-checksum-crc32c", &checksum)
                .body(Body::from(&body[..]))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-crc32c")
            .expect("checksum header"),
        checksum.as_str()
    );
    assert_eq!(
        response
            .headers()
            .get("x-amz-checksum-type")
            .expect("checksum type"),
        "FULL_OBJECT"
    );

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("crc32c.txt").expect("key"),
        )
        .await
        .expect("read metadata")
        .expect("metadata exists");
    assert_eq!(
        metadata.checksums.get("x-amz-checksum-crc32c"),
        Some(&checksum)
    );
}

#[tokio::test]
async fn put_object_rejects_missing_auth_when_anonymous_is_disabled() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/auth-required.txt")
                .header(header::CONTENT_LENGTH, "1")
                .body(Body::from("x"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let body = std::str::from_utf8(&body).expect("utf8 body");
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn put_object_accepts_anonymous_request_for_allowed_bucket() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/anonymous-allowed.txt")
                .header(header::CONTENT_LENGTH, "7")
                .body(Body::from("allowed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("anonymous-allowed.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_rejects_anonymous_request_for_disallowed_bucket() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            allowed_buckets: BTreeSet::from(["other-bucket".to_owned()]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/anonymous-denied.txt")
                .header(header::CONTENT_LENGTH, "6")
                .body(Body::from("denied"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("anonymous-denied.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_valid_header_sigv4() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/signed.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("signed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("signed.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_with_malformed_signature() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/malformed-signature.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });
    let authorization = format!(
        "{}Signature={}",
        authorization
            .rsplit_once("Signature=")
            .expect("signature field")
            .0,
        "ABC"
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("signed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("signature must be lowercase 64-character hex"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("malformed-signature.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_with_duplicate_authorization_field() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/duplicate-authorization-field.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });
    let authorization = format!("{authorization}, Signature={}", "0".repeat(64));

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("signed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("authorization header field Signature must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("duplicate-authorization-field.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_repeated_authorization_headers() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/repeated-authorization-header.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });
    let mut request = Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::HOST, "localhost:9000")
        .header(header::CONTENT_LENGTH, "6")
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from("signed"))
        .expect("build request");
    request.headers_mut().append(
        header::AUTHORIZATION,
        HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=duplicate"),
    );

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("Authorization header must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("repeated-authorization-header.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_repeated_sigv4_date_header() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/repeated-amz-date.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });
    let mut request = Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::HOST, "localhost:9000")
        .header(header::CONTENT_LENGTH, "6")
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .header(header::AUTHORIZATION, authorization)
        .body(Body::from("signed"))
        .expect("build request");
    request
        .headers_mut()
        .append("x-amz-date", HeaderValue::from_static("20260616T120001Z"));

    let response = router(state.clone())
        .oneshot(request)
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("x-amz-date must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("repeated-amz-date.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_with_malformed_credential_region() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/wrong-region.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-west-2",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("region"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AuthorizationHeaderMalformed</Code>"));
    assert!(body.contains("credential region is not configured"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("wrong-region.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_signed_request_allowed_by_auth_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allowed_buckets: BTreeSet::from(["test-bucket".to_owned()]),
            allowed_actions: BTreeSet::from([S3Action::PutObject]),
            ..permissive_auth_config()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/authorized.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "10")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("authorized"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("authorized.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_accepts_valid_header_sigv4_for_additional_credential() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            credentials: vec![AccessKeyConfig {
                access_key_id: "client".to_owned(),
                secret_key: "clientsecret".to_owned(),
                session_token: Some("client-session".to_owned()),
                active: true,
                allowed_buckets: BTreeSet::from(["client-bucket".to_owned()]),
                allowed_actions: BTreeSet::from([S3Action::PutObject]),
            }],
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/client-bucket/client-signed.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "client",
        secret_key: "clientsecret",
        region: "us-east-1",
        session_token: Some("client-session"),
        extra_signed_headers: &[("x-amz-security-token", "client-session")],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-security-token", "client-session")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("client"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("client-bucket").expect("bucket"),
            &ObjectKey::parse("client-signed.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_rejects_inactive_additional_credential() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            credentials: vec![AccessKeyConfig {
                access_key_id: "inactive".to_owned(),
                secret_key: "inactivesecret".to_owned(),
                session_token: None,
                active: false,
                allowed_buckets: BTreeSet::new(),
                allowed_actions: BTreeSet::new(),
            }],
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/inactive.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "inactive",
        secret_key: "inactivesecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "8")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("inactive"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("inactive.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_signed_request_for_disallowed_bucket() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allowed_buckets: BTreeSet::from(["other-bucket".to_owned()]),
            ..permissive_auth_config()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/denied-bucket.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("denied"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("denied-bucket.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_signed_request_for_disallowed_action() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allowed_actions: BTreeSet::from([S3Action::CreateMultipartUpload]),
            ..permissive_auth_config()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/denied-action.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("denied"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("denied-action.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_without_signed_host() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/missing-signed-host.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("signed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("missing signed header host"));
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_with_unsigned_x_amz_header() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/unsigned-amz-header.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-meta-owner", "rust")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("signed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("missing signed header x-amz-meta-owner"));
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_when_signed_path_changes() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let signed_path = "/test-bucket/signed-path.txt";
    let actual_path = "/test-bucket/changed-path.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path: signed_path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(actual_path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("changed-path.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_header_sigv4_when_signed_header_value_changes() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/changed-signed-header.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-meta-owner";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[("x-amz-meta-owner", "signed-value")],
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "4")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-meta-owner", "changed-value")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("body"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("changed-signed-header.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_requires_configured_session_token_for_header_sigv4() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let mut auth = permissive_auth_config();
    auth.session_token = Some("session-token".to_owned());
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth,
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/session-token.txt";
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: Some("session-token"),
        extra_signed_headers: &[],
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "5")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-security-token", "wrong-token")
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("token"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn put_object_rejects_skewed_header_sigv4_timestamp() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/skewed.txt";
    let amz_date = "20000101T000000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header(SignatureInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers,
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
        extra_signed_headers: &[],
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(path)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "6")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::from("skewed"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>RequestTimeTooSkewed</Code>"));
}

#[tokio::test]
async fn put_object_accepts_valid_presigned_url() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .body(Body::from("presigned"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_accepts_header_sigv4_with_x_amz_signature_query_param() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: permissive_auth_config(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/header-query-signature-param.txt";
    let query = "X-Amz-Signature=not-auth&x-id=PutObject";
    let amz_date = "20260616T120000Z";
    let body = "signed query";
    let payload_hash = hex::encode(sha2::Sha256::digest(body.as_bytes()));
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let authorization = authorization_header_with_canonical_query(
        SignatureInput {
            method: "PUT",
            path,
            host: "localhost:9000",
            amz_date,
            payload_hash: &payload_hash,
            signed_headers,
            access_key: "test",
            secret_key: "testsecret",
            region: "us-east-1",
            session_token: None,
            extra_signed_headers: &[],
        },
        query,
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("{path}?{query}"))
                .header(header::HOST, "localhost:9000")
                .header(header::AUTHORIZATION, authorization)
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header("x-amz-content-sha256", payload_hash)
                .header("x-amz-date", amz_date)
                .body(Body::from(body))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("header-query-signature-param.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_accepts_presigned_url_with_encoded_signature_field_name() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-encoded-signature-field.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    })
    .replace("&X-Amz-Signature=", "&X-Amz%2DSignature=");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "7")
                .body(Body::from("encoded"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-encoded-signature-field.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_accepts_presigned_url_with_encoded_algorithm_field_name() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-encoded-algorithm-field.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    })
    .replace("X-Amz-Algorithm=", "X-Amz%2DAlgorithm=");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .body(Body::from("algorithm"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-encoded-algorithm-field.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_accepts_presigned_url_with_signed_extra_query_params() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-extra-query.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url_with_extra_query(
        PresignInput {
            method: "PUT",
            path,
            host: "localhost:9000",
            amz_date: &amz_date,
            expires: 300,
            signed_headers: "host",
            access_key: "test",
            secret_key: "testsecret",
            region: "us-east-1",
            session_token: None,
        },
        &[
            ("response-content-type", "text/plain"),
            ("x-id", "PutObject"),
        ],
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "5")
                .body(Body::from("extra"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);

    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-extra-query.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_some());
}

#[tokio::test]
async fn put_object_rejects_presigned_url_when_signed_extra_query_param_changes() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-extra-query-tampered.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url_with_extra_query(
        PresignInput {
            method: "PUT",
            path,
            host: "localhost:9000",
            amz_date: &amz_date,
            expires: 300,
            signed_headers: "host",
            access_key: "test",
            secret_key: "testsecret",
            region: "us-east-1",
            session_token: None,
        },
        &[("response-content-type", "text/plain")],
    )
    .replace(
        "response-content-type=text%2Fplain",
        "response-content-type=application%2Fjson",
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "5")
                .body(Body::from("extra"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>SignatureDoesNotMatch</Code>"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-extra-query-tampered.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_presigned_url_with_malformed_signature() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-malformed-signature.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });
    let url = format!(
        "{}X-Amz-Signature={}",
        url.rsplit_once("X-Amz-Signature=")
            .expect("signature query")
            .0,
        "ABC"
    );

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .body(Body::from("presigned"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("signature must be lowercase 64-character hex"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-malformed-signature.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_presigned_url_with_duplicate_auth_field() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let path = "/test-bucket/presigned-duplicate-auth-field.txt";
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let mut url = presigned_url(PresignInput {
        method: "PUT",
        path,
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });
    url.push_str("&X-Amz-Credential=duplicate");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .body(Body::from("presigned"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("presigned URL field X-Amz-Credential must not appear more than once"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-duplicate-auth-field.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_rejects_expired_presigned_url() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config::new(temp_dir.path().to_path_buf()))
        .await
        .expect("create app state");
    let url = presigned_url(PresignInput {
        method: "PUT",
        path: "/test-bucket/expired.txt",
        host: "localhost:9000",
        amz_date: "20000101T000000Z",
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "7")
                .body(Body::from("expired"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
}

#[tokio::test]
async fn put_object_rejects_presigned_url_with_invalid_expires_bounds() {
    for expires in [0, 604_801] {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let state = AppState::new(Config::new(temp_dir.path().to_path_buf()))
            .await
            .expect("create app state");
        let key = format!("invalid-expires-{expires}.txt");
        let path = format!("/test-bucket/{key}");
        let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let url = presigned_url(PresignInput {
            method: "PUT",
            path: &path,
            host: "localhost:9000",
            amz_date: &amz_date,
            expires,
            signed_headers: "host",
            access_key: "test",
            secret_key: "testsecret",
            region: "us-east-1",
            session_token: None,
        });

        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(url)
                    .header(header::HOST, "localhost:9000")
                    .header(header::CONTENT_LENGTH, "7")
                    .body(Body::from("invalid"))
                    .expect("build request"),
            )
            .await
            .expect("send request");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = response_text(response).await;
        assert!(body.contains("<Code>AccessDenied</Code>"));
        assert!(body.contains("presigned URL expiration is invalid"));
        let metadata = state
            .object_store
            .head_object(
                &BucketName::parse("test-bucket").expect("bucket"),
                &ObjectKey::parse(&key).expect("key"),
            )
            .await
            .expect("read metadata");
        assert!(metadata.is_none());
    }
}

#[tokio::test]
async fn put_object_rejects_presigned_url_missing_required_field() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config::new(temp_dir.path().to_path_buf()))
        .await
        .expect("create app state");
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path: "/test-bucket/presigned-missing-signed-headers.txt",
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    })
    .replace("&X-Amz-SignedHeaders=host", "");

    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "7")
                .body(Body::from("missing"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("presigned URL is missing X-Amz-SignedHeaders"));
    let metadata = state
        .object_store
        .head_object(
            &BucketName::parse("test-bucket").expect("bucket"),
            &ObjectKey::parse("presigned-missing-signed-headers.txt").expect("key"),
        )
        .await
        .expect("read metadata");
    assert!(metadata.is_none());
}

#[tokio::test]
async fn put_object_accepts_presigned_url_with_configured_session_token() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            session_token: Some("session-token".to_owned()),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path: "/test-bucket/presigned-token.txt",
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: Some("session-token"),
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "5")
                .body(Body::from("token"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_object_rejects_presigned_url_without_signed_host() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path: "/test-bucket/presigned-missing-host.txt",
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .header("x-amz-date", &amz_date)
                .body(Body::from("presigned"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("missing signed header host"));
}

#[tokio::test]
async fn put_object_rejects_presigned_url_with_unsigned_x_amz_header() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig::default(),
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let url = presigned_url(PresignInput {
        method: "PUT",
        path: "/test-bucket/presigned-unsigned-amz-header.txt",
        host: "localhost:9000",
        amz_date: &amz_date,
        expires: 300,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .header(header::CONTENT_LENGTH, "9")
                .header("x-amz-meta-owner", "rust")
                .body(Body::from("presigned"))
                .expect("build request"),
        )
        .await
        .expect("send request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response_text(response).await;
    assert!(body.contains("<Code>AccessDenied</Code>"));
    assert!(body.contains("missing signed header x-amz-meta-owner"));
}

struct SignatureInput<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    amz_date: &'a str,
    payload_hash: &'a str,
    signed_headers: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    session_token: Option<&'a str>,
    extra_signed_headers: &'a [(&'a str, &'a str)],
}

fn authorization_header(input: SignatureInput<'_>) -> String {
    authorization_header_with_canonical_query(input, "")
}

fn authorization_header_with_canonical_query(
    input: SignatureInput<'_>,
    canonical_query: &str,
) -> String {
    let date = &input.amz_date[..8];
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        input.path,
        canonical_query,
        canonical_headers_for_signature(&input),
        input.signed_headers,
        input.payload_hash
    );
    let canonical_request_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        input.amz_date, date, input.region, canonical_request_hash
    );
    let signing_key = signing_key(input.secret_key, date, input.region);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request, SignedHeaders={}, Signature={}",
        input.access_key, date, input.region, input.signed_headers, signature
    )
}

fn authorization_signature(authorization: &str) -> &str {
    authorization
        .rsplit_once("Signature=")
        .expect("signature field")
        .1
}

fn signing_key(secret_key: &str, date: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("valid hmac key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn signed_aws_chunked_body(
    decoded: &[u8],
    signing_key: &[u8],
    seed_signature: &str,
    amz_date: &str,
    credential_scope: &str,
) -> Vec<u8> {
    let first_signature = signed_chunk_signature(
        signing_key,
        seed_signature,
        amz_date,
        credential_scope,
        decoded,
    );
    let final_signature = signed_chunk_signature(
        signing_key,
        &first_signature,
        amz_date,
        credential_scope,
        b"",
    );
    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        format!("{:x};chunk-signature={first_signature}\r\n", decoded.len()).as_bytes(),
    );
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n");
    encoded.extend_from_slice(format!("0;chunk-signature={final_signature}\r\n\r\n").as_bytes());
    encoded
}

fn signed_aws_chunked_body_with_crc32_trailer(
    decoded: &[u8],
    signing_key: &[u8],
    seed_signature: &str,
    amz_date: &str,
    credential_scope: &str,
) -> (Vec<u8>, String) {
    let first_signature = signed_chunk_signature(
        signing_key,
        seed_signature,
        amz_date,
        credential_scope,
        decoded,
    );
    let final_chunk_signature = signed_chunk_signature(
        signing_key,
        &first_signature,
        amz_date,
        credential_scope,
        b"",
    );
    let checksum = expected_crc32_checksum(decoded);
    let canonical_trailers = format!("x-amz-checksum-crc32:{checksum}\n");
    let trailer_signature = signed_trailer_signature(
        signing_key,
        &final_chunk_signature,
        amz_date,
        credential_scope,
        &canonical_trailers,
    );

    let mut encoded = Vec::new();
    encoded.extend_from_slice(
        format!("{:x};chunk-signature={first_signature}\r\n", decoded.len()).as_bytes(),
    );
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n");
    encoded.extend_from_slice(format!("0;chunk-signature={final_chunk_signature}\r\n").as_bytes());
    encoded.extend_from_slice(format!("x-amz-checksum-crc32:{checksum}\r\n").as_bytes());
    encoded.extend_from_slice(
        format!("x-amz-trailer-signature:{trailer_signature}\r\n\r\n").as_bytes(),
    );
    (encoded, checksum)
}

fn signed_chunk_signature(
    signing_key: &[u8],
    previous_signature: &str,
    amz_date: &str,
    credential_scope: &str,
    chunk_data: &[u8],
) -> String {
    let empty_hash = hex::encode(sha2::Sha256::digest([]));
    let chunk_hash = hex::encode(sha2::Sha256::digest(chunk_data));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{credential_scope}\n{previous_signature}\n{empty_hash}\n{chunk_hash}"
    );
    hex::encode(hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

fn signed_trailer_signature(
    signing_key: &[u8],
    previous_signature: &str,
    amz_date: &str,
    credential_scope: &str,
    canonical_trailers: &str,
) -> String {
    let trailer_hash = hex::encode(sha2::Sha256::digest(canonical_trailers.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256-TRAILER\n{amz_date}\n{credential_scope}\n{previous_signature}\n{trailer_hash}"
    );
    hex::encode(hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

struct PresignInput<'a> {
    method: &'a str,
    path: &'a str,
    host: &'a str,
    amz_date: &'a str,
    expires: u32,
    signed_headers: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
    region: &'a str,
    session_token: Option<&'a str>,
}

fn presigned_url(input: PresignInput<'_>) -> String {
    presigned_url_with_extra_query(input, &[])
}

fn presigned_url_with_extra_query(
    input: PresignInput<'_>,
    extra_query_params: &[(&str, &str)],
) -> String {
    let date = &input.amz_date[..8];
    let credential = format!(
        "{}/{}/{}/s3/aws4_request",
        input.access_key, date, input.region
    );
    let mut params = vec![
        ("X-Amz-Algorithm".to_owned(), "AWS4-HMAC-SHA256".to_owned()),
        ("X-Amz-Credential".to_owned(), credential),
        ("X-Amz-Date".to_owned(), input.amz_date.to_owned()),
        ("X-Amz-Expires".to_owned(), input.expires.to_string()),
        (
            "X-Amz-SignedHeaders".to_owned(),
            input.signed_headers.to_owned(),
        ),
    ];
    if let Some(session_token) = input.session_token {
        params.push(("X-Amz-Security-Token".to_owned(), session_token.to_owned()));
    }
    params.extend(
        extra_query_params
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    let mut encoded_params = params
        .into_iter()
        .map(|(name, value)| {
            (
                aws_uri_encode(name.as_bytes(), false),
                aws_uri_encode(value.as_bytes(), false),
            )
        })
        .collect::<Vec<_>>();
    encoded_params.sort();
    let canonical_query = encoded_params
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
        input.method,
        input.path,
        canonical_query,
        canonical_headers_for_presign(&input),
        input.signed_headers
    );
    let canonical_request_hash = hex::encode(sha2::Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}/{}/s3/aws4_request\n{}",
        input.amz_date, date, input.region, canonical_request_hash
    );
    let signing_key = signing_key(input.secret_key, date, input.region);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let query = format!("{canonical_query}&X-Amz-Signature={signature}");
    format!("{}?{}", input.path, query)
}

fn canonical_headers_for_presign(input: &PresignInput<'_>) -> String {
    input
        .signed_headers
        .split(';')
        .map(|name| {
            let value = match name {
                "host" => input.host,
                "x-amz-date" => input.amz_date,
                _ => panic!("unsupported signed header in presign test helper: {name}"),
            };
            format!("{name}:{value}\n")
        })
        .collect()
}

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    std::str::from_utf8(&body).expect("utf8 body").to_owned()
}

fn assert_tmp_dir_is_empty(root: &std::path::Path) {
    let tmp_dir = root.join("tmp");
    let entries = std::fs::read_dir(tmp_dir)
        .expect("read tmp dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("read tmp entries");
    assert!(entries.is_empty());
}

fn stored_metadata_path(root: &std::path::Path, bucket: &str, key: &str) -> std::path::PathBuf {
    let digest = stored_object_digest(bucket, key);
    root.join("metadata")
        .join(&digest[..2])
        .join(format!("{digest}.json"))
}

fn stored_object_path(root: &std::path::Path, bucket: &str, key: &str) -> std::path::PathBuf {
    let digest = stored_object_digest(bucket, key);
    root.join("objects")
        .join(&digest[..2])
        .join(format!("{digest}.data"))
}

fn stored_object_digest(bucket: &str, key: &str) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bucket.as_bytes());
    hasher.update([0]);
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn assert_has_request_id(response: &axum::response::Response) {
    let value = response
        .headers()
        .get("x-amz-request-id")
        .expect("request id header")
        .to_str()
        .expect("request id ascii");
    assert!(!value.is_empty());
}

struct RejectProcessor;

impl UploadProcessor for RejectProcessor {
    fn process<'a>(
        &'a self,
        _request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async {
            Err(UploadProcessorError::Rejected(
                "upload rejected by test processor".to_owned(),
            ))
        })
    }
}

struct ReplaceProcessor {
    replacement: Vec<u8>,
}

impl UploadProcessor for ReplaceProcessor {
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async move {
            std::fs::write(request.replacement_path, &self.replacement)
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;
            Ok(UploadProcessorAction::Replace)
        })
    }
}

struct AppendProcessor {
    suffix: &'static [u8],
}

impl UploadProcessor for AppendProcessor {
    fn process<'a>(
        &'a self,
        request: UploadProcessorRequest<'a>,
    ) -> BoxFuture<'a, Result<UploadProcessorAction, UploadProcessorError>> {
        Box::pin(async move {
            let mut bytes = read_file(request.current_path)?;
            bytes.extend_from_slice(self.suffix);
            std::fs::write(request.replacement_path, bytes)
                .map_err(|error| UploadProcessorError::Failed(error.to_string()))?;
            Ok(UploadProcessorAction::Replace)
        })
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, UploadProcessorError> {
    std::fs::read(path).map_err(|error| UploadProcessorError::Failed(error.to_string()))
}

fn canonical_headers_for_signature(input: &SignatureInput<'_>) -> String {
    input
        .signed_headers
        .split(';')
        .map(|name| {
            let value = match name {
                "host" => input.host,
                "x-amz-content-sha256" => input.payload_hash,
                "x-amz-date" => input.amz_date,
                "x-amz-security-token" => input.session_token.expect("session token"),
                _ => input
                    .extra_signed_headers
                    .iter()
                    .find_map(|(header_name, header_value)| {
                        (*header_name == name).then_some(*header_value)
                    })
                    .unwrap_or_else(|| panic!("unsupported signed header in test helper: {name}")),
            };
            format!("{name}:{value}\n")
        })
        .collect()
}

fn aws_uri_encode(bytes: &[u8], preserve_slash: bool) -> String {
    let mut encoded = String::new();
    for byte in bytes {
        match *byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(*byte as char);
            }
            b'/' if preserve_slash => encoded.push('/'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn aws_chunked_body_with_crc32_trailer(decoded: &[u8]) -> Vec<u8> {
    let checksum = expected_crc32_checksum(decoded);
    aws_chunked_body_with_custom_trailer(decoded, "x-amz-checksum-crc32", &checksum)
}

fn expected_crc32_checksum(decoded: &[u8]) -> String {
    let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(decoded);
    BASE64.encode(crc.to_be_bytes())
}

fn aws_chunked_body_with_custom_trailer(
    decoded: &[u8],
    trailer_name: &str,
    trailer_value: &str,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(format!("{:x}\r\n", decoded.len()).as_bytes());
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0\r\n");
    encoded.extend_from_slice(format!("{trailer_name}: {trailer_value}\r\n\r\n").as_bytes());
    encoded
}

fn aws_chunked_body_without_trailers(decoded: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(format!("{:x}\r\n", decoded.len()).as_bytes());
    encoded.extend_from_slice(decoded);
    encoded.extend_from_slice(b"\r\n0\r\n\r\n");
    encoded
}

fn split_body(bytes: Vec<u8>, chunk_size: usize) -> Body {
    let chunks = bytes
        .chunks(chunk_size)
        .map(|chunk| Ok::<_, std::convert::Infallible>(Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    Body::from_stream(stream::iter(chunks))
}
