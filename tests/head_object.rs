use std::collections::BTreeSet;

use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use crc::{CRC_32_ISO_HDLC, Crc};
use md5::{Digest, Md5};
use s3_endpoint::{
    AppState,
    config::{AuthConfig, Config, S3Action},
    router,
};
use tower::ServiceExt;

mod common;

async fn test_state(virtual_host_base_domain: Option<String>) -> (AppState, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            ..AuthConfig::default()
        },
        virtual_host_base_domain,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    (state, temp_dir)
}

#[tokio::test]
async fn head_object_returns_persisted_metadata_headers() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"hello s3";
    let checksum = BASE64.encode(
        Crc::<u32>::new(&CRC_32_ISO_HDLC)
            .checksum(body)
            .to_be_bytes(),
    );
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_LANGUAGE, "en-US")
                .header("x-amz-meta-owner", "rust")
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(&body[..]))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let head = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head.txt")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(head.status(), StatusCode::OK);
    assert_has_request_id(&head);
    assert_eq!(
        head.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_str(&body.len().to_string()).expect("content length"))
    );
    assert_eq!(
        head.headers().get(header::ETAG),
        Some(&HeaderValue::from_str(&expected_etag).expect("etag"))
    );
    assert_eq!(
        head.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/plain"))
    );
    assert_eq!(
        head.headers().get(header::CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        head.headers().get(header::CONTENT_LANGUAGE),
        Some(&HeaderValue::from_static("en-US"))
    );
    assert_eq!(
        head.headers().get("x-amz-meta-owner"),
        Some(&HeaderValue::from_static("rust"))
    );
    assert_eq!(
        head.headers().get("x-amz-checksum-crc32"),
        Some(&HeaderValue::from_str(&checksum).expect("checksum"))
    );
    assert_eq!(
        head.headers().get("x-amz-checksum-type"),
        Some(&HeaderValue::from_static("FULL_OBJECT"))
    );
    let last_modified = head
        .headers()
        .get(header::LAST_MODIFIED)
        .expect("last modified")
        .to_str()
        .expect("last modified ascii");
    assert!(last_modified.ends_with(" GMT"));
}

#[tokio::test]
async fn head_object_supports_virtual_hosted_style() {
    let (state, _temp_dir) = test_state(Some("s3.local".to_owned())).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/vh.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let head = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/vh.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(head.status(), StatusCode::OK);
    assert_has_request_id(&head);
    assert_eq!(
        head.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("4"))
    );
}

#[tokio::test]
async fn head_object_honors_if_match_and_if_none_match() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"conditional head";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head-conditional.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(&body[..]))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let if_match = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-conditional.txt")
                .header(header::IF_MATCH, &expected_etag)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_match.status(), StatusCode::OK);
    assert_has_request_id(&if_match);

    let if_match_mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-conditional.txt")
                .header(header::IF_MATCH, "\"not-the-etag\"")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_match_mismatch.status(), StatusCode::PRECONDITION_FAILED);
    assert_has_request_id(&if_match_mismatch);

    let if_none_match = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-conditional.txt")
                .header(header::IF_NONE_MATCH, "*")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_none_match.status(), StatusCode::NOT_MODIFIED);
    assert_has_request_id(&if_none_match);
}

#[tokio::test]
async fn head_object_uses_weak_etag_comparison_for_if_none_match_only() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"head weak etag";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));
    let weak_etag = format!("W/{expected_etag}");

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head-weak-etag.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(&body[..]))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let if_none_match = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-weak-etag.txt")
                .header(header::IF_NONE_MATCH, &weak_etag)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_none_match.status(), StatusCode::NOT_MODIFIED);
    assert_has_request_id(&if_none_match);

    let if_match = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-weak-etag.txt")
                .header(header::IF_MATCH, weak_etag)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_match.status(), StatusCode::PRECONDITION_FAILED);
    assert_has_request_id(&if_match);
}

#[tokio::test]
async fn head_object_honors_if_modified_since_and_if_unmodified_since() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head-date-conditional.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let baseline = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-date-conditional.txt")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(baseline.status(), StatusCode::OK);
    let last_modified = baseline
        .headers()
        .get(header::LAST_MODIFIED)
        .expect("last modified")
        .to_str()
        .expect("last modified ascii")
        .to_owned();

    let not_modified = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-date-conditional.txt")
                .header(header::IF_MODIFIED_SINCE, &last_modified)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_has_request_id(&not_modified);

    let unmodified = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-date-conditional.txt")
                .header(header::IF_UNMODIFIED_SINCE, &last_modified)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(unmodified.status(), StatusCode::OK);
    assert_has_request_id(&unmodified);

    let too_old = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-date-conditional.txt")
                .header(header::IF_UNMODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(too_old.status(), StatusCode::PRECONDITION_FAILED);
    assert_has_request_id(&too_old);
}

#[tokio::test]
async fn head_object_etag_conditions_take_precedence_over_date_conditions() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"head precedence";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head-etag-date-precedence.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(&body[..]))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let if_match_wins = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-etag-date-precedence.txt")
                .header(header::IF_MATCH, &expected_etag)
                .header(header::IF_UNMODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_match_wins.status(), StatusCode::OK);

    let if_none_match_wins = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-etag-date-precedence.txt")
                .header(header::IF_NONE_MATCH, "\"other\"")
                .header(header::IF_MODIFIED_SINCE, "Tue, 16 Jun 2099 00:00:00 GMT")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");
    assert_eq!(if_none_match_wins.status(), StatusCode::OK);
}

#[tokio::test]
async fn head_object_returns_no_such_key_for_missing_object() {
    let (state, _temp_dir) = test_state(None).await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/missing.txt")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_object_treats_metadata_without_object_file_as_missing() {
    let (state, temp_dir) = test_state(None).await;
    common::write_orphan_metadata(temp_dir.path(), "test-bucket", "orphan-runtime.txt");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/orphan-runtime.txt")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_object_rejects_percent_decoded_control_character_in_key() {
    let (state, _temp_dir) = test_state(None).await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/bad%0Akey.txt")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_object_rejects_signed_request_for_disallowed_action() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::PutObject]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let authorization = common::authorization_header(common::SignatureInput {
        method: "HEAD",
        path: "/test-bucket/private.txt",
        canonical_query: "",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/private.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_has_request_id(&response);
    assert_eq!(
        response.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("0"))
    );
    assert_empty_body(response).await;
}

#[tokio::test]
async fn head_object_accepts_signed_request_allowed_by_head_object_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::HeadObject]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/head-policy.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let amz_date = "20260616T120000Z";
    let payload_hash = "UNSIGNED-PAYLOAD";
    let authorization = common::authorization_header(common::SignatureInput {
        method: "HEAD",
        path: "/test-bucket/head-policy.txt",
        canonical_query: "",
        host: "localhost:9000",
        amz_date,
        payload_hash,
        signed_headers: "host;x-amz-content-sha256;x-amz-date",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/test-bucket/head-policy.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn head_object_accepts_presigned_url_allowed_by_head_object_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::HeadObject]),
            ..AuthConfig::default()
        },
        virtual_host_base_domain: None,
        upload_limits: Default::default(),
    })
    .await
    .expect("create app state");
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/presigned-head.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let url = common::presigned_url(common::PresignInput {
        method: "HEAD",
        path: "/test-bucket/presigned-head.txt",
        host: "localhost:9000",
        amz_date: "20260616T120000Z",
        expires: 604_800,
        signed_headers: "host",
        access_key: "test",
        secret_key: "testsecret",
        region: "us-east-1",
        session_token: None,
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .body(Body::empty())
                .expect("build head"),
        )
        .await
        .expect("send head");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
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

async fn assert_empty_body(response: axum::response::Response) {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert!(body.is_empty());
}
