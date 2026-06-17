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
async fn get_object_streams_stored_object_with_metadata_headers() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"hello downloaded object";
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
                .uri("/test-bucket/download.txt")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .header(header::CONTENT_TYPE, "text/plain")
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_DISPOSITION, "inline")
                .header(header::CONTENT_LANGUAGE, "en-US")
                .header(header::CACHE_CONTROL, "max-age=60")
                .header(header::EXPIRES, "Wed, 21 Oct 2026 07:28:00 GMT")
                .header("x-amz-meta-owner", "rust")
                .header("x-amz-checksum-crc32", &checksum)
                .body(Body::from(&body[..]))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/download.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::OK);
    assert_has_request_id(&get);
    assert_eq!(
        get.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_str(&body.len().to_string()).expect("content length"))
    );
    assert_eq!(
        get.headers().get(header::ETAG),
        Some(&HeaderValue::from_str(&expected_etag).expect("etag"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/plain"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_DISPOSITION),
        Some(&HeaderValue::from_static("inline"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_LANGUAGE),
        Some(&HeaderValue::from_static("en-US"))
    );
    assert_eq!(
        get.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("max-age=60"))
    );
    assert_eq!(
        get.headers().get(header::EXPIRES),
        Some(&HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"))
    );
    assert_eq!(
        get.headers().get("x-amz-meta-owner"),
        Some(&HeaderValue::from_static("rust"))
    );
    assert_eq!(
        get.headers().get("x-amz-checksum-crc32"),
        Some(&HeaderValue::from_str(&checksum).expect("checksum"))
    );

    let downloaded = to_bytes(get.into_body(), usize::MAX)
        .await
        .expect("read get body");
    assert_eq!(&downloaded[..], body);
}

#[tokio::test]
async fn get_object_applies_response_header_overrides() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/override.txt")
                .header(header::CONTENT_LENGTH, "4")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(
                    "/test-bucket/override.txt?response-content-type=text%2Fcsv&response-content-disposition=attachment%3B%20filename%3D%22data.csv%22&response-cache-control=no-cache&response-content-encoding=gzip&response-content-language=en-US&response-expires=Wed%2C%2021%20Oct%202026%2007%3A28%3A00%20GMT",
                )
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::OK);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/csv"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_DISPOSITION),
        Some(&HeaderValue::from_static(
            "attachment; filename=\"data.csv\""
        ))
    );
    assert_eq!(
        get.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-cache"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_LANGUAGE),
        Some(&HeaderValue::from_static("en-US"))
    );
    assert_eq!(
        get.headers().get(header::EXPIRES),
        Some(&HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"))
    );
}

#[tokio::test]
async fn get_object_applies_response_header_overrides_to_ranges() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/range-override.txt")
                .header(header::CONTENT_LENGTH, "10")
                .body(Body::from("0123456789"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/range-override.txt?response-content-type=text%2Fplain")
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        get.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("text/plain"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes 2-5/10"))
    );
}

#[tokio::test]
async fn get_object_rejects_invalid_or_duplicate_response_header_overrides() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-override.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let duplicate = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad-override.txt?response-content-type=text%2Fplain&response-content-type=text%2Fcsv")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send duplicate override get");
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    let body = response_text(duplicate).await;
    assert!(body.contains("response-content-type must not appear more than once"));

    let invalid_utf8 = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad-override.txt?response-content-type=text%FFplain")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send invalid override get");
    assert_eq!(invalid_utf8.status(), StatusCode::BAD_REQUEST);
    let body = response_text(invalid_utf8).await;
    assert!(body.contains("query string contains invalid percent-encoded UTF-8"));
}

#[tokio::test]
async fn get_object_supports_single_byte_ranges() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/ranged.txt")
                .header(header::CONTENT_LENGTH, "10")
                .body(Body::from("0123456789"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/ranged.txt")
                .header(header::RANGE, "bytes=2-5")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        get.headers().get(header::CONTENT_LENGTH),
        Some(&HeaderValue::from_static("4"))
    );
    assert_eq!(
        get.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes 2-5/10"))
    );
    assert_eq!(
        get.headers().get(header::ACCEPT_RANGES),
        Some(&HeaderValue::from_static("bytes"))
    );
    let downloaded = to_bytes(get.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&downloaded[..], b"2345");
}

#[tokio::test]
async fn get_object_honors_if_match_and_if_none_match() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"conditional body";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/conditional.txt")
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
                .method("GET")
                .uri("/test-bucket/conditional.txt")
                .header(header::IF_MATCH, &expected_etag)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_match.status(), StatusCode::OK);
    let downloaded = to_bytes(if_match.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&downloaded[..], body);

    let if_match_mismatch = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/conditional.txt")
                .header(header::IF_MATCH, "\"not-the-etag\"")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_match_mismatch.status(), StatusCode::PRECONDITION_FAILED);
    let error = response_text(if_match_mismatch).await;
    assert!(error.contains("<Code>PreconditionFailed</Code>"));

    let if_none_match = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/conditional.txt")
                .header(header::IF_NONE_MATCH, format!("\"other\", {expected_etag}"))
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_none_match.status(), StatusCode::NOT_MODIFIED);
    assert_has_request_id(&if_none_match);
}

#[tokio::test]
async fn get_object_uses_weak_etag_comparison_for_if_none_match_only() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"weak etag";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));
    let weak_etag = format!("W/{expected_etag}");

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/weak-etag.txt")
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
                .method("GET")
                .uri("/test-bucket/weak-etag.txt")
                .header(header::IF_NONE_MATCH, &weak_etag)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_none_match.status(), StatusCode::NOT_MODIFIED);

    let if_match = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/weak-etag.txt")
                .header(header::IF_MATCH, weak_etag)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_match.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn get_object_honors_if_modified_since_and_if_unmodified_since() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/date-conditional.txt")
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
                .method("GET")
                .uri("/test-bucket/date-conditional.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
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
                .method("GET")
                .uri("/test-bucket/date-conditional.txt")
                .header(header::IF_MODIFIED_SINCE, &last_modified)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    assert_has_request_id(&not_modified);

    let unmodified = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/date-conditional.txt")
                .header(header::IF_UNMODIFIED_SINCE, &last_modified)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(unmodified.status(), StatusCode::OK);

    let too_old = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/date-conditional.txt")
                .header(header::IF_UNMODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(too_old.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn get_object_etag_conditions_take_precedence_over_date_conditions() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);
    let body = b"precedence";
    let expected_etag = format!("\"{}\"", hex::encode(Md5::digest(body)));

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/etag-date-precedence.txt")
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
                .method("GET")
                .uri("/test-bucket/etag-date-precedence.txt")
                .header(header::IF_MATCH, &expected_etag)
                .header(header::IF_UNMODIFIED_SINCE, "Thu, 01 Jan 1970 00:00:00 GMT")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_match_wins.status(), StatusCode::OK);

    let if_none_match_wins = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/etag-date-precedence.txt")
                .header(header::IF_NONE_MATCH, "\"other\"")
                .header(header::IF_MODIFIED_SINCE, "Tue, 16 Jun 2099 00:00:00 GMT")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(if_none_match_wins.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_object_supports_open_ended_and_suffix_ranges() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/range-forms.txt")
                .header(header::CONTENT_LENGTH, "10")
                .body(Body::from("0123456789"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let open_ended = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/range-forms.txt")
                .header(header::RANGE, "bytes=7-")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(open_ended.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        open_ended.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes 7-9/10"))
    );
    let body = to_bytes(open_ended.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"789");

    let suffix = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/range-forms.txt")
                .header(header::RANGE, "bytes=-4")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(suffix.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        suffix.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes 6-9/10"))
    );
    let body = to_bytes(suffix.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"6789");
}

#[tokio::test]
async fn get_object_rejects_unsatisfiable_or_multi_range() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/bad-range.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let unsatisfiable = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad-range.txt")
                .header(header::RANGE, "bytes=10-12")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        unsatisfiable.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes */4"))
    );
    let body = response_text(unsatisfiable).await;
    assert!(body.contains("<Code>InvalidRange</Code>"));

    let multi_range = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad-range.txt")
                .header(header::RANGE, "bytes=0-1,2-3")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");
    assert_eq!(multi_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    let body = response_text(multi_range).await;
    assert!(body.contains("<Code>InvalidRange</Code>"));
}

#[tokio::test]
async fn get_object_returns_content_range_for_empty_object_unsatisfiable_range() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/test-bucket/empty-range.txt")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/empty-range.txt")
                .header(header::RANGE, "bytes=0-0")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        get.headers().get(header::CONTENT_RANGE),
        Some(&HeaderValue::from_static("bytes */0"))
    );
    let body = response_text(get).await;
    assert!(body.contains("<Code>InvalidRange</Code>"));
}

#[tokio::test]
async fn get_object_supports_virtual_hosted_style() {
    let (state, _temp_dir) = test_state(Some("s3.local".to_owned())).await;
    let app = router(state);

    let put = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/object.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let get = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/object.txt")
                .header(header::HOST, "test-bucket.s3.local")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(get.status(), StatusCode::OK);
    let downloaded = to_bytes(get.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&downloaded[..], b"body");
}

#[tokio::test]
async fn get_object_returns_no_such_key_for_missing_object() {
    let (state, _temp_dir) = test_state(None).await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/missing.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn get_object_treats_metadata_without_object_file_as_missing() {
    let (state, temp_dir) = test_state(None).await;
    common::write_orphan_metadata(temp_dir.path(), "test-bucket", "orphan-runtime.txt");

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/orphan-runtime.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_has_request_id(&response);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NoSuchKey</Code>"));
    assert!(body.contains("The specified key does not exist."));
}

#[tokio::test]
async fn get_object_rejects_percent_decoded_control_character_in_key() {
    let (state, _temp_dir) = test_state(None).await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket/bad%0Akey.txt")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_has_request_id(&response);
    let body = response_text(response).await;
    assert!(body.contains("<Code>InvalidRequest</Code>"));
    assert!(body.contains("object key contains invalid characters"));
}

#[tokio::test]
async fn get_list_objects_v2_returns_not_implemented() {
    let (state, _temp_dir) = test_state(None).await;

    let response = router(state)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/test-bucket?list-type=2")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = response_text(response).await;
    assert!(body.contains("<Code>NotImplemented</Code>"));
    assert!(body.contains("ListObjectsV2 is not implemented"));
}

#[tokio::test]
async fn get_list_type_other_than_two_returns_invalid_argument() {
    let (state, _temp_dir) = test_state(None).await;
    let app = router(state);

    for query in ["list-type=1", "list-type=%31"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/test-bucket?{query}"))
                    .body(Body::empty())
                    .expect("build get"),
            )
            .await
            .expect("send get");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_text(response).await;
        assert!(body.contains("<Code>InvalidArgument</Code>"));
        assert!(body.contains("list-type must be 2"));
    }
}

#[tokio::test]
async fn get_object_rejects_signed_request_for_disallowed_action() {
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
        method: "GET",
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
                .method("GET")
                .uri("/test-bucket/private.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn get_object_accepts_signed_request_allowed_by_get_object_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::GetObject]),
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
                .uri("/test-bucket/get-policy.txt")
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
        method: "GET",
        path: "/test-bucket/get-policy.txt",
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
                .method("GET")
                .uri("/test-bucket/get-policy.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
}

#[tokio::test]
async fn get_object_accepts_presigned_url_allowed_by_get_object_policy() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            allow_anonymous: true,
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::GetObject]),
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
                .uri("/test-bucket/presigned-get.txt")
                .header(header::CONTENT_LENGTH, "4")
                .body(Body::from("body"))
                .expect("build put"),
        )
        .await
        .expect("send put");
    assert_eq!(put.status(), StatusCode::OK);

    let url = common::presigned_url(common::PresignInput {
        method: "GET",
        path: "/test-bucket/presigned-get.txt",
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
                .method("GET")
                .uri(url)
                .header(header::HOST, "localhost:9000")
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::OK);
    assert_has_request_id(&response);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    assert_eq!(&body[..], b"body");
}

#[tokio::test]
async fn get_object_rejects_signed_request_allowed_only_for_head_object() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let state = AppState::new(Config {
        storage_root: temp_dir.path().to_path_buf(),
        auth: AuthConfig {
            max_skew_seconds: 10 * 365 * 24 * 60 * 60,
            allowed_actions: BTreeSet::from([S3Action::HeadObject]),
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
        method: "GET",
        path: "/test-bucket/head-only.txt",
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
                .method("GET")
                .uri("/test-bucket/head-only.txt")
                .header(header::HOST, "localhost:9000")
                .header("x-amz-date", amz_date)
                .header("x-amz-content-sha256", payload_hash)
                .header(header::AUTHORIZATION, authorization)
                .body(Body::empty())
                .expect("build get"),
        )
        .await
        .expect("send get");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
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

async fn response_text(response: axum::response::Response) -> String {
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body");
    std::str::from_utf8(&body).expect("utf8 body").to_owned()
}
