use axum::{
    body::Body,
    http::{Request, header},
};
use sha2::Digest as Sha2Digest;
use std::future::Future;

use crate::{
    AppState, auth,
    body::upload::validate_fixed_sha256_payload_hash,
    config::S3Action,
    error::S3Error,
    hooks::{AuthenticationRequest, AuthorizationContext, TargetContext},
    s3::{
        target::{resolve_bucket_name, resolve_s3_target},
        types::{BucketName, ObjectKey, S3Target},
    },
};

pub(crate) fn authenticate_request(
    state: &AppState,
    request: &Request<Body>,
) -> impl Future<Output = Result<auth::AuthContext, S3Error>> + Send + 'static {
    let state = state.clone();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    async move {
        if let Some(result) = state
            .authenticate_with_provider(AuthenticationRequest {
                method: method.clone(),
                uri: uri.clone(),
                headers: headers.clone(),
            })
            .await
        {
            let (principal, access_key_id) = result?.into_parts();
            return Ok(auth::AuthContext {
                mode: auth::AuthMode::Custom,
                principal,
                access_key_id,
                streaming_signing: None,
            });
        }

        auth::authenticate(&state.auth, &method, &uri, &headers)
    }
}

pub(crate) fn resolve_request_target(
    state: &AppState,
    request: &Request<Body>,
) -> Result<S3Target, S3Error> {
    let path = request.uri().path().to_owned();
    resolve_s3_target(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path))
}

pub(crate) fn resolve_request_bucket(
    state: &AppState,
    request: &Request<Body>,
) -> Result<BucketName, S3Error> {
    let path = request.uri().path().to_owned();
    resolve_bucket_name(
        &path,
        request
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok()),
        state.config.virtual_host_base_domain.as_deref(),
    )
    .map_err(|err| S3Error::invalid_request(err.to_string()).with_resource(path))
}

pub(crate) fn authorize_request(
    state: &AppState,
    auth_context: &auth::AuthContext,
    bucket: &BucketName,
    key: Option<&ObjectKey>,
    action: S3Action,
) -> Result<(), S3Error> {
    state.allow_target(TargetContext {
        bucket: bucket.clone(),
        key: key.cloned(),
        action,
    })?;
    auth::authorize(&state.auth, auth_context, bucket, action)?;
    state.authorize_with_policy(AuthorizationContext {
        principal: auth_context.principal.clone(),
        bucket: bucket.clone(),
        key: key.cloned(),
        action,
    })
}

pub(crate) fn authenticate_and_authorize_target(
    state: &AppState,
    request: &Request<Body>,
    action: S3Action,
) -> impl Future<Output = Result<(auth::AuthContext, S3Target), S3Error>> + Send + 'static {
    let auth = authenticate_request(state, request);
    let target = resolve_request_target(state, request);
    let state = state.clone();
    async move {
        let auth_context = auth.await?;
        let target = target?;
        authorize_request(
            &state,
            &auth_context,
            &target.bucket,
            Some(&target.key),
            action,
        )?;
        Ok((auth_context, target))
    }
}

pub(crate) fn validate_empty_payload_hash(request: &Request<Body>) -> Result<(), S3Error> {
    let empty_payload_digest = sha2::Sha256::digest([]);
    validate_fixed_sha256_payload_hash(request.headers(), empty_payload_digest.as_ref())
}
