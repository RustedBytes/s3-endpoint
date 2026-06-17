#![forbid(unsafe_code)]

use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

use clap::Parser;
use s3_endpoint::{
    AppState,
    config::{AccessKeyConfig, Config, S3Action, UploadLimits},
    router,
};
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "s3-endpoint")]
struct Cli {
    #[arg(long, env = "S3_ENDPOINT_ADDR", default_value = "127.0.0.1:9000")]
    addr: SocketAddr,

    #[arg(long, env = "S3_ENDPOINT_STORAGE_ROOT", default_value = "./data")]
    storage_root: std::path::PathBuf,

    #[arg(long, env = "S3_ENDPOINT_ALLOW_ANONYMOUS", default_value_t = false)]
    allow_anonymous: bool,

    #[arg(long, env = "S3_ENDPOINT_ACCESS_KEY_ID", default_value = "test")]
    access_key_id: String,

    #[arg(long, env = "S3_ENDPOINT_SECRET_KEY", default_value = "testsecret")]
    secret_key: String,

    #[arg(long, env = "S3_ENDPOINT_SESSION_TOKEN")]
    session_token: Option<String>,

    #[arg(
        long,
        env = "S3_ENDPOINT_CREDENTIALS_FILE",
        help = "JSON file containing additional credential entries"
    )]
    credentials_file: Option<PathBuf>,

    #[arg(long, env = "S3_ENDPOINT_REGION", default_value = "us-east-1")]
    region: String,

    #[arg(long, env = "S3_ENDPOINT_MAX_SKEW_SECONDS", default_value_t = 900)]
    max_skew_seconds: i64,

    #[arg(
        long,
        env = "S3_ENDPOINT_ALLOWED_BUCKETS",
        value_delimiter = ',',
        help = "Comma-separated bucket allow-list for authenticated requests; empty permits all buckets"
    )]
    allowed_buckets: Vec<String>,

    #[arg(
        long,
        env = "S3_ENDPOINT_ALLOWED_ACTIONS",
        value_delimiter = ',',
        value_parser = parse_s3_action,
        help = "Comma-separated action allow-list such as s3:PutObject,upload-part; empty permits all actions"
    )]
    allowed_actions: Vec<S3Action>,

    #[arg(long, env = "S3_ENDPOINT_VIRTUAL_HOST_BASE_DOMAIN")]
    virtual_host_base_domain: Option<String>,

    #[arg(long, env = "S3_ENDPOINT_MAX_OBJECT_SIZE")]
    max_object_size: Option<u64>,

    #[arg(long, env = "S3_ENDPOINT_MAX_PART_SIZE")]
    max_part_size: Option<u64>,

    #[arg(long, env = "S3_ENDPOINT_MIN_NON_FINAL_PART_SIZE")]
    min_non_final_part_size: Option<u64>,

    #[arg(long, env = "S3_ENDPOINT_MAX_CONCURRENT_S3_REQUESTS")]
    max_concurrent_s3_requests: Option<usize>,

    #[arg(long, env = "S3_ENDPOINT_MAX_ACTIVE_OBJECT_WRITERS")]
    max_active_object_writers: Option<usize>,

    #[arg(long, env = "S3_ENDPOINT_MAX_ACTIVE_MULTIPART_PART_WRITERS")]
    max_active_multipart_part_writers: Option<usize>,

    #[arg(long, env = "S3_ENDPOINT_MAX_ACTIVE_AWS_CHUNKED_DECODERS")]
    max_active_aws_chunked_decoders: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();
    let default_limits = UploadLimits::default();
    let credentials = load_credentials_file(cli.credentials_file.as_deref()).await?;
    let storage_root = cli.storage_root.clone();
    let region = cli.region.clone();
    let upload_limits = UploadLimits {
        max_object_size: cli
            .max_object_size
            .unwrap_or(default_limits.max_object_size),
        max_part_size: cli.max_part_size.unwrap_or(default_limits.max_part_size),
        min_non_final_part_size: cli
            .min_non_final_part_size
            .unwrap_or(default_limits.min_non_final_part_size),
        max_concurrent_s3_requests: cli
            .max_concurrent_s3_requests
            .unwrap_or(default_limits.max_concurrent_s3_requests),
        max_active_object_writers: cli
            .max_active_object_writers
            .unwrap_or(default_limits.max_active_object_writers),
        max_active_multipart_part_writers: cli
            .max_active_multipart_part_writers
            .unwrap_or(default_limits.max_active_multipart_part_writers),
        max_active_aws_chunked_decoders: cli
            .max_active_aws_chunked_decoders
            .unwrap_or(default_limits.max_active_aws_chunked_decoders),
    };
    log::info!(
        "starting s3-endpoint addr={} storage_root={} allow_anonymous={} region={} max_object_size={} max_part_size={} min_non_final_part_size={} max_concurrent_s3_requests={} max_active_object_writers={} max_active_multipart_part_writers={} max_active_aws_chunked_decoders={} extra_credentials={}",
        cli.addr,
        storage_root.display(),
        cli.allow_anonymous,
        region,
        upload_limits.max_object_size,
        upload_limits.max_part_size,
        upload_limits.min_non_final_part_size,
        upload_limits.max_concurrent_s3_requests,
        upload_limits.max_active_object_writers,
        upload_limits.max_active_multipart_part_writers,
        upload_limits.max_active_aws_chunked_decoders,
        credentials.len()
    );
    let state = AppState::new(Config {
        storage_root: cli.storage_root,
        auth: s3_endpoint::config::AuthConfig {
            allow_anonymous: cli.allow_anonymous,
            access_key_id: cli.access_key_id,
            secret_key: cli.secret_key,
            session_token: cli.session_token,
            region: cli.region,
            max_skew_seconds: cli.max_skew_seconds,
            allowed_buckets: cli.allowed_buckets.into_iter().collect(),
            allowed_actions: cli.allowed_actions.into_iter().collect(),
            credentials,
        },
        virtual_host_base_domain: cli.virtual_host_base_domain,
        upload_limits,
    })
    .await?;

    let listener = TcpListener::bind(cli.addr).await?;
    log::info!("s3-endpoint listening addr={}", cli.addr);
    tracing::info!(addr = %cli.addr, "listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn parse_s3_action(value: &str) -> Result<S3Action, String> {
    value.parse().map_err(|err| format!("{err}"))
}

async fn load_credentials_file(
    path: Option<&std::path::Path>,
) -> Result<Vec<AccessKeyConfig>, Box<dyn std::error::Error>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };

    log::info!("loading additional credentials path={}", path.display());
    let json = match tokio::fs::read_to_string(path).await {
        Ok(json) => json,
        Err(error) => {
            log::warn!(
                "failed to read additional credentials path={} error={}",
                path.display(),
                error
            );
            return Err(error.into());
        }
    };
    let credentials = match parse_credentials_json(&json) {
        Ok(credentials) => credentials,
        Err(error) => {
            log::warn!(
                "failed to parse additional credentials path={} error={}",
                path.display(),
                error
            );
            return Err(error.into());
        }
    };
    log::info!(
        "loaded additional credentials path={} count={}",
        path.display(),
        credentials.len()
    );
    Ok(credentials)
}

fn parse_credentials_json(json: &str) -> Result<Vec<AccessKeyConfig>, String> {
    let entries = serde_json::from_str::<Vec<CredentialFileEntry>>(json)
        .map_err(|err| format!("failed to parse credentials file: {err}"))?;

    entries
        .into_iter()
        .map(CredentialFileEntry::try_into_config)
        .collect()
}

#[derive(Debug, Deserialize)]
struct CredentialFileEntry {
    access_key_id: String,
    secret_key: String,
    #[serde(default)]
    session_token: Option<String>,
    #[serde(default = "default_active")]
    active: bool,
    #[serde(default)]
    allowed_buckets: Vec<String>,
    #[serde(default)]
    allowed_actions: Vec<String>,
}

impl CredentialFileEntry {
    fn try_into_config(self) -> Result<AccessKeyConfig, String> {
        Ok(AccessKeyConfig {
            access_key_id: self.access_key_id,
            secret_key: self.secret_key,
            session_token: self.session_token,
            active: self.active,
            allowed_buckets: self.allowed_buckets.into_iter().collect(),
            allowed_actions: self
                .allowed_actions
                .into_iter()
                .map(|action| action.parse::<S3Action>().map_err(|err| format!("{err}")))
                .collect::<Result<BTreeSet<_>, _>>()?,
        })
    }
}

fn default_active() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_json_parses_additional_credentials() {
        let credentials = parse_credentials_json(
            r#"[
              {
                "access_key_id": "client-a",
                "secret_key": "client-secret",
                "session_token": "client-session",
                "allowed_buckets": ["bucket-a", "bucket-b"],
                "allowed_actions": ["s3:PutObject", "upload-part"]
              }
            ]"#,
        )
        .expect("parse credentials");

        assert_eq!(credentials.len(), 1);
        let credential = &credentials[0];
        assert_eq!(credential.access_key_id, "client-a");
        assert_eq!(credential.secret_key, "client-secret");
        assert_eq!(credential.session_token.as_deref(), Some("client-session"));
        assert!(credential.active);
        assert!(credential.allowed_buckets.contains("bucket-a"));
        assert!(credential.allowed_buckets.contains("bucket-b"));
        assert!(credential.allowed_actions.contains(&S3Action::PutObject));
        assert!(credential.allowed_actions.contains(&S3Action::UploadPart));
    }

    #[test]
    fn credentials_json_allows_inactive_credentials() {
        let credentials = parse_credentials_json(
            r#"[
              {
                "access_key_id": "inactive-client",
                "secret_key": "inactive-secret",
                "active": false
              }
            ]"#,
        )
        .expect("parse credentials");

        assert_eq!(credentials.len(), 1);
        assert!(!credentials[0].active);
        assert!(credentials[0].allowed_buckets.is_empty());
        assert!(credentials[0].allowed_actions.is_empty());
    }

    #[test]
    fn credentials_json_rejects_unsupported_actions() {
        let error = parse_credentials_json(
            r#"[
              {
                "access_key_id": "bad-client",
                "secret_key": "bad-secret",
                "allowed_actions": ["s3:ListBucket"]
              }
            ]"#,
        )
        .expect_err("invalid action should fail");

        assert!(error.contains("allowed_actions must contain supported S3 action names"));
    }
}
