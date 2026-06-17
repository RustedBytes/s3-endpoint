use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::s3::types::BucketName;

/// Runtime configuration for the S3 endpoint.
#[derive(Clone, Debug)]
pub struct Config {
    /// Root directory used for object data, metadata, multipart sessions, and temp files.
    pub storage_root: PathBuf,
    /// Authentication and authorization configuration.
    pub auth: AuthConfig,
    /// Optional base domain for virtual-hosted-style bucket addressing.
    pub virtual_host_base_domain: Option<String>,
    /// Upload size and concurrency limits.
    pub upload_limits: UploadLimits,
}

impl Config {
    /// Creates a configuration with default auth and upload limits for a storage root.
    pub fn new(storage_root: PathBuf) -> Self {
        Self {
            storage_root,
            auth: AuthConfig::default(),
            virtual_host_base_domain: None,
            upload_limits: UploadLimits::default(),
        }
    }

    /// Validates auth and upload-limit settings.
    ///
    /// Returns an error when any limit is zero, multipart minimum part size is
    /// larger than the maximum part size, auth fields are malformed, or
    /// configured bucket/action allow-lists contain unsupported values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.upload_limits.validate()?;
        self.auth.validate()
    }

    /// Creates a fluent configuration builder for a storage root.
    pub fn builder(storage_root: impl Into<PathBuf>) -> ConfigBuilder {
        ConfigBuilder {
            config: Self::new(storage_root.into()),
        }
    }
}

/// Fluent builder for [`Config`].
#[derive(Clone, Debug)]
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Replaces the authentication configuration.
    pub fn auth(mut self, auth: AuthConfig) -> Self {
        self.config.auth = auth;
        self
    }

    /// Sets whether unsigned anonymous requests are accepted.
    pub fn allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.config.auth.allow_anonymous = allow_anonymous;
        self
    }

    /// Sets the SigV4 signing region.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.config.auth.region = region.into();
        self
    }

    /// Sets the optional virtual-hosted-style base domain.
    pub fn virtual_host_base_domain(mut self, domain: impl Into<String>) -> Self {
        self.config.virtual_host_base_domain = Some(domain.into());
        self
    }

    /// Clears virtual-hosted-style addressing support.
    pub fn without_virtual_host_base_domain(mut self) -> Self {
        self.config.virtual_host_base_domain = None;
        self
    }

    /// Replaces upload size and concurrency limits.
    pub fn upload_limits(mut self, upload_limits: UploadLimits) -> Self {
        self.config.upload_limits = upload_limits;
        self
    }

    /// Returns the constructed configuration.
    pub fn build(self) -> Config {
        self.config
    }
}

/// Upload size and concurrency limits.
#[derive(Clone, Debug)]
pub struct UploadLimits {
    /// Maximum decoded object size in bytes.
    pub max_object_size: u64,
    /// Maximum decoded multipart part size in bytes.
    pub max_part_size: u64,
    /// Minimum size for each non-final multipart part in bytes.
    pub min_non_final_part_size: u64,
    /// Maximum number of concurrent S3 requests admitted by the router.
    pub max_concurrent_s3_requests: usize,
    /// Maximum number of concurrent `PutObject` writers.
    pub max_active_object_writers: usize,
    /// Maximum number of concurrent multipart `UploadPart` writers.
    pub max_active_multipart_part_writers: usize,
    /// Maximum number of concurrent aws-chunked decoders.
    pub max_active_aws_chunked_decoders: usize,
}

impl Default for UploadLimits {
    fn default() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        const MIB: u64 = 1024 * 1024;
        Self {
            max_object_size: 10_000 * 5 * GIB,
            max_part_size: 5 * GIB,
            min_non_final_part_size: 5 * MIB,
            max_concurrent_s3_requests: 256,
            max_active_object_writers: 64,
            max_active_multipart_part_writers: 128,
            max_active_aws_chunked_decoders: 64,
        }
    }
}

impl UploadLimits {
    /// Creates a fluent upload-limit builder using production-oriented defaults.
    pub fn builder() -> UploadLimitsBuilder {
        UploadLimitsBuilder {
            limits: Self::default_s3_compatible(),
        }
    }

    /// Returns the default S3-compatible upload limits.
    pub fn default_s3_compatible() -> Self {
        Self::default()
    }

    /// Returns smaller limits intended for local development and tests.
    pub fn local_development() -> Self {
        const MIB: u64 = 1024 * 1024;
        Self {
            max_object_size: 1024 * MIB,
            max_part_size: 512 * MIB,
            min_non_final_part_size: 5 * MIB,
            max_concurrent_s3_requests: 64,
            max_active_object_writers: 16,
            max_active_multipart_part_writers: 32,
            max_active_aws_chunked_decoders: 16,
        }
    }

    /// Validates all upload limits.
    ///
    /// Returns an error when a limit is zero or when
    /// `min_non_final_part_size > max_part_size`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let limits = self.validated()?;
        if limits.min_non_final_part_size > limits.max_part_size {
            return Err(ConfigError::InvalidUploadLimit(
                "min_non_final_part_size must be less than or equal to max_part_size",
            ));
        }
        Ok(())
    }

    /// Converts raw numeric limits into non-zero validated limits.
    ///
    /// Returns an error when any configured limit is zero.
    pub fn validated(&self) -> Result<ValidatedUploadLimits, ConfigError> {
        Ok(ValidatedUploadLimits {
            max_object_size: PositiveUploadLimit::new(
                self.max_object_size,
                "max_object_size must be greater than 0",
            )?,
            max_part_size: PositiveUploadLimit::new(
                self.max_part_size,
                "max_part_size must be greater than 0",
            )?,
            min_non_final_part_size: PositiveUploadLimit::new(
                self.min_non_final_part_size,
                "min_non_final_part_size must be greater than 0",
            )?,
            max_concurrent_s3_requests: PositiveAdmissionLimit::new(
                self.max_concurrent_s3_requests,
                "max_concurrent_s3_requests must be greater than 0",
            )?,
            max_active_object_writers: PositiveAdmissionLimit::new(
                self.max_active_object_writers,
                "max_active_object_writers must be greater than 0",
            )?,
            max_active_multipart_part_writers: PositiveAdmissionLimit::new(
                self.max_active_multipart_part_writers,
                "max_active_multipart_part_writers must be greater than 0",
            )?,
            max_active_aws_chunked_decoders: PositiveAdmissionLimit::new(
                self.max_active_aws_chunked_decoders,
                "max_active_aws_chunked_decoders must be greater than 0",
            )?,
        })
    }
}

/// Fluent builder for [`UploadLimits`].
#[derive(Clone, Debug)]
pub struct UploadLimitsBuilder {
    limits: UploadLimits,
}

impl UploadLimitsBuilder {
    /// Sets the maximum decoded object size in bytes.
    pub fn max_object_size(mut self, value: u64) -> Self {
        self.limits.max_object_size = value;
        self
    }

    /// Sets the maximum decoded multipart part size in bytes.
    pub fn max_part_size(mut self, value: u64) -> Self {
        self.limits.max_part_size = value;
        self
    }

    /// Sets the minimum size for each non-final multipart part in bytes.
    pub fn min_non_final_part_size(mut self, value: u64) -> Self {
        self.limits.min_non_final_part_size = value;
        self
    }

    /// Sets the maximum number of concurrently admitted S3 requests.
    pub fn max_concurrent_s3_requests(mut self, value: usize) -> Self {
        self.limits.max_concurrent_s3_requests = value;
        self
    }

    /// Sets the maximum number of active `PutObject` writers.
    pub fn max_active_object_writers(mut self, value: usize) -> Self {
        self.limits.max_active_object_writers = value;
        self
    }

    /// Sets the maximum number of active multipart part writers.
    pub fn max_active_multipart_part_writers(mut self, value: usize) -> Self {
        self.limits.max_active_multipart_part_writers = value;
        self
    }

    /// Sets the maximum number of active aws-chunked decoders.
    pub fn max_active_aws_chunked_decoders(mut self, value: usize) -> Self {
        self.limits.max_active_aws_chunked_decoders = value;
        self
    }

    /// Returns the constructed upload limits.
    pub fn build(self) -> UploadLimits {
        self.limits
    }
}

/// Non-zero byte limit for upload sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PositiveUploadLimit(NonZeroU64);

impl PositiveUploadLimit {
    fn new(value: u64, error: &'static str) -> Result<Self, ConfigError> {
        NonZeroU64::new(value)
            .map(Self)
            .ok_or(ConfigError::InvalidUploadLimit(error))
    }

    /// Returns the configured byte limit.
    pub fn get(self) -> u64 {
        self.0.get()
    }
}

/// Non-zero limit for request or worker admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PositiveAdmissionLimit(NonZeroUsize);

impl PositiveAdmissionLimit {
    fn new(value: usize, error: &'static str) -> Result<Self, ConfigError> {
        NonZeroUsize::new(value)
            .map(Self)
            .ok_or(ConfigError::InvalidUploadLimit(error))
    }

    /// Returns the configured admission limit.
    pub fn get(self) -> usize {
        self.0.get()
    }
}

/// Upload limits after zero-value validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedUploadLimits {
    /// Maximum decoded object size in bytes.
    pub max_object_size: PositiveUploadLimit,
    /// Maximum decoded multipart part size in bytes.
    pub max_part_size: PositiveUploadLimit,
    /// Minimum size for each non-final multipart part in bytes.
    pub min_non_final_part_size: PositiveUploadLimit,
    /// Maximum number of concurrent S3 requests.
    pub max_concurrent_s3_requests: PositiveAdmissionLimit,
    /// Maximum number of concurrent `PutObject` writers.
    pub max_active_object_writers: PositiveAdmissionLimit,
    /// Maximum number of concurrent multipart `UploadPart` writers.
    pub max_active_multipart_part_writers: PositiveAdmissionLimit,
    /// Maximum number of concurrent aws-chunked decoders.
    pub max_active_aws_chunked_decoders: PositiveAdmissionLimit,
}

/// Configuration validation error.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    /// Upload limit validation failed.
    #[error("invalid upload limit: {0}")]
    InvalidUploadLimit(&'static str),

    /// Auth configuration validation failed.
    #[error("invalid auth configuration: {0}")]
    InvalidAuthConfig(&'static str),
}

/// Validated access key identifier.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct AccessKeyId(String);

impl AccessKeyId {
    /// Parses an access key ID.
    ///
    /// Returns an error when the value is empty or contains whitespace or
    /// control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        validate_access_key_id(&value)?;
        Ok(Self(value))
    }

    /// Returns the access key ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AccessKeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Secret key value with a redacted `Debug` implementation.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretKey(String);

impl SecretKey {
    /// Parses a secret key.
    ///
    /// Returns an error when the value is empty or contains control characters.
    pub fn parse(value: impl Into<String>) -> Result<Self, ConfigError> {
        let value = value.into();
        validate_secret_key(&value)?;
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Authentication, credential, and allow-list configuration.
#[derive(Clone)]
pub struct AuthConfig {
    /// Whether unsigned anonymous requests are allowed.
    pub allow_anonymous: bool,
    /// Primary access key ID.
    pub access_key_id: String,
    /// Primary secret key. This value is redacted from `Debug` output.
    pub secret_key: String,
    /// Optional primary session token. This value is redacted from `Debug` output.
    pub session_token: Option<String>,
    /// SigV4 signing region.
    pub region: String,
    /// Maximum accepted SigV4 timestamp skew in seconds.
    pub max_skew_seconds: i64,
    /// Optional bucket allow-list. Empty means all buckets are allowed.
    pub allowed_buckets: BTreeSet<String>,
    /// Optional action allow-list. Empty means all implemented actions are allowed.
    pub allowed_actions: BTreeSet<S3Action>,
    /// Additional access keys.
    pub credentials: Vec<AccessKeyConfig>,
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfig")
            .field("allow_anonymous", &self.allow_anonymous)
            .field("access_key_id", &self.access_key_id)
            .field("secret_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("region", &self.region)
            .field("max_skew_seconds", &self.max_skew_seconds)
            .field("allowed_buckets", &self.allowed_buckets)
            .field("allowed_actions", &self.allowed_actions)
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            allow_anonymous: false,
            access_key_id: "test".to_owned(),
            secret_key: "testsecret".to_owned(),
            session_token: None,
            region: "us-east-1".to_owned(),
            max_skew_seconds: 900,
            allowed_buckets: BTreeSet::new(),
            allowed_actions: BTreeSet::new(),
            credentials: Vec::new(),
        }
    }
}

impl AuthConfig {
    /// Creates a fluent authentication configuration builder.
    pub fn builder() -> AuthConfigBuilder {
        AuthConfigBuilder {
            config: Self::default(),
        }
    }

    /// Validates primary and additional credential configuration.
    ///
    /// Returns an error when credential strings are malformed, the region is
    /// invalid, skew is negative, allow-list buckets are invalid, or access key
    /// IDs are duplicated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_access_key_id(&self.access_key_id)?;
        validate_secret_key(&self.secret_key)?;
        validate_session_token(self.session_token.as_deref())?;
        if !is_valid_region(&self.region) {
            return Err(ConfigError::InvalidAuthConfig(
                "region must be a non-empty lowercase AWS region identifier",
            ));
        }
        if self.max_skew_seconds < 0 {
            return Err(ConfigError::InvalidAuthConfig(
                "max_skew_seconds must be greater than or equal to 0",
            ));
        }
        for bucket in &self.allowed_buckets {
            BucketName::parse(bucket.clone()).map_err(|_| {
                ConfigError::InvalidAuthConfig("allowed_buckets must contain valid bucket names")
            })?;
        }
        let mut access_key_ids = BTreeSet::from([self.access_key_id.as_str()]);
        for credential in &self.credentials {
            credential.validate()?;
            if !access_key_ids.insert(credential.access_key_id.as_str()) {
                return Err(ConfigError::InvalidAuthConfig(
                    "credential access_key_id values must be unique",
                ));
            }
        }
        Ok(())
    }

    /// Returns whether the anonymous/global allow-lists permit an action on a bucket.
    pub fn permits(&self, bucket: &BucketName, action: S3Action) -> bool {
        (self.allowed_buckets.is_empty() || self.allowed_buckets.contains(bucket.as_str()))
            && (self.allowed_actions.is_empty() || self.allowed_actions.contains(&action))
    }
}

/// Fluent builder for [`AuthConfig`].
#[derive(Clone)]
pub struct AuthConfigBuilder {
    config: AuthConfig,
}

impl fmt::Debug for AuthConfigBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthConfigBuilder")
            .field("config", &self.config)
            .finish()
    }
}

impl AuthConfigBuilder {
    /// Sets whether unsigned anonymous requests are accepted.
    pub fn allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.config.allow_anonymous = allow_anonymous;
        self
    }

    /// Sets the primary access key ID.
    pub fn access_key_id(mut self, access_key_id: impl Into<String>) -> Self {
        self.config.access_key_id = access_key_id.into();
        self
    }

    /// Sets the primary secret key.
    pub fn secret_key(mut self, secret_key: impl Into<String>) -> Self {
        self.config.secret_key = secret_key.into();
        self
    }

    /// Sets both primary credential fields.
    pub fn primary_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> Self {
        self.config.access_key_id = access_key_id.into();
        self.config.secret_key = secret_key.into();
        self
    }

    /// Sets the optional primary session token.
    pub fn session_token(mut self, session_token: impl Into<String>) -> Self {
        self.config.session_token = Some(session_token.into());
        self
    }

    /// Clears the primary session token.
    pub fn without_session_token(mut self) -> Self {
        self.config.session_token = None;
        self
    }

    /// Sets the SigV4 signing region.
    pub fn region(mut self, region: impl Into<String>) -> Self {
        self.config.region = region.into();
        self
    }

    /// Sets the maximum accepted SigV4 timestamp skew in seconds.
    pub fn max_skew_seconds(mut self, seconds: i64) -> Self {
        self.config.max_skew_seconds = seconds;
        self
    }

    /// Replaces the global bucket allow-list.
    pub fn allowed_buckets<I, S>(mut self, buckets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.allowed_buckets = buckets.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one bucket to the global allow-list.
    pub fn allow_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.config.allowed_buckets.insert(bucket.into());
        self
    }

    /// Replaces the global action allow-list.
    pub fn allowed_actions<I>(mut self, actions: I) -> Self
    where
        I: IntoIterator<Item = S3Action>,
    {
        self.config.allowed_actions = actions.into_iter().collect();
        self
    }

    /// Adds one action to the global allow-list.
    pub fn allow_action(mut self, action: S3Action) -> Self {
        self.config.allowed_actions.insert(action);
        self
    }

    /// Replaces the additional credential entries.
    pub fn credentials<I>(mut self, credentials: I) -> Self
    where
        I: IntoIterator<Item = AccessKeyConfig>,
    {
        self.config.credentials = credentials.into_iter().collect();
        self
    }

    /// Adds one additional credential entry.
    pub fn credential(mut self, credential: AccessKeyConfig) -> Self {
        self.config.credentials.push(credential);
        self
    }

    /// Returns the constructed authentication configuration.
    pub fn build(self) -> AuthConfig {
        self.config
    }
}

/// Validated authentication state indexed for request-time lookup.
#[derive(Clone)]
pub struct AuthState {
    allow_anonymous: bool,
    region: String,
    max_skew_seconds: i64,
    anonymous_allowed_buckets: BTreeSet<String>,
    credentials: HashMap<String, StoredAccessKey>,
}

impl fmt::Debug for AuthState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthState")
            .field("allow_anonymous", &self.allow_anonymous)
            .field("region", &self.region)
            .field("max_skew_seconds", &self.max_skew_seconds)
            .field("anonymous_allowed_buckets", &self.anonymous_allowed_buckets)
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl AuthState {
    /// Builds request-time auth state from configuration.
    ///
    /// Returns an error when `config` fails validation.
    pub fn new(config: &AuthConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let mut credentials = HashMap::with_capacity(config.credentials.len() + 1);
        let primary = StoredAccessKey {
            access_key_id: AccessKeyId::parse(config.access_key_id.clone())?,
            secret_key: SecretKey::parse(config.secret_key.clone())?,
            session_token: config.session_token.clone(),
            active: true,
            allowed_buckets: config.allowed_buckets.clone(),
            allowed_actions: config.allowed_actions.clone(),
        };
        credentials.insert(primary.access_key_id.as_str().to_owned(), primary);
        for credential in &config.credentials {
            let credential = StoredAccessKey {
                access_key_id: AccessKeyId::parse(credential.access_key_id.clone())?,
                secret_key: SecretKey::parse(credential.secret_key.clone())?,
                session_token: credential.session_token.clone(),
                active: credential.active,
                allowed_buckets: credential.allowed_buckets.clone(),
                allowed_actions: credential.allowed_actions.clone(),
            };
            credentials.insert(credential.access_key_id.as_str().to_owned(), credential);
        }

        Ok(Self {
            allow_anonymous: config.allow_anonymous,
            region: config.region.clone(),
            max_skew_seconds: config.max_skew_seconds,
            anonymous_allowed_buckets: config.allowed_buckets.clone(),
            credentials,
        })
    }

    pub(crate) fn allow_anonymous(&self) -> bool {
        self.allow_anonymous
    }

    pub(crate) fn region(&self) -> &str {
        &self.region
    }

    pub(crate) fn max_skew_seconds(&self) -> i64 {
        self.max_skew_seconds
    }

    pub(crate) fn permits_anonymous_bucket(&self, bucket: &BucketName) -> bool {
        self.anonymous_allowed_buckets.is_empty()
            || self.anonymous_allowed_buckets.contains(bucket.as_str())
    }

    pub(crate) fn credential(&self, access_key_id: &str) -> Option<ConfiguredAccessKey<'_>> {
        self.credentials
            .get(access_key_id)
            .map(StoredAccessKey::as_configured)
    }

    pub(crate) fn permits_credential(
        &self,
        access_key_id: &str,
        bucket: &BucketName,
        action: S3Action,
    ) -> bool {
        let Some(credential) = self.credential(access_key_id) else {
            return false;
        };
        (credential.allowed_buckets.is_empty()
            || credential.allowed_buckets.contains(bucket.as_str()))
            && (credential.allowed_actions.is_empty()
                || credential.allowed_actions.contains(&action))
    }
}

#[derive(Clone)]
struct StoredAccessKey {
    access_key_id: AccessKeyId,
    secret_key: SecretKey,
    session_token: Option<String>,
    active: bool,
    allowed_buckets: BTreeSet<String>,
    allowed_actions: BTreeSet<S3Action>,
}

impl StoredAccessKey {
    fn as_configured(&self) -> ConfiguredAccessKey<'_> {
        ConfiguredAccessKey {
            access_key_id: self.access_key_id.clone(),
            secret_key: self.secret_key.clone(),
            session_token: self.session_token.as_deref(),
            active: self.active,
            allowed_buckets: &self.allowed_buckets,
            allowed_actions: &self.allowed_actions,
        }
    }
}

/// Additional access key entry.
#[derive(Clone)]
pub struct AccessKeyConfig {
    /// Access key ID.
    pub access_key_id: String,
    /// Secret key. This value is redacted from `Debug` output.
    pub secret_key: String,
    /// Optional session token. This value is redacted from `Debug` output.
    pub session_token: Option<String>,
    /// Whether this credential can authenticate requests.
    pub active: bool,
    /// Optional bucket allow-list. Empty inherits no restriction beyond global auth config.
    pub allowed_buckets: BTreeSet<String>,
    /// Optional action allow-list. Empty permits all implemented actions for this credential.
    pub allowed_actions: BTreeSet<S3Action>,
}

impl fmt::Debug for AccessKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessKeyConfig")
            .field("access_key_id", &self.access_key_id)
            .field("secret_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .field("active", &self.active)
            .field("allowed_buckets", &self.allowed_buckets)
            .field("allowed_actions", &self.allowed_actions)
            .finish()
    }
}

impl AccessKeyConfig {
    /// Creates a fluent additional access-key builder.
    pub fn builder(
        access_key_id: impl Into<String>,
        secret_key: impl Into<String>,
    ) -> AccessKeyConfigBuilder {
        AccessKeyConfigBuilder {
            config: Self {
                access_key_id: access_key_id.into(),
                secret_key: secret_key.into(),
                session_token: None,
                active: true,
                allowed_buckets: BTreeSet::new(),
                allowed_actions: BTreeSet::new(),
            },
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_access_key_id(&self.access_key_id)?;
        validate_secret_key(&self.secret_key)?;
        validate_session_token(self.session_token.as_deref())?;
        for bucket in &self.allowed_buckets {
            BucketName::parse(bucket.clone()).map_err(|_| {
                ConfigError::InvalidAuthConfig("allowed_buckets must contain valid bucket names")
            })?;
        }
        Ok(())
    }
}

/// Fluent builder for [`AccessKeyConfig`].
#[derive(Clone)]
pub struct AccessKeyConfigBuilder {
    config: AccessKeyConfig,
}

impl fmt::Debug for AccessKeyConfigBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessKeyConfigBuilder")
            .field("config", &self.config)
            .finish()
    }
}

impl AccessKeyConfigBuilder {
    /// Sets the optional session token.
    pub fn session_token(mut self, session_token: impl Into<String>) -> Self {
        self.config.session_token = Some(session_token.into());
        self
    }

    /// Clears the optional session token.
    pub fn without_session_token(mut self) -> Self {
        self.config.session_token = None;
        self
    }

    /// Sets whether this credential can authenticate requests.
    pub fn active(mut self, active: bool) -> Self {
        self.config.active = active;
        self
    }

    /// Replaces the bucket allow-list.
    pub fn allowed_buckets<I, S>(mut self, buckets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config.allowed_buckets = buckets.into_iter().map(Into::into).collect();
        self
    }

    /// Adds one bucket to the allow-list.
    pub fn allow_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.config.allowed_buckets.insert(bucket.into());
        self
    }

    /// Replaces the action allow-list.
    pub fn allowed_actions<I>(mut self, actions: I) -> Self
    where
        I: IntoIterator<Item = S3Action>,
    {
        self.config.allowed_actions = actions.into_iter().collect();
        self
    }

    /// Adds one action to the allow-list.
    pub fn allow_action(mut self, action: S3Action) -> Self {
        self.config.allowed_actions.insert(action);
        self
    }

    /// Returns the constructed access-key configuration.
    pub fn build(self) -> AccessKeyConfig {
        self.config
    }
}

pub(crate) struct ConfiguredAccessKey<'a> {
    pub(crate) access_key_id: AccessKeyId,
    pub(crate) secret_key: SecretKey,
    pub(crate) session_token: Option<&'a str>,
    pub(crate) active: bool,
    pub(crate) allowed_buckets: &'a BTreeSet<String>,
    pub(crate) allowed_actions: &'a BTreeSet<S3Action>,
}

/// Implemented S3 IAM-style actions used by the simple allow-list authorizer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum S3Action {
    /// `s3:PutObject`.
    PutObject,
    /// `s3:GetObject`.
    GetObject,
    /// `s3:HeadObject`.
    HeadObject,
    /// `s3:DeleteObject`.
    DeleteObject,
    /// `s3:CreateMultipartUpload`.
    CreateMultipartUpload,
    /// `s3:UploadPart`.
    UploadPart,
    /// `s3:CompleteMultipartUpload`.
    CompleteMultipartUpload,
    /// `s3:AbortMultipartUpload`.
    AbortMultipartUpload,
    /// `s3:ListMultipartUploadParts`.
    ListMultipartUploadParts,
    /// `s3:HeadBucket`.
    HeadBucket,
}

impl S3Action {
    /// Returns the canonical IAM-style action string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PutObject => "s3:PutObject",
            Self::GetObject => "s3:GetObject",
            Self::HeadObject => "s3:HeadObject",
            Self::DeleteObject => "s3:DeleteObject",
            Self::CreateMultipartUpload => "s3:CreateMultipartUpload",
            Self::UploadPart => "s3:UploadPart",
            Self::CompleteMultipartUpload => "s3:CompleteMultipartUpload",
            Self::AbortMultipartUpload => "s3:AbortMultipartUpload",
            Self::ListMultipartUploadParts => "s3:ListMultipartUploadParts",
            Self::HeadBucket => "s3:HeadBucket",
        }
    }
}

impl FromStr for S3Action {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "s3:PutObject" | "PutObject" | "put-object" => Ok(Self::PutObject),
            "s3:GetObject" | "GetObject" | "get-object" => Ok(Self::GetObject),
            "s3:HeadObject" | "HeadObject" | "head-object" => Ok(Self::HeadObject),
            "s3:DeleteObject" | "DeleteObject" | "delete-object" => Ok(Self::DeleteObject),
            "s3:CreateMultipartUpload" | "CreateMultipartUpload" | "create-multipart-upload" => {
                Ok(Self::CreateMultipartUpload)
            }
            "s3:UploadPart" | "UploadPart" | "upload-part" => Ok(Self::UploadPart),
            "s3:CompleteMultipartUpload"
            | "CompleteMultipartUpload"
            | "complete-multipart-upload" => Ok(Self::CompleteMultipartUpload),
            "s3:AbortMultipartUpload" | "AbortMultipartUpload" | "abort-multipart-upload" => {
                Ok(Self::AbortMultipartUpload)
            }
            "s3:ListMultipartUploadParts"
            | "ListMultipartUploadParts"
            | "list-multipart-upload-parts" => Ok(Self::ListMultipartUploadParts),
            "s3:HeadBucket" | "HeadBucket" | "head-bucket" => Ok(Self::HeadBucket),
            _ => Err(ConfigError::InvalidAuthConfig(
                "allowed_actions must contain supported S3 action names",
            )),
        }
    }
}

fn is_valid_region(region: &str) -> bool {
    let mut bytes = region.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }

    let mut previous = first;
    for byte in bytes {
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-' {
            return false;
        }
        previous = byte;
    }

    previous.is_ascii_lowercase() || previous.is_ascii_digit()
}

fn validate_access_key_id(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::InvalidAuthConfig(
            "access_key_id must not be empty",
        ));
    }
    if value
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ConfigError::InvalidAuthConfig(
            "access_key_id must not contain whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_secret_key(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::InvalidAuthConfig(
            "secret_key must not be empty",
        ));
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ConfigError::InvalidAuthConfig(
            "secret_key must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_session_token(value: Option<&str>) -> Result<(), ConfigError> {
    if value.is_some_and(str::is_empty) {
        return Err(ConfigError::InvalidAuthConfig(
            "session_token must not be empty when configured",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_config_debug_redacts_secret_values() {
        let config = AuthConfig {
            secret_key: "super-secret".to_owned(),
            session_token: Some("session-secret".to_owned()),
            credentials: vec![AccessKeyConfig {
                access_key_id: "client".to_owned(),
                secret_key: "client-secret".to_owned(),
                session_token: Some("client-session".to_owned()),
                active: true,
                allowed_buckets: BTreeSet::new(),
                allowed_actions: BTreeSet::new(),
            }],
            ..AuthConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("secret_key: \"<redacted>\""));
        assert!(debug.contains("session_token: Some(\"<redacted>\")"));
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("session-secret"));
        assert!(!debug.contains("client-secret"));
        assert!(!debug.contains("client-session"));
    }

    #[test]
    fn secret_key_debug_redacts_value() {
        let secret = SecretKey::parse("super-secret").expect("secret");

        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("super-secret"));
    }

    #[test]
    fn access_key_id_validates_like_auth_config() {
        assert_eq!(
            AccessKeyId::parse("client")
                .expect("access key id")
                .as_str(),
            "client"
        );
        assert_eq!(
            AccessKeyId::parse("bad key"),
            Err(ConfigError::InvalidAuthConfig(
                "access_key_id must not contain whitespace or control characters"
            ))
        );
    }

    #[test]
    fn default_auth_config_is_valid() {
        AuthConfig::default().validate().expect("valid auth config");
    }

    #[test]
    fn config_builder_sets_embedded_server_options() {
        let limits = UploadLimits::builder()
            .max_object_size(1024)
            .max_part_size(512)
            .min_non_final_part_size(128)
            .max_concurrent_s3_requests(8)
            .max_active_object_writers(2)
            .max_active_multipart_part_writers(4)
            .max_active_aws_chunked_decoders(3)
            .build();
        let auth = AuthConfig::builder()
            .allow_anonymous(true)
            .primary_credentials("client", "secret")
            .session_token("token")
            .region("eu-west-1")
            .max_skew_seconds(60)
            .allow_bucket("media")
            .allow_action(S3Action::PutObject)
            .credential(
                AccessKeyConfig::builder("extra", "extra-secret")
                    .allow_bucket("archive")
                    .allow_action(S3Action::GetObject)
                    .build(),
            )
            .build();

        let config = Config::builder("/tmp/s3-data")
            .auth(auth)
            .virtual_host_base_domain("s3.test")
            .upload_limits(limits)
            .build();

        assert_eq!(config.storage_root, PathBuf::from("/tmp/s3-data"));
        assert_eq!(config.virtual_host_base_domain.as_deref(), Some("s3.test"));
        assert!(config.auth.allow_anonymous);
        assert_eq!(config.auth.access_key_id, "client");
        assert_eq!(config.auth.secret_key, "secret");
        assert_eq!(config.auth.session_token.as_deref(), Some("token"));
        assert_eq!(config.auth.region, "eu-west-1");
        assert_eq!(config.auth.max_skew_seconds, 60);
        assert!(config.auth.allowed_buckets.contains("media"));
        assert!(config.auth.allowed_actions.contains(&S3Action::PutObject));
        assert_eq!(config.auth.credentials.len(), 1);
        assert_eq!(config.auth.credentials[0].access_key_id, "extra");
        assert!(
            config.auth.credentials[0]
                .allowed_buckets
                .contains("archive")
        );
        assert_eq!(config.upload_limits.max_object_size, 1024);
        assert_eq!(config.upload_limits.max_part_size, 512);
        assert_eq!(config.upload_limits.min_non_final_part_size, 128);
        assert_eq!(config.upload_limits.max_concurrent_s3_requests, 8);
        assert_eq!(config.upload_limits.max_active_object_writers, 2);
        assert_eq!(config.upload_limits.max_active_multipart_part_writers, 4);
        assert_eq!(config.upload_limits.max_active_aws_chunked_decoders, 3);
    }

    #[test]
    fn upload_limit_presets_are_valid() {
        UploadLimits::default_s3_compatible()
            .validate()
            .expect("default limits");
        UploadLimits::local_development()
            .validate()
            .expect("local development limits");
    }

    #[test]
    fn auth_config_rejects_empty_access_key_id() {
        let config = AuthConfig {
            access_key_id: String::new(),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "access_key_id must not be empty"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_access_key_id_whitespace_or_control_characters() {
        let config = AuthConfig {
            access_key_id: "bad key".to_owned(),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "access_key_id must not contain whitespace or control characters"
            ))
        );

        let config = AuthConfig {
            access_key_id: "bad\nkey".to_owned(),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "access_key_id must not contain whitespace or control characters"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_empty_secret_key() {
        let config = AuthConfig {
            secret_key: String::new(),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "secret_key must not be empty"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_secret_key_control_characters() {
        let config = AuthConfig {
            secret_key: "bad\nsecret".to_owned(),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "secret_key must not contain control characters"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_empty_session_token() {
        let config = AuthConfig {
            session_token: Some(String::new()),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "session_token must not be empty when configured"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_invalid_region() {
        for region in ["", "US-EAST-1", "-us-east-1", "us-east-1-", "us_east_1"] {
            let config = AuthConfig {
                region: region.to_owned(),
                ..AuthConfig::default()
            };

            assert_eq!(
                config.validate(),
                Err(ConfigError::InvalidAuthConfig(
                    "region must be a non-empty lowercase AWS region identifier"
                ))
            );
        }
    }

    #[test]
    fn auth_config_rejects_negative_max_skew() {
        let config = AuthConfig {
            max_skew_seconds: -1,
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "max_skew_seconds must be greater than or equal to 0"
            ))
        );
    }

    #[test]
    fn auth_config_rejects_invalid_allowed_bucket() {
        let config = AuthConfig {
            allowed_buckets: BTreeSet::from(["bad/bucket".to_owned()]),
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "allowed_buckets must contain valid bucket names"
            ))
        );
    }

    #[test]
    fn auth_config_empty_allow_lists_permit_everything() {
        let config = AuthConfig::default();
        let bucket = BucketName::parse("any-bucket").expect("bucket");

        assert!(config.permits(&bucket, S3Action::PutObject));
        assert!(config.permits(&bucket, S3Action::AbortMultipartUpload));
    }

    #[test]
    fn auth_config_enforces_bucket_and_action_allow_lists() {
        let config = AuthConfig {
            allowed_buckets: BTreeSet::from(["allowed-bucket".to_owned()]),
            allowed_actions: BTreeSet::from([S3Action::PutObject]),
            ..AuthConfig::default()
        };
        let allowed_bucket = BucketName::parse("allowed-bucket").expect("bucket");
        let denied_bucket = BucketName::parse("denied-bucket").expect("bucket");

        assert!(config.permits(&allowed_bucket, S3Action::PutObject));
        assert!(!config.permits(&denied_bucket, S3Action::PutObject));
        assert!(!config.permits(&allowed_bucket, S3Action::CreateMultipartUpload));
    }

    #[test]
    fn auth_config_rejects_duplicate_credential_access_key_ids() {
        let config = AuthConfig {
            credentials: vec![AccessKeyConfig {
                access_key_id: "test".to_owned(),
                secret_key: "other-secret".to_owned(),
                session_token: None,
                active: true,
                allowed_buckets: BTreeSet::new(),
                allowed_actions: BTreeSet::new(),
            }],
            ..AuthConfig::default()
        };

        assert_eq!(
            config.validate(),
            Err(ConfigError::InvalidAuthConfig(
                "credential access_key_id values must be unique"
            ))
        );
    }

    #[test]
    fn auth_state_indexes_primary_and_additional_credentials() {
        let config = AuthConfig {
            credentials: vec![AccessKeyConfig {
                access_key_id: "client".to_owned(),
                secret_key: "client-secret".to_owned(),
                session_token: Some("client-session".to_owned()),
                active: false,
                allowed_buckets: BTreeSet::from(["client-bucket".to_owned()]),
                allowed_actions: BTreeSet::from([S3Action::PutObject]),
            }],
            ..AuthConfig::default()
        };
        let state = AuthState::new(&config).expect("auth state");

        let primary = state.credential("test").expect("primary credential");
        assert_eq!(primary.access_key_id.as_str(), "test");
        assert!(primary.active);

        let client = state.credential("client").expect("client credential");
        assert_eq!(client.access_key_id.as_str(), "client");
        assert_eq!(client.secret_key.as_str(), "client-secret");
        assert_eq!(client.session_token, Some("client-session"));
        assert!(!client.active);
        let bucket = BucketName::parse("client-bucket").expect("bucket");
        assert!(state.permits_credential("client", &bucket, S3Action::PutObject));
        assert!(!state.permits_credential("client", &bucket, S3Action::CreateMultipartUpload));
    }

    #[test]
    fn auth_state_debug_redacts_credential_values() {
        let config = AuthConfig {
            secret_key: "super-secret".to_owned(),
            session_token: Some("session-secret".to_owned()),
            credentials: vec![AccessKeyConfig {
                access_key_id: "client".to_owned(),
                secret_key: "client-secret".to_owned(),
                session_token: Some("client-session".to_owned()),
                active: true,
                allowed_buckets: BTreeSet::new(),
                allowed_actions: BTreeSet::new(),
            }],
            ..AuthConfig::default()
        };
        let state = AuthState::new(&config).expect("auth state");

        let debug = format!("{state:?}");

        assert!(debug.contains("credential_count: 2"));
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("session-secret"));
        assert!(!debug.contains("client-secret"));
        assert!(!debug.contains("client-session"));
    }

    #[test]
    fn s3_action_parses_iam_and_cli_names() {
        assert_eq!("s3:PutObject".parse::<S3Action>(), Ok(S3Action::PutObject));
        assert_eq!("s3:GetObject".parse::<S3Action>(), Ok(S3Action::GetObject));
        assert_eq!("get-object".parse::<S3Action>(), Ok(S3Action::GetObject));
        assert_eq!(
            "s3:HeadObject".parse::<S3Action>(),
            Ok(S3Action::HeadObject)
        );
        assert_eq!("head-object".parse::<S3Action>(), Ok(S3Action::HeadObject));
        assert_eq!(
            "s3:DeleteObject".parse::<S3Action>(),
            Ok(S3Action::DeleteObject)
        );
        assert_eq!(
            "CreateMultipartUpload".parse::<S3Action>(),
            Ok(S3Action::CreateMultipartUpload)
        );
        assert_eq!("upload-part".parse::<S3Action>(), Ok(S3Action::UploadPart));
        assert_eq!(
            "complete-multipart-upload".parse::<S3Action>(),
            Ok(S3Action::CompleteMultipartUpload)
        );
        assert_eq!(
            "abort-multipart-upload".parse::<S3Action>(),
            Ok(S3Action::AbortMultipartUpload)
        );
        assert_eq!(
            "list-multipart-upload-parts".parse::<S3Action>(),
            Ok(S3Action::ListMultipartUploadParts)
        );
        assert_eq!("head-bucket".parse::<S3Action>(), Ok(S3Action::HeadBucket));
    }

    #[test]
    fn s3_action_rejects_unsupported_actions() {
        assert_eq!(
            "s3:ListBucket".parse::<S3Action>(),
            Err(ConfigError::InvalidAuthConfig(
                "allowed_actions must contain supported S3 action names"
            ))
        );
    }

    #[test]
    fn default_upload_limits_are_valid() {
        UploadLimits::default().validate().expect("valid limits");
    }

    #[test]
    fn upload_limits_return_positive_validated_values() {
        let limits = UploadLimits {
            max_object_size: 10,
            max_part_size: 8,
            min_non_final_part_size: 4,
            ..Default::default()
        }
        .validated()
        .expect("validated limits");

        assert_eq!(limits.max_object_size.get(), 10);
        assert_eq!(limits.max_part_size.get(), 8);
        assert_eq!(limits.min_non_final_part_size.get(), 4);
        assert_eq!(limits.max_concurrent_s3_requests.get(), 256);
        assert_eq!(limits.max_active_object_writers.get(), 64);
        assert_eq!(limits.max_active_multipart_part_writers.get(), 128);
        assert_eq!(limits.max_active_aws_chunked_decoders.get(), 64);
    }

    #[test]
    fn upload_limits_reject_zero_values() {
        let limits = UploadLimits {
            max_object_size: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_object_size must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            max_part_size: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_part_size must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            min_non_final_part_size: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "min_non_final_part_size must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            max_concurrent_s3_requests: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_concurrent_s3_requests must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            max_active_object_writers: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_active_object_writers must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            max_active_multipart_part_writers: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_active_multipart_part_writers must be greater than 0"
            ))
        );

        let limits = UploadLimits {
            max_active_aws_chunked_decoders: 0,
            ..UploadLimits::default()
        };
        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "max_active_aws_chunked_decoders must be greater than 0"
            ))
        );
    }

    #[test]
    fn upload_limits_reject_min_part_size_larger_than_max_part_size() {
        let limits = UploadLimits {
            max_object_size: 100,
            max_part_size: 4,
            min_non_final_part_size: 5,
            ..Default::default()
        };

        assert_eq!(
            limits.validate(),
            Err(ConfigError::InvalidUploadLimit(
                "min_non_final_part_size must be less than or equal to max_part_size"
            ))
        );
    }
}
