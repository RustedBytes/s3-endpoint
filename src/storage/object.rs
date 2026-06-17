use std::{path::PathBuf, sync::Arc};

use md5::Digest as _;
use sha2::Sha256;
use tokio::{
    fs::{self, File},
    io::BufWriter,
};
use uuid::Uuid;

use super::{
    ObjectMetadata, StagedObject, StoreError, TempObjectWriter,
    fs_util::{
        backup_existing_file, create_parent_dir, remove_backup_file, remove_file_if_exists,
        rollback_published_file,
    },
};
use crate::s3::types::{BucketName, ObjectKey};

/// Filesystem-backed object store.
#[derive(Clone, Debug)]
pub struct FileObjectStore {
    root: Arc<PathBuf>,
}

impl FileObjectStore {
    /// Opens or creates a filesystem object store rooted at `root`.
    ///
    /// Creates required directories and removes stale temporary/orphaned files.
    /// Returns an error when directory creation, cleanup, or metadata parsing fails.
    pub async fn new(root: PathBuf) -> Result<Self, StoreError> {
        fs::create_dir_all(root.join("objects")).await?;
        fs::create_dir_all(root.join("metadata")).await?;
        fs::create_dir_all(root.join("tmp")).await?;
        let store = Self {
            root: Arc::new(root),
        };
        store.cleanup_stale_temp_files().await?;
        store.cleanup_orphaned_object_files().await?;
        store.cleanup_orphaned_metadata_files().await?;
        Ok(store)
    }

    /// Creates a temporary object writer for a bucket/key.
    ///
    /// The caller must write the full object body and then pass the writer to
    /// [`Self::commit_object`] or [`TempObjectWriter::discard`].
    pub async fn create_temp_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<TempObjectWriter, StoreError> {
        let temp_id = Uuid::new_v4();
        let path = self.root.join("tmp").join(format!("{temp_id}.part"));
        let file = File::create(&path).await?;

        Ok(TempObjectWriter {
            temp_id,
            cleanup: crate::storage::temp::TempFileCleanup::new(path.clone()),
            path,
            writer: BufWriter::new(file),
            bucket: bucket.clone(),
            key: key.clone(),
        })
    }

    /// Atomically publishes a temporary object and metadata.
    ///
    /// On failure, best-effort rollback restores the previous object/metadata
    /// pair when one existed and removes temporary files. Returns an error for
    /// filesystem or serialization failures.
    pub async fn commit_object(
        &self,
        temp: TempObjectWriter,
        metadata: ObjectMetadata,
    ) -> Result<(), StoreError> {
        self.commit_staged_object(temp.finish().await?, metadata)
            .await
    }

    /// Atomically publishes a staged object and metadata.
    ///
    /// This is used by upload middleware paths that need filesystem access to a
    /// fully decoded temporary object before it is committed.
    pub async fn commit_staged_object(
        &self,
        staged: StagedObject,
        metadata: ObjectMetadata,
    ) -> Result<(), StoreError> {
        let (temp_id, temp_path) = staged.into_parts();

        let object_path = self.object_path(&metadata.bucket, &metadata.key);
        let metadata_path = self.metadata_path(&metadata.bucket, &metadata.key);
        let metadata_tmp = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.metadata.json"));
        let object_backup = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.object.rollback.tmp"));
        let metadata_backup = self
            .root
            .join("tmp")
            .join(format!("{temp_id}.metadata.rollback.tmp"));

        let result = async {
            create_parent_dir(&object_path).await?;
            create_parent_dir(&metadata_path).await?;

            let json = serde_json::to_vec_pretty(&metadata)?;
            fs::write(&metadata_tmp, json).await?;
            let had_object = backup_existing_file(&object_path, &object_backup).await?;
            let had_metadata = backup_existing_file(&metadata_path, &metadata_backup).await?;

            fs::rename(&temp_path, &object_path).await?;
            if let Err(error) = fs::rename(&metadata_tmp, &metadata_path).await {
                rollback_published_file(&object_path, &object_backup, had_object).await;
                rollback_published_file(&metadata_path, &metadata_backup, had_metadata).await;
                return Err(StoreError::Io(error));
            }

            remove_backup_file(&object_backup, had_object).await?;
            remove_backup_file(&metadata_backup, had_metadata).await?;
            Ok(())
        }
        .await;

        if result.is_err() {
            let _ = remove_file_if_exists(temp_path).await;
            let _ = remove_file_if_exists(metadata_tmp).await;
            let _ = remove_file_if_exists(object_backup).await;
            let _ = remove_file_if_exists(metadata_backup).await;
        }

        result
    }

    /// Reads committed object metadata.
    ///
    /// Returns `Ok(None)` when either metadata or object bytes are missing, so
    /// orphaned metadata/data files are not exposed as objects.
    pub async fn head_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<Option<ObjectMetadata>, StoreError> {
        let metadata_path = self.metadata_path(bucket, key);
        let object_path = self.object_path(bucket, key);
        let metadata = match fs::read(metadata_path).await {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };

        match fs::metadata(object_path).await {
            Ok(object) if object.is_file() => Ok(Some(metadata)),
            Ok(_) => Ok(None),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Opens a committed object for streaming.
    ///
    /// Returns `Ok(None)` when the object is missing or disappears between
    /// metadata lookup and file open.
    pub async fn open_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<Option<(ObjectMetadata, File)>, StoreError> {
        let Some(metadata) = self.head_object(bucket, key).await? else {
            return Ok(None);
        };
        match File::open(self.object_path(bucket, key)).await {
            Ok(file) => Ok(Some((metadata, file))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    /// Deletes object metadata and bytes.
    ///
    /// Missing objects are treated as success, matching S3 delete semantics.
    pub async fn delete_object(
        &self,
        bucket: &BucketName,
        key: &ObjectKey,
    ) -> Result<(), StoreError> {
        let metadata_path = self.metadata_path(bucket, key);
        let object_path = self.object_path(bucket, key);

        match fs::remove_file(&metadata_path).await {
            Ok(()) => remove_file_if_exists(object_path).await,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(StoreError::Io(error)),
        }
    }

    fn object_path(&self, bucket: &BucketName, key: &ObjectKey) -> PathBuf {
        let digest = object_digest(bucket, key);
        self.root
            .join("objects")
            .join(&digest[..2])
            .join(format!("{digest}.data"))
    }

    fn metadata_path(&self, bucket: &BucketName, key: &ObjectKey) -> PathBuf {
        let digest = object_digest(bucket, key);
        self.root
            .join("metadata")
            .join(&digest[..2])
            .join(format!("{digest}.json"))
    }

    async fn cleanup_stale_temp_files(&self) -> Result<(), StoreError> {
        let mut entries = fs::read_dir(self.root.join("tmp")).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_file() {
                remove_file_if_exists(entry.path()).await?;
            }
        }
        Ok(())
    }

    async fn cleanup_orphaned_object_files(&self) -> Result<(), StoreError> {
        let mut prefixes = fs::read_dir(self.root.join("objects")).await?;
        while let Some(prefix_entry) = prefixes.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }

            let mut objects = fs::read_dir(prefix_entry.path()).await?;
            while let Some(object_entry) = objects.next_entry().await? {
                if !object_entry.file_type().await?.is_file() {
                    continue;
                }

                let Some(file_name) = object_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(digest) = file_name.strip_suffix(".data") else {
                    continue;
                };

                let metadata_path = if digest.len() >= 2 {
                    self.root
                        .join("metadata")
                        .join(&digest[..2])
                        .join(format!("{digest}.json"))
                } else {
                    self.root.join("metadata").join(format!("{digest}.json"))
                };

                match fs::metadata(metadata_path).await {
                    Ok(metadata) if metadata.is_file() => {}
                    Ok(_) => remove_file_if_exists(object_entry.path()).await?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        remove_file_if_exists(object_entry.path()).await?;
                    }
                    Err(error) => return Err(StoreError::Io(error)),
                }
            }
        }
        Ok(())
    }

    async fn cleanup_orphaned_metadata_files(&self) -> Result<(), StoreError> {
        let mut prefixes = fs::read_dir(self.root.join("metadata")).await?;
        while let Some(prefix_entry) = prefixes.next_entry().await? {
            if !prefix_entry.file_type().await?.is_dir() {
                continue;
            }

            let mut metadata_files = fs::read_dir(prefix_entry.path()).await?;
            while let Some(metadata_entry) = metadata_files.next_entry().await? {
                if !metadata_entry.file_type().await?.is_file() {
                    continue;
                }

                let Some(file_name) = metadata_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(digest) = file_name.strip_suffix(".json") else {
                    continue;
                };

                let object_path = if digest.len() >= 2 {
                    self.root
                        .join("objects")
                        .join(&digest[..2])
                        .join(format!("{digest}.data"))
                } else {
                    self.root.join("objects").join(format!("{digest}.data"))
                };

                match fs::metadata(object_path).await {
                    Ok(object) if object.is_file() => {}
                    Ok(_) => remove_file_if_exists(metadata_entry.path()).await?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        remove_file_if_exists(metadata_entry.path()).await?;
                    }
                    Err(error) => return Err(StoreError::Io(error)),
                }
            }
        }
        Ok(())
    }
}

fn object_digest(bucket: &BucketName, key: &ObjectKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bucket.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(key.as_str().as_bytes());
    hex::encode(hasher.finalize())
}
