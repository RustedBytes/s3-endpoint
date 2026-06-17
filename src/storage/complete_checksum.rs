use crc::{CRC_32_ISCSI, CRC_32_ISO_HDLC, Crc};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::body::checksum::{ChecksumDigests, ChecksumRequest};

static CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
static CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub(super) struct MultipartCompleteChecksumState<'a> {
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
    sha512: Option<Sha512>,
    crc32: Option<crc::Digest<'a, u32>>,
    crc32c: Option<crc::Digest<'a, u32>>,
}

impl MultipartCompleteChecksumState<'static> {
    /// Creates digest state only for checksums requested by the client.
    pub(super) fn new(checksum_request: &ChecksumRequest) -> Self {
        Self {
            md5: checksum_request.requires_md5().then(Md5::new),
            sha1: checksum_request.requires_sha1().then(Sha1::new),
            sha256: checksum_request.requires_sha256().then(Sha256::new),
            sha512: checksum_request.requires_sha512().then(Sha512::new),
            crc32: checksum_request.requires_crc32().then(|| CRC32.digest()),
            crc32c: checksum_request.requires_crc32c().then(|| CRC32C.digest()),
        }
    }
}

impl MultipartCompleteChecksumState<'_> {
    /// Feeds completed multipart object bytes into every enabled digest.
    pub(super) fn update(&mut self, bytes: &[u8]) {
        if let Some(md5) = &mut self.md5 {
            md5.update(bytes);
        }
        if let Some(sha1) = &mut self.sha1 {
            sha1.update(bytes);
        }
        if let Some(sha256) = &mut self.sha256 {
            sha256.update(bytes);
        }
        if let Some(sha512) = &mut self.sha512 {
            sha512.update(bytes);
        }
        if let Some(crc32) = &mut self.crc32 {
            crc32.update(bytes);
        }
        if let Some(crc32c) = &mut self.crc32c {
            crc32c.update(bytes);
        }
    }

    /// Finalizes enabled digests and returns default values for disabled algorithms.
    pub(super) fn finalize(self) -> ChecksumDigests {
        ChecksumDigests {
            md5: self
                .md5
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha1: self
                .sha1
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha256: self
                .sha256
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            sha512: self
                .sha512
                .map(|digest| digest.finalize().to_vec())
                .unwrap_or_default(),
            crc32: self
                .crc32
                .map(|digest| digest.finalize())
                .unwrap_or_default(),
            crc32c: self
                .crc32c
                .map(|digest| digest.finalize())
                .unwrap_or_default(),
        }
    }

    #[cfg(test)]
    /// Returns which digests are enabled for focused unit tests.
    pub(super) fn enabled_digests(&self) -> EnabledDigests {
        EnabledDigests {
            md5: self.md5.is_some(),
            sha1: self.sha1.is_some(),
            sha256: self.sha256.is_some(),
            sha512: self.sha512.is_some(),
            crc32: self.crc32.is_some(),
            crc32c: self.crc32c.is_some(),
        }
    }
}

#[cfg(test)]
pub(super) struct EnabledDigests {
    pub(super) md5: bool,
    pub(super) sha1: bool,
    pub(super) sha256: bool,
    pub(super) sha512: bool,
    pub(super) crc32: bool,
    pub(super) crc32c: bool,
}
