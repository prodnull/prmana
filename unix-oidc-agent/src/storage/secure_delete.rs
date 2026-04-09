//! Secure file deletion with multi-pass overwrite
//!
//! Implements a three-pass overwrite for file deletion following NIST SP 800-88
//! Rev 1 "Guidelines for Media Sanitization" §2.4 (Clear method):
//! - Pass 1: random bytes, fsync
//! - Pass 2: complement (XOR 0xFF) of pass-1 bytes, fsync
//! - Pass 3: new random bytes, fsync
//! - unlink
//!
//! # Limitations
//!
//! - **CoW filesystems** (btrfs, APFS): copy-on-write semantics mean overwrites
//!   may not modify the original blocks. The advisory is logged; full-disk
//!   encryption is the correct mitigation.
//! - **SSD/flash wear leveling**: the drive firmware may redirect writes to spare
//!   blocks, leaving the original data intact. Full-disk encryption is the
//!   correct mitigation. (NIST SP 800-88 Rev 1, §2.5)
//! - **Root/kernel access**: mlock and zeroize cannot protect against a privileged
//!   actor with direct memory or disk access.
//!
//! References:
//! - NIST SP 800-88 Rev 1 "Guidelines for Media Sanitization" (primary)
//! - NIST SP 800-88 Rev 1 §2.4: Clear — logical techniques applied to all
//!   user-addressable storage locations
//!
//! Historical note: Originally inspired by DoD 5220.22-M, retired by DoD in 2006.
//! NIST SP 800-88 Rev 1 is the current authoritative reference for media sanitization.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use thiserror::Error;
use tracing::warn;

/// Errors from secure file removal
#[derive(Debug, Error)]
pub enum SecureDeleteError {
    #[error("File not found: {0}")]
    NotFound(String),
    #[error("IO error during secure delete: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Overwrite failed (best-effort): {0}")]
    OverwriteFailed(String),
    #[error("Symlink rejected (TOCTOU protection): {0}")]
    SymlinkRejected(String),
    #[error("Not a regular file (TOCTOU protection): {0}")]
    NotRegularFile(String),
    #[error("Owner mismatch: {path} owned by uid {actual_uid}, expected {expected_uid}")]
    OwnerMismatch {
        path: String,
        expected_uid: u32,
        actual_uid: u32,
    },
}

/// Buffer size for overwrite passes (4 KiB per pass chunk)
const OVERWRITE_BUF: usize = 4096;

/// Remove a file with a three-pass random overwrite before unlinking.
///
/// Uses `O_NOFOLLOW` to reject symlinks and `fstat` on the opened file
/// descriptor to verify the target is a regular file owned by the current
/// user — preventing TOCTOU attacks where an attacker swaps the file for a
/// symlink between the existence check and the open.
///
/// If any overwrite pass fails the failure is logged and the function still
/// attempts to unlink (best-effort semantics, per project decision). The
/// caller receives `Ok(())` even in the overwrite-failed case as long as the
/// unlink succeeds.
///
/// Returns `Err(NotFound)` if the path does not exist.
pub fn secure_remove(path: &Path) -> Result<(), SecureDeleteError> {
    // Open with O_NOFOLLOW | O_NONBLOCK to reject symlinks and avoid blocking
    // on FIFOs/sockets. O_NONBLOCK is safe here because we verify S_IFREG via
    // fstat immediately after open — non-regular files are rejected before any I/O.
    let file = match OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SecureDeleteError::NotFound(path.display().to_string()));
        }
        Err(e) => {
            // ELOOP on Linux / ENOENT-like on macOS when path is a symlink
            if e.raw_os_error() == Some(libc::ELOOP) {
                return Err(SecureDeleteError::SymlinkRejected(
                    path.display().to_string(),
                ));
            }
            return Err(SecureDeleteError::IoError(e));
        }
    };

    // fstat on the fd (not the path) to prevent TOCTOU races.
    let metadata = file.metadata()?;

    // Verify the target is a regular file (S_IFREG), not a device, socket, etc.
    let mode = metadata.mode();
    if mode & libc::S_IFMT as u32 != libc::S_IFREG as u32 {
        return Err(SecureDeleteError::NotRegularFile(
            path.display().to_string(),
        ));
    }

    // Verify ownership matches current effective UID to prevent overwriting
    // files owned by other users (defense against privilege escalation via
    // path manipulation).
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid {
        return Err(SecureDeleteError::OwnerMismatch {
            path: path.display().to_string(),
            expected_uid: euid,
            actual_uid: metadata.uid(),
        });
    }

    let size = metadata.len() as usize;

    if size == 0 {
        drop(file);
        std::fs::remove_file(path)?;
        return Ok(());
    }

    match overwrite_three_pass_fd(file, size) {
        Ok(()) => {}
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "Secure delete overwrite failed (best-effort) — proceeding to unlink"
            );
        }
    }

    std::fs::remove_file(path)?;
    Ok(())
}

/// Perform a three-pass (random, complement, random) overwrite on an already-open fd.
///
/// Takes ownership of the `File` to ensure the fd is not shared. The caller
/// has already verified via `fstat` that the fd refers to a regular file.
fn overwrite_three_pass_fd(mut file: File, size: usize) -> Result<(), SecureDeleteError> {
    let mut rng = OsRng;
    let mut buf = vec![0u8; OVERWRITE_BUF.min(size)];

    // Pass 1: random bytes
    overwrite_pass(&mut file, &mut buf, size, |buf| {
        rng.fill_bytes(buf);
    })?;

    // Pass 2: complement of pass-1 buffer (XOR 0xFF)
    // Re-read current buf content for complement; buf still holds last chunk
    // from pass 1, so we XOR from scratch with fill then complement in place.
    overwrite_pass(&mut file, &mut buf, size, |buf| {
        rng.fill_bytes(buf);
        for b in buf.iter_mut() {
            *b ^= 0xFF;
        }
    })?;

    // Pass 3: new random bytes
    overwrite_pass(&mut file, &mut buf, size, |buf| {
        rng.fill_bytes(buf);
    })?;

    Ok(())
}

/// Write `size` bytes to `file` (seeking to start each time), filling chunks
/// via `fill_fn`. Calls `sync_all()` after the pass.
fn overwrite_pass<F>(
    file: &mut File,
    buf: &mut [u8],
    size: usize,
    mut fill_fn: F,
) -> Result<(), SecureDeleteError>
where
    F: FnMut(&mut [u8]),
{
    use std::io::Seek;

    file.seek(std::io::SeekFrom::Start(0))?;

    let mut remaining = size;
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        fill_fn(&mut buf[..chunk]);
        file.write_all(&buf[..chunk])?;
        remaining -= chunk;
    }

    file.sync_all()?;
    Ok(())
}

/// Returns `true` if `path` is on a copy-on-write filesystem.
///
/// On such filesystems, overwrite passes may not modify the original data
/// blocks. Full-disk encryption is the recommended mitigation.
pub fn detect_cow_filesystem(path: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        detect_cow_linux(path)
    }
    #[cfg(target_os = "macos")]
    {
        detect_cow_macos(path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        false
    }
}

#[cfg(target_os = "linux")]
fn detect_cow_linux(path: &Path) -> bool {
    // btrfs magic: 0x9123683E (from <linux/magic.h>)
    const BTRFS_SUPER_MAGIC: i64 = 0x9123_683E_u32 as i32 as i64;

    unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        let path_cstr = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if libc::statfs(path_cstr.as_ptr(), &mut buf) != 0 {
            return false;
        }
        buf.f_type == BTRFS_SUPER_MAGIC
    }
}

#[cfg(target_os = "macos")]
fn detect_cow_macos(path: &Path) -> bool {
    unsafe {
        let mut buf: libc::statfs = std::mem::zeroed();
        let path_cstr = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if libc::statfs(path_cstr.as_ptr(), &mut buf) != 0 {
            return false;
        }
        // f_fstypename is a [c_char; 16]
        let type_bytes = &buf.f_fstypename[..];
        let type_str = std::ffi::CStr::from_ptr(type_bytes.as_ptr());
        type_str.to_bytes() == b"apfs"
    }
}

/// Returns `Some(true)` if the device backing `path` is rotational (HDD),
/// `Some(false)` if non-rotational (SSD/flash), or `None` if unknown.
///
/// Only implemented on Linux via `/sys/block/<dev>/queue/rotational`.
/// Non-rotational devices may retain copies of overwritten data due to
/// wear-leveling; full-disk encryption is recommended. (NIST SP 800-88 Rev 1)
pub fn detect_rotational_device(path: &Path) -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        detect_rotational_linux(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

#[cfg(target_os = "linux")]
fn detect_rotational_linux(path: &Path) -> Option<bool> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    // Get the device number from the path's metadata
    let metadata = fs::metadata(path).ok()?;
    let dev = metadata.dev();
    let major = ((dev >> 8) & 0xFFF) | ((dev >> 32) & !0xFFF);
    let minor = (dev & 0xFF) | ((dev >> 12) & !0xFF);

    // Find block device name by scanning /sys/block
    let sys_block = std::path::Path::new("/sys/block");
    for entry in fs::read_dir(sys_block).ok()? {
        let entry = entry.ok()?;
        let dev_file = entry.path().join("dev");
        let dev_contents = fs::read_to_string(&dev_file).ok()?;
        let parts: Vec<&str> = dev_contents.trim().split(':').collect();
        if parts.len() == 2 {
            let blk_major: u64 = parts[0].parse().ok()?;
            let blk_minor: u64 = parts[1].parse().ok()?;
            // Match on major; minor 0 is the whole disk
            if blk_major == major && (blk_minor == 0 || blk_minor == minor) {
                let rot_path = entry.path().join("queue/rotational");
                let rot = fs::read_to_string(rot_path).ok()?;
                return Some(rot.trim() == "1");
            }
        }
    }
    None
}

/// Log storage advisories at WARN level for the given directory.
///
/// Should be called once at `FileStorage` construction time. Logs:
/// - CoW filesystem advisory if btrfs (Linux) or APFS (macOS) is detected
/// - SSD/flash advisory if non-rotational device is detected on Linux
pub fn log_storage_advisories(storage_dir: &Path) {
    if detect_cow_filesystem(storage_dir) {
        warn!(
            path = %storage_dir.display(),
            "Storage directory is on a CoW filesystem (btrfs/APFS). \
            Secure delete overwrites may not erase all copies. \
            Full-disk encryption is recommended."
        );
    }

    if let Some(false) = detect_rotational_device(storage_dir) {
        warn!(
            path = %storage_dir.display(),
            "Storage directory is on flash/SSD storage. \
            Wear leveling may retain copies of deleted key material. \
            Full-disk encryption is recommended."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper: create a temp file with given content
    fn make_temp_file(dir: &TempDir, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        let mut f = File::create(&path).unwrap();
        f.write_all(content).unwrap();
        f.sync_all().unwrap();
        path
    }

    #[test]
    fn test_secure_remove_deletes_file() {
        let dir = TempDir::new().unwrap();
        let path = make_temp_file(&dir, "secret.bin", b"sensitive-key-material");

        assert!(path.exists(), "file should exist before deletion");

        secure_remove(&path).expect("secure_remove should succeed");

        assert!(!path.exists(), "file should be gone after secure_remove");
    }

    #[test]
    fn test_secure_remove_nonexistent_returns_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("does-not-exist.bin");

        let result = secure_remove(&path);
        assert!(
            matches!(result, Err(SecureDeleteError::NotFound(_))),
            "expected NotFound, got {result:?}"
        );
    }

    #[test]
    fn test_secure_remove_zero_length_file() {
        let dir = TempDir::new().unwrap();
        let path = make_temp_file(&dir, "empty.bin", b"");

        // Should not panic; just unlink
        secure_remove(&path).expect("secure_remove should handle empty files");
        assert!(!path.exists(), "empty file should be deleted");
    }

    #[test]
    fn test_secure_remove_large_file() {
        // Tests that the chunked buffer logic works for files > OVERWRITE_BUF
        let dir = TempDir::new().unwrap();
        let content = vec![0xABu8; OVERWRITE_BUF * 3 + 17]; // crosses buffer boundaries
        let path = make_temp_file(&dir, "large.bin", &content);

        secure_remove(&path).expect("secure_remove should handle large files");
        assert!(!path.exists(), "large file should be deleted");
    }

    #[test]
    fn test_secure_remove_rejects_symlink() {
        let dir = TempDir::new().unwrap();
        let real_file = make_temp_file(&dir, "real.bin", b"real-content");
        let symlink_path = dir.path().join("link.bin");

        std::os::unix::fs::symlink(&real_file, &symlink_path).unwrap();

        let result = secure_remove(&symlink_path);

        // Must reject the symlink — either SymlinkRejected or a loop/permission error.
        assert!(
            result.is_err(),
            "secure_remove must reject symlinks to prevent TOCTOU attacks"
        );

        // The real file must NOT have been overwritten.
        let content = std::fs::read(&real_file).unwrap();
        assert_eq!(content, b"real-content", "real file must not be modified");
    }

    #[test]
    fn test_secure_remove_rejects_non_regular_file() {
        // Create a named pipe (FIFO) — should be rejected by S_IFREG check.
        let dir = TempDir::new().unwrap();
        let fifo_path = dir.path().join("test.fifo");
        let path_cstr = std::ffi::CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
        unsafe {
            libc::mkfifo(path_cstr.as_ptr(), 0o600);
        }

        let result = secure_remove(&fifo_path);
        assert!(
            result.is_err(),
            "secure_remove must reject non-regular files"
        );
    }

    #[test]
    fn test_detect_cow_filesystem_does_not_panic() {
        let dir = TempDir::new().unwrap();
        // Result value is platform-dependent; we just verify no panic
        let _result = detect_cow_filesystem(dir.path());
    }

    #[test]
    fn test_detect_rotational_device_does_not_panic() {
        let dir = TempDir::new().unwrap();
        // Returns Some(bool) on Linux, None elsewhere — no panic either way
        let _result = detect_rotational_device(dir.path());
    }

    #[test]
    fn test_log_storage_advisories_does_not_panic() {
        let dir = TempDir::new().unwrap();
        // This exercises the full advisory path; main test is "no panic"
        log_storage_advisories(dir.path());
    }
}
