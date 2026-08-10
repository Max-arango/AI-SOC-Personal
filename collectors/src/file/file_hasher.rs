//! File hasher — async SHA-256 computation for suspicious files.
//!
//! Computes hash and MIME type in `spawn_blocking` to avoid blocking
//! the async runtime. Limited to files under a configurable max size
//! (default 10 MB) to avoid DoS.

use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{debug, warn};

/// Result of hashing a file
#[derive(Debug, Clone)]
pub struct FileHashResult {
    pub sha256: String,
    pub entropy: f64,
    pub mime_type: String,
    pub size: u64,
    pub duration_ms: u64,
}

/// Compute SHA-256, entropy, and MIME type for a file asynchronously.
///
/// Files larger than `max_bytes` are skipped (returns empty result).
pub async fn hash_file(path: &str, max_bytes: u64) -> FileHashResult {
    let path_owned = path.to_string();
    let path_for_err = path_owned.clone();
    tokio::task::spawn_blocking(move || hash_file_sync(&path_owned, max_bytes))
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("File hasher task panicked for {}: {e:?}", path_for_err);
            FileHashResult::empty()
        })
}

fn hash_file_sync(path: &str, max_bytes: u64) -> FileHashResult {
    let start = Instant::now();

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            warn!("Failed to read {}: {e}", path);
            return FileHashResult::empty();
        }
    };

    if data.len() as u64 > max_bytes {
        debug!("Skipping {}: too large ({} > {})", path, data.len(), max_bytes);
        let mime = detect_mime_from_ext(path);
        return FileHashResult {
            sha256: String::new(),
            entropy: compute_entropy(&data[..4096.min(data.len())]),
            mime_type: mime,
            size: data.len() as u64,
            duration_ms: start.elapsed().as_millis() as u64,
        };
    }

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let sha256 = format!("{:x}", hasher.finalize());
    let entropy = compute_entropy(&data);
    let mime = detect_mime(&data, path);

    FileHashResult {
        sha256,
        entropy,
        mime_type: mime,
        size: data.len() as u64,
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

/// Shannon entropy: -Σ p(x) * log2(p(x))
fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    (entropy * 100.0).round() / 100.0
}

/// MIME type detection via magic bytes + extension fallback
fn detect_mime(data: &[u8], path: &str) -> String {
    // Magic byte detection
    if data.len() >= 2 {
        match (data[0], data[1]) {
            (0xFF, 0xD8) => return "image/jpeg".into(),
            (0x89, b'P') => return "image/png".into(),
            (0x47, 0x49) => return "image/gif".into(),
            (0x25, 0x50) => return "application/pdf".into(),
            (0x50, 0x4B) => return "application/zip".into(),
            (0x1F, 0x8B) => return "application/gzip".into(),
            (0x7F, b'E') => return "application/x-elf".into(),
            (0xCA, 0xFE) => return "application/x-mach-o".into(),
            _ => {}
        }
    }

    if data.len() >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00
    {
        return "font/ttf".into();
    }

    detect_mime_from_ext(path)
}

fn detect_mime_from_ext(path: &str) -> String {
    let lower = path.to_lowercase();
    if lower.ends_with(".sh") || lower.ends_with(".bash") || lower.ends_with(".zsh") {
        "text/x-shellscript"
    } else if lower.ends_with(".py") {
        "text/x-python"
    } else if lower.ends_with(".rb") {
        "text/x-ruby"
    } else if lower.ends_with(".js") {
        "application/javascript"
    } else if lower.ends_with(".pl") {
        "text/x-perl"
    } else if lower.ends_with(".php") {
        "text/x-php"
    } else if lower.ends_with(".exe") || lower.ends_with(".dll") {
        "application/x-dosexec"
    } else if lower.ends_with(".so") || lower.ends_with(".o") {
        "application/x-sharedlib"
    } else if lower.ends_with(".rpm") || lower.ends_with(".deb") {
        "application/x-package"
    } else if lower.ends_with(".tar") || lower.ends_with(".gz") || lower.ends_with(".bz2")
        || lower.ends_with(".xz")
    {
        "application/x-archive"
    } else if lower.ends_with(".json") {
        "application/json"
    } else if lower.ends_with(".xml") {
        "application/xml"
    } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        "application/x-yaml"
    } else if lower.ends_with(".toml") || lower.ends_with(".ini") || lower.ends_with(".cfg")
        || lower.ends_with(".conf")
    {
        "text/x-config"
    } else if lower.ends_with(".log") || lower.ends_with(".txt") || lower.ends_with(".md") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
    .to_string()
}

impl FileHashResult {
    pub fn empty() -> Self {
        Self {
            sha256: String::new(),
            entropy: 0.0,
            mime_type: String::new(),
            size: 0,
            duration_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_all_zeros_is_zero() {
        let data = vec![0u8; 256];
        let e = compute_entropy(&data);
        assert!((e - 0.0).abs() < 0.01);
    }

    #[test]
    fn entropy_of_uniform_is_eight() {
        let mut data = Vec::with_capacity(256);
        for i in 0..256 {
            data.push(i as u8);
        }
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.1, "Got {e}");
    }

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(compute_entropy(&[]), 0.0);
    }

    #[test]
    fn detect_elf_binary() {
        let data = vec![0x7F, b'E', b'L', b'F'];
        assert_eq!(detect_mime(&data, "unknown"), "application/x-elf");
    }

    #[test]
    fn detect_shell_script_by_ext() {
        assert_eq!(detect_mime_from_ext("/tmp/test.sh"), "text/x-shellscript");
        assert_eq!(detect_mime_from_ext("script.py"), "text/x-python");
        assert_eq!(detect_mime_from_ext("payload.exe"), "application/x-dosexec");
    }

    #[test]
    fn uuid_is_random() {
        // Test that UUID file names get `octet-stream` MIME
        let result = detect_mime_from_ext("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
        assert_eq!(result, "application/octet-stream");
    }
}
