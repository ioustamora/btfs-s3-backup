use cid::{Cid, Version};
use multihash::{self, Multihash, MultihashDigest, Identity, Hasher, Sha2_256, Code};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, time::Duration};
use walkdir::WalkDir;
use chrono::Utc;
use log::info;
use rayon::prelude::*;
use std::sync::{Arc, LazyLock};
use parking_lot::RwLock;
use thiserror::Error;
use std::io::{self, Read, BufReader};
use std::sync::atomic::{AtomicUsize, Ordering, AtomicBool};
use futures_util::StreamExt;
use memmap2::MmapOptions;
use rayon::iter::ParallelBridge;
use tokio::sync::mpsc;
use memmap2::Mmap;

use crate::config::Config;

const IGNORED_PATTERNS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "temp",
];

const SCAN_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour timeout
const BUFFER_SIZE: usize = 8192; // 8KB chunks for reading large files
const CACHE_SIZE_LIMIT: usize = 10_000; // Maximum number of entries in cache
const MAX_CACHE_MEMORY: usize = 100 * 1024 * 1024; // 100MB cache limit

static CACHE: LazyLock<FileCache> = LazyLock::new(|| {
    Arc::new(RwLock::new(HashMap::new()))
});

#[derive(Debug)]
struct FileMetadata {
    mtime: u64,
    size: u64,
    cid: String,
    last_check: std::time::SystemTime,
}

impl FileMetadata {
    fn new(metadata: &std::fs::Metadata, cid: String) -> Result<Self, ScanError> {
        Ok(Self {
            mtime: metadata.modified()
                .map_err(|e| ScanError::MetadataError(e.to_string()))?
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| ScanError::MetadataError(e.to_string()))?
                .as_secs(),
            size: metadata.len(),
            cid,
            last_check: std::time::SystemTime::now(),
        })
    }

    fn is_valid(&self, metadata: &std::fs::Metadata) -> bool {
        if let Ok(mtime) = metadata.modified()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH))
            .map(|d| d.as_secs()) {
            return self.mtime == mtime 
                && self.size == metadata.len() 
                && self.last_check.elapsed().unwrap_or_default().as_secs() < 3600;
        }
        false
    }
}

type FileCache = Arc<RwLock<HashMap<String, FileMetadata>>>;

// Define FileCache methods as a trait
trait FileCacheOps {
    fn get_cached(&self, path: &str, metadata: &std::fs::Metadata) -> Option<String>;
    fn update_cache(&self, path: String, metadata: &std::fs::Metadata, cid: String) -> Result<(), ScanError>;
    fn cleanup_old_entries(&self);
    fn cleanup_if_needed(&self);
}

impl FileCacheOps for FileCache {
    fn get_cached(&self, path: &str, metadata: &std::fs::Metadata) -> Option<String> {
        let guard = self.read();
        guard.get(path).and_then(|meta| {
            if meta.is_valid(metadata) {
                Some(meta.cid.clone())
            } else {
                None
            }
        })
    }

    fn update_cache(&self, path: String, metadata: &std::fs::Metadata, cid: String) -> Result<(), ScanError> {
        self.cleanup_if_needed();
        let file_metadata = FileMetadata::new(metadata, cid)?;
        self.write().insert(path, file_metadata);
        Ok(())
    }

    fn cleanup_old_entries(&self) {
        let now = std::time::SystemTime::now();
        self.write().retain(|_, meta| {
            meta.last_check.elapsed().unwrap_or_default().as_secs() < 3600
        });
    }

    fn cleanup_if_needed(&self) {
        let cache = self.read();
        let total_size: usize = cache.values()
            .map(|meta| std::mem::size_of_val(&meta.cid) + meta.cid.len())
            .sum();
            
        if total_size > MAX_CACHE_MEMORY || cache.len() > CACHE_SIZE_LIMIT {
            drop(cache); // Release read lock
            self.cleanup_old_entries();
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub timestamp: String,
    pub files: HashMap<String, String>, // CIDv0 -> Path
}

#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("Home directory not found")]
    NoHomeDir,
    #[error("Scan timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("File metadata error: {0}")]
    MetadataError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
}

fn hash_file(path: &std::path::Path) -> io::Result<(Vec<u8>, u64)> {
    let mut file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    
    match metadata.len() {
        0..=8192 => hash_small_file(&mut file, metadata.len()),
        8193..=1_048_576 => hash_medium_file(&mut file),
        1_048_577..=104_857_600 => hash_large_file(&file),
        _ => Err(io::Error::new(io::ErrorKind::Other, "File too large")),
    }
}

fn hash_small_file(file: &fs::File, size: u64) -> io::Result<(Vec<u8>, u64)> {
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    Ok((hasher.finalize().to_vec(), size))
}

fn hash_medium_file(file: &fs::File) -> io::Result<(Vec<u8>, u64)> {
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0; BUFFER_SIZE];
    let mut total_bytes = 0;
    
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 { break; }
        hasher.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }
    
    Ok((hasher.finalize().to_vec(), total_bytes))
}

fn hash_large_file(file: &fs::File) -> io::Result<(Vec<u8>, u64)> {
    let metadata = file.metadata()?;
    let mmap = unsafe { Mmap::map(file)? };
    let mut hasher = Sha256::new();
    hasher.update(&mmap);
    Ok((hasher.finalize().to_vec(), metadata.len()))
}

#[derive(Debug)]
struct ScanMetrics {
    processed: AtomicUsize,
    skipped: AtomicUsize,
    bytes: AtomicUsize,
    cancelled: AtomicBool,
}

#[derive(Debug)]
struct ScanContext {
    metrics: ScanMetrics,
    chunk_size: usize,
}

impl ScanContext {
    fn new() -> Self {
        Self {
            metrics: ScanMetrics {
                processed: AtomicUsize::new(0),
                skipped: AtomicUsize::new(0),
                bytes: AtomicUsize::new(0),
                cancelled: AtomicBool::new(false),
            },
            chunk_size: 1024 * 1024, // 1MB chunks for streaming
        }
    }
}

pub fn scan_home(cfg: &Config, prev: Option<&ScanResult>) -> Result<ScanResult, ScanError> {
    let start = std::time::Instant::now();
    let cache = &*CACHE;
    let home = dirs::home_dir().ok_or(ScanError::NoHomeDir)?;
    let timestamp = Utc::now().to_rfc3339();

    let prev_files = prev.map(|p| &p.files).unwrap_or(&HashMap::new());

    let files: HashMap<_, _> = WalkDir::new(&home)
        .into_iter()
        .par_bridge()
        .filter_map(|e| {
            if start.elapsed() > SCAN_TIMEOUT {
                return None;
            }
            let entry = e.ok()?;
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            
            // Check cache first
            if let Some(cached_cid) = cache.get_cached(path.to_str()?, &metadata) {
                return Some((cached_cid, path.to_string_lossy().into_owned()));
            }
            
            Some(entry)
        })
        .filter(|entry| {
            let path = entry.path();
            if let Ok(metadata) = entry.metadata() {
                entry.file_type().is_file() && 
                !IGNORED_PATTERNS.iter().any(|p| path.to_string_lossy().contains(p)) &&
                !cfg.exceptions.iter().any(|e| !e.is_empty() && path.starts_with(e)) &&
                prev_files.values().all(|p| p != &path.to_string_lossy())
            } else {
                false
            }
        })
        .filter_map(|entry| {
            let path = entry.path();
            hash_file(path).ok().and_then(|(hash, _)| {
                let code = Code::Sha2_256;
                let digest = code.digest(&hash);
                let cid = Cid::new_v1(0x70, digest);
                let metadata = entry.metadata().ok()?;
                cache.update_cache(path.to_string_lossy().into_owned(), &metadata, cid.to_string()).ok()?;
                Some((cid.to_string(), path.to_string_lossy().into_owned()))
            })
        })
        .flatten()
        .collect();

    // Merge with previous unchanged files
    let mut all_files = prev_files.clone();
    all_files.extend(files);

    if start.elapsed() > SCAN_TIMEOUT {
        return Err(ScanError::Timeout);
    }

    info!("Scanned {} files ({} new/changed)", all_files.len(), files.len());
    Ok(ScanResult { timestamp, files: all_files })
}