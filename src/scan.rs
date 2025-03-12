use cid::{Cid, Version};
use multihash::{Code, MultihashDigest};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use chrono::Utc;
use log::{info, warn};

use crate::config::Config;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub timestamp: String,
    pub files: HashMap<String, String>, // CIDv0 -> Path
}

pub fn scan_home(cfg: &Config, prev: Option<&ScanResult>) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let home = dirs::home_dir().ok_or("No home dir")?;
    let mut files = HashMap::new();
    let timestamp = Utc::now().to_rfc3339();

    for entry in WalkDir::new(&home).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if cfg.exceptions.iter().any(|e| !e.is_empty() && path.starts_with(e)) || !path.is_file() {
            continue;
        }
        if let Ok(bytes) = fs::read(path) {
            let hash = Sha256::digest(&bytes);
            let multihash = Code::Sha2_256.digest(&hash);
            let cid_v0 = Cid::new_v0(multihash)?.to_string();
            files.insert(cid_v0, path.to_string_lossy().into_owned());
        } else {
            warn!("Failed to read file: {:?}", path);
        }
    }

    info!("Scanned {} files", files.len());
    Ok(ScanResult { timestamp, files })
}