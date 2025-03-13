use dryoc::dryocbox::{DryocBox, PublicKey, SecretKey};
use dryoc::types::StackByteArray;
use dryoc::keypair::StackKeyPair;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use log::{info, debug};
use cid::{Cid, Version};
use multihash::{Code, MultihashDigest};
use sha2::{Digest, Sha256};
use rayon::prelude::*;

use crate::scan::ScanResult;

const MAX_FILE_SIZE: usize = 1024 * 1024 * 100; // 100MB limit

#[derive(thiserror::Error, Debug)]
pub enum EncryptError {
    #[error("File too large: {size} bytes")]
    FileTooLarge { size: usize },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Key error: {0}")]
    KeyError(String),
    #[error("CID error: {0}")]
    CidError(String),
    #[error("Max retries exceeded")]
    MaxRetries,
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Invalid key data: {0}")]
    InvalidKey(String),
    #[error("Buffer too large: {size} bytes")]
    BufferTooLarge { size: usize },
}

impl From<dryoc::Error> for EncryptError {
    fn from(err: dryoc::Error) -> Self {
        EncryptError::Encryption(err.to_string())
    }
}

impl From<cid::Error> for EncryptError {
    fn from(err: cid::Error) -> Self {
        EncryptError::CidError(err.to_string())
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupEntry {
    pub cid_v0: String,
    pub cid_v1: String,
    pub cid_v0x: String,
    pub cid_v1x: String,
    pub path: String,
    pub pathx: String,
}

pub type BackupData = HashMap<String, BackupEntry>;

pub fn ensure_keys() -> Result<(), Box<dyn std::error::Error>> {
    let secret_path = "secret.key";
    let public_path = "public.key";

    if !std::path::Path::new(secret_path).exists() || !std::path::Path::new(public_path).exists() {
        info!("Generating sodix-compatible keypair");
        let keypair = StackKeyPair::gen();
        let mut secret_file = File::create(secret_path)?;
        let mut public_file = File::create(public_path)?;
        secret_file.write_all(&keypair.secret_key.to_bytes())?;
        public_file.write_all(&keypair.public_key.to_bytes())?;
    }
    Ok(())
}

pub fn encrypt_file(data: &[u8]) -> Result<Vec<u8>, EncryptError> {
    if data.len() > MAX_FILE_SIZE {
        return Err(EncryptError::BufferTooLarge { size: data.len() });
    }
    
    let secret_key = SecretKey::new(fs::read("secret.key")
        .map_err(|e| EncryptError::Io(e))?);
    let public_key = PublicKey::new(fs::read("public.key")
        .map_err(|e| EncryptError::Io(e))?);

    let encrypted = DryocBox::encrypt_to_vecbox(
        data,
        &public_key,
        &secret_key,
        None // No sender secret key needed
    ).map_err(|e| EncryptError::Encryption(e.to_string()))?;

    Ok(encrypted.to_vec())
}

pub fn decrypt_file(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret_key = SecretKey::from_bytes(&fs::read("secret.key")?)?;
    let public_key = PublicKey::from_bytes(&fs::read("public.key")?)?;
    let dryoc_box = DryocBox::from_bytes(data)?;
    let decrypted = dryoc_box.decrypt_to_vec(&public_key, &secret_key)?;
    Ok(decrypted)
}

pub fn process_changes(scan: &ScanResult, cfg: &crate::config::Config) -> Result<BackupData, EncryptError> {
    let mut backup = HashMap::new();
    fs::create_dir_all(&cfg.temp_dir)?;

    let results: Vec<_> = scan.files.par_iter()
        .map(|(cid_v0, path)| -> Result<Option<BackupEntry>, EncryptError> {
            let bytes = fs::read(path).map_err(|e| EncryptError::Io(e))?;
            if bytes.len() > MAX_FILE_SIZE {
                return Ok(None);
            }

            let multihash = Code::Sha2_256.digest(&Sha256::digest(&bytes));
            let cid_v1 = Cid::new(Version::V1, cid::Codec::DagProtobuf, multihash).map_err(|e| EncryptError::CidError(e.to_string()))?.to_string();

            let encrypted = encrypt_file(&bytes)?;
            let encrypted_name = format!("{}.x", path.split('/').last().unwrap_or("file"));
            let encrypted_path = cfg.temp_dir.join(&encrypted_name);
            fs::write(&encrypted_path, &encrypted).map_err(|e| EncryptError::Io(e))?;

            let encrypted_hash = Sha256::digest(&encrypted);
            let encrypted_multihash = Code::Sha2_256.digest(&encrypted_hash);
            let cid_v0x = Cid::new_v0(encrypted_multihash).map_err(|e| EncryptError::CidError(e.to_string()))?.to_string();
            let cid_v1x = Cid::new(Version::V1, cid::Codec::DagProtobuf, encrypted_multihash).map_err(|e| EncryptError::CidError(e.to_string()))?.to_string();

            let pathx = format!("data/{}/{}", &cid_v0x[..4], encrypted_name);
            Ok(Some(BackupEntry {
                cid_v0: cid_v0.to_string(),
                cid_v1,
                cid_v0x,
                cid_v1x,
                path: path.to_string(),
                pathx,
            }))
        })
        .filter_map(|r| r.ok().flatten())
        .collect();

    for entry in results {
        backup.insert(entry.cid_v0.clone(), entry);
    }

    cleanup_temp_files(&cfg.temp_dir, &backup);
    info!("Processed {} changes", backup.len());
    Ok(backup)
}

fn cleanup_temp_files(temp_dir: &Path, backup: &BackupData) {
    if let Ok(entries) = fs::read_dir(temp_dir) {
        for entry in entries.filter_map(Result::ok) {
            if !backup.values().any(|b| entry.path().ends_with(&b.pathx)) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}