use dryoc::dryocbox::{DryocBox, PublicKey, SecretKey};
use dryoc::keypair::StackKeyPair;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use log::{info, debug, error};

use crate::scan::ScanResult;

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

pub fn encrypt_file(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret_key = SecretKey::from_bytes(&fs::read("secret.key")?)?;
    let public_key = PublicKey::from_bytes(&fs::read("public.key")?)?;
    let encrypted = DryocBox::encrypt_to_vecbox(data, &public_key, &secret_key)?;
    Ok(encrypted.to_vec())
}

pub fn decrypt_file(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secret_key = SecretKey::from_bytes(&fs::read("secret.key")?)?;
    let public_key = PublicKey::from_bytes(&fs::read("public.key")?)?;
    let dryoc_box = DryocBox::from_bytes(data)?;
    let decrypted = dryoc_box.decrypt_to_vec(&public_key, &secret_key)?;
    Ok(decrypted)
}

pub fn process_changes(scan: &ScanResult, _cfg: &crate::config::Config) -> Result<BackupData, Box<dyn std::error::Error>> {
    let mut backup = HashMap::new();
    let prev_files = scan.files.clone(); // For simplicity, assume all files are new if no prev scan

    for (cid_v0, path) in &scan.files {
        let bytes = fs::read(path)?;
        let multihash = Code::Sha2_256.digest(&Sha256::digest(&bytes));
        let cid_v1 = Cid::new(Version::V1, cid::Codec::DagProtobuf, multihash)?.to_string();

        let encrypted = encrypt_file(&bytes)?;
        let encrypted_name = format!("{}.x", path.split('/').last().unwrap_or("file"));
        let encrypted_path = encrypted_name.clone();
        fs::write(&encrypted_path, &encrypted)?;

        let encrypted_hash = Sha256::digest(&encrypted);
        let encrypted_multihash = Code::Sha2_256.digest(&encrypted_hash);
        let cid_v0x = Cid::new_v0(encrypted_multihash)?.to_string();
        let cid_v1x = Cid::new(Version::V1, cid::Codec::DagProtobuf, encrypted_multihash)?.to_string();

        let pathx = format!("backups/{}", encrypted_name);
        backup.insert(cid_v0.clone(), BackupEntry {
            cid_v0: cid_v0.clone(),
            cid_v1,
            cid_v0x,
            cid_v1x,
            path: path.clone(),
            pathx,
        });
    }

    for entry in backup.values() {
        debug!("Processed: {} -> {}", entry.path, entry.pathx);
    }
    info!("Processed {} changes", backup.len());
    Ok(backup)
}