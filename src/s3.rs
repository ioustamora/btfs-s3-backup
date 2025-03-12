use rusoto_core::Region;
use rusoto_s3::{S3Client, S3, CreateBucketRequest, ListObjectsV2Request, PutObjectRequest, GetObjectRequest};
use std::fs::{self, File};
use std::io::Write;
use tokio::io::AsyncReadExt;
use log::{info, warn, error};
use chrono::{DateTime, Utc};

use crate::scan::ScanResult;
use crate::encrypt::{BackupData, BackupEntry};

pub fn init_client(cfg: &crate::config::Config) -> Result<S3Client, Box<dyn std::error::Error>> {
    let region = Region::Custom {
        name: "btfs".to_string(),
        endpoint: cfg.s3_endpoint.clone(),
    };
    Ok(S3Client::new(region))
}

pub async fn ensure_bucket(client: &S3Client, bucket: &str) -> Result<(), Box<dyn std::error::Error>> {
    let buckets = client.list_buckets().await?.buckets.unwrap_or_default();
    if !buckets.iter().any(|b| b.name.as_deref() == Some(bucket)) {
        info!("Creating bucket '{}'", bucket);
        client.create_bucket(CreateBucketRequest { bucket: bucket.to_string(), ..Default::default() }).await?;
    }
    Ok(())
}

pub async fn download_latest_scan(client: &S3Client, bucket: &str) -> Result<Option<ScanResult>, Box<dyn std::error::Error>> {
    let mut latest_key = None;
    let mut latest_time = None;

    let mut continuation_token = None;
    loop {
        let resp = client.list_objects_v2(ListObjectsV2Request {
            bucket: bucket.to_string(),
            prefix: Some("scan-".to_string()),
            continuation_token: continuation_token.take(),
            ..Default::default()
        }).await?;

        for obj in resp.contents.unwrap_or_default() {
            if let Some(key) = &obj.key {
                if key.ends_with(".json.x") {
                    let ts_str = &key[5..key.len() - 7];
                    if let Ok(time) = DateTime::parse_from_rfc3339(ts_str) {
                        if latest_time.map_or(true, |t| time > t) {
                            latest_time = Some(time);
                            latest_key = Some(key.clone());
                        }
                    }
                }
            }
        }

        continuation_token = resp.next_continuation_token;
        if continuation_token.is_none() { break; }
    }

    if let Some(key) = latest_key {
        info!("Downloading latest scan: {}", key);
        let get_resp = client.get_object(GetObjectRequest {
            bucket: bucket.to_string(),
            key: key.clone(),
            ..Default::default()
        }).await?;

        let mut encrypted = Vec::new();
        get_resp.body.unwrap().into_async_read().read_to_end(&mut encrypted).await?;
        let decrypted = crate::encrypt::decrypt_file(&encrypted)?;
        let scan: ScanResult = serde_json::from_slice(&decrypted)?;
        Ok(Some(scan))
    } else {
        Ok(None)
    }
}

pub async fn upload_results(client: &S3Client, scan: &ScanResult, backup: &BackupData) -> Result<(), Box<dyn std::error::Error>> {
    let scan_json = serde_json::to_vec(&scan)?;
    let backup_json = serde_json::to_vec(&backup)?;

    let scan_encrypted = crate::encrypt::encrypt_file(&scan_json)?;
    let backup_encrypted = crate::encrypt::encrypt_file(&backup_json)?;

    let scan_key = format!("scan-{}.json.x", scan.timestamp);
    let backup_key = format!("backup-{}.json.x", scan.timestamp);

    client.put_object(PutObjectRequest {
        bucket: "backups".to_string(),
        key: scan_key.clone(),
        body: Some(scan_encrypted.into()),
        ..Default::default()
    }).await?;

    client.put_object(PutObjectRequest {
        bucket: "backups".to_string(),
        key: backup_key.clone(),
        body: Some(backup_encrypted.into()),
        ..Default::default()
    }).await?;

    for entry in backup.values() {
        let encrypted_bytes = fs::read(&entry.pathx.split('/').last().unwrap())?;
        client.put_object(PutObjectRequest {
            bucket: "backups".to_string(),
            key: entry.pathx.clone(),
            body: Some(encrypted_bytes.into()),
            ..Default::default()
        }).await?;
    }

    info!("Uploaded {} and {} with {} files", scan_key, backup_key, backup.len());
    Ok(())
}

pub async fn restore_backup(client: &S3Client, timestamp: &str, dest_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dest_dir)?;
    let backup_key = format!("backup-{}.json.x", timestamp);
    let scan_key = format!("scan-{}.json.x", timestamp);

    // Download and decrypt backup JSON
    let backup_resp = client.get_object(GetObjectRequest {
        bucket: "backups".to_string(),
        key: backup_key.clone(),
        ..Default::default()
    }).await?;
    let mut backup_encrypted = Vec::new();
    backup_resp.body.unwrap().into_async_read().read_to_end(&mut backup_encrypted).await?;
    let backup_decrypted = crate::encrypt::decrypt_file(&backup_encrypted)?;
    let backup: BackupData = serde_json::from_slice(&backup_decrypted)?;

    // Restore files
    for entry in backup.values() {
        let resp = client.get_object(GetObjectRequest {
            bucket: "backups".to_string(),
            key: entry.pathx.clone(),
            ..Default::default()
        }).await?;
        let mut encrypted = Vec::new();
        resp.body.unwrap().into_async_read().read_to_end(&mut encrypted).await?;
        let decrypted = crate::encrypt::decrypt_file(&encrypted)?;

        let dest_path = format!("{}/{}", dest_dir, entry.path.split('/').last().unwrap());
        fs::write(&dest_path, decrypted)?;
        info!("Restored {}", dest_path);
    }

    // Optionally restore scan JSON
    let scan_resp = client.get_object(GetObjectRequest {
        bucket: "backups".to_string(),
        key: scan_key.clone(),
        ..Default::default()
    }).await?;
    let mut scan_encrypted = Vec::new();
    scan_resp.body.unwrap().into_async_read().read_to_end(&mut scan_encrypted).await?;
    let scan_decrypted = crate::encrypt::decrypt_file(&scan_encrypted)?;
    fs::write(format!("{}/scan-{}.json", dest_dir, timestamp), scan_decrypted)?;

    info!("Restored backup from {}", timestamp);
    Ok(())
}