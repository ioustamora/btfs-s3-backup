use aws_sdk_s3::{
    error::SdkError,
    operation::{
        get_object::GetObjectError,
        list_objects_v2::ListObjectsV2Error,
        put_object::PutObjectError,
        create_multipart_upload::CreateMultipartUploadError,
        upload_part::UploadPartError,
        complete_multipart_upload::CompleteMultipartUploadError,
    },
    primitives::{ByteStream, ByteStreamError},
    types::{CompletedMultipartUpload, CompletedPart, ChecksumAlgorithm},
    Client, Config,
};
use aws_config::Region;
use governor::{
    clock::DefaultClock,
    RateLimiter,
    Quota,
};
use std::io::Read;
use bytes::Buf;
use std::sync::Arc;
use std::time::Duration;
use governor::{state::{direct::NotKeyed, InMemoryState}, DefaultDirectRateLimiter, middleware::NoOpMiddleware};
use aws_sdk_s3::config::retry::RetryConfig as AwsRetryConfig;
use aws_sdk_s3::types::{ObjectIdentifier};

use aws_config::meta::region::RegionProviderChain;
use std::fs::{self};
use tokio::io::AsyncReadExt;
use log::{info, error};
use chrono::{DateTime, Utc};
use std::num::NonZeroU32;
use backoff::ExponentialBackoff;
use std::future::Future;
use futures::stream::{self, StreamExt, TryStreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use futures::future::{self, TryFutureExt};
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use tokio::sync::Semaphore;
use tokio::io::AsyncWriteExt;

use crate::scan::ScanResult;
use crate::encrypt::{BackupData, BackupEntry};

const MULTIPART_THRESHOLD: usize = 5 * 1024 * 1024; // 5MB
const UPLOAD_PART_SIZE: usize = 5 * 1024 * 1024;

#[derive(thiserror::Error, Debug)]
pub enum S3Error {
    #[error("AWS SDK error: {0}")]
    Aws(#[from] SdkError<PutObjectError>),
    #[error("Rate limit exceeded")]
    RateLimit,
    #[error("Upload failed: {0}")]
    UploadFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Get object error: {0}")]
    GetObject(#[from] SdkError<GetObjectError>),
    #[error("List objects error: {0}")]
    ListObjects(#[from] SdkError<ListObjectsV2Error>),
    #[error("Max retries exceeded")]
    MaxRetries,
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Retryable error: {0}")]
    RetryableError(String),
    #[error("Upload failed with stream error: {0}")]
    StreamError(#[from] ByteStreamError),
    #[error("Create multipart upload error: {0}")]
    CreateMultipart(#[from] SdkError<CreateMultipartUploadError>),
    #[error("Upload part error: {0}")]
    UploadPart(#[from] SdkError<UploadPartError>),
    #[error("Complete multipart error: {0}")]
    CompleteMultipart(#[from] SdkError<CompleteMultipartUploadError>),
}

pub async fn init_client(cfg: &crate::config::Config) -> Result<Client, Box<dyn std::error::Error>> {
    let region = Region::new("btfs");
    let config = Config::builder()
        .endpoint_url(&cfg.s3_endpoint)
        .region(region)
        .build();
    Ok(Client::from_conf(config))
}

pub async fn ensure_bucket(client: &Client, bucket: &str) -> Result<(), Box<dyn std::error::Error>> {
    let buckets = client.list_buckets().await?.buckets.unwrap_or_default();
    if !buckets.iter().any(|b| b.name.as_deref() == Some(bucket)) {
        info!("Creating bucket '{}'", bucket);
        client.create_bucket().bucket(bucket).send().await?;
    }
    Ok(())
}

pub async fn download_latest_scan(client: &Client, bucket: &str) -> Result<Option<ScanResult>, Box<dyn std::error::Error>> {
    let mut latest_key = None;
    let mut latest_time = None;

    let mut continuation_token = None;
    loop {
        let resp = client.list_objects_v2()
            .bucket(bucket)
            .prefix("scan-")
            .set_continuation_token(continuation_token.take())
            .send()
            .await?;

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
        let get_resp = client.get_object()
            .bucket(bucket)
            .key(key.clone())
            .send()
            .await?;

        let mut encrypted = Vec::new();
        get_resp.body.collect().await?.into_bytes().reader().read_to_end(&mut encrypted).await?;
        let decrypted = crate::encrypt::decrypt_file(&encrypted)?;
        let scan: ScanResult = serde_json::from_slice(&decrypted)?;
        Ok(Some(scan))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
pub struct UploadProgress {
    total_files: usize,
    total_bytes: u64,
    uploaded_files: AtomicUsize,
    uploaded_bytes: AtomicU64,
}

impl UploadProgress {
    pub fn new(total_files: usize, total_bytes: u64) -> Self {
        Self {
            total_files,
            total_bytes,
            uploaded_files: AtomicUsize::new(0),
            uploaded_bytes: AtomicU64::new(0),
        }
    }
}

#[derive(Debug)]
struct UploadState {
    progress: Arc<UploadProgress>,
    pb: ProgressBar,
    stats: UploadStats,
}

#[derive(Debug)]
struct UploadStats {
    speed: AtomicU64,
    last_update: AtomicU64,
}

impl UploadState {
    fn increment_bytes(&self, bytes: u64) {
        self.progress.uploaded_bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pb.set_position(self.progress.uploaded_bytes.load(Ordering::Relaxed));
    }

    fn update_speed(&self, bytes: u64) {
        let now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        let last = self.stats.last_update.load(Ordering::Relaxed);
        if now > last {
            let speed = bytes / (now - last);
            self.stats.speed.store(speed, Ordering::Relaxed);
            self.stats.last_update.store(now, Ordering::Relaxed);
            let readable = bytesize::to_string(speed, true);
            self.pb.set_message(format!("Speed: {}/s", readable));
        }
    }

    async fn upload_large_file(&self, client: &Client, key: &str, data: Vec<u8>) -> Result<(), S3Error> {
        let upload_id = client.create_multipart_upload()
            .bucket("backups")
            .key(key)
            .send()
            .await?
            .upload_id
            .ok_or_else(|| S3Error::UploadFailed("No upload ID".into()))?;

        let mut parts = Vec::new();
        let mut part_number = 1;

        for chunk in data.chunks(UPLOAD_PART_SIZE) {
            let part = client.upload_part()
                .bucket("backups")
                .key(key)
                .upload_id(&upload_id)
                .body(ByteStream::from(chunk.to_vec()))
                .part_number(part_number)
                .send()
                .await?;

            parts.push(CompletedPart::builder()
                .e_tag(part.e_tag.unwrap_or_default())
                .part_number(part_number)
                .build());

            part_number += 1;
            self.increment_bytes(chunk.len() as u64);
        }

        client.complete_multipart_upload()
            .bucket("backups")
            .key(key)
            .upload_id(upload_id)
            .multipart_upload(CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build())
            .send()
            .await?;

        Ok(())
    }

    async fn start_upload(&self, client: &Client, key: &str) -> Result<String, S3Error> {
        let create_upload = client.create_multipart_upload()
            .bucket("backups")
            .key(key)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .send()
            .await?;

        Ok(create_upload.upload_id()
            .ok_or_else(|| S3Error::UploadFailed("No upload ID".to_string()))?.to_string())
    }

    async fn upload_with_retry(&self, client: &Client, key: &str, data: Vec<u8>) -> Result<(), S3Error> {
        let mut backoff = ExponentialBackoff::default();
        backoff.max_elapsed_time = Some(Duration::from_secs(300));

        backoff::future::retry_notify(
            backoff,
            || async {
                client.put_object()
                    .bucket("backups")
                    .key(key)
                    .body(ByteStream::from(data.clone()))
                    .send()
                    .await
                    .map_err(|e| backoff::Error::Permanent(S3Error::Aws(e)))
            },
            |err, duration| {
                error!("Retry error after {:?}: {}", duration, err);
            },
        ).await
    }
}

pub async fn upload_results(client: &Client, scan: &ScanResult, backup: &BackupData, cfg: &crate::config::Config) -> Result<(), S3Error> {
    let limiter = RateLimiter::direct(Default::default());

    let progress = Arc::new(UploadProgress::new(backup.len(), backup.values()
        .filter_map(|e| fs::metadata(&e.pathx).ok())
        .map(|m| m.len())
        .sum()));

    let pb = ProgressBar::new(progress.total_bytes);
    let style = ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta}) - {msg}")?
        .progress_chars("=>-");
    pb.set_style(style);

    let upload_semaphore = Arc::new(Semaphore::new(cfg.max_concurrent_uploads));

    // Upload metadata files
    let scan_json = serde_json::to_vec(scan).map_err(|e| S3Error::UploadFailed(e.to_string()))?;
    let backup_json = serde_json::to_vec(backup).map_err(|e| S3Error::UploadFailed(e.to_string()))?;

    // Upload metadata first
    let scan_key = format!("scan-{}.json.x", scan.timestamp);
    let backup_key = format!("backup-{}.json.x", scan.timestamp);

    // Upload metadata first with retry and progress
    let results = stream::iter([(scan_key.clone(), scan_json), (backup_key.clone(), backup_json)])
        .map(|(key, data)| async {
            let retries = cfg.max_retries;
            for attempt in 0..retries {
                match retry_with_backoff(|| async {
                    limiter.until_ready(DefaultClock::default()).await;
                    client.put_object()
                        .bucket("backups")
                        .key(&key)
                        .body(ByteStream::from(data.clone()))
                        .send()
                        .await
                }, RetryConfig::default()).await {
                    Ok(result) => return Ok(result),
                    Err(e) if attempt < retries - 1 => {
                        error!("Upload attempt {} failed: {}", attempt + 1, e);
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(S3Error::MaxRetries)
        })
        .buffer_unordered(2)
        .try_collect::<Vec<_>>()
        .await?;

    // Upload files with batching and rate limiting
    stream::iter(backup.values())
        .map(|entry| async {
            let permit = upload_semaphore.acquire().await?;
            let result = upload_file(client, entry, &limiter).await;
            drop(permit);
            result
        })
        .buffer_unordered(cfg.max_concurrent_uploads)
        .try_collect::<Vec<_>>()
        .await?;

    Ok(())
}

#[derive(Debug)]
struct RetryConfig {
    max_attempts: u32,
    initial_interval: Duration,
    max_interval: Duration,
    max_elapsed_time: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(30),
            max_elapsed_time: Duration::from_secs(300),
        }
    }
}

async fn retry_with_backoff<F, Fut, T, E>(f: F, config: RetryConfig) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    let mut backoff = ExponentialBackoff {
        initial_interval: config.initial_interval,
        max_interval: config.max_interval,
        max_elapsed_time: Some(config.max_elapsed_time),
        ..ExponentialBackoff::default()
    };
    
    backoff::future::retry(backoff, || async {
        f().await.map_err(backoff::Error::Transient)
    }).await
}

async fn upload_file(client: &Client, entry: &BackupEntry, limiter: &DefaultDirectRateLimiter) -> Result<(), S3Error> {
    let encrypted_bytes = fs::read(&entry.pathx.split('/').last().unwrap())?;
    
    if encrypted_bytes.len() > MULTIPART_THRESHOLD {
        // Use multipart upload for large files
        let upload_id = client.create_multipart_upload()
            .bucket("backups")
            .key(&entry.pathx)
            .checksum_algorithm(ChecksumAlgorithm::Sha256)
            .send()
            .await?
            .upload_id
            .ok_or_else(|| S3Error::UploadFailed("No upload ID".into()))?;

        // ...existing multipart upload code...
    } else {
        // Regular upload for small files
        limiter.until_ready(DefaultClock::default()).await;
        client.put_object()
            .bucket("backups")
            .key(&entry.pathx)
            .body(ByteStream::from(encrypted_bytes))
            .send()
            .await?;
    }
    Ok(())
}

pub async fn restore_backup(client: &Client, timestamp: &str, dest_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dest_dir)?;
    let backup_key = format!("backup-{}.json.x", timestamp);
    let scan_key = format!("scan-{}.json.x", timestamp);

    // Download and decrypt backup JSON
    let backup_resp = client.get_object()
        .bucket("backups")
        .key(backup_key.clone())
        .send()
        .await?;
    let mut backup_encrypted = Vec::new();
    backup_resp.body.collect().await?.into_bytes().reader().read_to_end(&mut backup_encrypted).await?;
    let backup_decrypted = crate::encrypt::decrypt_file(&backup_encrypted)?;
    let backup: BackupData = serde_json::from_slice(&backup_decrypted)?;

    // Restore files
    for entry in backup.values() {
        let resp = client.get_object()
            .bucket("backups")
            .key(entry.pathx.clone())
            .send()
            .await?;
        let mut encrypted = Vec::new();
        resp.body.collect().await?.into_bytes().reader().read_to_end(&mut encrypted).await?;
        let decrypted = crate::encrypt::decrypt_file(&encrypted)?;

        let dest_path = format!("{}/{}", dest_dir, entry.path.split('/').last().unwrap());
        fs::write(&dest_path, decrypted)?;
        info!("Restored {}", dest_path);
    }

    // Optionally restore scan JSON
    let scan_resp = client.get_object()
        .bucket("backups")
        .key(scan_key.clone())
        .send()
        .await?;
    let mut scan_encrypted = Vec::new();
    scan_resp.body.collect().await?.into_bytes().reader().read_to_end(&mut scan_encrypted).await?;
    let scan_decrypted = crate::encrypt::decrypt_file(&scan_encrypted)?;
    fs::write(format!("{}/scan-{}.json", dest_dir, timestamp), scan_decrypted)?;

    info!("Restored backup from {}", timestamp);
    Ok(())
}