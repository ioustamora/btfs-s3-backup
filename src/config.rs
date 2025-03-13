use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid S3 endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub s3_endpoint: String,
    pub scan_interval_minutes: u64, // Used only in polling mode
    pub exceptions: Vec<String>,
    pub temp_dir: PathBuf,
    pub max_concurrent_uploads: usize,
    pub upload_rate_limit: u32,      // Uploads per second
    pub scan_batch_size: usize,      // Files per batch
    pub max_retries: u32,            // Max retry attempts
}

impl Config {
    fn validate(&self) -> Result<(), ConfigError> {
        if !self.s3_endpoint.starts_with("http") {
            return Err(ConfigError::InvalidEndpoint(self.s3_endpoint.clone()));
        }
        if self.upload_rate_limit == 0 {
            return Err(ConfigError::InvalidConfig("Upload rate limit cannot be zero".into()));
        }
        if self.max_concurrent_uploads == 0 {
            return Err(ConfigError::InvalidConfig("max_concurrent_uploads cannot be zero".into()));
        }
        if self.scan_batch_size == 0 {
            return Err(ConfigError::InvalidConfig("scan_batch_size cannot be zero".into()));
        }
        if self.max_retries == 0 {
            return Err(ConfigError::InvalidConfig("max_retries cannot be zero".into()));
        }
        Ok(())
    }

    fn with_defaults() -> Self {
        Self {
            s3_endpoint: "http://localhost:6001".to_string(),
            scan_interval_minutes: 100,
            exceptions: vec![],
            temp_dir: PathBuf::from("temp"),
            max_concurrent_uploads: 4,
            upload_rate_limit: 10,
            scan_batch_size: 1000,
            max_retries: 3,
        }
    }
}

pub fn load_or_create_config() -> Result<Config, ConfigError> {
    let path = "config.json";
    if Path::new(path).exists() {
        let file = File::open(path)?;
        let config: Config = serde_json::from_reader(file)?;
        config.validate()?;
        Ok(config)
    } else {
        let default = Config::with_defaults();
        save_config(&default)?;
        Ok(default)
    }
}

pub fn save_config(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("config.json")?;
    serde_json::to_writer_pretty(file, cfg)?;
    Ok(())
}