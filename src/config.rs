use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub s3_endpoint: String,
    pub scan_interval_minutes: u64, // Used only in polling mode
    pub exceptions: Vec<String>,
}

pub fn load_or_create_config() -> Result<Config, Box<dyn std::error::Error>> {
    let path = "config.json";
    if Path::new(path).exists() {
        let file = File::open(path)?;
        Ok(serde_json::from_reader(file)?)
    } else {
        let default = Config {
            s3_endpoint: "http://localhost:6001".to_string(),
            scan_interval_minutes: 100,
            exceptions: vec![],
        };
        save_config(&default)?;
        Ok(default)
    }
}

pub fn save_config(cfg: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let file = File::create("config.json")?;
    serde_json::to_writer_pretty(file, cfg)?;
    Ok(())
}