use std::time::Duration;
use tokio::time::sleep;
use clap::Parser;
use log::{info, debug, error};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};

mod config;
mod s3;
mod scan;
mod encrypt;

#[derive(Parser)]
#[command(version, about = "BTFS S3 Backup Client")]
struct Cli {
    /// Set scan interval in minutes (overrides config, enables polling mode)
    #[arg(long)]
    interval: Option<u64>,
    /// Restore a backup by timestamp (e.g., 2025-03-12T12:00:00Z)
    #[arg(long)]
    restore: Option<String>,
    /// Simulate a scan without modifying S3 or files
    #[arg(long)]
    dry_run: bool,
    /// Enable verbose logging
    #[arg(long)]
    verbose: bool,
    /// Set S3 endpoint in config
    #[arg(long)]
    set_endpoint: Option<String>,
    /// Add an exception path to config
    #[arg(long)]
    add_exception: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    env_logger::Builder::new()
        .filter_level(if cli.verbose { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .init();

    let mut cfg = config::load_or_create_config()?;
    if let Some(endpoint) = &cli.set_endpoint {
        cfg.s3_endpoint = endpoint.clone();
        config::save_config(&cfg)?;
        info!("Updated S3 endpoint to {}", endpoint);
        return Ok(());
    }
    if let Some(path) = &cli.add_exception {
        cfg.exceptions.push(path.clone());
        config::save_config(&cfg)?;
        info!("Added exception: {}", path);
        return Ok(());
    }

    let s3_client = s3::init_client(&cfg)?;
    s3::ensure_bucket(&s3_client, "backups").await?;
    encrypt::ensure_keys()?;

    if let Some(timestamp) = cli.restore {
        s3::restore_backup(&s3_client, &timestamp, "restore").await?;
        return Ok(());
    }

    let mut latest_scan = if cli.dry_run {
        None
    } else {
        s3::download_latest_scan(&s3_client, "backups").await?
    };

    if let Some(interval) = cli.interval {
        // Polling mode
        cfg.scan_interval_minutes = interval;
        info!("Starting in polling mode with {} minute intervals", interval);
        loop {
            run_scan(&s3_client, &cfg, &mut latest_scan, cli.dry_run).await?;
            sleep(Duration::from_secs(interval * 60)).await;
        }
    } else {
        // Event watching mode
        info!("Starting in filesystem event watching mode");
        let (tx, rx) = std::sync::mpsc::channel();
        let mut watcher = RecommendedWatcher::new(tx, NotifyConfig::default().with_poll_interval(Duration::from_secs(60)))?;
        watcher.watch(&dirs::home_dir().ok_or("No home dir")?, RecursiveMode::Recursive)?;

        for res in rx {
            if res.is_ok() {
                run_scan(&s3_client, &cfg, &mut latest_scan, cli.dry_run).await?;
            } else {
                warn!("Watcher error: {:?}", res);
                sleep(Duration::from_secs(60)).await; // Fallback polling
                run_scan(&s3_client, &cfg, &mut latest_scan, cli.dry_run).await?;
            }
        }
    }

    Ok(())
}

async fn run_scan(s3_client: &rusoto_s3::S3Client, cfg: &config::Config, latest_scan: &mut Option<scan::ScanResult>, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting scan");
    let scan_result = scan::scan_home(cfg, latest_scan.as_ref())?;
    let backup_data = encrypt::process_changes(&scan_result, cfg)?;

    if !dry_run {
        s3::upload_results(s3_client, &scan_result, &backup_data).await?;
        *latest_scan = Some(scan_result);
    } else {
        debug!("Dry run: {} files scanned, {} changes detected", scan_result.files.len(), backup_data.len());
    }
    Ok(())
}