use std::time::Duration;
use tokio::time::{sleep, timeout};
use clap::Parser;
use log::{info, error, warn};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use indicatif::ProgressBar;
use aws_sdk_s3::Client;
use tokio::signal;
use tokio::sync::broadcast;
use std::sync::atomic::AtomicBool;

mod config;
mod s3;
mod scan;
mod encrypt;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const GRACEFUL_SHUTDOWN_DURATION: Duration = Duration::from_secs(10);

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

    let s3_client = s3::init_client(&cfg).await?;
    s3::ensure_bucket(&s3_client, "backups").await?;
    encrypt::ensure_keys()?;

    if let Some(timestamp) = cli.restore {
        let pb = ProgressBar::new_spinner();
        pb.set_message("Restoring backup...");
        s3::restore_backup(&s3_client, &timestamp, "restore").await?;
        pb.finish_with_message("Restore complete");
        return Ok(());
    }

    let mut latest_scan = if cli.dry_run {
        None
    } else {
        s3::download_latest_scan(&s3_client, "backups").await?
    };

    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    
    tokio::spawn(async move {
        match signal::ctrl_c().await {
            Ok(()) => {
                info!("Shutdown signal received");
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            }
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
            }
        }
    });

    while running.load(std::sync::atomic::Ordering::SeqCst) {
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
    }

    info!("Shutting down gracefully");
    Ok(())
}

async fn run_scan(s3_client: &Client, cfg: &config::Config, latest_scan: &mut Option<scan::ScanResult>, dry_run: bool) -> Result<(), Box<dyn std::error::Error>> {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(100));
    
    match timeout(SHUTDOWN_TIMEOUT, async {
        info!("Starting scan");
        let scan_result = scan::scan_home(cfg, latest_scan.as_ref())?;
        pb.set_message("Processing changes...");
        let backup_data = encrypt::process_changes(&scan_result, cfg)?;

        if !dry_run {
            pb.set_message("Uploading to S3...");
            s3::upload_results(s3_client, &scan_result, &backup_data, cfg).await?;
            *latest_scan = Some(scan_result);
        }
        
        pb.finish_with_message(format!("Processed {} files", backup_data.len()));
        Ok(())
    }).await {
        Ok(result) => {
            pb.finish_and_clear();
            result
        }
        Err(_) => {
            pb.finish_with_message("Operation timed out");
            Err("Operation timed out".into())
        }
    }
}