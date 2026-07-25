pub mod fleet;

use std::sync::Arc;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use fleet::FleetManager;

#[derive(Parser, Debug)]
#[command(name = "sentinel-mgmt")]
#[command(about = "Sentinel AI Management Server")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:7778")]
    listen: String,

    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&args.log_level))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .init();

    info!("Sentinel AI Management Server v0.2.0 starting");

    let fleet = FleetManager::new();
    info!(
        "Fleet manager initialized (listen: {}, agents: {})",
        args.listen,
        fleet.online_count()
    );

    info!("Management Server ready — gRPC endpoint: {}", args.listen);

    tokio::signal::ctrl_c().await?;
    info!("Management Server stopped");

    Ok(())
}
