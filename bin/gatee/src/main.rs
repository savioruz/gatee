use clap::Parser;
use gatee::run_server;
use gatee_ca::CertificateAuthority;
use gatee_config::Config;
use gatee_core::GatewayState;
use gatee_storage::{LogEmitter, Storage};
use gatee_web::build_web_router;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Gatee High-Performance Modular Forward Gateway"
)]
struct Cli {
    #[arg(short, long, env = "GATEE_CONFIG", default_value = "config.json")]
    config: PathBuf,

    #[arg(short, long, env = "GATEE_DB", default_value = "data/gatee.db")]
    db: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gatee=info,gatee_web=info,gatee_core=info".into()),
        )
        .init();

    let cli = Cli::parse();
    info!("Loading config from: {}", cli.config.display());

    let config = if cli.config.exists() {
        Config::from_file(&cli.config)?
    } else {
        anyhow::bail!("Config file not found at: {}", cli.config.display());
    };

    let ca = Arc::new(CertificateAuthority::load_or_generate(
        &config.ca_cert,
        &config.ca_key,
    )?);

    let storage = Storage::new_from_path(&cli.db).await?;
    let logger = LogEmitter::new(storage.clone(), 4096);
    let state = Arc::new(GatewayState::new(config.clone(), storage.clone()));

    let web_router = build_web_router(Arc::clone(&state), storage, Arc::clone(&ca));

    let listener = TcpListener::bind(&config.listen).await?;
    info!(
        "Gatee listening on {}, CA: {}",
        config.listen, config.ca_cert
    );

    run_server(listener, state, ca, web_router, logger).await?;
    Ok(())
}
