use clap::Parser;
use gatee::run_server;
use gatee_ca::CertificateAuthority;
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
    #[arg(short, long, env = "GATEE_LISTEN", default_value = "0.0.0.0:7890")]
    listen: String,

    #[arg(short, long, env = "GATEE_DB", default_value = "data/gatee.db")]
    db: PathBuf,

    #[arg(short, long, env = "GATEE_PASSWORD")]
    password: Option<String>,

    #[arg(long, env = "GATEE_CA_CERT", default_value = "data/ca.pem")]
    ca_cert: PathBuf,

    #[arg(long, env = "GATEE_CA_KEY", default_value = "data/ca-key.pem")]
    ca_key: PathBuf,
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
    info!("Starting Gatee with database: {}", cli.db.display());

    let storage = Storage::new_from_path(&cli.db).await?;
    storage.ensure_seeded(cli.password.as_deref()).await?;

    let ca = Arc::new(CertificateAuthority::load_or_generate(
        &cli.ca_cert,
        &cli.ca_key,
    )?);

    let logger = LogEmitter::new(storage.clone(), 4096);
    let state = Arc::new(GatewayState::new_with_storage(storage.clone()).await?);

    let web_router = build_web_router(Arc::clone(&state), storage, Arc::clone(&ca));

    let listener = TcpListener::bind(&cli.listen).await?;
    info!(
        "Gatee listening on {}, CA cert: {}",
        cli.listen,
        cli.ca_cert.display()
    );

    run_server(listener, state, ca, web_router, logger).await?;
    Ok(())
}
