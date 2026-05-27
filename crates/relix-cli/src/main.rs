mod audit;
mod cli;
mod proxy;
mod rules_loader;

use std::sync::Arc;

use anyhow::Result;
use axum::Router;
use axum::routing::any;
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::audit::AuditLog;
use crate::cli::{Cli, Command};
use crate::proxy::{ProxyState, proxy_handler};
use crate::rules_loader::{expand_tilde, load_rules};

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    match cli.command {
        Command::Start { port, upstream, rules, audit } => start(port, upstream, rules, audit).await,
        Command::Rules { path } => print_rules(&path),
        Command::Logs { audit } => tail_logs(&audit).await,
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_env("RELIX_LOG")
        .unwrap_or_else(|_| EnvFilter::new("relix=info,relix_core=info,info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn start(
    port: u16,
    upstream: String,
    rules_path: std::path::PathBuf,
    audit_path: String,
) -> Result<()> {
    let ruleset = load_rules(&rules_path).unwrap_or_else(|err| {
        warn!(error = %err, "failed to load rules, starting empty");
        relix_core::RuleSet::default()
    });
    info!(rules = ruleset.rules.len(), upstream = %upstream, port, "starting Relix");

    let audit = AuditLog::open(expand_tilde(&audit_path)).await?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()?;

    let state = ProxyState {
        upstream,
        client,
        rules: Arc::new(ruleset),
        audit,
    };

    let app = Router::new()
        .route("/", any(proxy_handler))
        .route("/{*path}", any(proxy_handler))
        .with_state(state);

    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Relix listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn print_rules(path: &std::path::Path) -> Result<()> {
    let ruleset = load_rules(path)?;
    println!("{}", serde_yaml::to_string(&ruleset)?);
    Ok(())
}

async fn tail_logs(path: &str) -> Result<()> {
    let path = expand_tilde(path);
    if !path.exists() {
        println!("no audit log at {}", path.display());
        return Ok(());
    }
    let content = tokio::fs::read_to_string(&path).await?;
    print!("{content}");
    Ok(())
}
