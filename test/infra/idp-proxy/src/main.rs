// idp-proxy — programmable HTTP fault-injection proxy for CI IdP outage testing.
//
// CLI subcommands:
//   serve  --upstream <URL> --listen <ADDR> --control <ADDR>
//   fault  --control <URL>  --mode <MODE>  [--duration <DUR>] [--latency <DUR>]
//
// Logging: initialised with `RUST_LOG=idp_proxy=info` by default.
// WARNING: Setting `RUST_LOG=debug` reveals more internals but MUST NOT be used
//          in environments where sensitive OIDC traffic flows through — the debug
//          filter still respects the structured-field constraints in proxy.rs and
//          control.rs, but caution is warranted.
use std::net::SocketAddr;

use anyhow::Context;
use clap::{Parser, Subcommand};
use reqwest::Url;
use serde_json::json;
use tracing::info;

mod control;
mod fault;
mod proxy;

#[derive(Debug, Parser)]
#[command(name = "idp-proxy")]
#[command(about = "Programmable HTTP fault-injection proxy for CI IdP outage simulation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the proxy server. Forwards traffic to --upstream, exposes
    /// a fault-injection control plane on --control (bind to loopback).
    Serve {
        /// Upstream IdP URL, e.g. http://keycloak:8080
        #[arg(long)]
        upstream: Url,
        /// Address to listen for proxied traffic, e.g. 0.0.0.0:9443
        #[arg(long)]
        listen: SocketAddr,
        /// Address to listen for control-plane commands.
        /// MUST be loopback (127.0.0.1) in CI — see README security posture.
        #[arg(long)]
        control: SocketAddr,
    },
    /// Inject a fault mode into a running proxy via its control plane.
    Fault {
        /// Control-plane URL, e.g. http://127.0.0.1:9444
        #[arg(long)]
        control: Url,
        /// Fault mode: 503 | slow | malformed-jwks | drop-connection | off
        #[arg(long)]
        mode: String,
        /// Duration, e.g. 60s, 5m (default: permanent until next command)
        #[arg(long)]
        duration: Option<String>,
        /// Latency for `slow` mode, e.g. 30s (default: 30s)
        #[arg(long)]
        latency: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("idp_proxy=info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            upstream,
            listen,
            control,
        } => {
            info!(%upstream, %listen, %control, "starting idp-proxy");
            proxy::run(upstream, listen, control).await?;
        }

        Commands::Fault {
            control,
            mode,
            duration,
            latency,
        } => {
            // Parse duration string (e.g. "60s", "5m") into seconds.
            let duration_secs: Option<u64> = match duration {
                None => None,
                Some(ref s) => {
                    let d = humantime::parse_duration(s)
                        .with_context(|| format!("invalid duration '{}'", s))?;
                    Some(d.as_secs())
                }
            };

            // Parse latency string for slow mode.
            let latency_ms: Option<u64> = match latency {
                None => None,
                Some(ref s) => {
                    let d = humantime::parse_duration(s)
                        .with_context(|| format!("invalid latency '{}'", s))?;
                    Some(d.as_millis() as u64)
                }
            };

            let body = json!({
                "mode": mode,
                "duration_secs": duration_secs,
                "latency_ms": latency_ms,
            });

            let url = control.join("/fault").context("building /fault URL")?;
            let client = reqwest::Client::new();

            let response: reqwest::Response = client
                .post(url.clone())
                .json(&body)
                .send()
                .await
                .with_context(|| format!("POST {} failed", url))?;

            let status = response.status();
            let text: String = response.text().await.unwrap_or_default();
            if status.is_success() {
                println!("ok: {}", text);
            } else {
                eprintln!("error ({}): {}", status, text);
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
