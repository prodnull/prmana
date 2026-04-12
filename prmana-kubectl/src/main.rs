//! prmana-kubectl — Kubernetes exec credential plugin for prmana.
//!
//! This binary serves as a kubectl exec credential plugin
//! (`client.authentication.k8s.io/v1`). It connects to the prmana-agent
//! daemon via Unix socket, requests a cluster-audience-scoped bearer token,
//! and emits an `ExecCredential` JSON response on stdout.
//!
//! ## Usage
//!
//! ```sh
//! # Get a token for cluster 'prod' (called automatically by kubectl)
//! prmana-kubectl get-token --cluster-id prod
//!
//! # Write exec stanza into ~/.kube/config
//! prmana-kubectl setup \
//!     --cluster-id prod \
//!     --server https://api.prod.example.com:6443 \
//!     --context prod
//! ```
//!
//! ## Security
//!
//! Tokens are **bearer tokens** with **NO cnf claim** (no DPoP). The Kubernetes
//! exec credential API cannot carry per-request proofs. Tokens are
//! **audience-isolated**: audience `<cluster_id>.kube.prmana` is rejected by
//! the prmana PAM/SSH validator, so a stolen kubectl token cannot be used to SSH.
//! Tokens are **short-lived**: 10-minute TTL, refreshed automatically.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;
mod exec_credential;
mod ipc_client;
mod kubeconfig;
mod protocol;
mod socket_path;

#[derive(Parser)]
#[command(
    name = "prmana-kubectl",
    version,
    about = "Kubernetes exec credential plugin for prmana — transparent SSO cluster access"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Emit an ExecCredential JSON for kubectl (called automatically by kubectl).
    ///
    /// Connects to prmana-agent, requests a short-lived bearer token for the
    /// specified cluster audience, and prints ExecCredential JSON to stdout.
    GetToken {
        /// Cluster identifier — forms the token audience `<cluster_id>.kube.prmana`.
        #[arg(long)]
        cluster_id: String,
    },

    /// Write an exec stanza into ~/.kube/config (run once per cluster).
    ///
    /// After running this, `kubectl --context <context>` commands automatically
    /// acquire fresh tokens via the exec plugin.
    Setup {
        /// Cluster identifier (used to form the audience and name entries).
        #[arg(long)]
        cluster_id: String,

        /// kube-apiserver URL, e.g. `https://api.prod.example.com:6443`
        #[arg(long)]
        server: String,

        /// kubectl context name to create/update in ~/.kube/config
        #[arg(long)]
        context: String,

        /// Optional CA certificate file path or base64-encoded data.
        /// If a file path, it is read and base64-encoded automatically.
        #[arg(long)]
        ca_cert: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // All diagnostic output goes to stderr; stdout is reserved for ExecCredential JSON.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::GetToken { cluster_id } => commands::get_token(&cluster_id).await,
        Command::Setup {
            cluster_id,
            server,
            context,
            ca_cert,
        } => commands::setup(&cluster_id, &server, &context, ca_cert.as_deref()).await,
    }
}
