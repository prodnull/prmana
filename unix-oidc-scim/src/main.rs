//! unix-oidc-scim: SCIM 2.0 provisioning service for unix-oidc.
//!
//! Provides RFC 7644 SCIM protocol endpoints for automated user lifecycle
//! management. Designed to run as a privileged service that receives
//! provisioning webhooks from OIDC identity providers.
//!
//! # Security
//!
//! The service refuses to start unless one of:
//! - `oidc_issuer` is configured (real JWT validation)
//! - `--insecure-no-auth` is passed (development only, logs CRITICAL warning)

use std::sync::Arc;

use anyhow::{bail, Result};
use clap::Parser;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use unix_oidc_scim::auth::AuthMode;
use unix_oidc_scim::config::ScimConfig;
use unix_oidc_scim::provisioner::Provisioner;
use unix_oidc_scim::routes::build_router;

/// unix-oidc-scim: SCIM 2.0 provisioning service for unix-oidc
#[derive(Parser)]
#[command(name = "unix-oidc-scim", version)]
struct Args {
    /// Config file path.
    #[arg(long, default_value = "/etc/unix-oidc/scim.yaml")]
    config: String,

    /// DANGEROUS: Disable Bearer token validation entirely.
    /// For development/testing only. Production deployments MUST NOT use this flag.
    #[arg(long, hide = true)]
    insecure_no_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("unix_oidc_scim=info,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();

    let args = Args::parse();

    // TODO: Load config from YAML file via figment using args.config
    let config = ScimConfig::default();

    // Determine auth mode — refuse to start without explicit auth config
    // or explicit bypass flag. This service can call useradd/userdel, so
    // accepting any Bearer token is a production-blocking auth bypass.
    let auth_mode = if args.insecure_no_auth {
        tracing::error!("╔══════════════════════════════════════════════════════════════╗");
        tracing::error!("║  CRITICAL: --insecure-no-auth is active.                   ║");
        tracing::error!("║  Bearer token validation is DISABLED.                      ║");
        tracing::error!("║  ANY request with a non-empty Bearer token will be         ║");
        tracing::error!("║  accepted. DO NOT use this in production.                  ║");
        tracing::error!("╚══════════════════════════════════════════════════════════════╝");
        AuthMode::Insecure
    } else if config.oidc_issuer.is_empty() {
        bail!(
            "oidc_issuer is not configured and --insecure-no-auth was not passed.\n\
             The SCIM service refuses to start without authentication.\n\
             Either configure oidc_issuer in {} or pass --insecure-no-auth for development.",
            args.config,
        );
    } else {
        tracing::info!(issuer = %config.oidc_issuer, "OIDC token validation enabled");
        AuthMode::Validated {
            issuer: config.oidc_issuer.clone(),
            audience: config.oidc_audience.clone(),
        }
    };

    let listen_addr = config.listen_addr.clone();
    let provisioner = Arc::new(Provisioner::new(config));
    let app = build_router(provisioner, auth_mode);

    tracing::info!(addr = %listen_addr, "unix-oidc-scim starting");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
