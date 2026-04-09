//! unix-oidc-scim: SCIM 2.0 provisioning service for unix-oidc.
//!
//! Provides RFC 7644 SCIM protocol endpoints for automated user lifecycle
//! management. Designed to run as a privileged service that receives
//! provisioning webhooks from OIDC identity providers.

use anyhow::Result;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("unix_oidc_scim=info,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();

    tracing::info!("unix-oidc-scim starting");
    tracing::info!("SCIM 2.0 provisioning service — Phase 37 skeleton");

    Ok(())
}
