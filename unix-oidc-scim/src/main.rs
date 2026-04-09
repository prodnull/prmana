//! unix-oidc-scim: SCIM 2.0 provisioning service for unix-oidc.
//!
//! Provides RFC 7644 SCIM protocol endpoints for automated user lifecycle
//! management. Designed to run as a privileged service that receives
//! provisioning webhooks from OIDC identity providers.

use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use unix_oidc_scim::config::ScimConfig;
use unix_oidc_scim::provisioner::Provisioner;
use unix_oidc_scim::routes::build_router;

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("unix_oidc_scim=info,warn"));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();

    // TODO: Load config from YAML file via figment
    let config = ScimConfig::default();
    let listen_addr = config.listen_addr.clone();

    let provisioner = Arc::new(Provisioner::new(config));
    let app = build_router(provisioner);

    tracing::info!(addr = %listen_addr, "unix-oidc-scim starting");

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
