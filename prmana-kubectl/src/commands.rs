//! CLI subcommand implementations.

use anyhow::Result;
use tracing::debug;

use crate::{exec_credential, ipc_client, kubeconfig, socket_path};

/// `prmana-kubectl get-token --cluster-id <id>`
///
/// Fetches a kubectl exec-credential token from the prmana agent and prints
/// the ExecCredential JSON to stdout. Called automatically by kubectl.
pub async fn get_token(cluster_id: &str) -> Result<()> {
    debug!(cluster_id = %cluster_id, "get-token subcommand");

    let socket = socket_path::resolve()?;
    let (token, exp_unix) = ipc_client::get_kubectl_credential(&socket, cluster_id).await?;

    let cred = exec_credential::build(token, exp_unix);
    exec_credential::emit_stdout(&cred)
}

/// `prmana-kubectl setup --cluster-id <id> --server <url> --context <name>`
///
/// Writes an exec stanza into `~/.kube/config` and prints next-step guidance.
pub async fn setup(
    cluster_id: &str,
    server: &str,
    context: &str,
    ca_cert: Option<&str>,
) -> Result<()> {
    let kubeconfig_path = kubeconfig::resolve_path()?;

    // If ca_cert is a file path, read it and base64-encode it
    let ca_cert_b64: Option<String> = match ca_cert {
        None => None,
        Some(path_or_b64) => {
            // If it looks like a file path (starts with / or ./ or ../), read it
            if path_or_b64.starts_with('/')
                || path_or_b64.starts_with("./")
                || path_or_b64.starts_with("../")
            {
                let bytes = tokio::fs::read(path_or_b64)
                    .await
                    .map_err(|e| anyhow::anyhow!("reading CA cert file {path_or_b64}: {e}"))?;
                use base64::Engine;
                Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
            } else {
                // Assume already base64-encoded
                Some(path_or_b64.to_string())
            }
        }
    };

    kubeconfig::write_exec_stanza(
        &kubeconfig_path,
        cluster_id,
        server,
        context,
        ca_cert_b64.as_deref(),
    )
    .await?;

    println!(
        "Wrote exec stanza for cluster '{}' to {}.",
        cluster_id,
        kubeconfig_path.display()
    );
    println!();
    println!("Next steps:");
    println!("  1. Ensure prmana-agent is running:");
    println!("       systemctl --user status prmana-agent");
    println!("  2. Log in (if not already):");
    println!("       prmana-agent login");
    println!("  3. Try it:");
    println!("       kubectl --context {} get pods", context);
    println!();
    println!(
        "The token is short-lived (10 min) and bound to audience '{}.kube.prmana'.",
        cluster_id
    );
    println!("It is refreshed automatically on each kubectl invocation.");
    Ok(())
}
