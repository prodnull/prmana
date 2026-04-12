//! kubeconfig reader/writer for prmana exec credential stanza injection.
//!
//! Merges a new cluster + user + context entry into an existing `~/.kube/config`
//! (or `$KUBECONFIG`) without overwriting other entries.
//!
//! Format reference: <https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/>

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Resolve the kubeconfig path:
/// 1. `$KUBECONFIG` environment variable (if set and non-empty, take first entry)
/// 2. `~/.kube/config`
pub fn resolve_path() -> Result<PathBuf> {
    if let Ok(kc) = std::env::var("KUBECONFIG") {
        if !kc.is_empty() {
            // KUBECONFIG may be colon-separated list; use the first entry
            let first = kc.split(':').next().unwrap_or(&kc);
            return Ok(PathBuf::from(first));
        }
    }
    let home =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    Ok(home.join(".kube").join("config"))
}

/// Write (or merge) a prmana exec credential stanza into a kubeconfig file.
///
/// # Arguments
/// - `path` — kubeconfig file path (created if absent, merged if present)
/// - `cluster_id` — cluster identifier (used in names and `--cluster-id` arg)
/// - `server` — kube-apiserver URL, e.g. `https://api.prod.example.com:6443`
/// - `context_name` — name for the kubectl context to create/update
/// - `ca_cert_b64` — optional base64-encoded CA certificate data
///
/// The written entries use naming convention:
/// - cluster name: `<cluster_id>`
/// - user name: `prmana-<cluster_id>`
/// - context name: `<context_name>`
pub async fn write_exec_stanza(
    path: &Path,
    cluster_id: &str,
    server: &str,
    context_name: &str,
    ca_cert_b64: Option<&str>,
) -> Result<()> {
    // Read existing config or start fresh
    let mut config: serde_yaml::Value = if path.exists() {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("reading kubeconfig at {}", path.display()))?;
        if content.trim().is_empty() {
            default_kubeconfig()
        } else {
            serde_yaml::from_str(&content)
                .with_context(|| format!("parsing kubeconfig at {}", path.display()))?
        }
    } else {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }
        default_kubeconfig()
    };

    let user_name = format!("prmana-{}", cluster_id);

    // Build cluster entry value
    let mut cluster_inner = serde_yaml::Mapping::new();
    cluster_inner.insert(
        serde_yaml::Value::String("server".to_string()),
        serde_yaml::Value::String(server.to_string()),
    );
    if let Some(ca) = ca_cert_b64 {
        cluster_inner.insert(
            serde_yaml::Value::String("certificate-authority-data".to_string()),
            serde_yaml::Value::String(ca.to_string()),
        );
    }
    let mut cluster_data = serde_yaml::Mapping::new();
    cluster_data.insert(
        serde_yaml::Value::String("cluster".to_string()),
        serde_yaml::Value::Mapping(cluster_inner),
    );

    // Build exec stanza value
    let mut exec_map = serde_yaml::Mapping::new();
    exec_map.insert(
        serde_yaml::Value::String("apiVersion".to_string()),
        serde_yaml::Value::String("client.authentication.k8s.io/v1".to_string()),
    );
    exec_map.insert(
        serde_yaml::Value::String("command".to_string()),
        serde_yaml::Value::String("prmana-kubectl".to_string()),
    );
    exec_map.insert(
        serde_yaml::Value::String("args".to_string()),
        serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String("get-token".to_string()),
            serde_yaml::Value::String("--cluster-id".to_string()),
            serde_yaml::Value::String(cluster_id.to_string()),
        ]),
    );
    exec_map.insert(
        serde_yaml::Value::String("interactiveMode".to_string()),
        serde_yaml::Value::String("IfAvailable".to_string()),
    );
    exec_map.insert(
        serde_yaml::Value::String("provideClusterInfo".to_string()),
        serde_yaml::Value::Bool(false),
    );

    // Build user entry value
    let mut user_inner = serde_yaml::Mapping::new();
    user_inner.insert(
        serde_yaml::Value::String("exec".to_string()),
        serde_yaml::Value::Mapping(exec_map),
    );
    let mut user_data = serde_yaml::Mapping::new();
    user_data.insert(
        serde_yaml::Value::String("user".to_string()),
        serde_yaml::Value::Mapping(user_inner),
    );

    // Build context entry value
    let mut ctx_inner = serde_yaml::Mapping::new();
    ctx_inner.insert(
        serde_yaml::Value::String("cluster".to_string()),
        serde_yaml::Value::String(cluster_id.to_string()),
    );
    ctx_inner.insert(
        serde_yaml::Value::String("user".to_string()),
        serde_yaml::Value::String(user_name.clone()),
    );
    let mut ctx_data = serde_yaml::Mapping::new();
    ctx_data.insert(
        serde_yaml::Value::String("context".to_string()),
        serde_yaml::Value::Mapping(ctx_inner),
    );

    // Upsert all three lists
    upsert_named_entry(&mut config, "clusters", cluster_id, cluster_data);
    upsert_named_entry(&mut config, "users", &user_name, user_data);
    upsert_named_entry(&mut config, "contexts", context_name, ctx_data);

    // Set current-context only if not already set
    if let serde_yaml::Value::Mapping(ref mut m) = config {
        let cc_key = serde_yaml::Value::String("current-context".to_string());
        if !m.contains_key(&cc_key) {
            m.insert(cc_key, serde_yaml::Value::String(context_name.to_string()));
        }
    }

    // Write back
    let output = serde_yaml::to_string(&config).context("serializing kubeconfig")?;
    tokio::fs::write(path, output.as_bytes())
        .await
        .with_context(|| format!("writing kubeconfig to {}", path.display()))?;

    Ok(())
}

/// Upsert a named entry in a kubeconfig list (clusters/users/contexts).
///
/// If an entry with `name == entry_name` already exists, it is replaced.
/// Otherwise the entry is appended. This provides idempotent behavior.
fn upsert_named_entry(
    config: &mut serde_yaml::Value,
    list_key: &str,
    entry_name: &str,
    entry_data: serde_yaml::Mapping,
) {
    let serde_yaml::Value::Mapping(ref mut root) = config else {
        return;
    };

    let list_key_val = serde_yaml::Value::String(list_key.to_string());
    let list = root
        .entry(list_key_val)
        .or_insert_with(|| serde_yaml::Value::Sequence(vec![]));

    let serde_yaml::Value::Sequence(ref mut seq) = list else {
        return;
    };

    // Build the new entry with `name` first, then the data fields
    let name_key = serde_yaml::Value::String("name".to_string());
    let name_val = serde_yaml::Value::String(entry_name.to_string());
    let mut new_mapping = serde_yaml::Mapping::new();
    new_mapping.insert(name_key.clone(), name_val.clone());
    for (k, v) in entry_data {
        new_mapping.insert(k, v);
    }
    let new_entry = serde_yaml::Value::Mapping(new_mapping);

    // Replace existing entry with same name, or append
    for item in seq.iter_mut() {
        if let serde_yaml::Value::Mapping(ref m) = item {
            if m.get(&name_key) == Some(&name_val) {
                *item = new_entry;
                return;
            }
        }
    }
    seq.push(new_entry);
}

/// Minimal valid kubeconfig skeleton.
fn default_kubeconfig() -> serde_yaml::Value {
    serde_yaml::from_str("apiVersion: v1\nkind: Config\nclusters: []\nusers: []\ncontexts: []\n")
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn write_and_read(
        dir: &TempDir,
        cluster_id: &str,
        server: &str,
        context_name: &str,
    ) -> serde_yaml::Value {
        let path = dir.path().join("config");
        write_exec_stanza(&path, cluster_id, server, context_name, None)
            .await
            .unwrap();
        let content = tokio::fs::read_to_string(&path).await.unwrap();
        serde_yaml::from_str(&content).unwrap()
    }

    /// Test K1: write creates correct cluster, user, context entries.
    #[tokio::test]
    async fn test_k1_write_creates_correct_entries() {
        let dir = tempfile::tempdir().unwrap();
        let config =
            write_and_read(&dir, "prod", "https://api.prod.example.com:6443", "prod").await;

        // Check clusters
        let clusters = &config["clusters"];
        assert!(clusters.is_sequence());
        let cluster = &clusters[0];
        assert_eq!(
            cluster["name"],
            serde_yaml::Value::String("prod".to_string())
        );
        assert_eq!(
            cluster["cluster"]["server"],
            serde_yaml::Value::String("https://api.prod.example.com:6443".to_string())
        );

        // Check users
        let users = &config["users"];
        assert_eq!(
            users[0]["name"],
            serde_yaml::Value::String("prmana-prod".to_string())
        );
        let exec = &users[0]["user"]["exec"];
        assert_eq!(
            exec["apiVersion"],
            serde_yaml::Value::String("client.authentication.k8s.io/v1".to_string())
        );
        assert_eq!(
            exec["command"],
            serde_yaml::Value::String("prmana-kubectl".to_string())
        );

        // Check interactiveMode
        assert_eq!(
            exec["interactiveMode"],
            serde_yaml::Value::String("IfAvailable".to_string())
        );
    }

    /// Test K2: existing config is merged, not overwritten.
    #[tokio::test]
    async fn test_k2_merge_preserves_existing_clusters() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");

        // Pre-existing kubeconfig with 2 clusters
        let existing = r#"
apiVersion: v1
kind: Config
clusters:
  - name: existing-cluster-1
    cluster:
      server: https://existing1.example.com
  - name: existing-cluster-2
    cluster:
      server: https://existing2.example.com
users:
  - name: existing-user
    user:
      token: old-token
contexts:
  - name: existing-context
    context:
      cluster: existing-cluster-1
      user: existing-user
current-context: existing-context
"#;
        tokio::fs::write(&path, existing).await.unwrap();

        write_exec_stanza(
            &path,
            "new-cluster",
            "https://new.example.com",
            "new-ctx",
            None,
        )
        .await
        .unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let config: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();

        let clusters = config["clusters"].as_sequence().unwrap();
        assert_eq!(clusters.len(), 3, "must have 3 clusters after merge");

        // existing-context must still be current-context (not overwritten)
        assert_eq!(
            config["current-context"],
            serde_yaml::Value::String("existing-context".to_string())
        );
    }

    /// Test K3: writing same entry twice is idempotent.
    #[tokio::test]
    async fn test_k3_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");

        write_exec_stanza(
            &path,
            "prod",
            "https://api.prod.example.com",
            "prod-ctx",
            None,
        )
        .await
        .unwrap();
        write_exec_stanza(
            &path,
            "prod",
            "https://api.prod.example.com",
            "prod-ctx",
            None,
        )
        .await
        .unwrap();

        let content = tokio::fs::read_to_string(&path).await.unwrap();
        let config: serde_yaml::Value = serde_yaml::from_str(&content).unwrap();
        let clusters = config["clusters"].as_sequence().unwrap();
        assert_eq!(clusters.len(), 1, "idempotent: must not duplicate cluster");
    }

    /// Test K4: exec stanza has correct apiVersion and interactiveMode.
    #[tokio::test]
    async fn test_k4_exec_stanza_fields() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_and_read(&dir, "prod", "https://api.prod.example.com", "prod").await;

        let exec = &config["users"][0]["user"]["exec"];
        assert_eq!(
            exec["apiVersion"],
            serde_yaml::Value::String("client.authentication.k8s.io/v1".to_string()),
            "must use stable v1 API"
        );
        assert_eq!(
            exec["interactiveMode"],
            serde_yaml::Value::String("IfAvailable".to_string()),
            "interactiveMode must be IfAvailable"
        );
        assert_eq!(
            exec["provideClusterInfo"],
            serde_yaml::Value::Bool(false),
            "provideClusterInfo must be false"
        );
    }

    /// Test K5: exec command is just `prmana-kubectl` (no absolute path).
    #[tokio::test]
    async fn test_k5_command_is_bare_binary_name() {
        let dir = tempfile::tempdir().unwrap();
        let config = write_and_read(&dir, "prod", "https://api.prod.example.com", "prod").await;

        let exec = &config["users"][0]["user"]["exec"];
        assert_eq!(
            exec["command"],
            serde_yaml::Value::String("prmana-kubectl".to_string()),
            "command must be bare name (no absolute path)"
        );
    }
}
