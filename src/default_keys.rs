use crate::config::DefaultKeysConfig;
use crate::error::{KeyProviderError, KeyProviderResult};
use crate::key_provider::KeyProvider;
use ssh_key::{PublicKey, Signature};
use std::path::PathBuf;

pub struct DefaultKeysProvider {
    ssh_dir: PathBuf,
    key_names: Vec<String>,
}

impl DefaultKeysProvider {
    pub fn new(config: DefaultKeysConfig) -> Self {
        let ssh_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ssh");

        Self {
            ssh_dir,
            key_names: config.names,
        }
    }

    #[allow(dead_code)]
    fn key_path(&self, name: &str) -> PathBuf {
        self.ssh_dir.join(name)
    }

    fn public_key_path(&self, name: &str) -> PathBuf {
        self.ssh_dir.join(format!("{}.pub", name))
    }
}

#[async_trait::async_trait]
impl KeyProvider for DefaultKeysProvider {
    fn name(&self) -> &str {
        "DefaultKeys"
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        let mut keys = Vec::new();

        for name in &self.key_names {
            let pub_path = self.public_key_path(name);

            if pub_path.exists() {
                let content = tokio::fs::read_to_string(&pub_path)
                    .await
                    .map_err(|e| KeyProviderError::ProviderError(e.to_string()))?;

                if let Ok(key) = PublicKey::from_openssh(content.trim()) {
                    keys.push(key);
                }
            }
        }

        Ok(keys)
    }

    async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
        Err(KeyProviderError::SignFailed(
            "Default keys provider does not support signing (no private key access)".to_string(),
        ))
    }
}
