use crate::error::{BitwardenError, KeyProviderError, KeyProviderResult};
use crate::key_provider::KeyProvider;
use ssh_key::{PublicKey, Signature};
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct BitwardenProvider {
    #[allow(dead_code)]
    ssh_agent_path: PathBuf,
}

impl BitwardenProvider {
    pub fn new(ssh_agent_path: PathBuf) -> Self {
        Self { ssh_agent_path }
    }
}

fn bitwarden_error_to_provider_error(err: BitwardenError) -> KeyProviderError {
    KeyProviderError::ProviderError(err.to_string())
}

#[async_trait::async_trait]
impl KeyProvider for BitwardenProvider {
    fn name(&self) -> &str {
        "Bitwarden"
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        // Use timeout to prevent hanging if bw CLI is unresponsive
        let output_result = timeout(Duration::from_secs(2), async {
            Command::new("bw")
                .arg("ssh")
                .arg("list")
                .output()
                .await
                .map_err(|e| {
                    bitwarden_error_to_provider_error(BitwardenError::CommandFailed(e.to_string()))
                })
        })
        .await;

        let output = match output_result {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(bitwarden_error_to_provider_error(
                    BitwardenError::CommandFailed("Bitwarden CLI timed out".to_string()),
                ))
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(bitwarden_error_to_provider_error(
                BitwardenError::CommandFailed(stderr.to_string()),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut keys = Vec::new();

        for line in stdout.lines() {
            if let Ok(key) = PublicKey::from_openssh(line) {
                keys.push(key);
            }
        }

        Ok(keys)
    }

    async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
        todo!("Implement signing via Bitwarden SSH agent socket")
    }
}
