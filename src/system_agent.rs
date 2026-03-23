use crate::error::{KeyProviderError, KeyProviderResult};
use crate::key_provider::KeyProvider;
use ssh_key::{PublicKey, Signature};
use std::env;
use tokio::net::UnixStream;

pub struct SystemAgentProvider {
    socket_path: Option<String>,
}

impl SystemAgentProvider {
    pub fn new() -> Self {
        let socket_path = env::var("SSH_AUTH_SOCK").ok();
        Self { socket_path }
    }

    /// Create a SystemAgentProvider with a specific socket path
    /// This is useful when you want to preserve the original SSH_AUTH_SOCK
    pub fn with_socket(socket_path: Option<String>) -> Self {
        Self { socket_path }
    }

    #[allow(dead_code)]
    pub fn is_available(&self) -> bool {
        self.socket_path.is_some()
    }
}

impl Default for SystemAgentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl KeyProvider for SystemAgentProvider {
    fn name(&self) -> &str {
        "SystemAgent"
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        let socket_path = self
            .socket_path
            .as_ref()
            .ok_or_else(|| KeyProviderError::ProviderError("SSH_AUTH_SOCK not set".to_string()))?;

        let mut stream = UnixStream::connect(socket_path)
            .await
            .map_err(|e| KeyProviderError::ProviderError(e.to_string()))?;

        let request = vec![0x0B];

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(&request)
            .await
            .map_err(|e| KeyProviderError::ProviderError(e.to_string()))?;

        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| KeyProviderError::ProviderError(e.to_string()))?;

        let _len = u32::from_be_bytes(len_buf);

        let mut response_type = [0u8; 1];
        stream
            .read_exact(&mut response_type)
            .await
            .map_err(|e| KeyProviderError::ProviderError(e.to_string()))?;

        if response_type[0] != 0x0C {
            return Err(KeyProviderError::ProviderError(
                "Unexpected response type".to_string(),
            ));
        }

        Ok(Vec::new())
    }

    async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
        todo!("Implement signing via system SSH agent")
    }
}
