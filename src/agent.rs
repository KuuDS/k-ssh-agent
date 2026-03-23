use crate::error::{AgentError, AgentResult};
use crate::key_provider::KeyProvider;
use crate::ssh_proto::{
    decode_request_identities, encode_failure, encode_identities, encode_sign_response,
    SshAgentMessage, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
};
use ssh_key::PublicKey;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;

pub struct Agent {
    socket_path: PathBuf,
    key_provider: Arc<Box<dyn KeyProvider>>,
}

impl Agent {
    pub fn new(socket_path: PathBuf, key_provider: Box<dyn KeyProvider>) -> Self {
        Self {
            socket_path,
            key_provider: Arc::new(key_provider),
        }
    }

    pub async fn run(&self) -> AgentResult<()> {
        start_server(&self.socket_path, Arc::clone(&self.key_provider)).await
    }
}

pub async fn start_server(
    socket_path: &Path,
    key_provider: Arc<Box<dyn KeyProvider>>,
) -> AgentResult<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(AgentError::SocketBindFailed)?;
    }

    let listener = UnixListener::bind(socket_path).map_err(AgentError::SocketBindFailed)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(AgentError::SocketBindFailed)?;
    }

    println!("SSH agent listening on {}", socket_path.display());

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                let key_provider = Arc::clone(&key_provider);

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &key_provider).await {
                        eprintln!("Connection error: {}", e);
                    }
                });
            }
            _ = signal::ctrl_c() => {
                println!("Received SIGINT, shutting down...");
                break;
            }
            _ = wait_for_sigterm() => {
                println!("Received SIGTERM, shutting down...");
                break;
            }
        }
    }

    if socket_path.exists() {
        std::fs::remove_file(socket_path).map_err(AgentError::SocketBindFailed)?;
    }

    Ok(())
}

#[cfg(unix)]
async fn wait_for_sigterm() {
    let Ok(mut stream) = signal::unix::signal(signal::unix::SignalKind::terminate()) else {
        return;
    };
    stream.recv().await;
}

#[cfg(not(unix))]
async fn wait_for_sigterm() {
    std::future::pending().await;
}

async fn handle_connection(
    mut stream: UnixStream,
    key_provider: &Arc<Box<dyn KeyProvider>>,
) -> AgentResult<()> {
    loop {
        match SshAgentMessage::read(&mut stream).await {
            Ok(msg) => {
                let response = handle_message(msg, key_provider).await?;
                response.write(&mut stream).await?;
            }
            Err(e) => {
                // Check if this is an EOF error (client disconnected)
                let error_str = e.to_string();
                if error_str.contains("unexpected EOF") || error_str.contains("early EOF") {
                    // Client disconnected normally, just close the connection
                    return Ok(());
                }

                // For other errors, send failure response and close
                let failure = SshAgentMessage {
                    msg_type: SSH_AGENT_FAILURE,
                    payload: encode_failure().unwrap_or_default(),
                };
                let _ = failure.write(&mut stream).await;
                return Err(e.into());
            }
        }
    }
}

async fn handle_message(
    msg: SshAgentMessage,
    key_provider: &Arc<Box<dyn KeyProvider>>,
) -> AgentResult<SshAgentMessage> {
    match msg.msg_type {
        SSH_AGENTC_REQUEST_IDENTITIES => {
            if decode_request_identities(&msg.payload).is_err() {
                let encoded = encode_failure().unwrap_or_default();
                let payload = encoded[5..].to_vec();
                return Ok(SshAgentMessage {
                    msg_type: SSH_AGENT_FAILURE,
                    payload,
                });
            }

            match list_all_keys(key_provider).await {
                Ok(keys) => {
                    let encoded = encode_identities(&keys)?;
                    let payload = encoded[5..].to_vec();
                    Ok(SshAgentMessage {
                        msg_type: SSH_AGENT_IDENTITIES_ANSWER,
                        payload,
                    })
                }
                Err(_) => {
                    let encoded = encode_failure().unwrap_or_default();
                    let payload = encoded[5..].to_vec();
                    Ok(SshAgentMessage {
                        msg_type: SSH_AGENT_FAILURE,
                        payload,
                    })
                }
            }
        }
        SSH_AGENTC_SIGN_REQUEST => match sign_data(&msg.payload, key_provider).await {
            Ok(signature) => {
                let encoded = encode_sign_response(&signature)?;
                let payload = encoded[5..].to_vec();
                Ok(SshAgentMessage {
                    msg_type: SSH_AGENT_SIGN_RESPONSE,
                    payload,
                })
            }
            Err(_) => {
                let encoded = encode_failure().unwrap_or_default();
                let payload = encoded[5..].to_vec();
                Ok(SshAgentMessage {
                    msg_type: SSH_AGENT_FAILURE,
                    payload,
                })
            }
        },
        _ => {
            eprintln!("Unknown message type: 0x{:02X}", msg.msg_type);
            let encoded = encode_failure().unwrap_or_default();
            let payload = encoded[5..].to_vec();
            Ok(SshAgentMessage {
                msg_type: SSH_AGENT_FAILURE,
                payload,
            })
        }
    }
}

async fn list_all_keys(key_provider: &Arc<Box<dyn KeyProvider>>) -> AgentResult<Vec<PublicKey>> {
    // Use the fallback chain's list_keys which handles iteration internally
    // Return empty list on error (no keys) instead of failing
    match key_provider.list_keys().await {
        Ok(keys) => Ok(keys),
        Err(e) => {
            eprintln!("No keys available from fallback chain: {}", e);
            Ok(Vec::new()) // Return empty list instead of error
        }
    }
}

async fn sign_data(data: &[u8], key_provider: &Arc<Box<dyn KeyProvider>>) -> AgentResult<Vec<u8>> {
    if data.len() < 4 {
        return Err(AgentError::ProtocolError(
            "Sign request too short".to_string(),
        ));
    }

    // Extract the public key from the sign request data
    // The format is: [4-byte key blob length][key blob][4-byte data length][data]
    let key_blob_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + key_blob_len + 4 {
        return Err(AgentError::ProtocolError(
            "Sign request too short".to_string(),
        ));
    }

    let key_blob = &data[4..4 + key_blob_len];
    let sign_data = &data[4 + key_blob_len + 4..];

    // Parse the public key from the blob
    let key = PublicKey::from_bytes(key_blob)
        .map_err(|e| AgentError::ProtocolError(format!("Invalid key blob: {}", e)))?;

    // Use the fallback chain's sign method which handles iteration internally
    let signature = key_provider.sign(sign_data, &key).await.map_err(|e| {
        eprintln!("Failed to sign data with fallback chain: {}", e);
        AgentError::NoKeys
    })?;

    Ok(signature.as_bytes().to_vec())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{KeyProviderError, KeyProviderResult};
    use crate::key_provider::FallbackChain;
    use ssh_key::{
        public::{Ed25519PublicKey, KeyData},
        Signature,
    };
    use tokio::sync::Mutex;

    struct MockProvider {
        name: String,
        keys: Arc<Mutex<Vec<PublicKey>>>,
        should_fail_list: Arc<Mutex<bool>>,
        should_fail_sign: Arc<Mutex<bool>>,
    }

    impl MockProvider {
        fn new(name: &str) -> Self {
            MockProvider {
                name: name.to_string(),
                keys: Arc::new(Mutex::new(Vec::new())),
                should_fail_list: Arc::new(Mutex::new(false)),
                should_fail_sign: Arc::new(Mutex::new(false)),
            }
        }

        async fn add_key(&self, key: PublicKey) {
            let mut keys = self.keys.lock().await;
            keys.push(key);
        }

        async fn set_should_fail_list(&self, fail: bool) {
            let mut should_fail = self.should_fail_list.lock().await;
            *should_fail = fail;
        }

        async fn set_should_fail_sign(&self, fail: bool) {
            let mut should_fail = self.should_fail_sign.lock().await;
            *should_fail = fail;
        }
    }

    #[async_trait::async_trait]
    impl KeyProvider for MockProvider {
        fn name(&self) -> &str {
            &self.name
        }

        async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
            let should_fail = self.should_fail_list.lock().await;
            if *should_fail {
                return Err(KeyProviderError::ProviderError(format!(
                    "{} failed",
                    self.name
                )));
            }
            let keys = self.keys.lock().await;
            Ok(keys.clone())
        }

        async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
            let should_fail = self.should_fail_sign.lock().await;
            if *should_fail {
                return Err(KeyProviderError::SignFailed(format!(
                    "{} sign failed",
                    self.name
                )));
            }

            let sig_data = vec![0u8; 64];
            Signature::new(ssh_key::Algorithm::Ed25519, sig_data).map_err(|e| {
                KeyProviderError::SignFailed(format!("Failed to create signature: {}", e))
            })
        }
    }

    fn create_test_public_key() -> PublicKey {
        let dummy_bytes = [0u8; 32];
        let ed25519_key = Ed25519PublicKey(dummy_bytes);
        let key_data = KeyData::Ed25519(ed25519_key);
        PublicKey::new(key_data, "test-key")
    }

    fn create_test_sign_request(key: &PublicKey, data: &[u8]) -> Vec<u8> {
        // Format: [4-byte key blob length][key blob][4-byte data length][data]
        let key_blob = key.to_bytes().expect("Failed to serialize key");
        let mut request = Vec::new();
        request.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        request.extend_from_slice(&key_blob);
        request.extend_from_slice(&(data.len() as u32).to_be_bytes());
        request.extend_from_slice(data);
        request
    }

    #[tokio::test]
    async fn test_list_all_keys_empty() {
        let chain = FallbackChain::new();
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));
        // list_all_keys returns empty list when no keys found (for SSH protocol compliance)
        let result = list_all_keys(&key_provider).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_all_keys_single_provider() {
        let mut chain = FallbackChain::new();
        let provider = MockProvider::new("test");
        let test_key = create_test_public_key();
        provider.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));
        let keys = list_all_keys(&key_provider).await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_list_all_keys_multiple_providers() {
        let mut chain = FallbackChain::new();
        let provider1 = MockProvider::new("provider1");
        let key1 = create_test_public_key();
        provider1.add_key(key1.clone()).await;

        let provider2 = MockProvider::new("provider2");
        let key2 = create_test_public_key();
        provider2.add_key(key2.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        // FallbackChain returns keys from first successful provider
        let keys = list_all_keys(&key_provider).await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_list_all_keys_skips_failing_provider() {
        let mut chain = FallbackChain::new();
        let provider1 = MockProvider::new("failing");
        provider1.set_should_fail_list(true).await;

        let provider2 = MockProvider::new("working");
        let test_key = create_test_public_key();
        provider2.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        let keys = list_all_keys(&key_provider).await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_sign_data_success() {
        let mut chain = FallbackChain::new();
        let provider = MockProvider::new("signer");
        let test_key = create_test_public_key();
        provider.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        let test_data = b"test data";
        let request = create_test_sign_request(&test_key, test_data);

        let result = sign_data(&request, &key_provider).await;
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_sign_data_chain_iteration() {
        let mut chain = FallbackChain::new();
        let provider1 = MockProvider::new("failing-signer");
        provider1.set_should_fail_sign(true).await;
        let test_key = create_test_public_key();
        provider1.add_key(test_key.clone()).await;

        let provider2 = MockProvider::new("working-signer");
        provider2.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        let test_data = b"test data";
        let request = create_test_sign_request(&test_key, test_data);
        let result = sign_data(&request, &key_provider).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_data_no_keys() {
        let chain = FallbackChain::new();
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));
        let test_data = b"test data";
        let request = create_test_sign_request(&create_test_public_key(), test_data);

        let result = sign_data(&request, &key_provider).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AgentError::NoKeys));
    }

    #[tokio::test]
    async fn test_handle_message_request_identities() {
        let mut chain = FallbackChain::new();
        let provider = MockProvider::new("test");
        let test_key = create_test_public_key();
        provider.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider));
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        let msg = SshAgentMessage {
            msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
            payload: vec![],
        };

        let result = handle_message(msg, &key_provider).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);
    }

    #[tokio::test]
    async fn test_handle_message_unknown_type() {
        let chain = FallbackChain::new();
        let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

        let msg = SshAgentMessage {
            msg_type: 0xFF,
            payload: vec![],
        };

        let result = handle_message(msg, &key_provider).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.msg_type, SSH_AGENT_FAILURE);
    }
}
