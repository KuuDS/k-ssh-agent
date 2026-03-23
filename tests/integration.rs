use async_trait::async_trait;
use k_ssh_agent::agent::start_server;
use k_ssh_agent::config::KeyFilterConfig;
use k_ssh_agent::config_aware_provider::ConfigAwareProvider;
use k_ssh_agent::error::{KeyProviderError, KeyProviderResult};
use k_ssh_agent::key_provider::{FallbackChain, KeyProvider};
use k_ssh_agent::ssh_config_parser::SshConfigParser;
use k_ssh_agent::ssh_proto::{
    SshAgentMessage, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE,
    SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_SIGN_RESPONSE,
};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{HashAlg, PublicKey, Signature};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::UnixStream;

struct MockKeyProvider {
    #[allow(dead_code)]
    name: String,
    keys: Vec<PublicKey>,
}

impl MockKeyProvider {
    fn new(name: &str, keys: Vec<PublicKey>) -> Self {
        MockKeyProvider {
            name: name.to_string(),
            keys,
        }
    }
}

#[async_trait]
impl KeyProvider for MockKeyProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        Ok(self.keys.clone())
    }

    async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
        let sig_data = vec![0u8; 64];
        Signature::new(ssh_key::Algorithm::Ed25519, sig_data)
            .map_err(|e| KeyProviderError::SignFailed(format!("Failed to create signature: {}", e)))
    }
}

fn create_test_public_key(comment: &str) -> PublicKey {
    create_test_public_key_with_seed(comment, 0)
}

fn create_test_public_key_with_seed(comment: &str, seed: u8) -> PublicKey {
    let mut dummy_bytes = [0u8; 32];
    dummy_bytes.fill(seed);
    let ed25519_key = Ed25519PublicKey(dummy_bytes);
    let key_data = KeyData::Ed25519(ed25519_key);
    PublicKey::new(key_data, comment)
}

fn create_sign_request(key: &PublicKey, data: &[u8]) -> Vec<u8> {
    let key_blob = key.to_bytes().expect("Failed to serialize key");
    let mut request = Vec::new();
    request.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
    request.extend_from_slice(&key_blob);
    request.extend_from_slice(&(data.len() as u32).to_be_bytes());
    request.extend_from_slice(data);
    request
}

async fn start_test_agent(
    socket_path: PathBuf,
    keys: Vec<PublicKey>,
) -> tokio::task::JoinHandle<()> {
    let mut chain = FallbackChain::new();
    let provider = MockKeyProvider::new("test-mock", keys);
    chain.add_provider(Box::new(provider));

    let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(chain));

    let handle = tokio::spawn(async move {
        let _ = start_server(&socket_path, key_provider).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    handle
}

#[tokio::test]
async fn test_list_keys_empty() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let _agent_handle = start_test_agent(socket_path.clone(), vec![]).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    // Agent should return empty key list, not failure (SSH protocol compliance)
    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);
    // Verify the response contains 0 keys (first byte after type is count)
    assert_eq!(&response.payload[0..4], &[0, 0, 0, 0]);
}

#[tokio::test]
async fn test_list_keys_single_key() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-key-1");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(key_count, 1);
}

#[tokio::test]
async fn test_list_keys_multiple_keys() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let key1 = create_test_public_key("test-key-1");
    let key2 = create_test_public_key("test-key-2");
    let key3 = create_test_public_key("test-key-3");
    let keys = vec![key1, key2, key3];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(key_count, 3);
}

#[tokio::test]
async fn test_sign_request_success() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-sign-key");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let test_data = b"test data to sign";
    let sign_request_payload = create_sign_request(&test_key, test_data);

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_SIGN_REQUEST,
        payload: sign_request_payload,
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_SIGN_RESPONSE);

    let sig_len = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]) as usize;
    assert!(sig_len > 0);
    assert!(response.payload.len() >= 4 + sig_len);
}

#[tokio::test]
async fn test_sign_request_with_empty_data() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-sign-key-empty");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let test_data = b"";
    let sign_request_payload = create_sign_request(&test_key, test_data);

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_SIGN_REQUEST,
        payload: sign_request_payload,
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_SIGN_RESPONSE);

    let sig_len = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]) as usize;
    assert!(sig_len > 0);
}

#[tokio::test]
async fn test_sign_request_large_data() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-sign-key-large");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let test_data = vec![0xAB; 1024];
    let sign_request_payload = create_sign_request(&test_key, &test_data);

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_SIGN_REQUEST,
        payload: sign_request_payload,
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_SIGN_RESPONSE);

    let sig_len = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]) as usize;
    assert!(sig_len > 0);
}

#[tokio::test]
async fn test_unknown_message_type() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-key");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: 0xFF,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_FAILURE);
}

#[tokio::test]
async fn test_invalid_message_type_zero() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_agent.sock");

    let test_key = create_test_public_key("test-key");
    let keys = vec![test_key.clone()];

    let _agent_handle = start_test_agent(socket_path.clone(), keys).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: 0x00,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_FAILURE);
}

// ============================================================================
// Integration Tests for Key Filtering
// ============================================================================

async fn start_config_aware_agent(
    socket_path: PathBuf,
    keys: Vec<PublicKey>,
    filter_config: KeyFilterConfig,
    ssh_config_parser: Option<SshConfigParser>,
) -> tokio::task::JoinHandle<()> {
    let mut chain = FallbackChain::new();
    let provider = MockKeyProvider::new("test-mock", keys);
    chain.add_provider(Box::new(provider));

    let config_aware_provider =
        ConfigAwareProvider::new(Box::new(chain), ssh_config_parser, filter_config);

    let key_provider: Arc<Box<dyn KeyProvider>> = Arc::new(Box::new(config_aware_provider));

    let handle = tokio::spawn(async move {
        let _ = start_server(&socket_path, key_provider).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    handle
}

#[tokio::test]
async fn test_key_filtering_by_fingerprint() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    // Create test keys with different fingerprints (different seeds)
    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let key2 = create_test_public_key_with_seed("test-key-2", 2);
    let key3 = create_test_public_key_with_seed("test-key-3", 3);
    let all_keys = vec![key1.clone(), key2.clone(), key3.clone()];

    // Get fingerprint of key1
    let key1_fp = key1.fingerprint(HashAlg::Sha256).to_string();

    // Configure filter to only allow key1
    let filter_config = KeyFilterConfig {
        enabled: true,
        ssh_config_path: String::new(),
        allowed_fingerprints: vec![key1_fp.clone()],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, None).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(
        key_count, 1,
        "Should return only 1 key (filtered by fingerprint)"
    );
}

#[tokio::test]
async fn test_key_filtering_by_fingerprint_multiple_allowed() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let key2 = create_test_public_key_with_seed("test-key-2", 2);
    let key3 = create_test_public_key_with_seed("test-key-3", 3);
    let all_keys = vec![key1.clone(), key2.clone(), key3.clone()];

    // Allow key1 and key3
    let key1_fp = key1.fingerprint(HashAlg::Sha256).to_string();
    let key3_fp = key3.fingerprint(HashAlg::Sha256).to_string();

    let filter_config = KeyFilterConfig {
        enabled: true,
        ssh_config_path: String::new(),
        allowed_fingerprints: vec![key1_fp.clone(), key3_fp.clone()],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, None).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(key_count, 2, "Should return 2 keys (key1 and key3)");
}

#[tokio::test]
async fn test_key_filtering_by_fingerprint_no_match() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let all_keys = vec![key1.clone()];

    // Filter with non-matching fingerprint
    let filter_config = KeyFilterConfig {
        enabled: true,
        ssh_config_path: String::new(),
        allowed_fingerprints: vec!["SHA256:nonexistent".to_string()],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, None).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(key_count, 0, "Should return 0 keys (no match)");
}

#[tokio::test]
async fn test_key_filtering_by_ssh_config() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    // Create test keys with different seeds
    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let key2 = create_test_public_key_with_seed("test-key-2", 2);
    let all_keys = vec![key1.clone(), key2.clone()];

    // Create temporary SSH config with IdentityFile pointing to key1
    let key1_path = temp_dir.path().join("key1");
    let key1_pub_path = temp_dir.path().join("key1.pub");
    let openssh_format = key1.to_openssh().unwrap();
    fs::write(&key1_pub_path, openssh_format).expect("Failed to write key1.pub");

    let ssh_config_content = format!(
        "Host testhost\n  IdentityFile {}\n",
        key1_path.to_string_lossy()
    );
    let ssh_config_path = temp_dir.path().join("ssh_config");
    fs::write(&ssh_config_path, ssh_config_content).expect("Failed to write ssh_config");

    // Load SSH config parser
    let parser = SshConfigParser::load(&ssh_config_path.to_string_lossy())
        .expect("Failed to load SSH config");

    // Configure filter with SSH config path
    let filter_config = KeyFilterConfig {
        enabled: true,
        ssh_config_path: ssh_config_path.to_string_lossy().to_string(),
        allowed_fingerprints: vec![],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, Some(parser)).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(
        key_count, 1,
        "Should return only 1 key (filtered by SSH config IdentityFile)"
    );
}

#[tokio::test]
async fn test_key_filtering_disabled_returns_all_keys() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let key2 = create_test_public_key_with_seed("test-key-2", 2);
    let key3 = create_test_public_key_with_seed("test-key-3", 3);
    let all_keys = vec![key1.clone(), key2.clone(), key3.clone()];

    // Filtering disabled
    let filter_config = KeyFilterConfig {
        enabled: false,
        ssh_config_path: String::new(),
        allowed_fingerprints: vec!["SHA256:nonexistent".to_string()],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, None).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(
        key_count, 3,
        "Should return all keys when filtering is disabled"
    );
}

#[tokio::test]
async fn test_key_filtering_fingerprint_without_sha256_prefix() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let socket_path = temp_dir.path().join("test_filter_agent.sock");

    let key1 = create_test_public_key_with_seed("test-key-1", 1);
    let all_keys = vec![key1.clone()];

    // Use fingerprint without SHA256: prefix
    let key1_fp = key1.fingerprint(HashAlg::Sha256).to_string();
    let key1_fp_no_prefix = key1_fp.strip_prefix("SHA256:").unwrap();

    let filter_config = KeyFilterConfig {
        enabled: true,
        ssh_config_path: String::new(),
        allowed_fingerprints: vec![key1_fp_no_prefix.to_string()],
    };

    let _agent_handle =
        start_config_aware_agent(socket_path.clone(), all_keys, filter_config, None).await;

    let mut stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to agent");

    let request = SshAgentMessage {
        msg_type: SSH_AGENTC_REQUEST_IDENTITIES,
        payload: vec![],
    };
    request
        .write(&mut stream)
        .await
        .expect("Failed to write request");

    let response = SshAgentMessage::read(&mut stream)
        .await
        .expect("Failed to read response");

    assert_eq!(response.msg_type, SSH_AGENT_IDENTITIES_ANSWER);

    let key_count = u32::from_be_bytes([
        response.payload[0],
        response.payload[1],
        response.payload[2],
        response.payload[3],
    ]);
    assert_eq!(
        key_count, 1,
        "Should match fingerprint without SHA256: prefix"
    );
}
