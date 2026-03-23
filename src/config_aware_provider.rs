use crate::config::KeyFilterConfig;
use crate::error::KeyProviderResult;
use crate::key_provider::KeyProvider;
use crate::ssh_config_parser::SshConfigParser;
use ssh_key::{HashAlg, PublicKey};

pub struct ConfigAwareProvider {
    inner: Box<dyn KeyProvider>,
    ssh_config_parser: Option<SshConfigParser>,
    filter_config: KeyFilterConfig,
}

impl ConfigAwareProvider {
    pub fn new(
        inner: Box<dyn KeyProvider>,
        ssh_config_parser: Option<SshConfigParser>,
        filter_config: KeyFilterConfig,
    ) -> Self {
        ConfigAwareProvider {
            inner,
            ssh_config_parser,
            filter_config,
        }
    }

    fn filter_by_fingerprint(&self, keys: &[PublicKey]) -> Vec<PublicKey> {
        if self.filter_config.allowed_fingerprints.is_empty() {
            return keys.to_vec();
        }

        let normalized_allowed: Vec<String> = self
            .filter_config
            .allowed_fingerprints
            .iter()
            .map(|fp| {
                if fp.starts_with("SHA256:") {
                    fp.clone()
                } else {
                    format!("SHA256:{}", fp)
                }
            })
            .collect();

        keys.iter()
            .filter(|key| {
                let fp_str = key.fingerprint(HashAlg::Sha256).to_string();
                normalized_allowed.contains(&fp_str)
            })
            .cloned()
            .collect()
    }

    fn filter_by_ssh_config(&self, keys: &[PublicKey]) -> Vec<PublicKey> {
        let Some(ref parser) = self.ssh_config_parser else {
            return keys.to_vec();
        };

        let identity_files = parser.get_all_identity_files();

        if identity_files.is_empty() {
            return keys.to_vec();
        }

        let allowed_fingerprints: Vec<String> = identity_files
            .iter()
            .filter_map(|path| {
                let pub_path = if path.extension().is_some_and(|ext| ext == "pub") {
                    path.clone()
                } else {
                    path.with_extension("pub")
                };

                match std::fs::read_to_string(&pub_path) {
                    Ok(contents) => match PublicKey::from_openssh(&contents) {
                        Ok(pub_key) => {
                            Some(pub_key.fingerprint(HashAlg::Sha256).to_string())
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse public key file {:?}: {}",
                                pub_path,
                                e
                            );
                            None
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            "Could not read public key file {:?}: {}",
                            pub_path,
                            e
                        );
                        None
                    }
                }
            })
            .collect();

        if allowed_fingerprints.is_empty() {
            tracing::warn!(
                "No public keys loaded from SSH config IdentityFile paths, returning all keys"
            );
            return keys.to_vec();
        }

        keys.iter()
            .filter(|key| {
                let fp_str = key.fingerprint(HashAlg::Sha256).to_string();
                allowed_fingerprints.contains(&fp_str)
            })
            .cloned()
            .collect()
    }

    fn apply_filters(&self, keys: Vec<PublicKey>) -> Vec<PublicKey> {
        if !self.filter_config.enabled {
            return keys;
        }

        let filtered = self.filter_by_fingerprint(&keys);
        self.filter_by_ssh_config(&filtered)
    }
}

#[async_trait::async_trait]
impl KeyProvider for ConfigAwareProvider {
    fn name(&self) -> &str {
        "ConfigAwareProvider"
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        let keys = self.inner.list_keys().await?;
        Ok(self.apply_filters(keys))
    }

    async fn sign(&self, data: &[u8], key: &PublicKey) -> KeyProviderResult<ssh_key::Signature> {
        self.inner.sign(data, key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::KeyProviderError;
    use crate::key_provider::KeyProvider;
    use ssh_key::public::{Ed25519PublicKey, KeyData};
    use ssh_key::Signature;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    struct MockProvider {
        keys: Arc<Mutex<Vec<PublicKey>>>,
    }

    impl MockProvider {
        fn new(keys: Vec<PublicKey>) -> Self {
            MockProvider {
                keys: Arc::new(Mutex::new(keys)),
            }
        }
    }

    #[async_trait::async_trait]
    impl KeyProvider for MockProvider {
        fn name(&self) -> &str {
            "MockProvider"
        }

        async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
            let keys = self.keys.lock().await;
            Ok(keys.clone())
        }

        async fn sign(&self, _data: &[u8], _key: &PublicKey) -> KeyProviderResult<Signature> {
            let sig_data = vec![0u8; 64];
            Signature::new(ssh_key::Algorithm::Ed25519, sig_data).map_err(|e| {
                KeyProviderError::SignFailed(format!("Failed to create test signature: {}", e))
            })
        }
    }

    fn create_test_key(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes.fill(seed);
        let ed25519_key = Ed25519PublicKey(bytes);
        let key_data = KeyData::Ed25519(ed25519_key);
        PublicKey::new(key_data, &format!("test-key-{}", seed))
    }

    #[tokio::test]
    async fn test_disabled_filter_returns_all_keys() {
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let keys = vec![key1.clone(), key2.clone()];

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: false,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec![],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_fingerprint_filter_single_key() {
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let keys = vec![key1.clone(), key2.clone()];

        let fp1 = key1.fingerprint(HashAlg::Sha256).to_string();

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec![fp1.clone()],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 1);
        assert_eq!(
            filtered_keys[0].fingerprint(HashAlg::Sha256).to_string(),
            fp1
        );
    }

    #[tokio::test]
    async fn test_fingerprint_filter_multiple_keys() {
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);
        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let fp1 = key1.fingerprint(HashAlg::Sha256).to_string();
        let fp3 = key3.fingerprint(HashAlg::Sha256).to_string();

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec![fp1.clone(), fp3.clone()],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 2);
    }

    #[tokio::test]
    async fn test_fingerprint_filter_without_sha256_prefix() {
        let key1 = create_test_key(1);
        let keys = vec![key1.clone()];

        let fp1 = key1.fingerprint(HashAlg::Sha256).to_string();
        let fp1_no_prefix = fp1.strip_prefix("SHA256:").unwrap();

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec![fp1_no_prefix.to_string()],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_fingerprint_filter_no_match() {
        let key1 = create_test_key(1);
        let keys = vec![key1.clone()];

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec!["SHA256:nonexistent".to_string()],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_ssh_config_filter_with_identity_files() {
        let temp_dir = TempDir::new().unwrap();
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let keys = vec![key1.clone(), key2.clone()];

        let key1_path = temp_dir.path().join("key1");
        let key1_pub_path = temp_dir.path().join("key1.pub");
        let openssh_format = key1.to_openssh().unwrap();
        fs::write(&key1_pub_path, openssh_format).unwrap();

        let ssh_config_content = format!(
            "Host test\n  IdentityFile {}\n",
            key1_path.to_string_lossy()
        );
        let ssh_config_path = temp_dir.path().join("ssh_config");
        fs::write(&ssh_config_path, ssh_config_content).unwrap();

        let parser =
            SshConfigParser::load(&ssh_config_path.to_string_lossy()).unwrap();
        
        let identity_files = parser.get_all_identity_files();
        assert_eq!(identity_files.len(), 1, "Should find one IdentityFile");

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: ssh_config_path.to_string_lossy().to_string(),
            allowed_fingerprints: vec![],
        };

        let provider =
            ConfigAwareProvider::new(Box::new(mock_provider), Some(parser), config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_ssh_config_filter_no_identity_files() {
        let key1 = create_test_key(1);
        let keys = vec![key1.clone()];

        let temp_dir = TempDir::new().unwrap();
        let ssh_config_path = temp_dir.path().join("ssh_config");
        fs::write(&ssh_config_path, "Host test\n  User testuser\n").unwrap();

        let parser =
            SshConfigParser::load(&ssh_config_path.to_string_lossy()).unwrap();

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: ssh_config_path.to_string_lossy().to_string(),
            allowed_fingerprints: vec![],
        };

        let provider =
            ConfigAwareProvider::new(Box::new(mock_provider), Some(parser), config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_combined_fingerprint_and_ssh_config_filter() {
        let temp_dir = TempDir::new().unwrap();
        let key1 = create_test_key(1);
        let key2 = create_test_key(2);
        let key3 = create_test_key(3);
        let keys = vec![key1.clone(), key2.clone(), key3.clone()];

        let key1_pub_path = temp_dir.path().join("key1.pub");
        let openssh_format = key1.to_openssh().unwrap();
        fs::write(&key1_pub_path, openssh_format).unwrap();

        let ssh_config_content = format!(
            "Host test\n  IdentityFile {}\n",
            key1_pub_path.to_string_lossy().trim_end_matches(".pub")
        );
        let ssh_config_path = temp_dir.path().join("ssh_config");
        fs::write(&ssh_config_path, ssh_config_content).unwrap();

        let fp2 = key2.fingerprint(HashAlg::Sha256).to_string();

        let parser =
            SshConfigParser::load(&ssh_config_path.to_string_lossy()).unwrap();

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: ssh_config_path.to_string_lossy().to_string(),
            allowed_fingerprints: vec![fp2.clone()],
        };

        let provider =
            ConfigAwareProvider::new(Box::new(mock_provider), Some(parser), config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        let filtered_keys = result.unwrap();
        assert_eq!(filtered_keys.len(), 0);
    }

    #[tokio::test]
    async fn test_sign_passthrough() {
        let key = create_test_key(1);
        let keys = vec![key.clone()];

        let mock_provider = MockProvider::new(keys);
        let config = KeyFilterConfig::default();

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let test_data = b"test data to sign";
        let result = provider.sign(test_data, &key).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_provider_name() {
        let key = create_test_key(1);
        let mock_provider = MockProvider::new(vec![key]);
        let config = KeyFilterConfig::default();

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        assert_eq!(provider.name(), "ConfigAwareProvider");
    }

    #[tokio::test]
    async fn test_empty_keys_with_filter() {
        let mock_provider = MockProvider::new(vec![]);
        let config = KeyFilterConfig {
            enabled: true,
            ssh_config_path: String::new(),
            allowed_fingerprints: vec!["SHA256:test".to_string()],
        };

        let provider = ConfigAwareProvider::new(Box::new(mock_provider), None, config);
        let result = provider.list_keys().await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }
}
