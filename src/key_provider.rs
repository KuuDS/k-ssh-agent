use crate::error::{KeyProviderError, KeyProviderResult};
use ssh_key::{PublicKey, Signature};

#[async_trait::async_trait]
pub trait KeyProvider: Send + Sync {
    /// Returns the provider name for debugging/logging
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// List all available public keys from this provider
    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>>;

    /// Sign data with the specified key
    async fn sign(&self, data: &[u8], key: &PublicKey) -> KeyProviderResult<Signature>;
}

/// Fallback chain that tries providers in order
pub struct FallbackChain {
    providers: Vec<Box<dyn KeyProvider>>,
}

impl FallbackChain {
    pub fn new() -> Self {
        FallbackChain {
            providers: Vec::new(),
        }
    }

    pub fn add_provider(&mut self, provider: Box<dyn KeyProvider>) {
        self.providers.push(provider);
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl KeyProvider for FallbackChain {
    fn name(&self) -> &str {
        "FallbackChain"
    }

    async fn list_keys(&self) -> KeyProviderResult<Vec<PublicKey>> {
        // Try each provider in order, return first successful result
        for provider in &self.providers {
            match provider.list_keys().await {
                Ok(keys) if !keys.is_empty() => return Ok(keys),
                Ok(_) => continue,  // Empty list, try next provider
                Err(_) => continue, // Error, try next provider
            }
        }
        Err(KeyProviderError::NotFound(
            "No keys available from any provider".to_string(),
        ))
    }

    async fn sign(&self, data: &[u8], key: &PublicKey) -> KeyProviderResult<Signature> {
        // Try each provider in order
        for provider in &self.providers {
            match provider.sign(data, key).await {
                Ok(sig) => return Ok(sig),
                Err(_) => continue, // Try next provider
            }
        }
        Err(KeyProviderError::SignFailed(
            "No provider could sign the data".to_string(),
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::public::{Ed25519PublicKey, KeyData};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Mock provider for testing
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
            // Create a dummy signature for testing
            // In real implementation, this would be a proper SSH signature
            use ssh_key::Algorithm;
            use ssh_key::Signature;

            // Create a minimal valid signature for testing
            // This is a workaround since we can't easily create real signatures in tests
            // without private keys
            let sig_data = vec![0u8; 64]; // Dummy signature bytes

            // We'll use a simple algorithm for testing
            let algorithm = Algorithm::Ed25519;

            // Create signature - this might need adjustment based on ssh-key API
            // For now, we'll return an error to indicate this is a test placeholder
            // Actually, let's create a proper test signature
            match Signature::new(algorithm, sig_data) {
                Ok(sig) => Ok(sig),
                Err(e) => Err(KeyProviderError::SignFailed(format!(
                    "Failed to create test signature: {}",
                    e
                ))),
            }
        }
    }

    #[tokio::test]
    async fn test_empty_chain_returns_error() {
        let chain = FallbackChain::new();
        let result = chain.list_keys().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyProviderError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_single_provider_success() {
        let mut chain = FallbackChain::new();
        let provider = MockProvider::new("test-provider");

        // Add a test key
        let test_key = create_test_public_key();
        provider.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider));

        let result = chain.list_keys().await;
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_chain_iteration_on_error() {
        let mut chain = FallbackChain::new();

        // First provider fails
        let provider1 = MockProvider::new("failing-provider");
        provider1.set_should_fail_list(true).await;

        // Second provider succeeds
        let provider2 = MockProvider::new("working-provider");
        let test_key = create_test_public_key();
        provider2.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));

        let result = chain.list_keys().await;
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_chain_iteration_on_empty_result() {
        let mut chain = FallbackChain::new();

        // First provider returns empty list
        let provider1 = MockProvider::new("empty-provider");
        // Don't add any keys, so it returns empty list

        // Second provider has keys
        let provider2 = MockProvider::new("working-provider");
        let test_key = create_test_public_key();
        provider2.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));

        let result = chain.list_keys().await;
        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_sign_success() {
        let mut chain = FallbackChain::new();
        let provider = MockProvider::new("signer");
        let test_key = create_test_public_key();
        provider.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider));

        let test_data = b"test data to sign";
        let result = chain.sign(test_data, &test_key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sign_chain_iteration() {
        let mut chain = FallbackChain::new();

        // First provider fails to sign
        let provider1 = MockProvider::new("failing-signer");
        provider1.set_should_fail_sign(true).await;
        let test_key = create_test_public_key();
        provider1.add_key(test_key.clone()).await;

        // Second provider succeeds
        let provider2 = MockProvider::new("working-signer");
        provider2.add_key(test_key.clone()).await;

        chain.add_provider(Box::new(provider1));
        chain.add_provider(Box::new(provider2));

        let test_data = b"test data to sign";
        let result = chain.sign(test_data, &test_key).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_provider_name() {
        let provider = MockProvider::new("custom-name");
        assert_eq!(provider.name(), "custom-name");

        let chain = FallbackChain::new();
        assert_eq!(chain.name(), "FallbackChain");
    }

    // Helper function to create a test public key
    fn create_test_public_key() -> PublicKey {
        // Create a dummy Ed25519 public key for testing
        let dummy_bytes = [0u8; 32];
        let ed25519_key = Ed25519PublicKey(dummy_bytes);
        let key_data = KeyData::Ed25519(ed25519_key);
        PublicKey::new(key_data, "test-key")
    }
}
