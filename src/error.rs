use std::io;
use thiserror::Error;

// ============================================================================
// Type aliases
// ============================================================================

#[allow(dead_code)]
pub type Result<T> = std::result::Result<T, ConfigError>;
#[allow(dead_code)]
pub type BitwardenResult<T> = std::result::Result<T, BitwardenError>;
pub type AgentResult<T> = std::result::Result<T, AgentError>;
pub type KeyProviderResult<T> = std::result::Result<T, KeyProviderError>;
pub type SshProtoResult<T> = std::result::Result<T, SshProtoError>;

// ============================================================================
// ConfigError
// ============================================================================

#[derive(Error, Debug)]
pub enum ConfigError {
    #[allow(dead_code)]
    #[error("Config file not found: {0}")]
    NotFound(String),

    #[error("Failed to parse config: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}

// ============================================================================
// BitwardenError
// ============================================================================

#[derive(Error, Debug)]
pub enum BitwardenError {
    #[allow(dead_code)]
    #[error("Bitwarden CLI not found")]
    CliNotFound,

    #[allow(dead_code)]
    #[error("Vault is locked")]
    VaultLocked,

    #[error("Failed to execute bw command: {0}")]
    CommandFailed(String),

    #[allow(dead_code)]
    #[error("Failed to parse bw output: {0}")]
    ParseError(String),
}

// ============================================================================
// AgentError
// ============================================================================

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Failed to bind socket: {0}")]
    SocketBindFailed(#[from] io::Error),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("No keys available")]
    NoKeys,
}

impl From<SshProtoError> for AgentError {
    fn from(err: SshProtoError) -> Self {
        AgentError::ProtocolError(err.to_string())
    }
}

// ============================================================================
// KeyProviderError
// ============================================================================

#[derive(Error, Debug)]
pub enum KeyProviderError {
    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Failed to sign: {0}")]
    SignFailed(String),

    #[error("Provider error: {0}")]
    ProviderError(String),
}

// ============================================================================
// SshProtoError
// ============================================================================

#[derive(Error, Debug)]
pub enum SshProtoError {
    #[allow(dead_code)]
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_config_error_display() {
        let not_found = ConfigError::NotFound("/path/to/config.toml".to_string());
        assert!(not_found.to_string().contains("Config file not found"));
        assert!(not_found.to_string().contains("/path/to/config.toml"));

        // Test ParseError variant - create from actual toml parse failure
        let invalid_toml = "invalid = ";
        let result: std::result::Result<toml::Value, toml::de::Error> =
            toml::from_str(invalid_toml);
        assert!(result.is_err());
        let parse_error = ConfigError::ParseError(result.unwrap_err());
        assert!(parse_error.to_string().contains("Failed to parse config"));

        let io_error = ConfigError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        assert!(io_error.to_string().contains("IO error"));
    }

    #[test]
    fn test_config_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let config_err: ConfigError = io_err.into();
        assert!(matches!(config_err, ConfigError::Io(_)));
    }

    #[test]
    fn test_bitwarden_error_display() {
        let cli_not_found = BitwardenError::CliNotFound;
        assert_eq!(cli_not_found.to_string(), "Bitwarden CLI not found");

        let vault_locked = BitwardenError::VaultLocked;
        assert_eq!(vault_locked.to_string(), "Vault is locked");

        let command_failed = BitwardenError::CommandFailed("exit code 1".to_string());
        assert!(command_failed
            .to_string()
            .contains("Failed to execute bw command"));
        assert!(command_failed.to_string().contains("exit code 1"));

        let parse_error = BitwardenError::ParseError("invalid JSON".to_string());
        assert!(parse_error
            .to_string()
            .contains("Failed to parse bw output"));
        assert!(parse_error.to_string().contains("invalid JSON"));
    }

    #[test]
    fn test_agent_error_display() {
        let socket_error = AgentError::SocketBindFailed(io::Error::new(
            io::ErrorKind::AddrInUse,
            "address in use",
        ));
        assert!(socket_error.to_string().contains("Failed to bind socket"));
        assert!(socket_error.to_string().contains("address in use"));

        let protocol_error = AgentError::ProtocolError("invalid message".to_string());
        assert!(protocol_error.to_string().contains("Protocol error"));
        assert!(protocol_error.to_string().contains("invalid message"));

        let no_keys = AgentError::NoKeys;
        assert_eq!(no_keys.to_string(), "No keys available");
    }

    #[test]
    fn test_agent_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::AddrInUse, "address in use");
        let agent_err: AgentError = io_err.into();
        assert!(matches!(agent_err, AgentError::SocketBindFailed(_)));
    }

    #[test]
    fn test_key_provider_error_display() {
        let not_found = KeyProviderError::NotFound("id_ed25519".to_string());
        assert!(not_found.to_string().contains("Key not found"));
        assert!(not_found.to_string().contains("id_ed25519"));

        let sign_failed = KeyProviderError::SignFailed("timeout".to_string());
        assert!(sign_failed.to_string().contains("Failed to sign"));
        assert!(sign_failed.to_string().contains("timeout"));

        let provider_error = KeyProviderError::ProviderError("connection refused".to_string());
        assert!(provider_error.to_string().contains("Provider error"));
        assert!(provider_error.to_string().contains("connection refused"));
    }

    #[test]
    fn test_ssh_proto_error_display() {
        let invalid_type = SshProtoError::InvalidMessageType(0xFF);
        assert!(invalid_type.to_string().contains("Invalid message type"));
        assert!(invalid_type.to_string().contains("255"));

        let encoding_error = SshProtoError::EncodingError("buffer overflow".to_string());
        assert!(encoding_error.to_string().contains("Encoding error"));
        assert!(encoding_error.to_string().contains("buffer overflow"));

        let decoding_error = SshProtoError::DecodingError("unexpected EOF".to_string());
        assert!(decoding_error.to_string().contains("Decoding error"));
        assert!(decoding_error.to_string().contains("unexpected EOF"));
    }

    #[test]
    fn test_error_traits() {
        // Test that all error types implement std::error::Error
        fn assert_error<E: std::error::Error>() {}

        assert_error::<ConfigError>();
        assert_error::<BitwardenError>();
        assert_error::<AgentError>();
        assert_error::<KeyProviderError>();
        assert_error::<SshProtoError>();
    }
}
