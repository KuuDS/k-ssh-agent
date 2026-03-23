use serde::Deserialize;
use std::path::PathBuf;

use crate::error::ConfigError;

fn default_ssh_config_path() -> String {
    dirs::home_dir()
        .map(|h| h.join(".ssh/config").to_string_lossy().to_string())
        .unwrap_or_else(|| "~/.ssh/config".to_string())
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct Config {
    pub bitwarden: BitwardenConfig,
    #[serde(default)]
    pub default_keys: DefaultKeysConfig,
    #[serde(default)]
    pub agent: Option<AgentConfig>,
    #[serde(default)]
    pub key_filter: KeyFilterConfig,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct BitwardenConfig {
    pub ssh_agent_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DefaultKeysConfig {
    #[serde(default = "default_key_names")]
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub socket_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct KeyFilterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ssh_config_path")]
    pub ssh_config_path: String,
    #[serde(default)]
    pub allowed_fingerprints: Vec<String>,
}

fn default_key_names() -> Vec<String> {
    vec!["id_ed25519".to_string(), "id_rsa".to_string()]
}

impl Default for DefaultKeysConfig {
    fn default() -> Self {
        Self {
            names: default_key_names(),
        }
    }
}

pub fn load() -> Result<Config, ConfigError> {
    let config_path = config_dir().join("config.toml");

    if !config_path.exists() {
        return Ok(Config::default());
    }

    let config_content = std::fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_content)?;

    Ok(config)
}

pub fn config_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".ksshagent")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();

        assert!(config.bitwarden.ssh_agent_path.is_none());
        assert_eq!(config.default_keys.names, vec!["id_ed25519", "id_rsa"]);
        assert!(config.agent.is_none());
    }

    #[test]
    fn test_default_bitwarden_config() {
        let bw_config = BitwardenConfig::default();
        assert!(bw_config.ssh_agent_path.is_none());
    }

    #[test]
    fn test_default_default_keys_config() {
        let keys_config = DefaultKeysConfig::default();
        assert_eq!(keys_config.names, vec!["id_ed25519", "id_rsa"]);
    }

    #[test]
    fn test_load_missing_config() {
        let result = load();
        assert!(
            result.is_ok(),
            "Loading missing config should return defaults, not error"
        );

        let config = result.unwrap();
        assert_eq!(config.default_keys.names, vec!["id_ed25519", "id_rsa"]);
    }

    #[test]
    fn test_load_valid_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join(".ksshagent");
        fs::create_dir(&config_dir).unwrap();

        let config_content = r#"
[bitwarden]
ssh_agent_path = "/tmp/bw-ssh-agent.sock"

[default_keys]
names = ["id_ed25519", "id_rsa", "id_ecdsa"]

[agent]
socket_path = "/tmp/ksshagent.sock"
"#;

        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, config_content).unwrap();

        let content = fs::read_to_string(&config_path).unwrap();
        let config: Config = toml::from_str(&content).unwrap();

        assert_eq!(
            config.bitwarden.ssh_agent_path,
            Some("/tmp/bw-ssh-agent.sock".to_string())
        );
        assert_eq!(
            config.default_keys.names,
            vec!["id_ed25519", "id_rsa", "id_ecdsa"]
        );
        assert!(config.agent.is_some());
        assert_eq!(
            config.agent.as_ref().unwrap().socket_path,
            Some("/tmp/ksshagent.sock".to_string())
        );
    }

    #[test]
    fn test_load_partial_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path().join(".ksshagent");
        fs::create_dir(&config_dir).unwrap();

        let config_content = r#"
[bitwarden]
"#;

        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, config_content).unwrap();

        let content = fs::read_to_string(&config_path).unwrap();
        let config: Config = toml::from_str(&content).unwrap();

        assert!(config.bitwarden.ssh_agent_path.is_none());
        assert_eq!(config.default_keys.names, vec!["id_ed25519", "id_rsa"]);
    }

    #[test]
    fn test_config_dir_uses_home() {
        let dir = config_dir();
        assert!(dir.ends_with(".ksshagent"));
    }
}
