use ssh2_config::{ParseRule, SshConfig};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use crate::error::ConfigError;
use std::io;

/// SSH Config parser that wraps ssh2_config::SshConfig
/// Provides methods to extract IdentityFile configurations for hosts
pub struct SshConfigParser {
    config: SshConfig,
}

impl SshConfigParser {
    /// Load and parse SSH config from the given path
    /// Expands ~ to home directory
    /// Returns Ok with empty config if file doesn't exist
    pub fn load(ssh_config_path: &str) -> Result<Self, ConfigError> {
        let path = expand_tilde(ssh_config_path);

        if !path.exists() {
            // Return empty config if file doesn't exist
            return Ok(SshConfigParser {
                config: SshConfig::default(),
            });
        }

        let file = File::open(&path).map_err(|e| {
            ConfigError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to open SSH config: {}", e),
            ))
        })?;

        let mut reader = BufReader::new(file);
        let config = SshConfig::default()
            .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .map_err(|e| {
                ConfigError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse SSH config: {}", e),
                ))
            })?;

        Ok(SshConfigParser { config })
    }

    /// Get identity files for a specific host
    /// Returns all IdentityFile paths configured for the given host
    /// Supports Host pattern matching (wildcards, multiple hosts, negation)
    #[allow(dead_code)]
    pub fn get_identity_files(&self, host: &str) -> Vec<PathBuf> {
        let params = self.config.query(host);

        params
            .identity_file
            .unwrap_or_default()
            .iter()
            .map(|p| expand_tilde(&p.to_string_lossy()))
            .collect()
    }

    /// Get all identity files from all Host sections
    /// Used when SSH Agent protocol doesn't provide host information
    /// Returns unique paths (no duplicates)
    pub fn get_all_identity_files(&self) -> Vec<PathBuf> {
        let mut all_files = Vec::new();

        // Iterate through all Host sections in the config
        for host_section in self.config.get_hosts() {
            if let Some(identity_files) = &host_section.params.identity_file {
                for path in identity_files.iter() {
                    let expanded = expand_tilde(&path.to_string_lossy());
                    if !all_files.contains(&expanded) {
                        all_files.push(expanded);
                    }
                }
            }
        }

        all_files
    }
}

/// Expand ~ to home directory
fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with('~') {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(&path[2..])
    } else {
        PathBuf::from(path)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Create a temporary SSH config file with the given content
    /// Returns both the TempDir (to keep it alive) and the config path
    fn create_temp_ssh_config(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config");
        fs::write(&config_path, content).unwrap();
        (temp_dir, config_path)
    }

    #[test]
    fn test_load_missing_config() {
        // Should not error on missing config
        let result = SshConfigParser::load("/nonexistent/path/config");
        assert!(result.is_ok());
        let parser = result.unwrap();
        assert!(parser.get_identity_files("anyhost").is_empty());
    }

    #[test]
    fn test_load_invalid_config() {
        // ssh2_config is very permissive and doesn't fail on invalid configs
        // This test documents that behavior
        let (_temp_dir, temp_config) = create_temp_ssh_config("Invalid {{{ config");
        let result = SshConfigParser::load(&temp_config.to_string_lossy());
        // ssh2_config allows unknown fields, so this won't error
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_ssh_config_with_identity_file() {
        let (_temp_dir, temp_config) =
            create_temp_ssh_config("Host test\n  IdentityFile ~/.ssh/test_key\n  User testuser");
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();
        let identity_files = parser.get_identity_files("test");
        assert_eq!(identity_files.len(), 1);
        assert!(identity_files[0].ends_with("test_key"));
    }

    #[test]
    fn test_exact_host_match() {
        let (_temp_dir, temp_config) =
            create_temp_ssh_config("Host github.com\n  IdentityFile ~/.ssh/github_key\n  User git");
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        // Exact match
        let files = parser.get_identity_files("github.com");
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("github_key"));

        // No match for different host
        let files = parser.get_identity_files("gitlab.com");
        assert!(files.is_empty());
    }

    #[test]
    fn test_wildcard_match() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host *.example.com\n  IdentityFile ~/.ssh/example_key\n  User admin",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        // Wildcard match
        let files = parser.get_identity_files("server1.example.com");
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("example_key"));

        let files = parser.get_identity_files("db.example.com");
        assert_eq!(files.len(), 1);

        // No match
        let files = parser.get_identity_files("example.com");
        assert!(files.is_empty());
    }

    #[test]
    fn test_multiple_hosts() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host server1 server2 server3\n  IdentityFile ~/.ssh/shared_key\n  User deploy",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        // All three hosts should match
        for host in &["server1", "server2", "server3"] {
            let files = parser.get_identity_files(host);
            assert_eq!(files.len(), 1);
            assert!(files[0].ends_with("shared_key"));
        }

        // Non-matching host
        let files = parser.get_identity_files("server4");
        assert!(files.is_empty());
    }

    #[test]
    fn test_negation_pattern() {
        // Note: ssh2_config doesn't fully support negation patterns (!pattern)
        // This test documents the current behavior
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host *.com !*.untrusted.com\n  IdentityFile ~/.ssh/trusted_key",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let files = parser.get_identity_files("trusted.com");
        assert_eq!(files.len(), 1);

        // ssh2_config currently doesn't exclude negated patterns
        // This is a known limitation of the library
        let files = parser.get_identity_files("untrusted.com");
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn test_get_all_identity_files() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host host1\n  IdentityFile ~/.ssh/key1\n\nHost host2\n  IdentityFile ~/.ssh/key2\n\nHost host3\n  IdentityFile ~/.ssh/key1",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let all_files = parser.get_all_identity_files();
        // Should have 2 unique files (key1 appears twice but should be deduplicated)
        assert_eq!(all_files.len(), 2);
        assert!(all_files.iter().any(|f| f.ends_with("key1")));
        assert!(all_files.iter().any(|f| f.ends_with("key2")));
    }

    #[test]
    fn test_get_all_identity_files_empty() {
        let (_temp_dir, temp_config) =
            create_temp_ssh_config("Host test\n  User testuser\n  Port 2222");
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let all_files = parser.get_all_identity_files();
        assert!(all_files.is_empty());
    }

    #[test]
    fn test_tilde_expansion() {
        let (_temp_dir, temp_config) =
            create_temp_ssh_config("Host test\n  IdentityFile ~/custom/path/key\n");
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let files = parser.get_identity_files("test");
        assert_eq!(files.len(), 1);

        // Should expand ~ to home directory
        if let Some(home) = dirs::home_dir() {
            assert!(files[0].starts_with(&home));
            assert!(files[0].ends_with("custom/path/key"));
        }
    }

    #[test]
    fn test_complex_config() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host *\n  IdentityFile ~/.ssh/default_key\n  ServerAliveInterval 60\n\nHost github.com\n  IdentityFile ~/.ssh/github_key\n  User git\n\nHost *.internal\n  IdentityFile ~/.ssh/internal_key\n  User admin",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        // github.com should match both * and github.com sections
        // The more specific match (github.com) takes precedence
        let files = parser.get_identity_files("github.com");
        assert!(!files.is_empty());

        // internal server matches * and *.internal
        let files = parser.get_identity_files("server.internal");
        assert!(!files.is_empty());

        // random host only matches *
        let files = parser.get_identity_files("random.host");
        assert!(!files.is_empty());
    }
}
