use ssh2_config::{ParseRule, SshConfig};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::path::{Path, PathBuf};

use crate::error::ConfigError;
use std::io;

pub struct SshConfigParser {
    config: SshConfig,
}

impl SshConfigParser {
    pub fn load(ssh_config_path: &str) -> Result<Self, ConfigError> {
        let path = expand_tilde(ssh_config_path);

        if !path.exists() {
            return Ok(SshConfigParser {
                config: SshConfig::default(),
            });
        }

        let config = Self::load_with_includes(&path)?;

        Ok(SshConfigParser { config })
    }

    fn load_with_includes(path: &Path) -> Result<SshConfig, ConfigError> {
        let base_dir = path.parent().unwrap_or(Path::new("."));

        let merged_content = Self::read_config_with_includes(path, base_dir)?;

        let mut cursor = Cursor::new(merged_content);
        let config = SshConfig::default()
            .parse(&mut cursor, ParseRule::ALLOW_UNKNOWN_FIELDS)
            .map_err(|e| {
                ConfigError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to parse SSH config: {}", e),
                ))
            })?;

        Ok(config)
    }

    fn read_config_with_includes(path: &Path, base_dir: &Path) -> Result<String, ConfigError> {
        let file = File::open(path).map_err(|e| {
            ConfigError::Io(std::io::Error::new(
                e.kind(),
                format!("Failed to open SSH config: {}", e),
            ))
        })?;

        let reader = BufReader::new(file);
        let mut result = String::new();

        for line in reader.lines() {
            let line =
                line.map_err(|e| ConfigError::Io(io::Error::new(io::ErrorKind::InvalidData, e)))?;

            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                result.push_str(&line);
                result.push('\n');
                continue;
            }

            if trimmed.to_lowercase().starts_with("include") {
                let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    let patterns = parts[1].trim();
                    for pattern in patterns.split_whitespace() {
                        let include_paths = Self::resolve_include_pattern(pattern, base_dir);
                        for include_path in include_paths {
                            if include_path.exists() && include_path.is_file() {
                                match Self::read_config_with_includes(
                                    &include_path,
                                    include_path.parent().unwrap_or(base_dir),
                                ) {
                                    Ok(content) => {
                                        result.push_str(&content);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                }
                result.push('\n');
            } else {
                result.push_str(&line);
                result.push('\n');
            }
        }

        Ok(result)
    }

    fn resolve_include_pattern(pattern: &str, base_dir: &Path) -> Vec<PathBuf> {
        let pattern_expanded = expand_tilde(pattern);
        let pattern_path = if pattern.starts_with('/') || pattern.starts_with('~') {
            pattern_expanded
        } else {
            base_dir.join(pattern_expanded)
        };

        let pattern_str = pattern_path.to_string_lossy();

        if pattern_str.contains('*') || pattern_str.contains('?') || pattern_str.contains('[') {
            match glob::glob(&pattern_str) {
                Ok(paths) => paths.filter_map(Result::ok).collect(),
                Err(_) => {
                    if pattern_path.exists() {
                        vec![pattern_path]
                    } else {
                        vec![]
                    }
                }
            }
        } else if pattern_path.exists() {
            vec![pattern_path]
        } else {
            vec![]
        }
    }

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

    pub fn get_all_identity_files(&self) -> Vec<PathBuf> {
        let mut all_files = Vec::new();

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

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with('~') {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        if path.len() > 1 && path.chars().nth(1) == Some('/') {
            home.join(&path[2..])
        } else {
            home
        }
    } else {
        PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_temp_ssh_config(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config");
        fs::write(&config_path, content).unwrap();
        (temp_dir, config_path)
    }

    #[test]
    fn test_load_missing_config() {
        let result = SshConfigParser::load("/nonexistent/path/config");
        assert!(result.is_ok());
        let parser = result.unwrap();
        assert!(parser.get_identity_files("anyhost").is_empty());
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

        let files = parser.get_identity_files("github.com");
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("github_key"));

        let files = parser.get_identity_files("gitlab.com");
        assert!(files.is_empty());
    }

    #[test]
    fn test_wildcard_match() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host *.example.com\n  IdentityFile ~/.ssh/example_key\n  User admin",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let files = parser.get_identity_files("server1.example.com");
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("example_key"));

        let files = parser.get_identity_files("example.com");
        assert!(files.is_empty());
    }

    #[test]
    fn test_multiple_hosts() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host server1 server2 server3\n  IdentityFile ~/.ssh/shared_key\n  User deploy",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        for host in &["server1", "server2", "server3"] {
            let files = parser.get_identity_files(host);
            assert_eq!(files.len(), 1);
            assert!(files[0].ends_with("shared_key"));
        }

        let files = parser.get_identity_files("server4");
        assert!(files.is_empty());
    }

    #[test]
    fn test_get_all_identity_files() {
        let (_temp_dir, temp_config) = create_temp_ssh_config(
            "Host host1\n  IdentityFile ~/.ssh/key1\n\nHost host2\n  IdentityFile ~/.ssh/key2\n\nHost host3\n  IdentityFile ~/.ssh/key1",
        );
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let all_files = parser.get_all_identity_files();
        assert_eq!(all_files.len(), 2);
        assert!(all_files.iter().any(|f| f.ends_with("key1")));
        assert!(all_files.iter().any(|f| f.ends_with("key2")));
    }

    #[test]
    fn test_tilde_expansion() {
        let (_temp_dir, temp_config) =
            create_temp_ssh_config("Host test\n  IdentityFile ~/custom/path/key\n");
        let parser = SshConfigParser::load(&temp_config.to_string_lossy()).unwrap();

        let files = parser.get_identity_files("test");
        assert_eq!(files.len(), 1);

        if let Some(home) = dirs::home_dir() {
            assert!(files[0].starts_with(&home));
            assert!(files[0].ends_with("custom/path/key"));
        }
    }

    #[test]
    fn test_include_directive() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        let main_config = config_dir.join("config");
        fs::write(
            &main_config,
            "Include config.d/*\n\nHost main\n  IdentityFile ~/.ssh/main_key\n",
        )
        .unwrap();

        let config_d = config_dir.join("config.d");
        fs::create_dir(&config_d).unwrap();
        let included_config = config_d.join("extra.conf");
        fs::write(
            &included_config,
            "Host included\n  IdentityFile ~/.ssh/included_key\n",
        )
        .unwrap();

        let parser = SshConfigParser::load(&main_config.to_string_lossy()).unwrap();

        let main_files = parser.get_identity_files("main");
        assert_eq!(main_files.len(), 1);
        assert!(main_files[0].ends_with("main_key"));

        let included_files = parser.get_identity_files("included");
        assert_eq!(included_files.len(), 1);
        assert!(included_files[0].ends_with("included_key"));
    }

    #[test]
    fn test_include_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        let main_config = config_dir.join("config");
        fs::write(&main_config, "Include config.d/a.conf config.d/b.conf\n").unwrap();

        let config_d = config_dir.join("config.d");
        fs::create_dir(&config_d).unwrap();
        fs::write(
            config_d.join("a.conf"),
            "Host hostA\n  IdentityFile ~/.ssh/keyA\n",
        )
        .unwrap();
        fs::write(
            config_d.join("b.conf"),
            "Host hostB\n  IdentityFile ~/.ssh/keyB\n",
        )
        .unwrap();

        let parser = SshConfigParser::load(&main_config.to_string_lossy()).unwrap();

        assert!(parser
            .get_identity_files("hostA")
            .iter()
            .any(|f| f.ends_with("keyA")));
        assert!(parser
            .get_identity_files("hostB")
            .iter()
            .any(|f| f.ends_with("keyB")));
    }

    #[test]
    fn test_resolve_include_pattern() {
        let temp_dir = TempDir::new().unwrap();
        let base_dir = temp_dir.path();

        fs::write(base_dir.join("file1.conf"), "Host f1\n").unwrap();
        fs::write(base_dir.join("file2.conf"), "Host f2\n").unwrap();

        let paths = SshConfigParser::resolve_include_pattern("*.conf", base_dir);
        assert_eq!(paths.len(), 2);
    }
}
