# k-ssh-agent

A secure SSH agent that combines Bitwarden SSH agent with system SSH agent using a fallback chain approach.

## Overview

k-ssh-agent is an SSH agent that seamlessly integrates with Bitwarden for managing SSH keys stored in your password vault, while maintaining compatibility with your system SSH agent and local default keys. The agent uses a fallback chain approach:

1. **Bitwarden SSH agent** - Keys stored securely in Bitwarden
2. **System SSH agent** - Keys from your system's SSH agent
3. **Default keys** - Local keys from `~/.ssh/` directory

This allows you to use your Bitwarden-stored SSH keys transparently with existing SSH workflows while maintaining secure storage of your private keys.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-username/k-ssh-agent.git
cd k-ssh-agent

# Build and install
cargo build --release
cargo install --path .
```

### Direct Install

```bash
# Install directly from Git repository
cargo install --git https://github.com/your-username/k-ssh-agent
```

## Quick Start

1. **Initialize and configure the agent**:

```bash
# Generate default config at ~/.ksshagent/config.toml
k-ssh-agent init
```

2. **Start the agent**:

```bash
k-ssh-agent
```

3. **Set your SSH_AUTH_SOCK environment variable**:

```bash
export SSH_AUTH_SOCK=/tmp/ksshagent.sock
```

4. **Use SSH as normal**:

```bash
ssh git@github.com
ssh user@server
```

## Configuration

The agent looks for configuration in `~/.ksshagent/config.toml`. Available options:

```toml
[bitwarden]
# Path to Bitwarden SSH agent socket (optional - auto-detected if not specified)
# Default locations:
#   - macOS (.dmg): ~/.bitwarden-ssh-agent.sock
#   - macOS (App Store): ~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
#   - Linux (generic): ~/.bitwarden-ssh-agent.sock
#   - Linux (Snap): ~/snap/bitwarden/current/.bitwarden-ssh-agent.sock
#   - Linux (Flatpak): ~/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock
ssh_agent_path = "~/.bitwarden-ssh-agent.sock"

[default_keys]
# Names of default keys to load from ~/.ssh/
names = ["id_ed25519", "id_rsa"]

[key_filter]
# Enable key filtering based on SSH config and fingerprints (optional)
# Default: false (backward compatible - all keys are used)
enabled = false

# Path to SSH config file for Host-based filtering
# Default: ~/.ssh/config
ssh_config_path = "~/.ssh/config"

# List of allowed key fingerprints (SHA256 format)
# If specified, only keys matching these fingerprints will be used
# Fingerprints can be with or without "SHA256:" prefix
allowed_fingerprints = [
    "SHA256:abcdef123456...",
    "SHA256:xyz789..."
]
```

## CLI Commands

### init

Generate a default configuration file.

```bash
# Generate default config at ~/.ksshagent/config.toml
k-ssh-agent init

# Specify custom output path
k-ssh-agent init --output ./custom-config.toml

# Force overwrite existing config
k-ssh-agent init --force
```

### run

Start the SSH agent server.

```bash
k-ssh-agent run
k-ssh-agent run --foreground  # Run in foreground
```

### status

Show connected keys count and provider info.

```bash
k-ssh-agent status
```

### config

Show config file path and contents.

```bash
k-ssh-agent config
```

## Key Filtering

k-ssh-agent supports optional key filtering to control which SSH keys are exposed to SSH clients. This is useful when you have many keys but want to use only specific ones for certain hosts or sessions.

### How It Works

When key filtering is enabled, the agent filters keys through two stages:

1. **Fingerprint Filter**: If `allowed_fingerprints` is specified, only keys matching those fingerprints are included
2. **SSH Config Filter**: If your SSH config has `IdentityFile` directives, only keys matching those paths are included

Both filters are applied in sequence (fingerprint filter first, then SSH config filter). If either filter results in an empty list, no keys are returned.

### Getting Key Fingerprints

To get the fingerprint of your SSH keys:

```bash
# Using ssh-add (if key is loaded)
ssh-add -l

# Using ssh-keygen (from public key file)
ssh-keygen -lf ~/.ssh/id_ed25519.pub

# Example output: SHA256:abcdef1234567890...
```

### Example: Filter by Fingerprint

Create `~/.ksshagent/config.toml`:

```toml
[key_filter]
enabled = true
allowed_fingerprints = [
    "SHA256:AbCdEf123456...",
    "SHA256:XyZ789..."
]
```

This configuration ensures only the specified keys are used, even if you have many keys in Bitwarden or your system agent.

### Example: Filter by SSH Config

The agent automatically reads your SSH config to determine which keys to use:

**~/.ssh/config**:
```
Host github.com
    IdentityFile ~/.ssh/github_key
    
Host gitlab.com
    IdentityFile ~/.ssh/gitlab_key
```

**~/.ksshagent/config.toml**:
```toml
[key_filter]
enabled = true
ssh_config_path = "~/.ssh/config"
```

The agent will only expose keys that match the `IdentityFile` paths in your SSH config.

### Example: Combined Filtering

You can combine both fingerprint and SSH config filtering:

```toml
[key_filter]
enabled = true
ssh_config_path = "~/.ssh/config"
allowed_fingerprints = [
    "SHA256:Primarykey123..."
]
```

This configuration:
1. First filters to only the primary key fingerprint
2. Then checks if that key matches any `IdentityFile` in your SSH config
3. Returns the key only if it passes both filters

### Troubleshooting

**Problem**: "No keys available" error when filtering is enabled

**Solutions**:
1. Verify fingerprints are correct: `ssh-keygen -lf ~/.ssh/your_key.pub`
2. Check if fingerprints match exactly (including case sensitivity)
3. Try without the "SHA256:" prefix or with it - both formats are supported
4. Temporarily disable filtering (`enabled = false`) to confirm keys are available
5. Ensure SSH config file exists and is readable
6. Check that `IdentityFile` paths in SSH config point to existing key files

**Problem**: Filtering too aggressive, keys not showing up

**Solutions**:
1. Add more fingerprints to `allowed_fingerprints` list
2. Disable SSH config filtering by removing `ssh_config_path`
3. Use `ssh-add -l` to see all available keys and their fingerprints
4. Check agent logs for warnings about key loading failures

### Backward Compatibility

Key filtering is **disabled by default** (`enabled = false`). This ensures:
- Existing configurations continue to work without changes
- All available keys are used unless explicitly filtered
- No breaking changes to current SSH workflows

To enable filtering, explicitly set `enabled = true` in your `[key_filter]` section.

## Features

- **Secure Key Storage**: Integrates with Bitwarden for encrypted storage of SSH keys
- **Fallback Chain**: Automatic fallback through Bitwarden → System → Default keys
- **Transparent Operation**: Works with existing SSH tools and workflows
- **Zero Knowledge Security**: Private keys never leave their secure stores
- **Configurable**: Flexible configuration via TOML file
- **Cross-platform**: Built with Rust for reliable cross-platform support
- **Memory Security**: Uses `zeroize` and `secrecy` crates for secure memory handling

## License

This project is dual licensed under either:

- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

You may choose either license when using this software.