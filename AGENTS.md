# AGENTS.md — k-ssh-agent

## 1. OVERVIEW
SSH agent combining Bitwarden SSH agent with system SSH agent using fallback chain: Bitwarden → System → Default keys. Configuration via `~/.ksshagent/config.toml`.

## 2. PROJECT STRUCTURE
```
k-ssh-agent/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point, CLI parsing
│   ├── config.rs            # Config loading (~/.ksshagent/config.toml)
│   ├── agent.rs             # Main SSH agent server (Unix socket)
│   ├── key_provider.rs      # Trait for key providers
│   ├── bitwarden.rs         # Bitwarden CLI integration
│   ├── system_agent.rs      # System SSH_AGENT forwarding
│   ├── default_keys.rs      # Fallback: ~/.ssh/id_* keys
│   ├── error.rs             # Error types (thiserror)
│   └── ssh_proto.rs         # SSH agent protocol encoding/decoding
├── tests/
│   ├── integration/
│   └── fixtures/
└── .github/workflows/
    └── ci.yml
```

## 3. WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Config parsing | `src/config.rs` | TOML via serde |
| SSH agent socket | `src/agent.rs` | Unix domain socket |
| Key provider trait | `src/key_provider.rs` | Fallback chain pattern |
| Bitwarden CLI | `src/bitwarden.rs` | Spawn `bw` commands |
| Protocol encoding | `src/ssh_proto.rs` | ssh-key, ssh-encoding crates |
| Error types | `src/error.rs` | thiserror + anyhow |

## 4. CONVENTIONS
- **Edition**: Rust 2021
- **Security**: `zeroize` for secrets, `secrecy` crate, no logging sensitive data
- **Async**: Tokio runtime (multi-threaded)
- **Errors**: `thiserror` for library, `anyhow` for main.rs
- **Style**: `rustfmt` default, `clippy` all warnings
- **Config**: TOML via `serde`

## 5. ANTI-PATTERNS
- ❌ Hardcoded secrets or keys
- ❌ Logging private keys, passphrases, tokens
- ❌ Insecure temp files (use `tempfile` crate)
- ❌ Blocking calls in async context (use `tokio::spawn_blocking`)
- ❌ Global mutable state
- ❌ Tight coupling between modules
- ❌ Unit tests only, no integration tests
- ❌ Testing with real SSH keys (use fixtures)

## 6. UNIQUE STYLES
**Fallback chain trait**:
```rust
trait KeyProvider: Send + Sync {
    async fn list_keys(&self) -> Result<Vec<PublicKey>>;
    async fn sign(&self, data: &[u8], key: &PublicKey) -> Result<Signature>;
}
// Chain: BitwardenProvider → SystemAgentProvider → DefaultKeysProvider
```

**Config format** (`~/.ksshagent/config.toml`):
```toml
[bitwarden]
ssh_agent_path = "/Users/yi/.local/share/bitwarden/ssh-agent"

[default_keys]
names = ["id_ed25519", "id_rsa"]
```

## 7. COMMANDS
```bash
cargo init --bin
cargo add toml serde serde_json thiserror anyhow
cargo add tokio --features full
cargo add zeroize secrecy
cargo add ssh-key ssh-encoding ssh-cipher
cargo add dirs tempfile
cargo add clap --features derive  # CLI parsing

cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo audit
```

## 8. SSH AGENT PROTOCOL REFERENCE
**Message format**: `[4-byte length][type][payload...]`

**Key requests**:
- `SSH_AGENTC_REQUEST_IDENTITIES` (0x0B) → list keys
- `SSH_AGENTC_SIGN_REQUEST` (0x0D) → sign data
- `SSH_AGENT_IDENTITIES_ANSWER` (0x0C) → key list response
- `SSH_AGENT_SIGN_RESPONSE` (0x0E) → signature response

**Links**:
- [OpenSSH PROTOCOL.agent](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.agent)
- [RFC 4251](https://datatracker.ietf.org/doc/html/rfc4251)

## 9. BITWARDEN INTEGRATION
**CLI commands**:
```bash
bw login <email>
bw unlock --passwordenv BW_PASSWORD
bw export --format json  # or use bw SSH agent directly
```

**Security**:
- Never store BW password in config
- Use environment variable or prompt
- Clear unlock session on exit
- BW SSH agent socket path from config

## 10. NOTES & GOTCHAS
- **Unix socket**: Clean up stale socket on startup (`/tmp/ksshagent.sock`)
- **Signal handling**: Graceful shutdown on SIGINT/SIGTERM
- **Cross-platform**: Windows named pipes vs Unix sockets (start with Unix only)
- **Testing**: Mock `bw` CLI, mock system agent socket
- **SSH_AUTH_SOCK**: Point to our socket, forward to system agent via original socket

## 11. NEXT STEPS
- [ ] `cargo init --bin` + add dependencies
- [ ] Create module structure (empty files)
- [ ] Implement `error.rs` (error types)
- [ ] Implement `config.rs` (TOML loading)
- [ ] Implement `ssh_proto.rs` (protocol encoding)
- [ ] Implement `key_provider.rs` (trait)
- [ ] Implement `bitwarden.rs` (BW CLI wrapper)
- [ ] Implement `system_agent.rs` (forward to system)
- [ ] Implement `default_keys.rs` (fallback keys)
- [ ] Implement `agent.rs` (main server loop)
- [ ] Implement `main.rs` (entry point, CLI)
- [ ] Add integration tests
- [ ] Set up CI workflow
- [ ] Write README.md

## 12. REFERENCES
**Crates**:
- [`ssh-key`](https://docs.rs/ssh-key) — SSH key parsing/encoding
- [`ssh-encoding`](https://docs.rs/ssh-encoding) — SSH wire format
- [`zeroize`](https://docs.rs/zeroize) — Secure memory clearing
- [`secrecy`](https://docs.rs/secrecy) — Secret wrapper types
- [`tokio`](https://docs.rs/tokio) — Async runtime
- [`toml`](https://docs.rs/toml) — Config parsing
- [`dirs`](https://docs.rs/dirs) — Home directory paths

**External**:
- [OpenSSH Agent Protocol](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.agent)
- [Bitwarden CLI Docs](https://bitwarden.com/help/cli/)
- [SSH Agent Forwarding](https://www.bryansinger.com/2007/08/01/ssh-agent-forwarding-demystified/)
