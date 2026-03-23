mod agent;
mod bitwarden;
mod config;
mod config_aware_provider;
mod default_keys;
mod error;
mod key_provider;
mod service;
mod ssh_config_parser;
mod ssh_proto;
mod system_agent;

use anyhow::Result;
use clap::{Parser, Subcommand};
use key_provider::KeyProvider;
use ssh_config_parser::SshConfigParser;
use std::path::PathBuf;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "k-ssh-agent")]
#[command(about = "SSH agent with Bitwarden integration")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Enable verbose/debug logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Override config file path
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start the SSH agent server
    Run(RunArgs),

    /// Show connected keys count and provider info
    Status,

    /// Show config file path and contents
    Config,

    /// Initialize a new configuration file
    Init(InitArgs),

    /// Manage macOS Launch Agent service (install/uninstall/start/stop/restart/status)
    Service(ServiceArgs),
}

#[derive(Parser, Debug, Default)]
struct RunArgs {
    /// Socket path for the SSH agent
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

#[derive(Parser, Debug, Default)]
struct InitArgs {
    /// Force overwrite existing config file
    #[arg(short, long)]
    force: bool,

    /// Output path (default: ~/.ksshagent/config.toml)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
struct ServiceArgs {
    #[command(subcommand)]
    action: ServiceAction,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum ServiceAction {
    /// Install the Launch Agent service
    Install,
    /// Uninstall the Launch Agent service
    Uninstall,
    /// Start the service
    Start,
    /// Stop the service
    Stop,
    /// Restart the service
    Restart,
    /// Show service status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if args.verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    debug!("Starting k-ssh-agent with args: {:?}", args);

    // Load config
    let config = load_config(args.config.as_ref())?;

    debug!("Loaded config: {:?}", config);

    // Execute command
    match args.command {
        Some(Command::Run(run_args)) => cmd_run(&config, &run_args).await?,
        Some(Command::Status) => cmd_status(&config).await?,
        Some(Command::Config) => cmd_config(&config, args.config)?,
        Some(Command::Init(init_args)) => cmd_init(&init_args)?,
        Some(Command::Service(service_args)) => cmd_service(service_args.action)?,
        None => cmd_run(&config, &RunArgs::default()).await?,
    }

    Ok(())
}

fn load_config(override_path: Option<&PathBuf>) -> Result<config::Config> {
    match override_path {
        Some(path) => {
            debug!("Loading config from override path: {:?}", path);
            let content = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&content)?)
        }
        None => match config::load() {
            Ok(cfg) => {
                debug!("Loaded config from default location");
                Ok(cfg)
            }
            Err(e) => {
                debug!("Could not load config: {}, using defaults", e);
                Ok(config::Config::default())
            }
        },
    }
}

async fn cmd_run(config: &config::Config, args: &RunArgs) -> Result<()> {
    info!("Starting k-ssh-agent...");

    // Determine socket path
    let socket_path = config
        .agent
        .as_ref()
        .and_then(|a| a.socket_path.clone())
        .map(PathBuf::from)
        .or_else(|| args.socket.clone())
        .unwrap_or_else(|| PathBuf::from("/tmp/ksshagent.sock"));

    debug!("Using socket path: {:?}", socket_path);

    // Determine Bitwarden SSH agent path based on platform and installation method
    // Official Bitwarden SSH agent socket locations:
    // - macOS (.dmg): ~/.bitwarden-ssh-agent.sock
    // - macOS (App Store): ~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
    // - Linux (generic): ~/.bitwarden-ssh-agent.sock
    // - Linux (Snap): ~/snap/bitwarden/current/.bitwarden-ssh-agent.sock
    // - Linux (Flatpak): ~/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock
    let bw_path = config
        .bitwarden
        .ssh_agent_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Try common Bitwarden SSH agent socket locations in order of preference
            let home = dirs::home_dir().unwrap_or_default();

            // Check for Snap installation first (Linux)
            let snap_path = home.join("snap/bitwarden/current/.bitwarden-ssh-agent.sock");
            if snap_path.exists() {
                debug!("Found Bitwarden Snap installation");
                return snap_path;
            }

            // Check for Flatpak installation (Linux)
            let flatpak_path =
                home.join(".var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock");
            if flatpak_path.exists() {
                debug!("Found Bitwarden Flatpak installation");
                return flatpak_path;
            }

            // Check for macOS App Store installation
            let appstore_path = home
                .join("Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock");
            if appstore_path.exists() {
                debug!("Found Bitwarden macOS App Store installation");
                return appstore_path;
            }

            // Default to standard location (~/.bitwarden-ssh-agent.sock)
            debug!("Using default Bitwarden SSH agent socket location");
            home.join(".bitwarden-ssh-agent.sock")
        });

    debug!("Using Bitwarden SSH agent path: {:?}", bw_path);

    // Save the original SSH_AUTH_SOCK before we override it
    let original_ssh_auth_sock = std::env::var("SSH_AUTH_SOCK").ok();
    debug!("Original SSH_AUTH_SOCK: {:?}", original_ssh_auth_sock);

    // Create base FallbackChain
    let mut chain = key_provider::FallbackChain::new();
    chain.add_provider(Box::new(bitwarden::BitwardenProvider::new(bw_path)));
    chain.add_provider(Box::new(system_agent::SystemAgentProvider::with_socket(
        original_ssh_auth_sock,
    )));
    chain.add_provider(Box::new(default_keys::DefaultKeysProvider::new(
        config.default_keys.clone(),
    )));

    // Wrap with ConfigAwareProvider if filtering is enabled
    let provider: Box<dyn KeyProvider> = if config.key_filter.enabled {
        let ssh_config_parser = SshConfigParser::load(&config.key_filter.ssh_config_path).ok();
        Box::new(config_aware_provider::ConfigAwareProvider::new(
            Box::new(chain),
            ssh_config_parser,
            config.key_filter.clone(),
        ))
    } else {
        Box::new(chain)
    };

    // Create and run agent
    let agent = agent::Agent::new(socket_path.clone(), provider);

    // Set SSH_AUTH_SOCK for child processes (Unix only)
    #[cfg(unix)]
    {
        std::env::set_var("SSH_AUTH_SOCK", &socket_path);
        debug!("Set SSH_AUTH_SOCK={:?}", socket_path);
    }

    // Run agent
    if args.foreground {
        info!("Running in foreground mode");
        agent.run().await?;
    } else {
        info!("Running agent (daemon mode)");
        agent.run().await?;
    }

    Ok(())
}

async fn cmd_status(config: &config::Config) -> Result<()> {
    info!("Checking SSH agent status...");

    // Determine Bitwarden SSH agent path
    let bw_path = config
        .bitwarden
        .ssh_agent_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_default()
                .join(".local/share/bitwarden/ssh-agent")
        });

    // Create base FallbackChain
    let mut chain = key_provider::FallbackChain::new();
    chain.add_provider(Box::new(bitwarden::BitwardenProvider::new(bw_path.clone())));
    chain.add_provider(Box::new(system_agent::SystemAgentProvider::new()));
    chain.add_provider(Box::new(default_keys::DefaultKeysProvider::new(
        config.default_keys.clone(),
    )));

    // Wrap with ConfigAwareProvider if filtering is enabled
    let provider: Box<dyn KeyProvider> = if config.key_filter.enabled {
        let ssh_config_parser = SshConfigParser::load(&config.key_filter.ssh_config_path).ok();
        Box::new(config_aware_provider::ConfigAwareProvider::new(
            Box::new(chain),
            ssh_config_parser,
            config.key_filter.clone(),
        ))
    } else {
        Box::new(chain)
    };

    // Count keys from the provider chain
    // Use timeout to prevent hanging
    use tokio::time::{timeout, Duration};
    match timeout(Duration::from_secs(3), provider.list_keys()).await {
        Ok(Ok(keys)) => {
            println!("Total keys: {}", keys.len());
            for key in keys {
                use ssh_key::HashAlg;
                println!("  - {}", key.fingerprint(HashAlg::Sha256));
            }
        }
        Ok(Err(e)) => {
            debug!("Failed to list keys: {}", e);
            println!("Total keys: 0 (no keys configured)");
        }
        Err(_) => {
            debug!("Listing keys timed out");
            println!("Total keys: 0 (timeout checking providers)");
        }
    }

    // Show config paths
    let config_path = args_config_path()?;
    println!("\nConfig file path: {:?}", config_path);
    println!("Bitwarden SSH agent: {:?}", bw_path);

    Ok(())
}

fn cmd_config(config: &config::Config, override_path: Option<PathBuf>) -> Result<()> {
    let config_path = match override_path {
        Some(path) => path,
        None => args_config_path()?,
    };

    println!("Config file path: {:?}", config_path);

    if config_path.exists() {
        println!("\nConfig contents:");
        let content = std::fs::read_to_string(&config_path)?;
        println!("{}", content);
    } else {
        println!("\nConfig file does not exist. Using defaults.");
    }

    println!("\nCurrent configuration:");
    println!("{:#?}", config);

    Ok(())
}

fn args_config_path() -> Result<PathBuf> {
    Ok(config::config_dir().join("config.toml"))
}

fn cmd_init(args: &InitArgs) -> Result<()> {
    use std::fs;
    use std::io::{self, Write};

    // Determine output path
    let output_path = args.output.clone().unwrap_or_else(|| {
        let home = dirs::home_dir().expect("Could not determine home directory");
        home.join(".ksshagent/config.toml")
    });

    // Check if file exists
    if output_path.exists() && !args.force {
        print!(
            "Config file already exists at {:?}. Overwrite? [y/N] ",
            output_path
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Default config template
    let config_template = r#"# k-ssh-agent Configuration
# Generated by: k-ssh-agent init

[bitwarden]
# Path to Bitwarden SSH agent socket
# Default locations (auto-detected):
#   - macOS (.dmg): ~/.bitwarden-ssh-agent.sock
#   - macOS (App Store): ~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock
#   - Linux (generic): ~/.bitwarden-ssh-agent.sock
#   - Linux (Snap): ~/snap/bitwarden/current/.bitwarden-ssh-agent.sock
#   - Linux (Flatpak): ~/.var/app/com.bitwarden.desktop/data/.bitwarden-ssh-agent.sock
# ssh_agent_path = "~/.bitwarden-ssh-agent.sock"

[default_keys]
# Names of default keys to load from ~/.ssh/
names = ["id_ed25519", "id_rsa"]

[agent]
# Socket path for k-ssh-agent (default: /tmp/ksshagent.sock)
# socket_path = "/tmp/ksshagent.sock"

[key_filter]
# Enable key filtering to avoid "Too many authentication failures"
# When enabled, only returns keys matching SSH config IdentityFile or allowed_fingerprints
enabled = false

# SSH config file path (default: ~/.ssh/config)
# ssh_config_path = "~/.ssh/config"

# Allowed key fingerprints (optional, format: SHA256:xxx or xxx)
# Get fingerprints with: ssh-add -l  OR  ssh-keygen -lf ~/.ssh/id_ed25519.pub
# allowed_fingerprints = [
#     "SHA256:VrzNKaV7VcU7jT7hLZJMxxAo6whPc+VVXKaH0exqXiM"
# ]
"#;

    // Write config file
    fs::write(&output_path, config_template)?;

    println!("✓ Configuration file created at {:?}", output_path);
    println!("\nEdit this file to customize your k-ssh-agent settings.");
    println!("Then run: k-ssh-agent");

    Ok(())
}

fn cmd_service(action: ServiceAction) -> Result<()> {
    use service::ServiceAction as SA;

    let action = match action {
        ServiceAction::Install => SA::Install,
        ServiceAction::Uninstall => SA::Uninstall,
        ServiceAction::Start => SA::Start,
        ServiceAction::Stop => SA::Stop,
        ServiceAction::Restart => SA::Restart,
        ServiceAction::Status => SA::Status,
    };

    service::execute(action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_run_command() {
        let args = Args::parse_from(["k-ssh-agent", "run"]);
        assert!(matches!(args.command, Some(Command::Run(_))));
    }

    #[test]
    fn test_parse_run_with_socket() {
        let args = Args::parse_from(["k-ssh-agent", "run", "--socket", "/tmp/test.sock"]);
        if let Some(Command::Run(run_args)) = args.command {
            assert_eq!(run_args.socket, Some(PathBuf::from("/tmp/test.sock")));
        } else {
            panic!("Expected Run command");
        }
    }

    #[test]
    fn test_parse_run_with_foreground() {
        let args = Args::parse_from(["k-ssh-agent", "run", "-f"]);
        if let Some(Command::Run(run_args)) = args.command {
            assert!(run_args.foreground);
        } else {
            panic!("Expected Run command");
        }
    }

    #[test]
    fn test_parse_status_command() {
        let args = Args::parse_from(["k-ssh-agent", "status"]);
        assert!(matches!(args.command, Some(Command::Status)));
    }

    #[test]
    fn test_parse_config_command() {
        let args = Args::parse_from(["k-ssh-agent", "config"]);
        assert!(matches!(args.command, Some(Command::Config)));
    }

    #[test]
    fn test_parse_verbose_flag() {
        let args = Args::parse_from(["k-ssh-agent", "-v", "status"]);
        assert!(args.verbose);
    }

    #[test]
    fn test_parse_config_override() {
        let args = Args::parse_from(["k-ssh-agent", "--config", "/tmp/test.toml", "config"]);
        assert_eq!(args.config, Some(PathBuf::from("/tmp/test.toml")));
    }

    #[test]
    fn test_parse_default_command() {
        // No command should default to run
        let args = Args::parse_from(["k-ssh-agent"]);
        assert!(args.command.is_none());
    }

    #[test]
    fn test_parse_run_all_options() {
        let args = Args::parse_from([
            "k-ssh-agent",
            "-v",
            "--config",
            "/tmp/test.toml",
            "run",
            "--socket",
            "/tmp/agent.sock",
            "-f",
        ]);
        assert!(args.verbose);
        assert_eq!(args.config, Some(PathBuf::from("/tmp/test.toml")));
        if let Some(Command::Run(run_args)) = args.command {
            assert_eq!(run_args.socket, Some(PathBuf::from("/tmp/agent.sock")));
            assert!(run_args.foreground);
        } else {
            panic!("Expected Run command");
        }
    }

    #[test]
    fn test_parse_init_command() {
        let args = Args::parse_from(["k-ssh-agent", "init"]);
        assert!(matches!(args.command, Some(Command::Init(_))));
    }

    #[test]
    fn test_parse_init_with_force() {
        let args = Args::parse_from(["k-ssh-agent", "init", "--force"]);
        if let Some(Command::Init(init_args)) = args.command {
            assert!(init_args.force);
        } else {
            panic!("Expected Init command");
        }
    }

    #[test]
    fn test_parse_init_with_output() {
        let args = Args::parse_from(["k-ssh-agent", "init", "-o", "/tmp/test.toml"]);
        if let Some(Command::Init(init_args)) = args.command {
            assert_eq!(init_args.output, Some(PathBuf::from("/tmp/test.toml")));
        } else {
            panic!("Expected Init command");
        }
    }
}
