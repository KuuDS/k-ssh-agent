use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy)]
pub enum ServiceAction {
    Install,
    Uninstall,
    Start,
    Stop,
    Restart,
    Status,
}

pub struct ServiceManager {
    plist_path: PathBuf,
    label: String,
}

impl ServiceManager {
    pub fn new() -> Self {
        let label = "com.ksshagent.agent".to_string();
        let plist_path = dirs::home_dir()
            .expect("Could not determine home directory")
            .join("Library/LaunchAgents")
            .join(format!("{}.plist", label));

        Self { plist_path, label }
    }

    fn check_macos(&self) -> Result<()> {
        if !cfg!(target_os = "macos") {
            anyhow::bail!("Service management is only supported on macOS");
        }
        Ok(())
    }

    fn get_executable_path(&self) -> Result<PathBuf> {
        let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

        if exe_path.to_string_lossy().contains("target/") {
            let home = dirs::home_dir().unwrap_or_default();
            let candidates = vec![
                home.join(".cargo/bin/k-ssh-agent"),
                PathBuf::from("/usr/local/bin/k-ssh-agent"),
                PathBuf::from("/opt/homebrew/bin/k-ssh-agent"),
            ];

            for candidate in candidates {
                if candidate.exists() {
                    debug!("Found installed binary at: {:?}", candidate);
                    return Ok(candidate);
                }
            }

            warn!(
                "Running from build directory. Service will use: {:?}",
                exe_path
            );
            warn!("Consider installing with: cargo install --path .");
        }

        Ok(exe_path)
    }

    fn generate_plist(&self, exe_path: &Path) -> String {
        let exe_path_str = exe_path.to_string_lossy();

        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>run</string>
        <string>--foreground</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
    </dict>
    
    <key>StandardOutPath</key>
    <string>{}/Library/Logs/k-ssh-agent.log</string>
    
    <key>StandardErrorPath</key>
    <string>{}/Library/Logs/k-ssh-agent.error.log</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>"#,
            self.label,
            exe_path_str,
            dirs::home_dir().unwrap_or_default().to_string_lossy(),
            dirs::home_dir().unwrap_or_default().to_string_lossy()
        )
    }

    pub fn install(&self) -> Result<()> {
        self.check_macos()?;

        info!("Installing k-ssh-agent service...");

        let exe_path = self.get_executable_path()?;
        if !exe_path.exists() {
            anyhow::bail!("Executable not found at: {:?}", exe_path);
        }

        let launch_agents_dir = self.plist_path.parent().unwrap();
        if !launch_agents_dir.exists() {
            fs::create_dir_all(launch_agents_dir)
                .with_context(|| format!("Failed to create directory: {:?}", launch_agents_dir))?;
        }

        let logs_dir = dirs::home_dir().unwrap_or_default().join("Library/Logs");
        if !logs_dir.exists() {
            fs::create_dir_all(&logs_dir)
                .with_context(|| format!("Failed to create logs directory: {:?}", logs_dir))?;
        }

        if self.plist_path.exists() {
            warn!(
                "Service is already installed. Use 'k-ssh-agent service restart' to apply changes."
            );
            println!("Service is already installed at: {:?}", self.plist_path);
            return Ok(());
        }

        let plist_content = self.generate_plist(&exe_path);
        fs::write(&self.plist_path, plist_content)
            .with_context(|| format!("Failed to write plist file: {:?}", self.plist_path))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.plist_path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o644);
            fs::set_permissions(&self.plist_path, permissions)?;
        }

        println!("✓ Service installed successfully");
        println!("  Plist: {:?}", self.plist_path);
        println!("  Binary: {:?}", exe_path);
        println!("\nTo start the service, run:");
        println!("  k-ssh-agent service start");
        println!("\nThe service will automatically start on login.");

        info!("Service installed at {:?}", self.plist_path);

        Ok(())
    }

    pub fn uninstall(&self) -> Result<()> {
        self.check_macos()?;

        info!("Uninstalling k-ssh-agent service...");

        let _ = self.stop();

        if self.plist_path.exists() {
            fs::remove_file(&self.plist_path)
                .with_context(|| format!("Failed to remove plist file: {:?}", self.plist_path))?;
            println!("✓ Service uninstalled successfully");
            info!("Removed plist: {:?}", self.plist_path);
        } else {
            println!("Service is not installed (plist not found)");
        }

        Ok(())
    }

    pub fn start(&self) -> Result<()> {
        self.check_macos()?;

        info!("Starting k-ssh-agent service...");

        if !self.plist_path.exists() {
            anyhow::bail!("Service is not installed. Run 'k-ssh-agent service install' first.");
        }

        if self.is_running()? {
            println!("Service is already running.");
            return Ok(());
        }

        let output = Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&self.plist_path)
            .output()
            .context("Failed to execute launchctl load")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("already") || stderr.contains("exists") {
                println!("Service is already loaded.");
                return Ok(());
            }
            anyhow::bail!("Failed to start service: {}", stderr);
        }

        println!("✓ Service started successfully");
        info!("Service started");

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        self.check_macos()?;

        info!("Stopping k-ssh-agent service...");

        if !self.is_running()? {
            println!("Service is not running");
            return Ok(());
        }

        let output = Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&self.plist_path)
            .output();

        match output {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if stderr.contains("not") && stderr.contains("loaded") {
                        println!("Service is not running");
                        return Ok(());
                    }
                    anyhow::bail!("Failed to stop service: {}", stderr);
                }
                println!("✓ Service stopped successfully");
                info!("Service stopped");
            }
            Err(e) => {
                debug!("Failed to execute launchctl unload: {}", e);
                println!("Service is not running");
            }
        }

        Ok(())
    }

    pub fn restart(&self) -> Result<()> {
        self.check_macos()?;

        info!("Restarting k-ssh-agent service...");

        let _ = self.stop();
        std::thread::sleep(std::time::Duration::from_millis(500));
        self.start()?;

        println!("✓ Service restarted successfully");

        Ok(())
    }

    pub fn status(&self) -> Result<()> {
        self.check_macos()?;

        info!("Checking service status...");

        let installed = self.plist_path.exists();
        let running = self.is_running()?;

        println!("k-ssh-agent service status:");
        println!("  Installed: {}", if installed { "✓ yes" } else { "✗ no" });
        println!("  Running:   {}", if running { "✓ yes" } else { "✗ no" });

        if installed {
            println!("  Plist:     {:?}", self.plist_path);
        }

        if running {
            let socket_path = "/tmp/ksshagent.sock";
            println!("  Socket:    {}", socket_path);
            println!("\nTo use this agent, set:");
            println!("  export SSH_AUTH_SOCK={}", socket_path);
        } else if installed {
            println!("\nTo start the service:");
            println!("  k-ssh-agent service start");
        } else {
            println!("\nTo install the service:");
            println!("  k-ssh-agent service install");
        }

        Ok(())
    }

    fn is_running(&self) -> Result<bool> {
        let output = Command::new("launchctl")
            .args(["list"])
            .output()
            .context("Failed to execute launchctl list")?;

        if !output.status.success() {
            return Ok(false);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains(&self.label))
    }
}

pub fn execute(action: ServiceAction) -> Result<()> {
    let manager = ServiceManager::new();

    match action {
        ServiceAction::Install => manager.install(),
        ServiceAction::Uninstall => manager.uninstall(),
        ServiceAction::Start => manager.start(),
        ServiceAction::Stop => manager.stop(),
        ServiceAction::Restart => manager.restart(),
        ServiceAction::Status => manager.status(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_manager_creation() {
        let manager = ServiceManager::new();
        assert_eq!(manager.label, "com.ksshagent.agent");
        let path_str = manager.plist_path.to_string_lossy();
        assert!(path_str.ends_with(".plist"));
        assert!(path_str.contains("LaunchAgents"));
    }

    #[test]
    fn test_generate_plist() {
        let manager = ServiceManager::new();
        let exe_path = PathBuf::from("/usr/local/bin/k-ssh-agent");
        let plist = manager.generate_plist(&exe_path);

        assert!(plist.contains("com.ksshagent.agent"));
        assert!(plist.contains("/usr/local/bin/k-ssh-agent"));
        assert!(plist.contains("run"));
        assert!(plist.contains("--foreground"));
        assert!(plist.contains("RunAtLoad"));
        assert!(plist.contains("KeepAlive"));
    }
}
