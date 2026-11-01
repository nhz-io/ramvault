//! The vault runs as an on-demand LaunchAgent: `unlock` bootstraps it, the vault boots itself
//! out when it exits. The plist lives outside ~/Library/LaunchAgents, so nothing starts at login
//! and nothing runs while locked.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Command, Stdio};

pub const LABEL: &str = "io.nhz.ramvault";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn plist(exe: &Path, stderr_log: &Path, env: &[(String, String)]) -> String {
    let [exe, stderr_log] = [exe, stderr_log].map(|p| xml_escape(&p.to_string_lossy()));
    let env: String = env
        .iter()
        .map(|(k, v)| {
            format!(
                "\t\t<key>{}</key>\n\t\t<string>{}</string>\n",
                xml_escape(k),
                xml_escape(v)
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>serve</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
{env}	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<false/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>{stderr_log}</string>
</dict>
</plist>
"#
    )
}

fn domain() -> String {
    format!("gui/{}", unsafe { libc::getuid() })
}

/// Did launchd start this process as our job?
pub fn running_as_job() -> bool {
    std::env::var("XPC_SERVICE_NAME").is_ok_and(|v| v == LABEL)
}

/// Writes the plist and starts the vault process.
pub fn start(env: &[(String, String)]) -> Result<()> {
    // Not canonicalized: under Homebrew this stays the stable /opt/homebrew/bin symlink.
    let exe = std::env::current_exe()?;
    let path = crate::paths::plist()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, plist(&exe, &crate::paths::stderr_log()?, env))
        .with_context(|| format!("write {}", path.display()))?;
    // A job left loaded by a crash would make bootstrap fail; clear it first.
    stop();
    let out = Command::new("launchctl")
        .args(["bootstrap", &domain()])
        .arg(&path)
        .output()?;
    if !out.status.success() {
        bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

pub fn stop() {
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("{}/{LABEL}", domain())])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(test)]
mod tests {
    #[test]
    fn plist_lints() {
        let p = super::plist(
            "/Users/a b/.local/bin/ramvault".as_ref(),
            "/tmp/x&y.log".as_ref(),
            &[("RAMVAULT_MOUNT".into(), "~/a&b".into())],
        );
        assert!(p.contains("x&amp;y"));
        let f = std::env::temp_dir().join(format!("ramvault-plist-{}", std::process::id()));
        std::fs::write(&f, p).unwrap();
        let ok = std::process::Command::new("plutil")
            .arg("-lint")
            .arg(&f)
            .output()
            .unwrap()
            .status
            .success();
        std::fs::remove_file(&f).unwrap();
        assert!(ok);
    }
}
