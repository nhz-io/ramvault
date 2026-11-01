//! Where things live. Nothing here ever holds file contents.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// Mount point; profiles appear as `~/.ramvault/<profile>/<file>`. HOME is resolved to its real
/// path because the kernel reports mounts and open files by that path. The mount point itself is
/// not touched here (this runs inside FUSE callbacks, and it may be a dead mount).
pub fn mount_point() -> Result<PathBuf> {
    let home = home()?;
    let home =
        std::fs::canonicalize(&home).with_context(|| format!("resolve {}", home.display()))?;
    Ok(home.join(".ramvault"))
}

/// Control socket between the CLI and the vault process.
pub fn socket() -> Result<PathBuf> {
    Ok(home()?.join("Library/Caches/ramvault/ctl.sock"))
}

/// Profile executables named by `ramvault unlock <name>`.
pub fn profiles_dir() -> Result<PathBuf> {
    Ok(home()?.join(".config/ramvault/profiles"))
}

/// The LaunchAgent plist, deliberately outside ~/Library/LaunchAgents so it never starts at login.
pub fn plist() -> Result<PathBuf> {
    Ok(home()?.join(format!(
        "Library/Application Support/ramvault/{}.plist",
        crate::launchd::LABEL
    )))
}

pub fn audit_log() -> Result<PathBuf> {
    Ok(home()?.join("Library/Logs/ramvault.log"))
}

pub fn stderr_log() -> Result<PathBuf> {
    Ok(home()?.join("Library/Logs/ramvault.err.log"))
}
