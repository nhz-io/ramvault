//! Where things live. Nothing here ever holds file contents.

use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// Mount point, from settings (config file / RAMVAULT_MOUNT). Only the vault calls this; the
/// CLI asks the running vault where it is mounted.
pub fn mount_point() -> Result<PathBuf> {
    Ok(crate::settings::load()?.mount)
}

/// Serializes vault starts between concurrent `unlock`s.
pub fn start_lock() -> Result<PathBuf> {
    Ok(home()?.join("Library/Caches/ramvault/start.lock"))
}

/// Where the running (or crashed) vault mounted; removed on a clean exit. Lets the next start
/// tell a dead ramvault mount from someone else's macFUSE volume.
pub fn mount_record() -> Result<PathBuf> {
    Ok(home()?.join("Library/Caches/ramvault/mounted"))
}

/// `~/.config/ramvault/config.toml`.
pub fn config_file() -> Result<PathBuf> {
    Ok(home()?.join(".config/ramvault/config.toml"))
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
