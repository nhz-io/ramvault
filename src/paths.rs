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

/// `~/Library/Application Support/ramvault` (0700): plist, control socket, start lock, mount
/// record. Not under ~/Library/Caches, which cleanup tools purge.
pub fn state_dir() -> Result<PathBuf> {
    Ok(home()?.join("Library/Application Support/ramvault"))
}

/// Creates the state directory (0700) if needed.
pub fn ensure_state_dir() -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let d = state_dir()?;
    std::fs::create_dir_all(&d).with_context(|| format!("create {}", d.display()))?;
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
    Ok(d)
}

/// Serializes vault starts between concurrent `unlock`s.
pub fn start_lock() -> Result<PathBuf> {
    Ok(state_dir()?.join("start.lock"))
}

/// Where the running (or crashed) vault mounted; removed on a clean exit. Lets the next start
/// tell a dead ramvault mount from someone else's macFUSE volume.
pub fn mount_record() -> Result<PathBuf> {
    Ok(state_dir()?.join("mounted"))
}

/// The vault's process ID, written first thing at start, removed on exit.
pub fn pid_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("vault.pid"))
}

/// The running vault's PID, if `vault.pid` names a live `ramvault` process (not a reused PID).
pub fn vault_pid() -> Option<i32> {
    let pid: i32 = std::fs::read_to_string(pid_file().ok()?)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    if pid <= 0 || unsafe { libc::kill(pid, 0) } != 0 {
        return None;
    }
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let exe = PathBuf::from(String::from_utf8(buf).ok()?);
    (exe.file_name()? == "ramvault").then_some(pid)
}

/// `~/.config/ramvault/config.toml`.
pub fn config_file() -> Result<PathBuf> {
    Ok(home()?.join(".config/ramvault/config.toml"))
}

/// Control socket between the CLI and the vault process.
pub fn socket() -> Result<PathBuf> {
    Ok(state_dir()?.join("ctl.sock"))
}

/// Profile executables named by `ramvault unlock <name>`.
pub fn profiles_dir() -> Result<PathBuf> {
    Ok(home()?.join(".config/ramvault/profiles"))
}

/// The LaunchAgent plist, deliberately outside ~/Library/LaunchAgents so it never starts at login.
pub fn plist() -> Result<PathBuf> {
    Ok(state_dir()?.join(format!("{}.plist", crate::launchd::LABEL)))
}

pub fn audit_log() -> Result<PathBuf> {
    Ok(home()?.join("Library/Logs/ramvault.log"))
}

pub fn stderr_log() -> Result<PathBuf> {
    Ok(home()?.join("Library/Logs/ramvault.err.log"))
}
