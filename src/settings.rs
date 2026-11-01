//! Settings: `~/.config/ramvault/config.toml`, overridden per run by environment variables.
//!
//! ```toml
//! mount = "~/.ramvault"   # RAMVAULT_MOUNT; absolute or ~/…
//! idle = 3600             # RAMVAULT_IDLE; seconds without an open before a profile is dropped
//! max = 86400             # RAMVAULT_MAX; seconds after unlock before a profile is dropped (≤ 86400)
//! ```

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::PathBuf;

pub const DEFAULT_IDLE: u64 = 3600;
/// Also the hard cap: credentials never stay longer than a day.
pub const DEFAULT_MAX: u64 = 86400;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct File {
    mount: Option<String>,
    idle: Option<u64>,
    max: Option<u64>,
}

pub struct Settings {
    /// Resolved mount point (parent canonicalized; the kernel reports mounts by real path).
    pub mount: PathBuf,
    pub idle: u64,
    pub max: u64,
}

pub fn load() -> Result<Settings> {
    let path = crate::paths::config_file()?;
    let file: File = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("{}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display()))?,
    };
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());

    let mount = match env("RAMVAULT_MOUNT") {
        Some(v) => resolve_mount(&v).context("RAMVAULT_MOUNT")?,
        None => match &file.mount {
            Some(v) => resolve_mount(v).with_context(|| format!("{}: mount", path.display()))?,
            None => resolve_mount("~/.ramvault")?,
        },
    };
    let secs = |key: &str, from_file: Option<u64>, default: u64| -> Result<u64> {
        let (n, src) = match env(key) {
            Some(v) => (
                v.parse::<u64>()
                    .with_context(|| format!("{key}={v}: expected seconds"))?,
                key.to_string(),
            ),
            None => match from_file {
                Some(n) => (n, format!("{}", path.display())),
                None => return Ok(default),
            },
        };
        if n == 0 || n > DEFAULT_MAX {
            bail!("{src}: {n} s is out of range (1..={DEFAULT_MAX})");
        }
        Ok(n)
    };
    Ok(Settings {
        mount,
        idle: secs("RAMVAULT_IDLE", file.idle, DEFAULT_IDLE)?,
        max: secs("RAMVAULT_MAX", file.max, DEFAULT_MAX)?,
    })
}

/// `~/…` or absolute -> real parent + last component. The mount point itself isn't touched
/// (it may be a dead mount from a crashed vault).
fn resolve_mount(v: &str) -> Result<PathBuf> {
    let p = match v.strip_prefix("~/") {
        Some(rest) => crate::paths::home()?.join(rest),
        None => PathBuf::from(v),
    };
    if !p.is_absolute() {
        bail!("{v}: must be an absolute path or start with ~/");
    }
    let (Some(parent), Some(name)) = (p.parent(), p.file_name()) else {
        bail!("{v}: not a usable mount point");
    };
    let parent = std::fs::canonicalize(parent)
        .with_context(|| format!("{v}: parent {} must exist", parent.display()))?;
    Ok(parent.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn mount_paths() {
        let home = std::fs::canonicalize(crate::paths::home().unwrap()).unwrap();
        assert_eq!(
            resolve_mount("~/.ramvault").unwrap(),
            home.join(".ramvault")
        );
        assert_eq!(
            resolve_mount("/tmp/rv").unwrap(),
            Path::new("/private/tmp/rv")
        );
        assert!(resolve_mount("relative/x").is_err());
        assert!(resolve_mount("/").is_err());
        assert!(resolve_mount("/no/such/parent/rv").is_err());
    }

    #[test]
    fn file_rejects_unknown_keys() {
        assert!(toml::from_str::<File>("mount = \"~/v\"\nidle = 10").is_ok());
        assert!(toml::from_str::<File>("mountpoint = \"~/v\"").is_err());
    }
}
