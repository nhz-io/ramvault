//! Is the mount point usable? Checked by the CLI before starting the vault (clear, fast errors)
//! and again by the vault before mounting.

use anyhow::{Context, Result, bail};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, PartialEq)]
pub enum State {
    /// Doesn't exist yet; the vault creates it (0700).
    Missing,
    /// An empty directory owned by the user.
    EmptyDir,
    /// A macFUSE mount left by a vault that died without unmounting; the vault clears it.
    Stale,
}

/// Refuses anything ramvault could damage or hide: files, symlinks, non-empty directories,
/// directories owned by someone else, and other filesystems mounted there.
pub fn check(p: &Path) -> Result<State> {
    if crate::daemon::is_mounted(p) {
        return Ok(State::Stale);
    }
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::Missing),
        Err(e) => return Err(e).with_context(|| format!("mount point {}", p.display())),
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        bail!(
            "mount point {} is a symlink; set mount to the real path",
            p.display()
        );
    }
    if !ft.is_dir() {
        bail!("mount point {} exists and is not a directory", p.display());
    }
    if meta.uid() != unsafe { libc::getuid() } {
        bail!(
            "mount point {} is owned by uid {}, not you",
            p.display(),
            meta.uid()
        );
    }
    let parent = p.parent().context("mount point has no parent")?;
    let parent_dev = std::fs::metadata(parent)
        .with_context(|| format!("{}", parent.display()))?
        .dev();
    if meta.dev() != parent_dev {
        bail!(
            "something else is already mounted at {}; unmount it or choose another mount point",
            p.display()
        );
    }
    let mut entries =
        std::fs::read_dir(p).with_context(|| format!("mount point {}", p.display()))?;
    if entries.next().is_some() {
        bail!(
            "mount point {} is not empty; ramvault won't mount over (and hide) existing files",
            p.display()
        );
    }
    Ok(State::EmptyDir)
}

/// Vault side: make the mount point ready (clear a stale mount, create, 0700).
pub fn prepare(p: &Path) -> Result<()> {
    if check(p)? == State::Stale {
        let ok = std::process::Command::new("/sbin/umount")
            .arg("-f")
            .arg(p)
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            bail!(
                "{} is still mounted from an earlier vault; run `umount -f {}`",
                p.display(),
                p.display()
            );
        }
        if check(p)? == State::Stale {
            bail!("{} is still mounted after `umount -f`", p.display());
        }
    }
    match std::fs::create_dir(p) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            Err(e).with_context(|| format!("create {}", p.display()))
        }
        _ => Ok(std::fs::set_permissions(
            p,
            std::fs::Permissions::from_mode(0o700),
        )?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ramvault-mp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(d).unwrap()
    }

    #[test]
    fn states_and_refusals() {
        let d = tmp("states");
        assert_eq!(check(&d.join("new")).unwrap(), State::Missing);
        std::fs::create_dir(d.join("empty")).unwrap();
        assert_eq!(check(&d.join("empty")).unwrap(), State::EmptyDir);
        std::fs::write(d.join("file"), b"x").unwrap();
        assert!(
            check(&d.join("file"))
                .unwrap_err()
                .to_string()
                .contains("not a directory")
        );
        std::os::unix::fs::symlink(d.join("empty"), d.join("link")).unwrap();
        assert!(
            check(&d.join("link"))
                .unwrap_err()
                .to_string()
                .contains("symlink")
        );
        std::fs::create_dir(d.join("full")).unwrap();
        std::fs::write(d.join("full/keep"), b"x").unwrap();
        assert!(
            check(&d.join("full"))
                .unwrap_err()
                .to_string()
                .contains("not empty")
        );
        assert!(check(Path::new("/dev")).is_err()); // root's, and another filesystem
        prepare(&d.join("new")).unwrap();
        let mode = std::fs::metadata(d.join("new"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
