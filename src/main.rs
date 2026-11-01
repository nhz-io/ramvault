mod audit;
mod daemon;
mod fs;
mod launchd;
mod mountpoint;
mod paths;
mod proto;
mod secret;
mod settings;
mod vault;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use proto::{Request, call, call_keep, valid_name};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run profiles and serve their files from ~/.ramvault (starts the vault if needed).
    /// Timers and mount point come from ~/.config/ramvault/config.toml or RAMVAULT_IDLE / RAMVAULT_MAX / RAMVAULT_MOUNT.
    Unlock {
        /// Name in ~/.config/ramvault/profiles/, or a path to an executable.
        #[arg(required = true)]
        profiles: Vec<String>,
    },
    /// Zeroize and remove profiles now (all of them, and stop the vault, when none are named).
    Lock { profiles: Vec<String> },
    /// Unlocked profiles, their files, env and remaining time.
    Status,
    /// Print `export KEY=...` lines for unlocked profiles, for `eval "$(ramvault env)"`.
    Env { profiles: Vec<String> },

    /// [inside a profile] Store stdin as file NAME of the profile being unlocked.
    Put { name: String },
    /// [inside a profile] Declare env KEY pointing at file NAME of this profile.
    Export { key: String, name: String },

    /// The vault process itself (started by launchd).
    #[command(hide = true)]
    Serve,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("ramvault: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        // On failure the vault has already unmounted; the unlocking CLI sees it exit and
        // reports the error. (No self-bootout: launchd's SIGTERM is blocked here.)
        Cmd::Serve => daemon::serve(),
        Cmd::Unlock { profiles } => unlock(&profiles),
        Cmd::Lock { profiles } => {
            if call(&Request::Status, None).is_err() {
                println!("locked (vault not running)");
                return Ok(());
            }
            call(&Request::Lock { profiles }, None)?;
            Ok(())
        }
        Cmd::Status => status(),
        Cmd::Env { profiles } => {
            let unlocked = call(&Request::Status, None)
                .map(|r| r.profiles)
                .unwrap_or_default();
            // A silent empty output would let `eval` leave tools on some other config.
            let missing: Vec<&String> = profiles
                .iter()
                .filter(|n| !unlocked.iter().any(|p| &p.name == *n))
                .collect();
            if !missing.is_empty() {
                bail!(
                    "not unlocked: {}",
                    missing
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            for p in unlocked
                .iter()
                .filter(|p| profiles.is_empty() || profiles.contains(&p.name))
            {
                for (k, v) in &p.env {
                    println!("export {k}={}", shell_quote(v));
                }
            }
            Ok(())
        }
        Cmd::Put { name } => {
            let token = profile_token()?;
            let data = secret::Secret::read_to_end(&mut std::io::stdin().lock())?;
            let len = data.len();
            call(&Request::Put { token, name, len }, Some(&data))?;
            Ok(())
        }
        Cmd::Export { key, name } => {
            let token = profile_token()?;
            call(
                &Request::Export {
                    token,
                    key,
                    file: name,
                },
                None,
            )?;
            Ok(())
        }
    }
}

fn profile_token() -> Result<String> {
    std::env::var("RAMVAULT_TOKEN")
        .context("only works inside a profile run by `ramvault unlock` (RAMVAULT_TOKEN not set)")
}

/// Profile name or path -> (name in the vault, executable).
fn resolve_profile(arg: &str) -> Result<(String, PathBuf)> {
    let path = if arg.contains('/') {
        PathBuf::from(arg)
    } else {
        paths::profiles_dir()?.join(arg)
    };
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.strip_suffix(".sh").unwrap_or(n).to_string())
        .unwrap_or_default();
    if !valid_name(&name) {
        bail!("bad profile name {name:?} (letters, digits, . _ -)");
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&path).with_context(|| format!("profile {}", path.display()))?;
        if !m.is_file() || m.permissions().mode() & 0o111 == 0 {
            bail!("profile {} is not an executable file", path.display());
        }
    }
    Ok((name, path))
}

fn ensure_vault() -> Result<()> {
    // One start at a time: a second `unlock` racing this one waits here, then finds the vault.
    let _start = start_lock()?;
    if let Ok(resp) = call(&Request::Status, None) {
        // The mount point is fixed while the vault runs.
        let wanted = settings::load()?.mount;
        if let Some(m) = resp.mount.filter(|m| *m != wanted) {
            eprintln!(
                "ramvault: vault already mounted at {}; mount point {} applies after `ramvault lock`",
                m.display(),
                wanted.display()
            );
        }
        return Ok(());
    }
    // Fail fast, with the reason, instead of a vault that never starts.
    mountpoint::check(&settings::load()?.mount)?;
    let env: Vec<(String, String)> = ["RAMVAULT_MOUNT"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    launchd::start(&env)?;
    // No deadline: the first mount can wait on a macOS prompt for as long as the user takes.
    // Wait while the vault process lives; if it exits, show why. Ctrl-C stops waiting (a vault
    // that mounts later exits by itself after 30 s with no profiles).
    let started = Instant::now();
    let mut told = false;
    loop {
        if call(&Request::Status, None).is_ok() {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed > Duration::from_secs(2) && !launchd::is_running() {
            launchd::stop();
            let log = paths::stderr_log()?;
            let tail = std::fs::read_to_string(&log).unwrap_or_default();
            let tail: Vec<&str> = tail.lines().rev().take(5).collect();
            let why: String = tail.into_iter().rev().collect::<Vec<_>>().join("\n  ");
            bail!(
                "the vault exited before it was ready:\n  {}\n(full log: {}){}",
                if why.is_empty() { "(no output)" } else { &why },
                log.display(),
                if why.contains("not enabled") {
                    FSKIT_HINT
                } else {
                    ""
                }
            );
        }
        if !told && elapsed > Duration::from_secs(3) {
            eprintln!("ramvault: waiting for the vault to mount…{FSKIT_HINT}");
            told = true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

const FSKIT_HINT: &str = "\nIf macOS asks about a file system extension: System Settings → General → Login Items & \
Extensions → File System Extensions → (i) → view By Category → enable macFUSE and macFUSE (local).";

/// Exclusive lock on `start.lock`, released when the returned file is dropped.
fn start_lock() -> Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    paths::ensure_state_dir()?;
    let path = paths::start_lock()?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!(
            "lock {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    Ok(f)
}

fn unlock(args: &[String]) -> Result<()> {
    // Validated here, before anything starts: config file plus RAMVAULT_* overrides.
    let settings::Settings { idle, max, .. } = settings::load()?;
    let profiles = args
        .iter()
        .map(|a| resolve_profile(a))
        .collect::<Result<Vec<_>>>()?;
    ensure_vault()?;
    let exe = std::env::current_exe()?;
    let mut failed = false;
    for (name, path) in profiles {
        // Held until commit/abort: if this process dies, the vault drops the staged profile.
        let (begun, _staging) = call_keep(
            &Request::Begin {
                profile: name.clone(),
                idle,
                max,
            },
            None,
        )?;
        let token = begun.token.context("no token")?;
        let mount = begun
            .mount
            .context("vault did not say where it is mounted")?;
        let st = Command::new(&path)
            .env("RAMVAULT_TOKEN", &token)
            .env("RAMVAULT_PROFILE", &name)
            .env("RAMVAULT_DIR", mount.join(&name))
            .env("RAMVAULT_BIN", &exe)
            .status()
            .with_context(|| format!("run {}", path.display()));
        let result = match st {
            Ok(s) if s.success() => call(
                &Request::Commit {
                    token: token.clone(),
                },
                None,
            ),
            Ok(s) => Err(anyhow::anyhow!("profile exited with {s}")),
            Err(e) => Err(e),
        };
        match result {
            Ok(resp) => {
                for p in resp.profiles {
                    println!(
                        "unlocked {} ({} file(s), idle {}s, max {}s)",
                        p.name,
                        p.files.len(),
                        p.idle_left,
                        p.max_left
                    );
                    for (k, v) in &p.env {
                        println!("  export {k}={}", shell_quote(v));
                    }
                }
            }
            Err(e) => {
                let _ = call(&Request::Abort { token }, None);
                eprintln!("ramvault: {name}: {e:#}");
                failed = true;
            }
        }
    }
    if failed {
        bail!("some profiles failed to unlock");
    }
    Ok(())
}

fn status() -> Result<()> {
    let Ok(resp) = call(&Request::Status, None) else {
        println!("locked (vault not running)");
        return Ok(());
    };
    if let Some(m) = &resp.mount {
        println!("vault mounted at {}", m.display());
    }
    if resp.profiles.is_empty() {
        println!("no profiles");
    }
    for p in resp.profiles {
        println!(
            "{}: idle {} left, max {} left",
            p.name,
            hms(p.idle_left),
            hms(p.max_left)
        );
        for (f, size) in &p.files {
            println!("  file   {f} ({size} bytes)");
        }
        for (k, v) in &p.env {
            println!("  env    {k}={v}");
        }
    }
    Ok(())
}

fn hms(s: u64) -> String {
    format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}
