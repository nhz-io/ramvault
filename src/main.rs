mod audit;
mod caller;
mod daemon;
mod fs;
mod holders;
mod launchd;
mod paths;
mod proto;
mod secret;
mod vault;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use proto::{Request, call, valid_name};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

const DEFAULT_IDLE: u64 = 3600;
const DEFAULT_MAX: u64 = 86400;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run profiles and serve their files from ~/.ramvault (starts the vault if needed).
    /// RAMVAULT_IDLE (default 3600 s) and RAMVAULT_MAX (default and cap 86400 s) set the timers.
    Unlock {
        /// Name in ~/.config/ramvault/profiles/, or a path to an executable.
        #[arg(required = true)]
        profiles: Vec<String>,
    },
    /// Zeroize and remove profiles now (all of them, and stop the vault, when none are named).
    Lock { profiles: Vec<String> },
    /// Unlocked profiles, their files, env, allowed programs and remaining time.
    Status,
    /// Print `export KEY=...` lines for unlocked profiles, for `eval "$(ramvault env)"`.
    Env { profiles: Vec<String> },

    /// [inside a profile] Store stdin as file NAME of the profile being unlocked.
    Put { name: String },
    /// [inside a profile] Declare env KEY pointing at file NAME of this profile.
    Export { key: String, name: String },
    /// [inside a profile] Allow PROGRAMs (name in PATH or path) to read this profile's files.
    Allow {
        #[arg(required = true)]
        programs: Vec<String>,
    },

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
        Cmd::Serve => daemon::serve().inspect_err(|_| {
            if launchd::running_as_job() {
                let _ = std::fs::remove_file(paths::socket().unwrap_or_default());
                launchd::stop(); // don't stay loaded after a failed start
            }
        }),
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
            let Ok(resp) = call(&Request::Status, None) else {
                return Ok(());
            };
            for p in resp
                .profiles
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
        Cmd::Allow { programs } => {
            let token = profile_token()?;
            for p in programs {
                // Resolved here, with the profile's PATH; the vault reads the signature.
                let program = caller::resolve_program(&p)?;
                call(
                    &Request::Allow {
                        token: token.clone(),
                        program,
                    },
                    None,
                )?;
            }
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

fn secs_env(key: &str, default: u64) -> Result<u64> {
    match std::env::var(key) {
        Ok(v) => v
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .with_context(|| format!("{key}={v}: expected seconds > 0")),
        Err(_) => Ok(default),
    }
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
    if call(&Request::Status, None).is_ok() {
        return Ok(());
    }
    let env: Vec<(String, String)> = ["RAMVAULT_FUSE_OPTIONS"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    launchd::start(&env)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if call(&Request::Status, None).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    launchd::stop();
    bail!(
        "vault did not start; see {}",
        paths::stderr_log()?.display()
    )
}

fn unlock(args: &[String]) -> Result<()> {
    let idle = secs_env("RAMVAULT_IDLE", DEFAULT_IDLE)?;
    let max = secs_env("RAMVAULT_MAX", DEFAULT_MAX)?.min(DEFAULT_MAX);
    let profiles = args
        .iter()
        .map(|a| resolve_profile(a))
        .collect::<Result<Vec<_>>>()?;
    ensure_vault()?;
    let mount = paths::mount_point()?;
    let exe = std::env::current_exe()?;
    let mut failed = false;
    for (name, path) in profiles {
        let token = call(
            &Request::Begin {
                profile: name.clone(),
                idle,
                max,
            },
            None,
        )?
        .token
        .context("no token")?;
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
    if resp.profiles.is_empty() {
        println!("vault running, no profiles");
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
        for a in &p.allow {
            println!("  allow  {}", a.display());
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
