//! `ramvault serve`: the vault process. Mounts the FUSE tree, answers the control socket,
//! expires profiles, and on the last one gone zeroizes, unmounts and exits.

use crate::audit::AuditLog;
use crate::fs::Shared;
use crate::proto::{Request, Response, valid_env_key, valid_name};
use crate::secret::{MAX_LEN, Secret};
use crate::vault::{Profile, Vault};
use anyhow::{Context, Result, bail};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A vault with no profiles (e.g. an `unlock` that failed) exits after this long.
const EMPTY_GRACE: Duration = Duration::from_secs(30);
/// Mount retries (500 ms apart) for FSKit's asynchronous teardown of a previous volume: only
/// failures faster than MOUNT_FAST_FAIL, within MOUNT_RETRY_WINDOW of the first attempt.
const MOUNT_FAST_FAIL: Duration = Duration::from_secs(2);
const MOUNT_RETRY_WINDOW: Duration = Duration::from_secs(5);
/// A profile still delivering after this long (hung) is dropped; leaves room for Touch ID prompts.
const STAGING_LIMIT: Duration = Duration::from_secs(600);

struct Daemon {
    shared: Arc<Shared>,
    mount: PathBuf,
    socket: PathBuf,
    session: Mutex<Option<std::thread::JoinHandle<()>>>,
    shutdown: Mutex<bool>,
    /// Set as soon as shutdown begins: no more requests are served.
    closing: std::sync::atomic::AtomicBool,
}

static DAEMON: OnceLock<Daemon> = OnceLock::new();

pub fn serve() -> Result<()> {
    harden();
    let signals = block_signals();
    crate::paths::ensure_state_dir()?;
    // First thing: lets `unlock` see this vault is alive (and wait) while it is still mounting.
    std::fs::write(crate::paths::pid_file()?, std::process::id().to_string())?;

    let log = AuditLog::open(&crate::paths::audit_log()?)?;
    let shared = Arc::new(Shared {
        vault: Mutex::new(Vault::default()),
        log,
    });

    let mount = crate::paths::mount_point()?;
    crate::mountpoint::prepare(&mount)?;
    // FSKit tears a previous volume down asynchronously and has no "done" signal; a mount right
    // after a vault exits can fail transiently (mount(8) returns 69, within a second). Retry only
    // such fast failures, briefly. A slow failure (e.g. macFUSE waited on the "enable file system
    // extension" prompt) is reported at once instead of showing the prompt again.
    let first = Instant::now();
    let mut attempt = 0;
    let session = loop {
        let t = Instant::now();
        match crate::fs::mount(shared.clone(), &mount, FUSE_OPTIONS) {
            Ok(s) => break s,
            Err(e) if t.elapsed() < MOUNT_FAST_FAIL && first.elapsed() < MOUNT_RETRY_WINDOW => {
                attempt += 1;
                eprintln!("ramvault: mount attempt {attempt} failed ({e:#}), retrying");
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "mount {} (is macFUSE installed and its FSKit module enabled?)",
                        mount.display()
                    )
                });
            }
        }
    };
    // Anything failing from here on must not leave the volume mounted.
    let (socket, listener) = match finish_start(&mount) {
        Ok(x) => x,
        Err(e) => {
            crate::fs::stop();
            if crate::mountpoint::wait_gone(&mount, Duration::from_secs(5)) {
                if let Ok(r) = crate::paths::mount_record() {
                    let _ = std::fs::remove_file(r);
                }
            }
            return Err(e);
        }
    };

    shared
        .log
        .record("start", json!({"pid": std::process::id(), "mount": mount}));

    let d = DAEMON.get_or_init(|| Daemon {
        shared,
        mount,
        socket,
        session: Mutex::new(Some(session)),
        shutdown: Mutex::new(false),
        closing: std::sync::atomic::AtomicBool::new(false),
    });
    std::thread::spawn(move || {
        let mut sig: libc::c_int = 0;
        unsafe { libc::sigwait(&signals, &mut sig) };
        d.exit(&format!("signal {sig}"));
    });
    std::thread::spawn(move || d.tick_loop());

    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        std::thread::spawn(move || {
            if let Err(e) = d.handle(conn) {
                eprintln!("ramvault: control connection: {e:#}");
            }
        });
    }
    Ok(())
}

/// After mounting: wait for the volume, record it, open the control socket.
fn finish_start(mount: &std::path::Path) -> Result<(PathBuf, UnixListener)> {
    // FSKit attaches the volume asynchronously; answer `unlock` only once it is really there.
    wait_mounted(mount)?;
    let source = crate::mountpoint::mounted_source(mount).context("mount vanished")?;
    std::fs::write(
        crate::paths::mount_record()?,
        crate::mountpoint::record_line(mount, &source),
    )?;
    let socket = crate::paths::socket()?;
    let _ = std::fs::remove_file(&socket);
    let listener =
        UnixListener::bind(&socket).with_context(|| format!("bind {}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    Ok((socket, listener))
}

fn wait_mounted(mount: &std::path::Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if crate::mountpoint::is_mounted(mount) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    bail!("{} did not appear as a macFUSE volume", mount.display())
}

/// No core dumps (they would write vault memory to disk) and no debugger attach.
fn harden() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    const PT_DENY_ATTACH: libc::c_int = 31;
    unsafe { libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
}

/// SIGTERM (launchctl bootout) / SIGINT / SIGHUP go to one thread that shuts down cleanly.
fn block_signals() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut set, s);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        set
    }
}

/// macFUSE mount options: FSKit (user space, no kext), read-only, hidden from Finder, and no
/// macFUSE error dialogs (errors go to ramvault.err.log, which `unlock` shows).
const FUSE_OPTIONS: &str = "backend=fskit,ro,noexec,nosuid,nodev,fsname=ramvault,volname=ramvault,nobrowse,noappledouble,noapplexattr,noalerts";

impl Daemon {
    fn tick_loop(&self) {
        let started = Instant::now();
        let mut had_profiles = false;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = Instant::now();
            {
                let mut v = self.shared.vault.lock().unwrap();
                let gone: Vec<(String, &str)> = v
                    .profiles
                    .values()
                    .filter_map(|p| p.expired(now).map(|r| (p.name.clone(), r)))
                    .collect();
                for (name, reason) in gone {
                    v.profiles.remove(&name); // drop zeroizes
                    self.shared
                        .log
                        .record("expire", json!({"profile": name, "reason": reason}));
                }
                let hung: Vec<String> = v
                    .staging
                    .iter()
                    .filter(|(_, p)| now.duration_since(p.unlocked) >= STAGING_LIMIT)
                    .map(|(t, _)| t.clone())
                    .collect();
                for t in hung {
                    if let Some(p) = v.staging.remove(&t) {
                        self.shared.log.record(
                            "abandon",
                            json!({"profile": p.name, "reason": "still delivering after 10 min"}),
                        );
                    }
                }
                had_profiles |= !v.profiles.is_empty();
                let empty = v.profiles.is_empty() && v.staging.is_empty();
                if empty && (had_profiles || now.duration_since(started) >= EMPTY_GRACE) {
                    drop(v);
                    self.exit("no profiles left");
                }
            }
            let unmounted = self
                .session
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|s| s.is_finished());
            if unmounted {
                self.exit("unmounted externally");
            }
        }
    }

    /// Zeroize everything, unmount, remove the socket, leave launchd, exit. Runs once.
    /// Stop taking requests: `unlock` must not hand profiles to a vault that is about to go.
    fn close(&self) {
        use std::sync::atomic::Ordering;
        if !self.closing.swap(true, Ordering::SeqCst) {
            let _ = std::fs::remove_file(&self.socket);
        }
    }

    fn exit(&self, reason: &str) -> ! {
        self.close();
        let mut done = self.shutdown.lock().unwrap();
        if !*done {
            {
                let mut v = self.shared.vault.lock().unwrap();
                v.profiles.clear();
                v.staging.clear();
            }
            if let Some(serving) = self.session.lock().unwrap().take() {
                crate::fs::stop();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !serving.is_finished() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if !serving.is_finished() {
                    eprintln!(
                        "ramvault: unmount {} timed out, forcing",
                        self.mount.display()
                    );
                    let _ = std::process::Command::new("/sbin/umount")
                        .arg("-f")
                        .arg(&self.mount)
                        .status();
                }
            }
            let _ = std::fs::remove_file(&self.socket);
            // FSKit detaches the volume asynchronously; leave only once it is gone, so the
            // next vault doesn't find it half-detached.
            if crate::mountpoint::wait_gone(&self.mount, Duration::from_secs(5)) {
                if let Ok(r) = crate::paths::mount_record() {
                    let _ = std::fs::remove_file(r);
                }
            }
            self.shared.log.record("stop", json!({"reason": reason}));
            *done = true;
            // No self-bootout: a late `launchctl bootout` could hit the next vault, which a
            // waiting `unlock` starts as soon as vault.pid is gone. The job stays loaded but not
            // running (KeepAlive is off); the next `unlock` resets it.
            if let Ok(p) = crate::paths::pid_file() {
                let _ = std::fs::remove_file(p);
            }
        }
        std::process::exit(0);
    }

    fn handle(&self, mut conn: UnixStream) -> Result<()> {
        peer_is_us(&conn)?;
        if self.closing.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("vault is shutting down");
        }
        // Unbuffered: a buffered reader would keep a stray, never-wiped copy of a `Put` payload.
        let line = read_header(&mut conn)?;
        let req: Request = serde_json::from_str(&line).context("bad request")?;
        let resp = match self.dispatch(req, &mut conn) {
            Ok(r) => r,
            Err(e) => Response::err(format!("{e:#}")),
        };
        let mut out = serde_json::to_vec(&resp)?;
        out.push(b'\n');
        conn.write_all(&out)?;
        if let Some(token) = resp.token {
            // `Begin`: the unlocking CLI holds this connection until it commits or aborts.
            // EOF (done, Ctrl-C, killed) drops whatever is still staged under the token.
            let mut b = [0u8; 64];
            while matches!(conn.read(&mut b), Ok(n) if n > 0) {}
            if let Some(p) = self.shared.vault.lock().unwrap().staging.remove(&token) {
                self.shared
                    .log
                    .record("abandon", json!({"profile": p.name}));
            }
        }
        Ok(())
    }

    fn dispatch(&self, req: Request, reader: &mut impl std::io::Read) -> Result<Response> {
        let log = &self.shared.log;
        let mut v = self.shared.vault.lock().unwrap();
        match req {
            Request::Begin { profile, idle, max } => {
                if !valid_name(&profile) {
                    bail!("bad profile name {profile:?}");
                }
                let token = token()?;
                let now = Instant::now();
                v.staging.insert(
                    token.clone(),
                    Profile {
                        name: profile,
                        files: BTreeMap::new(),
                        env: vec![],
                        unlocked: now,
                        unlocked_wall: std::time::SystemTime::now(),
                        last_use: now,
                        idle: Duration::from_secs(idle),
                        max: Duration::from_secs(max),
                    },
                );
                Ok(Response {
                    ok: true,
                    token: Some(token),
                    mount: Some(self.mount.clone()),
                    ..Default::default()
                })
            }
            Request::Put { token, name, len } => {
                if len > MAX_LEN {
                    bail!("file larger than 1 MiB");
                }
                // Read the payload first so the connection stays in sync even on refusal.
                drop(v);
                let data = Secret::read_exact(reader, len)?;
                let mut v = self.shared.vault.lock().unwrap();
                let p = staged(&mut v, &token)?;
                if !valid_name(&name) {
                    bail!("bad file name {name:?}");
                }
                if p.files.contains_key(&name) {
                    bail!("{name} already delivered (files are write-once)");
                }
                p.files.insert(name, crate::vault::File { data });
                Ok(Response::ok())
            }
            Request::Export { token, key, file } => {
                let mount = self.mount.clone();
                let p = staged(&mut v, &token)?;
                if !valid_env_key(&key) || !valid_name(&file) {
                    bail!("bad export {key}={file}");
                }
                let value = Vault::env_value(&mount, &p.name, &file);
                p.env.retain(|(k, _)| *k != key);
                p.env.push((key, value));
                Ok(Response::ok())
            }
            Request::Commit { token } => {
                let p = v
                    .staging
                    .remove(&token)
                    .context("unknown or expired token")?;
                if p.files.is_empty() {
                    bail!("profile {} delivered no files", p.name);
                }
                if let Some((k, _)) = p.env.iter().find(|(_, val)| {
                    !p.files
                        .keys()
                        .any(|f| *val == Vault::env_value(&self.mount, &p.name, f))
                }) {
                    bail!(
                        "profile {} exports {k} for a file it did not deliver",
                        p.name
                    );
                }
                log.record(
                    "unlock",
                    json!({
                        "profile": p.name,
                        "files": p.files.iter().map(|(n, f)| json!({"name": n, "size": f.data.len()})).collect::<Vec<_>>(),
                        "idle": p.idle.as_secs(),
                        "max": p.max.as_secs(),
                    }),
                );
                let status = p.status(Instant::now());
                v.profiles.insert(p.name.clone(), p); // replaces (and zeroizes) an older unlock
                Ok(Response {
                    ok: true,
                    profiles: vec![status],
                    ..Default::default()
                })
            }
            Request::Abort { token } => {
                v.staging.remove(&token);
                Ok(Response::ok())
            }
            Request::Status => {
                let now = Instant::now();
                Ok(Response {
                    ok: true,
                    profiles: v.profiles.values().map(|p| p.status(now)).collect(),
                    mount: Some(self.mount.clone()),
                    ..Default::default()
                })
            }
            Request::Lock { profiles } => {
                // `lock` with no names stops everything, including unlocks in progress; naming
                // profiles leaves another unlock that is still delivering alone.
                let all = profiles.is_empty();
                let names: Vec<String> = if all {
                    v.profiles.keys().cloned().collect()
                } else {
                    profiles
                };
                let mut unknown = vec![];
                for n in names {
                    if v.profiles.remove(&n).is_some() {
                        log.record("lock", json!({"profile": n}));
                    } else {
                        unknown.push(n);
                    }
                }
                let empty = v.profiles.is_empty() && (all || v.staging.is_empty());
                drop(v);
                if empty {
                    self.close();
                    // Reply first, then exit from another thread.
                    std::thread::spawn(|| {
                        std::thread::sleep(Duration::from_millis(100));
                        DAEMON.get().unwrap().exit("locked");
                    });
                }
                if !unknown.is_empty() {
                    bail!("not unlocked: {}", unknown.join(", "));
                }
                Ok(Response::ok())
            }
        }
    }
}

/// One request line, read byte by byte (requests are small JSON headers).
fn read_header(conn: &mut UnixStream) -> Result<String> {
    let mut line = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    loop {
        if conn.read(&mut b)? == 0 {
            bail!("connection closed before a request");
        }
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 64 * 1024 {
            bail!("request line too long");
        }
    }
    Ok(String::from_utf8(line)?)
}

fn staged<'a>(v: &'a mut Vault, token: &str) -> Result<&'a mut Profile> {
    v.staging
        .get_mut(token)
        .context("unknown token (not inside `ramvault unlock`?)")
}

fn token() -> Result<String> {
    let mut b = [0u8; 24];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Only our own user may talk to the vault (the socket is 0600 in a 0700 dir, this is belt and braces).
fn peer_is_us(conn: &UnixStream) -> Result<()> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    if unsafe { libc::getpeereid(conn.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        bail!("getpeereid: {}", std::io::Error::last_os_error());
    }
    if uid != unsafe { libc::getuid() } {
        bail!("peer uid {uid} refused");
    }
    Ok(())
}
