//! The FUSE side: a read-only tree `/<profile>/<file>` served from the vault's memory through
//! macFUSE's libfuse3 (src/shim.c), so the FSKit backend works.
//!
//! FSKit reports no caller PID. Instead, each read is checked against the processes that hold the
//! file open at that moment (src/holders.rs); a fresh mtime on every lookup (src/shim.c) makes
//! FSKit drop its cache on open, so every open is followed by a read that reaches this check.

use crate::audit::AuditLog;
use crate::caller::Identity;
use crate::vault::{Node, Vault};
use anyhow::{Result, bail};
use serde_json::json;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

pub struct Shared {
    pub vault: Mutex<Vault>,
    pub log: AuditLog,
}

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();

unsafe extern "C" {
    fn rv_fuse_mount(mountpoint: *const c_char, opts: *const c_char) -> c_int;
    fn rv_fuse_loop() -> c_int;
    fn rv_fuse_unmount();
}

/// Mounts and starts serving on a background thread. Call once.
pub fn mount(
    shared: Arc<Shared>,
    mountpoint: &std::path::Path,
    opts: &str,
) -> Result<std::thread::JoinHandle<()>> {
    if SHARED.set(shared).is_err() {
        bail!("already mounted");
    }
    let mp = CString::new(mountpoint.as_os_str().as_encoded_bytes())?;
    let opts = CString::new(opts)?;
    let rc = unsafe { rv_fuse_mount(mp.as_ptr(), opts.as_ptr()) };
    if rc != 0 {
        bail!("{}", std::io::Error::from_raw_os_error(-rc));
    }
    Ok(std::thread::spawn(|| {
        unsafe { rv_fuse_loop() };
    }))
}

/// Unmounts; the serving thread then returns.
pub fn unmount() {
    if SHARED.get().is_some() {
        unsafe { rv_fuse_unmount() };
    }
}

fn shared() -> &'static Shared {
    SHARED.get().expect("fs not mounted")
}

/// "/", "/profile" or "/profile/file" -> components.
fn split(path: *const c_char) -> Option<Vec<String>> {
    let s = unsafe { CStr::from_ptr(path) }.to_str().ok()?;
    Some(
        s.split('/')
            .filter(|c| !c.is_empty())
            .map(String::from)
            .collect(),
    )
}

fn with_node<T>(path: *const c_char, f: impl FnOnce(&Vault, Node) -> T) -> Result<T, c_int> {
    let parts = split(path).ok_or(libc::ENOENT)?;
    let v = shared().vault.lock().unwrap();
    let node = match parts.as_slice() {
        [] => Node::Root,
        [p] => Node::Dir(v.profiles.get(p).ok_or(libc::ENOENT)?),
        [p, n] => {
            let prof = v.profiles.get(p).ok_or(libc::ENOENT)?;
            let (name, file) = prof.files.get_key_value(n).ok_or(libc::ENOENT)?;
            Node::File(prof, name, file)
        }
        _ => return Err(libc::ENOENT),
    };
    Ok(f(&v, node))
}

/// Logs an open. Who opened is unknown here (FSKit reports no PID, and the opener holds no
/// descriptor yet); the decision happens on read.
fn log_open(path: *const c_char, pid: i32, uid: u32) -> Result<(), c_int> {
    let (profile, file) = with_node(path, |_, node| match node {
        Node::File(p, name, _) => Ok((p.name.clone(), name.to_string())),
        _ => Err(libc::EISDIR),
    })??;
    shared().log.record(
        "open",
        json!({"pid": pid, "uid": uid, "profile": profile, "file": file}),
    );
    Ok(())
}

/// May this read be served? Every process holding the file open must be one of the profile's
/// allowed programs, and there must be at least one. Logs the decision; refreshes last-use.
fn check_read(path: *const c_char) -> Result<(), c_int> {
    let sh = shared();
    let (profile, file, allow) = with_node(path, |_, node| match node {
        Node::File(p, name, _) => Ok((p.name.clone(), name.to_string(), p.allow.clone())),
        _ => Err(libc::EISDIR),
    })??;
    let started = Instant::now();
    let full = crate::paths::mount_point()
        .map_err(|_| libc::EIO)?
        .join(&profile)
        .join(&file);
    let readers: Vec<(i32, Option<Identity>, bool)> = crate::holders::holders(&full)
        .into_iter()
        .map(|pid| {
            let id = Identity::of_pid(pid).ok();
            let ok = id
                .as_ref()
                .is_some_and(|c| allow.iter().any(|a| a.admits(pid, c)));
            (pid, id, ok)
        })
        .collect();
    let allowed = !readers.is_empty() && readers.iter().all(|(_, _, ok)| *ok);
    sh.log.record(
        if allowed { "read" } else { "deny" },
        json!({
            "profile": profile,
            "file": file,
            "readers": readers.iter().map(|(pid, id, ok)| json!({
                "pid": pid,
                "path": id.as_ref().map(|c| &c.path),
                "signing_id": id.as_ref().and_then(|c| c.signing_id.as_ref()),
                "team_id": id.as_ref().and_then(|c| c.team_id.as_ref()),
                "allowed": ok,
            })).collect::<Vec<_>>(),
            "check_ms": started.elapsed().as_millis() as u64,
        }),
    );
    if !allowed {
        return Err(libc::EACCES);
    }
    if let Some(p) = sh.vault.lock().unwrap().profiles.get_mut(&profile) {
        p.last_use = Instant::now();
    }
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn rv_getattr(path: *const c_char, mode: *mut u32, size: *mut u64) -> c_int {
    let r = with_node(path, |_, node| match node {
        Node::Root | Node::Dir(_) => (libc::S_IFDIR as u32 | 0o500, 0),
        Node::File(_, _, f) => (libc::S_IFREG as u32 | 0o400, f.data.len() as u64),
    });
    match r {
        Ok((m, s)) => {
            unsafe {
                *mode = m;
                *size = s;
            }
            0
        }
        Err(e) => -e,
    }
}

#[unsafe(no_mangle)]
extern "C" fn rv_readdir(
    path: *const c_char,
    ctx: *mut c_void,
    add: extern "C" fn(*mut c_void, *const c_char),
) -> c_int {
    let names = with_node(path, |v, node| match node {
        Node::Root => Ok(v.profiles.keys().cloned().collect::<Vec<_>>()),
        Node::Dir(p) => Ok(p.files.keys().cloned().collect()),
        Node::File(..) => Err(libc::ENOTDIR),
    });
    match names {
        Ok(Ok(names)) => {
            for n in [".", ".."].into_iter().map(String::from).chain(names) {
                let c = CString::new(n).unwrap();
                add(ctx, c.as_ptr());
            }
            0
        }
        Ok(Err(e)) | Err(e) => -e,
    }
}

#[unsafe(no_mangle)]
extern "C" fn rv_open(path: *const c_char, flags: c_int, pid: i32, uid: u32) -> c_int {
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return -libc::EROFS;
    }
    match log_open(path, pid, uid) {
        Ok(()) => 0,
        Err(e) => -e,
    }
}

#[unsafe(no_mangle)]
extern "C" fn rv_read(
    path: *const c_char,
    _pid: i32,
    _uid: u32,
    buf: *mut c_char,
    size: usize,
    off: i64,
) -> c_int {
    if let Err(e) = check_read(path) {
        return -e;
    }
    let r = with_node(path, |_, node| {
        let Node::File(_, _, f) = node else {
            return -libc::EISDIR;
        };
        let data = f.data.as_bytes();
        let start = (off.max(0) as usize).min(data.len());
        let end = start.saturating_add(size).min(data.len());
        let n = end - start;
        unsafe { std::ptr::copy_nonoverlapping(data[start..].as_ptr(), buf.cast(), n) };
        n as c_int
    });
    r.unwrap_or_else(|e| -e)
}
