//! The FUSE side: a read-only tree `/<profile>/<file>` served from the vault's memory through
//! macFUSE's libfuse3 (src/shim.c), so the FSKit backend works.
//!
//! Every open is logged and resets the profile's idle timer. FSKit may serve repeated reads from
//! its own cache, so opens, not reads, are what counts as use.

use crate::audit::AuditLog;
use crate::vault::{Node, Vault};
use anyhow::{Result, bail};
use serde_json::json;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, UNIX_EPOCH};

pub struct Shared {
    pub vault: Mutex<Vault>,
    pub log: AuditLog,
}

static SHARED: OnceLock<Arc<Shared>> = OnceLock::new();

unsafe extern "C" {
    fn rv_fuse_mount(mountpoint: *const c_char, opts: *const c_char) -> c_int;
    fn rv_fuse_loop() -> c_int;
    fn rv_fuse_exit();
    fn rv_fuse_unmount();
}

/// Mounts and starts serving on a background thread. Call once.
pub fn mount(
    shared: Arc<Shared>,
    mountpoint: &std::path::Path,
    opts: &str,
) -> Result<std::thread::JoinHandle<()>> {
    // Set once; a retried mount reuses it.
    let _ = SHARED.set(shared);
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

/// Ends the serving loop, then unmounts (which wakes the loop so it sees the exit); the serving
/// thread then returns.
pub fn stop() {
    if SHARED.get().is_some() {
        unsafe {
            rv_fuse_exit();
            rv_fuse_unmount();
        }
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

/// Logs an open and refreshes its profile's last-use. The PID is 0 with FSKit (no caller identity).
fn log_open(path: *const c_char, pid: i32, uid: u32) -> Result<(), c_int> {
    let sh = shared();
    let (profile, file) = with_node(path, |_, node| match node {
        Node::File(p, name, _) => Ok((p.name.clone(), name.to_string())),
        _ => Err(libc::EISDIR),
    })??;
    sh.log.record(
        "open",
        json!({"pid": pid, "uid": uid, "profile": profile, "file": file}),
    );
    if let Some(p) = sh.vault.lock().unwrap().profiles.get_mut(&profile) {
        p.last_use = Instant::now();
    }
    Ok(())
}

#[unsafe(no_mangle)]
extern "C" fn rv_getattr(
    path: *const c_char,
    mode: *mut u32,
    size: *mut u64,
    mtime: *mut libc::timespec,
) -> c_int {
    let r = with_node(path, |_, node| match node {
        Node::Root | Node::Dir(_) => (libc::S_IFDIR as u32 | 0o500, 0, None),
        Node::File(p, _, f) => (
            libc::S_IFREG as u32 | 0o400,
            f.data.len() as u64,
            Some(p.unlocked_wall),
        ),
    });
    match r {
        Ok((m, s, t)) => {
            let d = t
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .unwrap_or_default();
            unsafe {
                *mode = m;
                *size = s;
                *mtime = libc::timespec {
                    tv_sec: d.as_secs() as libc::time_t,
                    tv_nsec: d.subsec_nanos() as libc::c_long,
                };
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
