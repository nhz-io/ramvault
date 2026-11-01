//! Which processes have a given file open right now.
//!
//! FSKit tells the filesystem nothing about the caller, but a process inside `read(2)` holds
//! the file open, so scanning open descriptors finds it. Only the user's own processes are
//! visible without root, which is exactly the set that can reach the mount.

use std::ffi::c_void;
use std::path::Path;

const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;
/// sizeof(struct vnode_fdinfowithpath): proc_fileinfo (24) + vnode_info (152) + path (1024).
const VNODE_PATH_INFO_LEN: usize = 1200;
const VIP_PATH_OFFSET: usize = 176;

/// PIDs (other than ours) with `path` open.
pub fn holders(path: &Path) -> Vec<i32> {
    let want = path.as_os_str().as_encoded_bytes();
    let me = std::process::id() as i32;
    all_pids()
        .into_iter()
        .filter(|&pid| pid > 0 && pid != me && has_open(pid, want))
        .collect()
}

/// PROC_UID_ONLY: only processes whose effective uid is ours (the rest can't reach the mount).
const PROC_UID_ONLY: u32 = 4;

fn all_pids() -> Vec<i32> {
    let uid = unsafe { libc::getuid() };
    let n = unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) };
    if n <= 0 {
        return vec![];
    }
    let mut pids = vec![0i32; n as usize / size_of::<i32>() + 64];
    let bytes = (pids.len() * size_of::<i32>()) as libc::c_int;
    let n = unsafe { libc::proc_listpids(PROC_UID_ONLY, uid, pids.as_mut_ptr().cast(), bytes) };
    pids.truncate(n.max(0) as usize / size_of::<i32>());
    pids
}

fn has_open(pid: i32, want: &[u8]) -> bool {
    let fd_size = size_of::<libc::proc_fdinfo>() as libc::c_int;
    let bytes =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return false; // gone, or another user's process
    }
    let mut fds: Vec<libc::proc_fdinfo> =
        Vec::with_capacity(bytes as usize / fd_size as usize + 16);
    let cap = (fds.capacity() as libc::c_int) * fd_size;
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut c_void,
            cap,
        )
    };
    if got <= 0 {
        return false;
    }
    unsafe { fds.set_len(got as usize / fd_size as usize) };
    let mut info = [0u8; VNODE_PATH_INFO_LEN];
    fds.iter()
        .filter(|f| f.proc_fdtype == libc::PROX_FDTYPE_VNODE as u32)
        .any(|f| {
            let n = unsafe {
                libc::proc_pidfdinfo(
                    pid,
                    f.proc_fd,
                    PROC_PIDFDVNODEPATHINFO,
                    info.as_mut_ptr().cast(),
                    VNODE_PATH_INFO_LEN as libc::c_int,
                )
            };
            if n as usize != VNODE_PATH_INFO_LEN {
                return false;
            }
            let p = &info[VIP_PATH_OFFSET..];
            let len = p.iter().position(|&b| b == 0).unwrap_or(p.len());
            &p[..len] == want
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_a_child_holding_a_file() {
        let dir = std::env::temp_dir().join(format!("ramvault-holders-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::canonicalize(&dir).unwrap().join("f");
        std::fs::write(&file, b"x").unwrap();
        // `tail -f` keeps the file open.
        let mut child = std::process::Command::new("/usr/bin/tail")
            .arg("-f")
            .arg(&file)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let found = super::holders(&file);
        child.kill().unwrap();
        let _ = child.wait();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(found.contains(&(child.id() as i32)), "{found:?}");
    }
}
