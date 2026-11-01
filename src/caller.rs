//! Who is reading: executable path and code signature of a process, compared with the programs
//! a profile allowed at unlock time. Readers are found by `holders` (FSKit gives no PID).
//!
//! A PID could in theory be reused between the scan and this check; the window is milliseconds
//! and the replacement would have to be the same user's process holding the same file open.

use anyhow::{Result, anyhow, bail};
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::base::{CFTypeRef, OSStatus};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::CFStringRef;
use core_foundation_sys::url::CFURLRef;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::path::{Path, PathBuf};

type SecCodeRef = *const c_void;

const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecGuestAttributePid: CFStringRef;
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attributes: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: SecCodeRef, flags: u32, requirement: *const c_void) -> OSStatus;
    fn SecStaticCodeCreateWithPath(path: CFURLRef, flags: u32, code: *mut SecCodeRef) -> OSStatus;
    fn SecStaticCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: *const c_void,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFStringRef,
        flags: u32,
        requirement: *mut *const c_void,
    ) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

/// What we know about a program: from a running PID or from a file.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Identity {
    pub path: PathBuf,
    pub signing_id: Option<String>,
    pub team_id: Option<String>,
    pub cdhash: Option<String>,
    /// Signature checked out (SecCodeCheckValidity / SecStaticCodeCheckValidity).
    pub valid: bool,
    /// For allowed programs: the code requirement a running reader must satisfy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<String>,
}

impl Identity {
    /// A program a profile allows, resolved now: symlinks followed, signature read.
    /// Refuses scripts (the reader would be the interpreter) and code without a valid signature
    /// (nothing to verify a reader against).
    pub fn of_program(path: &Path) -> Result<Identity> {
        let path = std::fs::canonicalize(path).map_err(|e| anyhow!("{}: {e}", path.display()))?;
        if is_script(&path) {
            bail!(
                "{} is a script: the process reading would be its interpreter, which can't be \
                 allowed safely; allow the program the script runs (e.g. kubectl) instead",
                path.display()
            );
        }
        let mut id = Identity {
            path: path.clone(),
            ..Default::default()
        };
        let url = CFURL::from_path(&path, false).ok_or_else(|| anyhow!("bad path"))?;
        let mut code: SecCodeRef = std::ptr::null();
        let rc = unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) };
        if rc != 0 {
            bail!("{}: not a code-signed program", path.display());
        }
        let code = Owned(code);
        id.valid = unsafe { SecStaticCodeCheckValidity(code.0, 0, std::ptr::null()) } == 0;
        signing_info(code.0, &mut id);
        id.requirement = requirement_for(code.0, &id);
        if id.requirement.is_none() {
            bail!(
                "{}: no valid code signature, so readers can't be verified against it",
                path.display()
            );
        }
        Ok(id)
    }

    /// A running process.
    pub fn of_pid(pid: i32) -> Result<Identity> {
        if pid <= 0 {
            bail!("no PID");
        }
        let mut id = Identity {
            path: pid_path(pid)?,
            ..Default::default()
        };
        let Some(code) = guest(pid) else {
            return Ok(id);
        };
        id.valid = unsafe { SecCodeCheckValidity(code.0, 0, std::ptr::null()) } == 0;
        signing_info(code.0, &mut id);
        Ok(id)
    }

    /// Is the process `pid` (whose identity is `running`) this allowed program?
    /// Same resolved path, and its running code satisfies the requirement recorded at unlock (Apple-signed + identifier, Developer ID team + identifier,
    /// or for ad-hoc code the exact cdhash). Requirements are checked against the running code,
    /// so universal binaries match whichever slice is executing.
    pub fn admits(&self, pid: i32, running: &Identity) -> bool {
        if self.path != running.path {
            return false;
        }
        self.requirement
            .as_deref()
            .is_some_and(|req| satisfies(pid, req))
    }
}

/// Requirement text for a signed program, or None if it is unsigned or broken.
fn requirement_for(code: SecCodeRef, id: &Identity) -> Option<String> {
    let ident = id.signing_id.as_ref()?;
    if !id.valid {
        return None;
    }
    let quoted = ident.replace('"', "");
    let platform = format!("anchor apple and identifier \"{quoted}\"");
    if static_satisfies(code, &platform) {
        return Some(platform);
    }
    if let Some(team) = &id.team_id {
        let team = team.replace('"', "");
        return Some(format!(
            "anchor apple generic and identifier \"{quoted}\" and certificate leaf[subject.OU] = \"{team}\""
        ));
    }
    id.cdhash.as_ref().map(|h| format!("cdhash H\"{h}\""))
}

fn requirement(text: &str) -> Option<Owned> {
    let text = CFString::new(text);
    let mut req: *const c_void = std::ptr::null();
    let rc = unsafe { SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut req) };
    (rc == 0 && !req.is_null()).then(|| Owned(req))
}

fn static_satisfies(code: SecCodeRef, req: &str) -> bool {
    requirement(req).is_some_and(|r| unsafe { SecStaticCodeCheckValidity(code, 0, r.0) } == 0)
}

fn satisfies(pid: i32, req: &str) -> bool {
    let Some(code) = guest(pid) else {
        return false;
    };
    requirement(req).is_some_and(|r| unsafe { SecCodeCheckValidity(code.0, 0, r.0) } == 0)
}

fn guest(pid: i32) -> Option<Owned> {
    let mut attrs = CFMutableDictionary::<CFString, CFType>::new();
    attrs.set(
        unsafe { CFString::wrap_under_get_rule(kSecGuestAttributePid) },
        CFNumber::from(pid).as_CFType(),
    );
    let mut code: SecCodeRef = std::ptr::null();
    let rc = unsafe {
        SecCodeCopyGuestWithAttributes(std::ptr::null(), attrs.as_concrete_TypeRef(), 0, &mut code)
    };
    (rc == 0 && !code.is_null()).then(|| Owned(code))
}

struct Owned(SecCodeRef);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { core_foundation_sys::base::CFRelease(self.0 as CFTypeRef) };
    }
}

fn signing_info(code: SecCodeRef, id: &mut Identity) {
    let mut info: CFDictionaryRef = std::ptr::null();
    let rc =
        unsafe { SecCodeCopySigningInformation(code, K_SEC_CS_SIGNING_INFORMATION, &mut info) };
    if rc != 0 || info.is_null() {
        return;
    }
    let info: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_create_rule(info) };
    let get = |k: CFStringRef| {
        info.find(unsafe { CFString::wrap_under_get_rule(k) })
            .map(|v| v.clone())
    };
    id.signing_id = get(unsafe { kSecCodeInfoIdentifier })
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string());
    id.team_id = get(unsafe { kSecCodeInfoTeamIdentifier })
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string());
    id.cdhash = get(unsafe { kSecCodeInfoUnique })
        .and_then(|v| v.downcast::<CFData>())
        .map(|d| d.bytes().iter().map(|b| format!("{b:02x}")).collect());
}

fn is_script(path: &Path) -> bool {
    use std::io::Read;
    let mut head = [0u8; 2];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| &head == b"#!")
}

fn pid_path(pid: i32) -> Result<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        bail!("proc_pidpath({pid}): {}", std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(String::from_utf8(buf)?))
}

/// `name` as a path, or looked up in PATH; symlinks resolved (Homebrew links into the Cellar).
pub fn resolve_program(name: &str) -> Result<PathBuf> {
    let found = if name.contains('/') {
        Some(PathBuf::from(name))
    } else {
        std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(name))
                .find(|c| is_executable(c))
        })
    };
    let path = found.ok_or_else(|| anyhow!("{name}: not found in PATH"))?;
    Ok(std::fs::canonicalize(&path).map_err(|e| anyhow!("{}: {e}", path.display()))?)
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn(prog: &str, args: &[&str]) -> std::process::Child {
        let c = std::process::Command::new(prog).args(args).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        c
    }

    fn check(allowed: &Identity, child: &mut std::process::Child) -> bool {
        let pid = child.id() as i32;
        let running = Identity::of_pid(pid).unwrap();
        let ok = allowed.admits(pid, &running);
        child.kill().unwrap();
        let _ = child.wait();
        ok
    }

    #[test]
    fn platform_binary_matches_running_slice() {
        let allowed = Identity::of_program(Path::new("/bin/sleep")).unwrap();
        assert!(
            allowed
                .requirement
                .as_deref()
                .unwrap()
                .starts_with("anchor apple and")
        );
        assert!(check(&allowed, &mut spawn("/bin/sleep", &["5"])));
    }

    #[test]
    fn other_program_refused() {
        let allowed = Identity::of_program(Path::new("/bin/cat")).unwrap();
        assert!(!check(&allowed, &mut spawn("/bin/sleep", &["5"])));
    }

    #[test]
    fn same_path_other_requirement_refused() {
        let mut allowed = Identity::of_program(Path::new("/bin/sleep")).unwrap();
        allowed.requirement = Some("anchor apple and identifier \"com.apple.cat\"".into());
        assert!(!check(&allowed, &mut spawn("/bin/sleep", &["5"])));
        allowed.requirement = Some("cdhash H\"0000000000000000000000000000000000000000\"".into());
        assert!(!check(&allowed, &mut spawn("/bin/sleep", &["5"])));
    }

    #[test]
    fn scripts_refused() {
        let dir = std::env::temp_dir().join(format!("ramvault-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("helper.sh");
        std::fs::write(&f, b"#!/bin/sh\ncat \"$1\"\n").unwrap();
        let e = Identity::of_program(&f).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(e.to_string().contains("is a script"), "{e}");
    }

    #[test]
    fn unsigned_refused() {
        let dir = std::env::temp_dir().join(format!("ramvault-unsigned-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("prog");
        std::fs::write(&f, b"\x7fELF not a mach-o").unwrap();
        let e = Identity::of_program(&f).unwrap_err();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            e.to_string().contains("code-signed") || e.to_string().contains("signature"),
            "{e}"
        );
    }

    #[test]
    fn adhoc_binary_uses_cdhash() {
        // The test binary itself is ad-hoc signed by the linker.
        let exe = std::env::current_exe().unwrap();
        let allowed = Identity::of_program(&exe).unwrap();
        assert!(
            allowed
                .requirement
                .as_deref()
                .unwrap()
                .starts_with("cdhash")
        );
        let me = Identity::of_pid(std::process::id() as i32).unwrap();
        assert!(allowed.admits(std::process::id() as i32, &me));
    }
}
