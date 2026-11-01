//! Control protocol over ~/Library/Caches/ramvault/ctl.sock: one JSON request line, then
//! (for `Put` only) exactly `len` raw bytes, then one JSON response line.

use crate::secret::Secret;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Start delivering a profile; returns a token the profile's helpers use.
    Begin {
        profile: String,
        idle: u64,
        max: u64,
    },
    Put {
        token: String,
        name: String,
        len: usize,
    },
    Export {
        token: String,
        key: String,
        file: String,
    },
    Commit {
        token: String,
    },
    Abort {
        token: String,
    },
    Status,
    /// Remove these profiles (all when empty); the vault exits once none are left.
    Lock {
        profiles: Vec<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<ProfileStatus>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProfileStatus {
    pub name: String,
    pub files: Vec<(String, usize)>,
    pub env: Vec<(String, String)>,
    pub idle_left: u64,
    pub max_left: u64,
}

impl Response {
    pub fn ok() -> Response {
        Response {
            ok: true,
            ..Default::default()
        }
    }
    pub fn err(e: impl std::fmt::Display) -> Response {
        Response {
            ok: false,
            error: Some(e.to_string()),
            ..Default::default()
        }
    }
}

pub fn connect() -> Result<UnixStream> {
    let path = crate::paths::socket()?;
    UnixStream::connect(&path).with_context(|| format!("connect {}", path.display()))
}

/// Sends one request (plus optional payload) and reads the response.
pub fn call(req: &Request, payload: Option<&Secret>) -> Result<Response> {
    call_keep(req, payload).map(|(resp, _)| resp)
}

/// Like `call`, but hands back the connection. For `Begin` the vault keeps the staged profile
/// only while this connection is open, so an interrupted `unlock` cleans up by itself.
pub fn call_keep(req: &Request, payload: Option<&Secret>) -> Result<(Response, UnixStream)> {
    let mut s = connect()?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    s.write_all(&line)?;
    if let Some(p) = payload {
        s.write_all(p.as_bytes())?;
    }
    let mut resp = String::new();
    BufReader::new(&s).read_line(&mut resp)?;
    if resp.is_empty() {
        bail!("vault closed the connection");
    }
    let resp: Response = serde_json::from_str(&resp)?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "request failed".into()));
    }
    Ok((resp, s))
}

/// Profile and file names: one path component, no surprises.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn valid_env_key(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(|c: char| c.is_ascii_digit())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(valid_name("talosconfig"));
        assert!(valid_name("kube-config.yaml"));
        assert!(!valid_name(".."));
        assert!(!valid_name(".hidden"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name(""));
        assert!(valid_env_key("KUBECONFIG"));
        assert!(!valid_env_key("1X"));
        assert!(!valid_env_key("A-B"));
    }
}
