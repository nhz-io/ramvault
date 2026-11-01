//! JSON-lines log: start, unlock, every open, expire, lock, abandon, stop.
//! ~/Library/Logs/ramvault.log (0600), rotated to ramvault.log.1 at 1 MiB (one old file kept).
//! Never contains file contents.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Rotate when the log passes this size.
const MAX_LOG: u64 = 1 << 20;

pub struct AuditLog {
    file: Mutex<File>,
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<AuditLog> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(AuditLog {
            file: Mutex::new(open_append(path)?),
            path: path.into(),
        })
    }

    pub fn record(&self, event: &str, extra: Value) {
        let now = OffsetDateTime::now_utc();
        let mut rec = json!({
            "time": now.format(&Rfc3339).unwrap_or_default(),
            "event": event,
        });
        if let (Value::Object(r), Value::Object(x)) = (&mut rec, extra) {
            r.extend(x);
        }
        let line = format!("{rec}\n");
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(line.as_bytes());
            if f.metadata().is_ok_and(|m| m.len() > MAX_LOG) {
                let old = self.path.with_extension("log.1");
                if std::fs::rename(&self.path, old).is_ok() {
                    if let Ok(new) = open_append(&self.path) {
                        *f = new;
                    }
                }
            }
        }
    }
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open audit log {}", path.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rotates_at_limit() {
        let dir = std::env::temp_dir().join(format!("ramvault-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("ramvault.log");
        let log = super::AuditLog::open(&path).unwrap();
        let big = "x".repeat(4096);
        for _ in 0..300 {
            log.record("open", serde_json::json!({"pad": big}));
        }
        let cur = std::fs::metadata(&path).unwrap().len();
        let old = std::fs::metadata(dir.join("ramvault.log.1")).unwrap().len();
        assert!(cur <= super::MAX_LOG && old > super::MAX_LOG, "{cur} {old}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
