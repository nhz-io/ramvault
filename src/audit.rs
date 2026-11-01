//! Append-only JSON-lines log: every unlock, delivery, read, refusal and eject.
//! ~/Library/Logs/ramvault.log (0600). Never contains file contents.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<AuditLog> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open audit log {}", path.display()))?;
        Ok(AuditLog {
            file: Mutex::new(file),
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
        }
    }
}
