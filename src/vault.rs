//! In-memory vault state: unlocked profiles, their files, env and timers.

use crate::proto::ProfileStatus;
use crate::secret::Secret;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

pub struct File {
    pub data: Secret,
}

pub struct Profile {
    pub name: String,
    pub files: BTreeMap<String, File>,
    pub env: Vec<(String, String)>,
    pub unlocked: Instant,
    /// Wall-clock unlock time, reported as the files' mtime (changes on re-unlock, so caches refresh).
    pub unlocked_wall: SystemTime,
    pub last_use: Instant,
    pub idle: Duration,
    pub max: Duration,
}

impl Profile {
    /// Why this profile has to go now, if it does.
    pub fn expired(&self, now: Instant) -> Option<&'static str> {
        if now.duration_since(self.unlocked) >= self.max {
            Some("max")
        } else if now.duration_since(self.last_use) >= self.idle {
            Some("idle")
        } else {
            None
        }
    }

    pub fn status(&self, now: Instant) -> ProfileStatus {
        let left = |since: Instant, limit: Duration| {
            limit.saturating_sub(now.duration_since(since)).as_secs()
        };
        ProfileStatus {
            name: self.name.clone(),
            files: self
                .files
                .iter()
                .map(|(n, f)| (n.clone(), f.data.len()))
                .collect(),
            env: self.env.clone(),
            idle_left: left(self.last_use, self.idle),
            max_left: left(self.unlocked, self.max),
        }
    }
}

pub enum Node<'a> {
    Root,
    Dir(&'a Profile),
    File(&'a Profile, &'a str, &'a File),
}

#[derive(Default)]
pub struct Vault {
    pub profiles: BTreeMap<String, Profile>,
    /// Profiles being delivered, keyed by token; invisible until committed.
    pub staging: HashMap<String, Profile>,
}

impl Vault {
    pub fn env_value(mount: &Path, profile: &str, file: &str) -> String {
        mount
            .join(profile)
            .join(file)
            .to_string_lossy()
            .into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(idle: u64, max: u64) -> Profile {
        let now = Instant::now();
        Profile {
            name: "p".into(),
            files: BTreeMap::new(),
            env: vec![],
            unlocked: now,
            unlocked_wall: SystemTime::now(),
            last_use: now,
            idle: Duration::from_secs(idle),
            max: Duration::from_secs(max),
        }
    }

    #[test]
    fn expiry() {
        let p = profile(10, 100);
        let t = p.unlocked;
        assert_eq!(p.expired(t + Duration::from_secs(5)), None);
        assert_eq!(p.expired(t + Duration::from_secs(10)), Some("idle"));
        let mut p = profile(10, 100);
        p.last_use = p.unlocked + Duration::from_secs(95);
        assert_eq!(
            p.expired(p.unlocked + Duration::from_secs(100)),
            Some("max")
        );
        let s = p.status(p.unlocked + Duration::from_secs(97));
        assert_eq!((s.idle_left, s.max_left), (8, 3));
    }
}
