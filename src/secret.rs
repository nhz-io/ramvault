//! File contents held only in memory: mlock'd (kept out of swap), zeroized on drop.

use std::io::Read;
use zeroize::Zeroize;

/// Upper bound for one delivered file; credentials are small.
pub const MAX_LEN: usize = 1 << 20;

pub struct Secret {
    buf: Vec<u8>,
    locked: bool,
}

impl Secret {
    /// Takes ownership of `buf` without copying it, so no stray copy is left behind.
    pub fn new(buf: Vec<u8>) -> Secret {
        let locked = !buf.is_empty() && unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) } == 0;
        Secret { buf, locked }
    }

    /// Reads exactly `len` bytes into a buffer allocated once (no reallocation copies).
    pub fn read_exact(r: &mut impl Read, len: usize) -> std::io::Result<Secret> {
        let mut s = Secret::new(vec![0u8; len]);
        if let Err(e) = r.read_exact(&mut s.buf) {
            return Err(e); // `s` zeroizes on drop
        }
        Ok(s)
    }

    /// Reads until EOF, up to MAX_LEN. Growth copies into a fresh buffer and wipes the old one.
    pub fn read_to_end(r: &mut impl Read) -> std::io::Result<Secret> {
        let mut buf = vec![0u8; 4096];
        let mut n = 0;
        loop {
            if n == buf.len() {
                if buf.len() >= MAX_LEN {
                    buf.zeroize();
                    return Err(std::io::Error::other("input larger than 1 MiB"));
                }
                let mut bigger = vec![0u8; (buf.len() * 2).min(MAX_LEN)];
                bigger[..n].copy_from_slice(&buf[..n]);
                buf.zeroize();
                buf = bigger;
            }
            match r.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    buf.zeroize();
                    return Err(e);
                }
            }
        }
        let mut exact = vec![0u8; n];
        exact.copy_from_slice(&buf[..n]);
        buf.zeroize();
        Ok(Secret::new(exact))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.buf.zeroize();
        if self.locked {
            unsafe { libc::munlock(self.buf.as_ptr().cast(), self.buf.capacity()) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_to_end_grows() {
        let data: Vec<u8> = (0..10_000u32).map(|i| i as u8).collect();
        let s = Secret::read_to_end(&mut &data[..]).unwrap();
        assert_eq!(s.as_bytes(), &data[..]);
    }

    #[test]
    fn read_to_end_limit() {
        let data = vec![1u8; MAX_LEN + 1];
        assert!(Secret::read_to_end(&mut &data[..]).is_err());
    }
}
