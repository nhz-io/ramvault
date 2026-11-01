# ramvault

Short-lived credentials for macOS (Apple Silicon), served from a filesystem that exists only in
memory and ejects itself when you stop using it.

`ramvault unlock talos` runs a *profile* (your script) that mints or decrypts credentials and pipes
them into the vault. Tools then read plain files such as `~/.ramvault/talos/talosconfig`, with no
Touch ID prompt per read. After `RAMVAULT_IDLE` seconds without use (default 1 h), or
`RAMVAULT_MAX` seconds after unlock (default and hard cap 24 h), the vault wipes its copies,
unmounts and exits. Nothing runs while it's locked.

## Why

Decrypting sops/age files with a Secure Enclave key costs one prompt per decrypt, which is painful
with the lid closed. Caching decrypted files on disk defeats the point. ramvault keeps them in one
process's mlock'd memory for a bounded time, and pairs best with credentials that are short-lived
and least-privilege anyway (e.g. a 24 h `os:reader` talosconfig).

## Design

| Piece | How |
|---|---|
| Process | `ramvault serve`, started on demand by `unlock` via `launchctl bootstrap gui/<uid>` of `~/Library/Application Support/ramvault/io.nhz.ramvault.plist`, deliberately **not** in `~/Library/LaunchAgents`, so it never starts at login. On exit it simply exits: the job stays loaded but not running (`KeepAlive` off) until the next `unlock` resets it. |
| Filesystem | macFUSE 5 with its **FSKit** backend (user space, no kernel extension), read-only, `nobrowse`, `noalerts` (no macFUSE error dialogs; errors go to `ramvault.err.log` and `unlock` shows them), mounted at `~/.ramvault` (configurable). A mount right after the previous vault exited is retried for up to 5 s (FSKit tears volumes down asynchronously). Tree: `/<profile>/<file>`, dirs 0500, files 0400, owner = you. |
| FUSE glue | ~110 lines of C (`src/shim.c`) over macFUSE's libfuse3; every operation is answered in Rust (`src/fs.rs`). Not the `fuser` crate: it needs a `/dev/macfuse` file descriptor, which only the kext backend has. FSKit talks over its own channel that only libfuse drives. |
| Delivery | `unlock` asks the vault for a one-time token and runs the profile with `RAMVAULT_TOKEN` etc. The profile calls `ramvault put <name>` (stdin → control socket → vault memory), `ramvault export KEY <name>`. Exit 0 commits atomically; anything else discards. Files are write-once. |
| Who can read | Any process running as you; macFUSE refuses other users. There is no per-program check (see below). |
| Memory | ramvault keeps each file in one exact-size buffer, `mlock`ed (no swap; if the lock fails the file is refused and `unlock` fails) and zeroized (`zeroize`) on expiry, lock, re-unlock and exit; delivery doesn't copy it anywhere else in ramvault. Core dumps off (`RLIMIT_CORE=0`), `PT_DENY_ATTACH`. **Not wiped by ramvault:** copies made by libfuse while answering a read (its reply buffers, freed without wiping, gone when the vault exits), by FSKit/macFUSE in their own processes (their cache, dropped on unmount), and by every program that reads the file. |
| Timers | Per profile: idle since the last open of one of its files, max since unlock. The vault exits when the last profile is gone (or 30 s after start with none). |
| State | `~/Library/Application Support/ramvault/` (0700): plist, control socket `ctl.sock` (0600, peer uid checked, JSON lines), start lock, `vault.pid`, record of where the vault mounted. Not in `~/Library/Caches`, which cleanup tools purge. |
| Audit log | `~/Library/Logs/ramvault.log` (0600), JSON lines: start, unlock (file names and sizes), every open, expire, lock, abandon (interrupted or hung unlock), stop. Never contents. Rotated to `ramvault.log.1` at 1 MiB, so at most about 2 MiB on disk. |

### What it protects against, and what not

The point is that credentials don't live long: they exist only in memory, only for your user, for
at most `RAMVAULT_MAX` (24 h), and are wiped after `RAMVAULT_IDLE` (1 h) without use. Pair it
with credentials that are least-privilege and short-lived themselves (`view`, `os:reader`, 24 h).

It does **not** decide which of your programs may read: while unlocked, anything running as you
can read the files. A per-program check was built and dropped: macFUSE's FSKit backend doesn't
report the calling process, and the workarounds (scanning open files during reads) couldn't
stop concurrent readers or malware simply running the allowed tool (`kubectl config view --raw`).

Notes:

- Idle time counts from the last open that reaches ramvault. FSKit serves repeated reads from
  its own cache, and while one process holds a file open it doesn't forward other processes'
  opens of that file either: those aren't logged and don't reset the idle timer, so a profile
  can expire while a long-running tool keeps its file open. Tools like `kubectl` and
  `talosctl` open, read and close, so each use counts.
- An interrupted `unlock` (Ctrl-C, closed terminal) drops the half-delivered profile at once:
  the vault keeps a staged profile only while the unlocking command's connection is open, and
  at most 10 minutes (a hung profile).
- Several `unlock`s at once are fine: starting the vault is serialized by a lock file.
- Starting the vault has no timeout: the first mount can wait on a macOS prompt (enable the
  file system extension) for as long as you take; if the volume still hasn't appeared after 15 s,
  `unlock` says what it's waiting for. If the vault exits instead, `unlock` shows its error
  (`~/Library/Logs/ramvault.err.log`, emptied before each start). Rerunning `unlock` after
  Ctrl-C waits for the vault that is already starting (`vault.pid` in the state directory)
  instead of restarting it; a vault that is shutting down stops taking requests at once, so an
  `unlock` right after `lock` starts a fresh one.
- `ramvault env` fails when nothing (or not the named profile) is unlocked, so
  `eval "$(ramvault env)"` can't silently leave tools on another config. In a shell startup
  file use `eval "$(ramvault env 2>/dev/null)"`.
- `ramvault lock <name>` fails, naming it, if that profile isn't unlocked.
- A vault that died without unmounting (killed, crashed) leaves a dead mount; the next start
  force-unmounts it.
- The volume has no disk device behind it: no disk image, no network, only memory and local system
  calls (kernel → `fskitd` → macFUSE's extension → ramvault). macOS's privacy system files such
  volumes under "network volumes". So the first time an app (your terminal) reads `~/.ramvault`,
  macOS asks to allow it access to files on network volumes. Allow once per app. (macFUSE's
  `local` option would avoid the prompt, but attaches a placeholder disk-image file on disk, so
  ramvault doesn't use it.)
- Every byte read passes through macFUSE (third-party, signed by Benjamin Fleischer). That's the
  price of a real filesystem on macOS without a kernel extension; a built-in NFS server would
  avoid it but needs a listening TCP port and hangs processes if the vault dies.

## Install

Requires macFUSE 5 with its FSKit module enabled (one time):

```bash
brew install --cask macfuse
```

System Settings → General → Login Items & Extensions → File System Extensions → (i) → switch the
view to **By Category** and enable **macFUSE** and **macFUSE (local)**. In the "By Application"
view the toggles ignore clicks ([macfuse/macfuse#1194](https://github.com/macfuse/macfuse/issues/1194)),
and mounts fail with "File system extension not enabled" until both are on.

Then build (needs Command Line Tools, Rust, and `brew install pkgconf`):

```bash
cargo install --path . --root ~/.local
```

## Use

A profile is any executable, in `~/.config/ramvault/profiles/<name>` or given by path. It must
never write secrets to disk; pipe them into `ramvault put`:

```sh
#!/bin/sh
set -eu
sops -d --extract '["talosconfig"]' ~/secrets/talos.sops.yaml | ramvault put talosconfig
ramvault export TALOSCONFIG talosconfig
```

```bash
ramvault unlock talos          # several profiles at once: ramvault unlock talos kube
eval "$(ramvault env)"         # export TALOSCONFIG=~/.ramvault/talos/talosconfig ...
ramvault status                # mount point, files, env, idle/max time left
ramvault lock                  # zeroize + unmount now (or: ramvault lock talos)
```

Inside a profile: `RAMVAULT_PROFILE`, `RAMVAULT_DIR` (where its files will appear) and
`RAMVAULT_BIN` (this binary) are set. Re-unlocking a profile replaces its files and restarts its timers.

Try it with the demo profile (dummy file):

```bash
RAMVAULT_IDLE=10 ramvault unlock examples/profiles/demo
```

```bash
cat ~/.ramvault/demo/demo.txt
```

The second command prints the dummy line. After 10 s without an open, `ramvault status` says
`locked (vault not running)`.

### Settings

Optional `~/.config/ramvault/config.toml`; an environment variable overrides each key for one run
(e.g. `RAMVAULT_IDLE=10 ramvault unlock demo`). Bad values are reported before anything starts.

```toml
mount = "~/.ramvault"   # where the vault appears; absolute or ~/…, its parent must exist
idle = 3600             # seconds without an open before a profile is dropped
max = 86400             # seconds after unlock before a profile is dropped (at most 86400)
```

| Key | Variable | Default | Read when |
|---|---|---|---|
| `mount` | `RAMVAULT_MOUNT` | `~/.ramvault` | the vault starts (fixed while it runs; `ramvault status` shows it) |
| `idle` | `RAMVAULT_IDLE` | 3600 | `unlock` (per profile) |
| `max` | `RAMVAULT_MAX` | 86400 (also the cap) | `unlock` (per profile) |

The mount point must be missing (created with mode 0700), an empty directory you own, or a dead
ramvault mount (cleared; the vault records the volume it mounted, `macfuse://<uuid>` from the
mount table, so another app's macFUSE volume is
never mistaken for one). Anything else is refused before the vault starts, with the reason: a
file, a symlink, a non-empty directory (its files would be hidden), a directory owned by someone
else, or another filesystem already mounted there.

## Verified on panna (macOS 27.2, macFUSE 5.5.0)

- Demo profile unlocks via launchd; `cat` reads it; `eval "$(ramvault env)"` points at it.
- Interrupted unlock: Ctrl-C during a profile drops the staged profile (`abandon` in the log).
- Crash recovery: after `kill -9` of the vault, the next unlock clears the dead mount and works;
  a macFUSE volume at the mount point that isn't the recorded one is refused.
- Idle eject: with `RAMVAULT_IDLE=3..6` the profile expires, the volume unmounts and the process
  exits (the launchd job stays loaded, not running, until the next unlock); an open resets the
  timer.
- Lock then immediate unlock, repeated: each cycle starts a fresh vault and reads work.
- Nothing on disk: a random marker delivered by a profile and read back was not found in
  `~/Library/Logs`, `~/Library/Application Support/ramvault`,
  `~/.config`, `/private/tmp`, `$TMPDIR`, before or after lock.

## Build from source

```bash
cargo test
```

```bash
cargo build --release
```

## License

MIT
