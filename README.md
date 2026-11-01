# ramvault

Short-lived credentials for macOS (Apple Silicon), served from a filesystem that exists only in
memory and ejects itself when you stop using it.

`ramvault unlock talos` runs a *profile* (your script) that mints or decrypts credentials and pipes
them into the vault. Tools then read plain files such as `~/.ramvault/talos/talosconfig`, with no
Touch ID prompt per read, and only the programs the profile allows (e.g. `talosctl`) can read them
(or, per profile with `ramvault allow --any`, any of your processes, faster and without the check). After `RAMVAULT_IDLE` seconds without a read (default 1 h), or
`RAMVAULT_MAX` seconds after unlock (default and hard cap 24 h), the vault zeroizes its memory,
unmounts and exits. Nothing runs while it's locked.

## Why

Decrypting sops/age files with a Secure Enclave key costs one prompt per decrypt, which is painful
with the lid closed. Caching decrypted files on disk defeats the point. ramvault keeps them in one
process's mlock'd memory for a bounded time, and pairs best with credentials that are short-lived
and least-privilege anyway (e.g. a 24 h `os:reader` talosconfig).

## Design

| Piece | How |
|---|---|
| Process | `ramvault serve`, started on demand by `unlock` via `launchctl bootstrap gui/<uid>` of `~/Library/Application Support/ramvault/io.nhz.ramvault.plist`, deliberately **not** in `~/Library/LaunchAgents`, so it never starts at login. On exit it `bootout`s itself. |
| Filesystem | macFUSE 5 with its **FSKit** backend (user space, no kernel extension), read-only, `nobrowse`, mounted at `~/.ramvault`. Tree: `/<profile>/<file>`, dirs 0500, files 0400, owner = you. |
| FUSE glue | ~110 lines of C (`src/shim.c`) over macFUSE's libfuse3; every operation is answered in Rust (`src/fs.rs`). Not the `fuser` crate: it needs a `/dev/macfuse` file descriptor, which only the kext backend has. FSKit talks over its own channel that only libfuse drives. |
| Delivery | `unlock` asks the vault for a one-time token and runs the profile with `RAMVAULT_TOKEN` etc. The profile calls `ramvault put <name>` (stdin → control socket → vault memory), `ramvault export KEY <name>`, `ramvault allow <program>…` or `ramvault allow --any`. Exit 0 commits atomically; anything else discards. Files are write-once. |
| Caller check | Per profile. With `allow <program>…`: on every read, all processes holding the file open (yours only) are found by scanning open descriptors; each must be an allowed program, or the read fails with `EACCES`. With `allow --any`: off. See below. |
| Memory | Each file is one exact-size buffer, `mlock`ed (no swap), zeroized (`zeroize`) on expiry, lock, re-unlock and exit. Core dumps off (`RLIMIT_CORE=0`), `PT_DENY_ATTACH`. |
| Timers | Per profile: idle since the last allowed read (with `--any`: the last open), max since unlock. The vault exits when the last profile is gone (or 30 s after start with none). |
| Control | `~/Library/Caches/ramvault/ctl.sock` (0600, dir 0700, peer uid checked). JSON lines. |
| Audit log | `~/Library/Logs/ramvault.log` (0600), JSON lines: start, unlock (file names, sizes, allowed programs), every open, every read / deny with the reading processes (pid, path, signing id, verdict), expire, lock, stop. Never contents. |

### What it protects against, and what not

It protects the credential **file**: it lives only in memory, only for a bounded time, and with
`allow <program>…` only the named programs can read its contents, so other programs (a stray
script, a compromised editor plugin, an `npm install` hook) can't copy it to use elsewhere.

It does **not** stop malware running as you from **using** the credential through an allowed
program: anything that can run `kubectl` can do `kubectl get secrets`, or simply
`kubectl config view --raw` to print the whole file. Ad-hoc signed tools (most Homebrew bottles)
also accept injected libraries (`DYLD_INSERT_LIBRARIES`) without failing the signature check. What
bounds that damage is the credential itself: least privilege (`view`, `os:reader`), a short
lifetime (24 h), and idle eject. So:

- allow only the programs that consume the credential (`talosctl`, `kubectl`), never generic
  readers (`cat`, `less`, `python3`, shells): `cat file | anything` would pass the check;
- mint credentials with the least privilege and shortest lifetime that work.

### Who can read

Each profile declares its readers, one of:

- `ramvault allow talosctl kubectl`: only these programs (checked on every read, below);
- `ramvault allow --any`: any process running as you. No scan and no signature checks, and FSKit
  may cache contents, so reads are faster (about 3 ms per `cat` on panna, against about 14 ms
  with the check).

A profile that declares neither, or both, fails to unlock.

#### How readers are checked

macFUSE's FSKit backend doesn't say which process is calling: FSKit hands the filesystem the
operation without caller credentials, so the PID is always 0. Only the kext backend reports PIDs,
and that needs Reduced Security on Apple Silicon. ramvault identifies readers another way:

1. Every lookup reports a fresh modification time (`src/shim.c`), so FSKit drops its cached
   pages on each open and every open is followed by a `read` that reaches ramvault.
2. A process inside `read(2)` holds the file open. ramvault lists your processes
   (`proc_listpids`) and their open files (`proc_pidinfo` / `proc_pidfdinfo`) to find every
   holder of `~/.ramvault/<profile>/<file>` (`src/holders.rs`). No root, no entitlements.
3. Each holder must be one of the profile's allowed programs: same resolved path, and its running
   code satisfies the code requirement recorded at unlock (`src/caller.rs`):
   - Apple binaries: `anchor apple and identifier "com.apple.cat"`;
   - Developer ID apps: the same identifier and Team ID;
   - ad-hoc signed code (e.g. Homebrew bottles): the exact cdhash.

   Requirements are checked against the running code, so universal binaries match whichever slice
   runs.
4. The read is allowed only if there is at least one holder and **all** holders are allowed.
   With no holder (e.g. memory-mapped access) it's refused.

`allow` refuses:

- **scripts** (`#!`): the process reading would be the interpreter (`/bin/sh`, `python3`), and
  allowing that would let every script read; allow the program the script runs instead;
- **programs without a valid code signature**: there would be nothing to verify a reader against.
  On Apple Silicon every native program is signed (at least ad-hoc), so this only rules out
  unsigned Intel binaries under Rosetta.

Limits, by design or by FSKit:

- **Concurrent readers aren't checked.** While a process holds the file open, FSKit forwards
  neither further opens nor reads: a second process that opens it meanwhile is served from
  FSKit's cache, unchecked (verified: `head` read the file while an allowed `tail -f` held it).
  Readers like `kubectl` and `talosctl` hold the file for milliseconds, but a same-user attacker
  can time it. This is the same class of attacker the section above can't stop, and only the
  kext backend (per-operation PIDs) would close it.

- Opening and `stat` work for any of your processes; only contents are protected.
- An interrupted `unlock` (Ctrl-C, closed terminal) drops the half-delivered profile at once:
  the vault keeps a staged profile only while the unlocking command's connection is open.
- A vault that died without unmounting (killed, crashed) leaves a dead mount; the next start
  force-unmounts it.
- Upgrading an allowed program (e.g. `brew upgrade kubectl`) changes its path or cdhash. Unlock
  the profile again to pick up the new one.
- A PID could in theory be reused between the scan and the signature check (milliseconds, and the
  newcomer would have to be your own process holding the same file open).
- A check takes about 10–35 ms per read (`allow --any` skips it).

Also:

- The volume has no disk device behind it: no disk image, no network, only memory and local system
  calls (kernel → `fskitd` → macFUSE's extension → ramvault). macOS's privacy system files such
  volumes under "network volumes". So the first time an app (your terminal) reads `~/.ramvault`,
  macOS asks to allow it access to files on network volumes. Allow once per app. (macFUSE's
  `local` option would avoid the prompt, but attaches a placeholder disk-image file on disk, so
  ramvault doesn't use it.)
- Every byte read passes through macFUSE (third-party, signed by Benjamin Fleischer). That's the
  price of a real filesystem on macOS without a kernel extension.

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
ramvault allow talosctl            # name in PATH or a path; at least one is required
```

```bash
ramvault unlock talos          # several profiles at once: ramvault unlock talos kube
eval "$(ramvault env)"         # export TALOSCONFIG=~/.ramvault/talos/talosconfig ...
ramvault status                # files, env, allowed programs, idle/max time left
ramvault lock                  # zeroize + unmount now (or: ramvault lock talos)
```

Inside a profile: `RAMVAULT_PROFILE`, `RAMVAULT_DIR` (where its files will appear) and
`RAMVAULT_BIN` (this binary) are set. Re-unlocking a profile replaces its files and restarts its timers.

Try it with the demo profile (dummy file, readable only by `/sbin/md5`):

```bash
RAMVAULT_IDLE=10 ramvault unlock examples/profiles/demo
```

```bash
md5 ~/.ramvault/demo/demo.txt
```

The second command prints the file's MD5; `cat ~/.ramvault/demo/demo.txt` fails with
"Permission denied". After 10 s without an allowed read, `ramvault status` says
`locked (vault not running)`.

| Variable | Default | Meaning |
|---|---|---|
| `RAMVAULT_IDLE` | 3600 | seconds without an allowed read (`--any`: an open) before a profile is dropped (read at `unlock`) |
| `RAMVAULT_MAX` | 86400 | seconds after unlock before a profile is dropped; capped at 86400 |
| `RAMVAULT_FUSE_OPTIONS` | | extra macFUSE mount options, comma-separated (read when the vault starts) |

## Verified on panna (macOS 27.2, macFUSE 5.5.0)

- Demo profile unlocks via launchd; `cat` reads it; `eval "$(ramvault env)"` points at it.
- Caller check: the allowed program reads (also a 6 KB file); `head`, `python3` refused, including
  right after an allowed read (no FSKit cache leak); the allowed program is refused while a
  disallowed process holds the file open.
- `allow --any` profile next to a checked one: `cat`, `head`, `python3` all read it; 3.0 ms per
  `cat` against 13.8 ms for the checked profile; its opens keep it alive while the checked one
  expires; `allow` of a script, no readers declared, or both modes all fail with a clear message.
- Idle eject: with `RAMVAULT_IDLE=4..6` the profile expires, the volume unmounts, the process exits
  and the launchd job is gone; an allowed read resets the timer.
- Nothing on disk: a random marker delivered by a profile and read back was not found in
  `~/Library/Logs`, `~/Library/Caches/ramvault`, `~/Library/Application Support/ramvault`,
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
