# fix(ssh): one persistent connection per unit instead of a login per poll

## Summary

Every collector poll used to start a fresh `ssh` process. This adds a small
connection manager (`server/collectors/sshPool.js`) that keeps **one** `ssh2`
connection per unit and runs each poll as a channel on it. `sshExec()` routes
through the pool by default; the old subprocess path stays behind
`SPARKDASH_SSH_MODE=spawn` and is unchanged.

- `server/collectors/sshPool.js` — lazily connects per host, reuses the
  connection for every collector, and exposes `exec(target, command, {timeoutMs})`
  → `{ stdout, stderr, code }`.
- Keepalive: 10 s interval, 3 missed probes; `readyTimeout` 15 s.
- Reconnect on `close`/`error`/`end` with exponential backoff (1 s → 30 s) plus
  jitter, one in-flight attempt per host.
- At most 4 concurrent channels per host (sshd `MaxSessions` defaults to 10);
  extra commands wait in a small queue.
- A command timeout closes **only its channel**; the shared connection stays up.
- A unit is reported offline only after 2 consecutive failed connects, so one
  slow poll no longer flips a healthy unit.
- Clean shutdown closes every connection on SIGINT/SIGTERM.
- Connection lifecycle is logged with timestamps: `host-added`, `connected`,
  `disconnected`, `connect-failed`, `reconnect-scheduled`, `online`, `offline`,
  `closed`. No key material, passwords or file contents are logged; the identity
  file is referenced by path and read at connect time.

`ssh2` is pinned at `1.17.0` in `package.json` and the lockfile.

`server/index.js` closes the pool in `shutdown()`. `server/sparks/SparkMonitor.js`
ignores a poll error flagged `transient` (the pool is still inside its reconnect
grace window), so it no longer counts a redialing unit as a failed liveness poll.

## Why

Multiplexing OpenSSH logins needs Unix-domain sockets (`ControlMaster` /
`ControlPath`). Windows OpenSSH has none — it fails with
`getsockname failed: Not a socket` — so on Windows every poll was a full login.
With slow logins over Wi-Fi, polls exceeded their timeouts and units that were
perfectly healthy were shown offline. `ssh2` speaks SSH over a plain TCP socket
from Node, so it works identically on Windows, Linux and macOS and needs no
control socket at all.

## Testing

Unit tests, run on Windows and Linux:

- `sshPool.test.js` (14 tests): one connection reused across many execs,
  reconnect with backoff after a forced close, a command timeout that keeps the
  connection, the channel cap queueing, the offline grace window and recovery,
  shutdown, stdout/stderr/exit-code plumbing, stdin handling and the pool key.
- `ssh.test.js` and `ssh.multiplex.test.js` still pass, so the `spawn` fallback
  and its ControlMaster/ControlPath option selection are untouched.

Full suite on Linux (Ubuntu under WSL, Node 24.15.0):

- `npm run typecheck` — clean.
- `npm run build` — clean.
- `npm test` — 1,706 server/script tests: 1,690 pass, 0 fail, 16 skipped;
  961 frontend tests across 141 files pass; `i18n:check` and `test:i18n-check`
  pass.

Windows (Node 24.12.0): `npm run typecheck`, `npm run build`, `npm run
i18n:check` and the frontend suite (141 files, 961 tests) are all clean, and the
SSH suites pass 53/53 (`sshPool` 14, `ssh` 31, `ssh.multiplex` 8). The server
suite is 1,706 tests: 1,512 pass, 176 fail, 18 skipped. All 176 failures are
pre-existing, not new. Each of the 26 files that fail was then run on its own
against a clean `git archive` checkout of base commit `da20ac5`, same Node, same
command, with the base checkout's `node_modules` junctioned in: every one of them
produced the identical test/pass/fail counts and the identical failing
`test at <file>:line` identifiers, with no test failing only on this branch.
They drive `sh` wrapper scripts, check POSIX mode bits or read `/proc`, none of
which exist on Windows. Three test files were made portable as part of this
change (`frontend-dir`, `dotenv-order`, `MacRuntimeControl`): expected paths are
now built with `path.join`, the spawned server is stopped before its temporary
working directory is removed (Windows locks a directory that is a live process's
cwd, and a failing `t.after` hook aborts the later ones, which used to leave the
runner hanging on the macOS control-token test), and the POSIX-only token-file
test is skipped on Windows.

Live soak: 30 minutes, two units, direct SSH, driven from a Windows host, with
this branch served on its own port while the existing install kept running
untouched on the port it already uses. The numbers are the pool's own per-host
totals, printed when it closed.

| | Unit A | Unit B |
| --- | --- | --- |
| Commands run (polls) | 9,103 | 9,266 |
| Failed commands | 31 | 0 |
| Reconnect attempts | 5 | 0 |
| Offline transitions | 1 — the deliberate sever | 0 |
| Logins on the unit for this process | 2 | 1 |

- Unit B was left alone for the whole window: 9,266 polls, no failures, no
  reconnect, no offline transition, one login. That login is the connection the
  pool opened at the start and held for all thirty minutes.
- Unit A took the deliberate disconnect below: 31 failed commands, all inside
  that window, one offline transition, and one extra login when it redialled.
  Four of its five reconnect attempts were refused while the link was blocked and
  never reached the unit, so they cost no login.
- Both units ran about five commands a second on one connection each, and the
  per-host channel cap was never the bottleneck — the queue stayed empty.
- Dashboard values kept updating: the reported uptime advanced with wall clock,
  and GPU temperature, utilization and VRAM moved between samples.

Deliberate disconnect, at ten minutes in: outbound traffic from the test process
to unit A was blocked for 20 seconds, then released. The pool logged the drop at
once, redialled with backoff (1.0 s, 2.4 s, 4.4 s, 9.8 s — each refused while
blocked), reported the unit offline after the second failed attempt, and
reconnected on its own 18 s after the block was lifted. Nothing was done by hand.
That is the only offline transition on either unit; there were no spontaneous
ones.

What the units logged: `journalctl -u ssh ... | grep -c "Accepted publickey"`
counts 2,753 and 2,688 over the window. Those are not this process's logins. The
pre-existing install was still polling on its own port with one `ssh` process per
poll — about 2,350–2,400 logins per 30 minutes per unit, measured over the half
hour before the run — and it was not touched. A single `ssh2` connection shows up
in the journal exactly once, so the pool's 2 and 1 connects are its whole login
contribution. The comparison that settles it is polls against logins: 9,103 and
9,266 commands ran, while logins on each unit stayed at the spawn-only baseline.
Logging in per poll would have meant roughly 9,000 logins.

The run stopped itself at 30:00 through the server's normal shutdown path: the
pool printed its per-host summary, closed both connections, and the port it was
serving on was gone. The existing install was untouched throughout and still
answers on its own port.

## Platform notes

- **Windows**: the pool is the only path that works — no Unix sockets are
  involved, so `ControlMaster` is never requested. The `spawn` fallback passes
  `ControlMaster=no ControlPath=none`, which is what Windows OpenSSH requires.
- **Linux / macOS**: the pool works the same way (TCP + `ssh2`). `spawn` keeps
  the existing `ControlMaster=auto` + `ControlPersist` behaviour for anyone who
  opts into it with `SPARKDASH_SSH_MODE=spawn`.
- **macOS was not run for this change** (no Apple host was available). The pool
  path is platform-neutral by construction rather than by test: it opens a plain
  TCP socket through `ssh2` (pure JavaScript, no native addons, no compiled
  binaries) and runs each command as a channel; it never spawns a process, never
  goes through a shell, contains no `process.platform` branch, and touches no
  Unix-domain socket. `sshPool.test.js` mocks the transport, so it exercises the
  same code path on any OS.
- The identity file, agent socket and password are resolved exactly as before
  (`SSH_IDENTITY_FILE`, `SSH_AUTH_SOCK`, per-unit encrypted password). The pool
  keeps the identity file's *path* (and a password, for password-auth units)
  on its in-memory host record only, so it can dial; the key itself is read
  from disk at connect time, and neither the key material nor the password is
  logged, written to disk or copied anywhere. The pool key and every log line
  use only `user@host:port`.

## Compatibility

`SPARKDASH_SSH_MODE=pool` is the default. `SPARKDASH_SSH_MODE=spawn`, `SSH_POOL=0`
and `SSH_MULTIPLEX=0` all select the legacy one-process-per-command path, so an
existing deployment can opt out without other edits. `SSH_CONTROL_PERSIST_SECONDS`
now only affects `spawn` mode.
