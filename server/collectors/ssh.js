/**
 * sshExec — centralized SSH command execution.
 *
 * Two transports, chosen by `sshMode()`:
 *   - pool  (default) — one persistent ssh2 connection per host, shared by
 *     every poller (see sshPool.js). No login per poll, no ControlMaster.
 *   - spawn           — one `ssh` subprocess per command, the legacy path and
 *     the fallback when a host's sshd refuses session sharing.
 *
 * The spawn path still uses execFile + argv arrays (no shell interpolation of
 * user/host/cmd) and sshpass -e (password via env, never on argv).
 */
import { decodeClixml, powershellCommand } from "./windowsMetrics.js";
import { execFile } from "child_process";
import crypto from "crypto";
import fs from "fs";
import os from "os";
import path from "path";
import {
  COMFY_PORT,
  COMFY_PROBE_TIMEOUT_MS,
  SSH_CONNECT_TIMEOUT,
  SSH_MULTIPLEX,
} from "../config.js";
import { isAllowedTargetHost, isValidSshUser, normalizeSshPort } from "../validate.js";
import { llmProbeHost } from "./llmHost.js";

/** A decoded PowerShell error keeps its first line or two; the rest is position noise. */
const CLIXML_MESSAGE_MAX = 300;

// Detect sshpass without shelling out to `which` on every cold call —
// checking PATH entries directly is faster and avoids spawning a shell.
let _sshpassAvailable = null;
const _multiplexStates = new Map();
// Windows OpenSSH keeps a handle to every process started over a connection until that
// connection closes (PowerShell/Win32-OpenSSH#2138), so a master kept alive by polling pins
// cmd.exe/conhost.exe/powershell.exe handles for days and leaks gigabytes of the monitored
// PC's kernel memory. A Windows unit therefore moves to a new socket every hour: the retired
// master has no sessions left, exits once ControlPersist runs out, and Windows frees what it
// held. Reconnecting per command is no fix there — it leaks on every new connection too
// (#2476) and brings back #73's session churn.
const WINDOWS_MASTER_MAX_AGE_MS = 60 * 60 * 1000;
// Keep the private directory short even on macOS, where TMPDIR can already
// consume most of a Unix socket's 104-byte path limit.
const _controlSalt = crypto.randomBytes(32);

/** ssh's own exit code for transport-level failures (dropped connection, auth). */
const SSH_TRANSPORT_EXIT = 255;

// Created on first use: a pooled install never touches a socket directory, so
// Windows (which has no Unix sockets) never reaches the ControlMaster path.
let _controlDir = null;

function controlPersistSeconds() {
  const configured = Number.parseInt(
    process.env.SSH_CONTROL_PERSIST_SECONDS ?? process.env.SSH_CONTROL_PERSIST ?? "60",
    10
  );
  return Number.isFinite(configured) ? Math.min(3600, Math.max(0, configured)) : 60;
}

/**
 * Create (once) the private directory that holds the control sockets.
 *
 * `/tmp` is the base when the platform has it: Unix socket paths are capped at
 * ~104 bytes, and a long macOS TMPDIR would blow that. Windows has neither
 * `/tmp` nor Unix sockets, so the OS temp dir is the only workable fallback
 * there (and pool mode never asks for this directory at all).
 */
function ensureControlDir() {
  if (!_controlDir) {
    try {
      _controlDir = fs.mkdtempSync("/tmp/sparkdash-ssh-");
    } catch {
      _controlDir = fs.mkdtempSync(path.join(os.tmpdir(), "sparkdash-ssh-"));
    }
  }
  fs.mkdirSync(_controlDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(_controlDir, 0o700);
  return _controlDir;
}

/**
 * Build an isolated OpenSSH control socket config. Credentials are included
 * only in the digest so two password records cannot share an authenticated
 * transport; the secret itself is never exposed in argv or the socket path.
 */
export function sshMultiplexConfig(spark, targetHost, user, auth, password, port = 22) {
  const persistSeconds = controlPersistSeconds();
  if (persistSeconds === 0) return null;

  const controlDir = ensureControlDir();
  const identityFile = process.env.SSH_IDENTITY_FILE || "default";
  const sshPort = normalizeSshPort(port) ?? 22;
  const isolation = [spark.id, user, targetHost, String(sshPort), auth || "key", identityFile, password || ""];
  // One socket per hour on Windows; everything else keeps its socket for as long as it polls.
  if (spark.platform === "windows") {
    isolation.push(`master-${Math.floor(Date.now() / WINDOWS_MASTER_MAX_AGE_MS)}`);
  }
  const isolationKey = isolation.join("\0");
  const digest = crypto
    .createHash("sha256")
    .update(_controlSalt)
    .update(isolationKey)
    .digest("hex")
    .slice(0, 24);
  return {
    key: digest,
    persistSeconds,
    args: [
      "-o",
      "ControlMaster=auto",
      "-o",
      `ControlPersist=${persistSeconds}`,
      "-o",
      `ControlPath=${controlDir}/${digest}`,
    ],
  };
}

/** Establish or re-check the master before concurrent pollers run. */
export async function ensureMultiplexReady(config, establish) {
  if (!config) return;

  const now = Date.now();
  // Forget readiness for sockets that have run out. A rotated Windows unit leaves one entry
  // behind per hour; pruning the whole map keeps it bounded no matter how many units rotate.
  for (const [key, stale] of _multiplexStates) {
    if (now >= stale.expiresAt) _multiplexStates.delete(key);
  }
  let state = _multiplexStates.get(config.key);

  if (!state) {
    state = {
      ready: Promise.resolve().then(establish),
      expiresAt: now + config.persistSeconds * 1000,
    };
    _multiplexStates.set(config.key, state);
  }

  try {
    await state.ready;
  } catch (err) {
    if (_multiplexStates.get(config.key) === state) _multiplexStates.delete(config.key);
    throw err;
  }
}

/** Forget cached readiness after a multiplexed command fails. */
export function invalidateMultiplex(config) {
  if (config) _multiplexStates.delete(config.key);
}

process.once("exit", () => {
  if (!_controlDir) return;
  try {
    fs.rmSync(_controlDir, { recursive: true, force: true });
  } catch {
    // ControlPersist bounds any master left behind by an abrupt shutdown.
  }
});

function sshpassAvailable() {
  if (_sshpassAvailable !== null) return _sshpassAvailable;
  try {
    const candidates = [
      "/usr/bin/sshpass",
      "/usr/local/bin/sshpass",
      "/bin/sshpass",
      "/opt/homebrew/bin/sshpass",
    ];
    for (const p of candidates) {
      try {
        if (fs.existsSync(p) && fs.statSync(p).isFile()) {
          _sshpassAvailable = true;
          return _sshpassAvailable;
        }
      } catch {
        /* ignore */
      }
    }
    // Fall back to a PATH scan in case sshpass lives somewhere unusual.
    const pathDirs = (process.env.PATH || "").split(":");
    for (const dir of pathDirs) {
      if (!dir) continue;
      try {
        const candidate = `${dir}/sshpass`;
        if (fs.existsSync(candidate)) {
          _sshpassAvailable = true;
          return _sshpassAvailable;
        }
      } catch {
        /* ignore */
      }
    }
    _sshpassAvailable = false;
  } catch {
    _sshpassAvailable = false;
  }
  return _sshpassAvailable;
}

/**
 * Validate a unit's SSH coordinates once, for both transports.
 *
 * Throws the same errors the spawn path always threw, so a bad unit record
 * fails identically in pool mode. The password is only carried when the unit
 * is configured for password auth.
 *
 * @param {object} spark
 * @returns {{ host: string, port: number, user: string, password?: string }}
 */
export function resolveSshTarget(spark) {
  const { host, user, auth, password } = spark?.ssh || {};
  const targetHost = host || spark?.lanIp;
  const sshPort = normalizeSshPort(spark?.ssh?.port) ?? 22;

  if (!targetHost || !user) {
    throw new Error(`SSH config missing for ${spark?.id}: host=${targetHost}, user=${user}`);
  }
  if (!isAllowedTargetHost(targetHost)) {
    throw new Error(`SSH host not allowed: ${targetHost}`);
  }
  if (!isValidSshUser(user)) {
    throw new Error(`SSH user not allowed: ${user}`);
  }

  return { host: targetHost, port: sshPort, user, password: auth === "pass" ? password : undefined };
}

/** Default OpenSSH key names, in the order the `ssh` client tries them. */
const DEFAULT_KEY_NAMES = ["id_ed25519", "id_rsa", "id_ecdsa"];

/**
 * The private key a pooled connection presents, with the same precedence the
 * `ssh` client uses: SSH_IDENTITY_FILE, else the default keys under ~/.ssh.
 * Returns null when neither exists, so the pool falls back to the agent.
 *
 * Path only — the key itself is read by the pool at connect time and never
 * logged or copied anywhere.
 */
export function pooledIdentityFile() {
  if (process.env.SSH_IDENTITY_FILE) return process.env.SSH_IDENTITY_FILE;
  const home = process.env.HOME || process.env.USERPROFILE;
  if (!home) return null;
  for (const name of DEFAULT_KEY_NAMES) {
    const candidate = path.join(home, ".ssh", name);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      /* try the next candidate */
    }
  }
  return null;
}

/**
 * Build file/args/env for an ssh (or sshpass) invocation. No shell interpolation.
 *
 * `extraSshArgs` sit after the shared ConnectTimeout / StrictHostKeyChecking
 * options and before `-- user@host`. `remoteArgv` is the remote command (omit
 * for `-N` tunnels).
 *
 * Pass `multiplex: false` for invocations that need a connection of their own
 * — a `-N` port forward has to own its channel so that killing the process
 * tears the forward down with it.
 *
 * @param {object} spark
 * @param {{ extraSshArgs?: string[], remoteArgv?: string[], multiplex?: boolean }} [opts]
 * @returns {{ file: string, args: string[], env: NodeJS.ProcessEnv, targetHost: string, sshPort: number }}
 */
export function sshCommandSpec(spark, opts = {}) {
  const extraSshArgs = Array.isArray(opts.extraSshArgs) ? opts.extraSshArgs : [];
  const remoteArgv = Array.isArray(opts.remoteArgv) ? opts.remoteArgv : [];
  const { auth, password } = spark?.ssh || {};
  const { host: targetHost, port: sshPort, user } = resolveSshTarget(spark);

  // Base SSH options (no shell metacharacters in argv)
  // accept-new: trust first-seen host key (LAN ops); pin known_hosts for stricter envs
  const baseOpts = [
    "-o",
    `ConnectTimeout=${SSH_CONNECT_TIMEOUT}`,
    "-o",
    "StrictHostKeyChecking=accept-new",
    "-p",
    String(sshPort),
  ];

  const remote = `${user}@${targetHost}`;
  const multiplex =
    opts.multiplex === false || !SSH_MULTIPLEX
      ? null
      : sshMultiplexConfig(spark, targetHost, user, auth, password, sshPort);
  // The readiness gate and command must use the same socket and persistence.
  // Explicitly disable both creating and joining a master when reuse is off,
  // including when a user's ssh_config enables multiplexing independently.
  const controlOpts =
    multiplex?.args ?? ["-o", "ControlMaster=no", "-o", "ControlPath=none"];
  // `--` stops option parsing before destination.
  let file;
  let args;
  // Minimal child env — only what ssh/sshpass actually need. Spreading the full
  // `process.env` would leak every host var (AWS_*, GITHUB_TOKEN, etc.) into the
  // child; this whitelist scopes to PATH, HOME, USER/LOGNAME (ssh logging +
  // known_hosts mixing), TERM, and SSH_AUTH_SOCK so agent-forwarded key auth
  // still works. SSHPASS is added below only for password auth.
  const env = {
    PATH: process.env.PATH || "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    HOME: process.env.HOME || "/root",
    USER: process.env.USER,
    LOGNAME: process.env.LOGNAME,
    TERM: process.env.TERM || "xterm",
    ...(process.env.SSH_AUTH_SOCK ? { SSH_AUTH_SOCK: process.env.SSH_AUTH_SOCK } : {}),
  };

  if (auth === "pass") {
    if (!password) {
      throw new Error(
        `SSH password auth selected for ${spark.id} but no password is set (Edit Spark once — passwords are stored encrypted and survive restarts)`
      );
    }
    if (!sshpassAvailable()) {
      throw new Error(`sshpass is not installed. Install it with: sudo apt-get install sshpass`);
    }
    // Password via env (sshpass -e) — never on argv or in process list as -p
    env.SSHPASS = password;
    file = "sshpass";
    args = [
      "-e",
      "ssh",
      ...baseOpts,
      ...controlOpts,
      ...extraSshArgs,
      "--",
      remote,
      ...remoteArgv,
    ];
  } else {
    // Key-based SSH (default) — BatchMode prevents hanging on missing keys
    file = "ssh";
    args = [...baseOpts, ...controlOpts, "-o", "BatchMode=yes"];
    const identityFile = process.env.SSH_IDENTITY_FILE;
    if (identityFile) {
      args.push("-i", identityFile);
    }
    args.push(...extraSshArgs, "--", remote, ...remoteArgv);
  }

  return { file, args, env, targetHost, multiplex, sshPort };
}

/**
 * A Windows OpenSSH server runs commands through cmd.exe, which has no `true`,
 * `cat` or `/proc`. Say so instead of leaving a cmd.exe error as the whole story.
 * On a Windows unit, a refused key gets the administrator-account gotcha: sshd ignores
 * ~/.ssh/authorized_keys for administrators.
 */
export function explainSshFailure(message, { windows = false } = {}) {
  // PowerShell serialises its error stream as CLIXML when stderr is redirected, so a
  // failed command on a Windows unit otherwise arrives as "#< CLIXML <Objs …>".
  const clixml = decodeClixml(message);
  if (clixml != null) {
    const decoded = clixml
      ? clixml.length > CLIXML_MESSAGE_MAX
        ? `${clixml.slice(0, CLIXML_MESSAGE_MAX)}…`
        : clixml
      : "PowerShell reported a failure with no message on its error stream.";
    // A standard Windows account is not entitled to the CIM/WMI classes the collector
    // reads, which is the common cause and is not visible in the message itself.
    return /access is denied|access denied|permissiondenied|unauthorizedaccess/i.test(clixml)
      ? `${decoded} (this usually means the Windows account sparkDash signs in as may not read WMI/CIM: grant it read access to the root\\cimv2 namespace, or use an account that has it.)`
      : decoded;
  }
  if (/is not recognized as an internal or external command/i.test(message)) {
    return `${message} (this looks like a Windows host: set the Unit type to "Windows PC with an NVIDIA GPU" in the unit's settings.)`;
  }
  if (windows && /permission denied \(.*publickey/i.test(message)) {
    return `${message} (if this Windows user is an administrator, sshd ignores ~/.ssh/authorized_keys and reads C:\\ProgramData\\ssh\\administrators_authorized_keys, which only Administrators and SYSTEM may write.)`;
  }
  return message;
}

/**
 * Decide what a finished ssh command yields.
 *
 * Commands like `df` exit nonzero after printing a complete table when a
 * single mount fails (a stale FUSE mount, a dead NFS share). Callers that can
 * use that output pass `allowNonZeroExit`; timeouts, spawn failures, and ssh
 * transport failures never count, because those produce no trustworthy result.
 *
 * @param {{ error?: (Error & { code?: number | string, killed?: boolean }) | null, stdout?: unknown, allowNonZeroExit?: boolean }} outcome
 * @returns {string | null} trimmed stdout, or null when the caller must reject
 */
export function sshExecOutcome({ error = null, stdout, allowNonZeroExit = false } = {}) {
  const out = String(stdout ?? "").trim();
  if (!error) return out;
  // 255 is ssh's own transport-failure code (dropped connection, auth), not the
  // remote command's status; a partial table from a dead transport is not a result.
  if (
    allowNonZeroExit &&
    out &&
    !error.killed &&
    typeof error.code === "number" &&
    error.code !== SSH_TRANSPORT_EXIT
  ) {
    return out;
  }
  return null;
}

/**
 * Execute a command on a remote Spark via SSH.
 *
 * @param {Object} spark - Spark config object
 * @param {string} cmd - Command to execute (passed as a single remote argv via bash -c)
 * @param {{ timeoutMs?: number, allowNonZeroExit?: boolean }} [options]
 * @returns {Promise<string>} - Trimmed stdout
 */
/** The single remote argv for a command: PowerShell-encoded on Windows units, as written elsewhere. */
export function remoteArgvFor(spark, cmd) {
  return [spark?.platform === "windows" ? powershellCommand(cmd) : cmd];
}

/**
 * Which transport runs a remote command.
 *
 *   "pool"  (default) — one persistent ssh2 connection per host (sshPool.js)
 *   "spawn"           — the legacy `ssh` subprocess per command, kept as the
 *                       fallback for hosts whose sshd refuses session sharing
 *
 * The legacy opt-outs are honoured too, so an existing deployment keeps its old
 * behaviour without edits: `SSH_POOL=0`, and `SSH_MULTIPLEX=0` (which has
 * always meant "one connection per command").
 */
export function sshMode() {
  const configured = String(process.env.SPARKDASH_SSH_MODE || "").trim().toLowerCase();
  if (configured) return configured === "spawn" ? "spawn" : "pool";
  if (process.env.SSH_POOL === "0") return "spawn";
  if (process.env.SSH_MULTIPLEX === "0") return "spawn";
  return "pool";
}

/**
 * The process-wide pool, loaded on first use so the spawn path (and the tests
 * that exercise it) never need ssh2 on disk.
 */
let _poolPromise = null;
function pool() {
  if (!_poolPromise) _poolPromise = import("./sshPool.js").then((m) => m.pool());
  return _poolPromise;
}

/** Test seam: run sshExec against a pool instance the caller supplies. */
export function setSshPool(p) {
  _poolPromise = Promise.resolve(p);
}

/** Close every pooled connection (server shutdown). A no-op if none was opened. */
export async function closeSshPool() {
  if (!_poolPromise) return;
  const p = await _poolPromise;
  p.closeAll();
}

/**
 * Run a command on the unit's shared ssh2 connection and translate the result
 * into what callers have always received: trimmed stdout, or the same
 * "SSH to host:port failed: …" rejection the spawn path produces.
 *
 * `options.input` still travels on stdin only (a sudo password), and
 * `options.allowNonZeroExit` still lets a caller keep output from a command
 * that exited nonzero after printing a usable table (e.g. `df`).
 */
async function sshExecPooled(spark, cmd, options, timeoutMs) {
  const { host: targetHost, port: sshPort, user, password } = resolveSshTarget(spark);
  const isWindows = spark?.platform === "windows";

  let result;
  try {
    const p = await pool();
    result = await p.exec(
      {
        host: targetHost,
        port: sshPort,
        user,
        password,
        // Path only; the pool reads the key at connect time.
        identityFile: password ? null : pooledIdentityFile(),
        agent: process.env.SSH_AUTH_SOCK,
      },
      remoteArgvFor(spark, cmd)[0],
      {
        timeoutMs,
        input: typeof options.input === "string" ? options.input : undefined,
        // PowerShell waits for stdin to close; nothing is ever sent on it.
        endStdin: isWindows,
      }
    );
  } catch (err) {
    const wrapped = new Error(
      `SSH to ${targetHost}:${sshPort} failed: ${explainSshFailure(err?.message || String(err), { windows: isWindows })}`
    );
    // Inside the pool's reconnect grace window the host is not offline yet;
    // keep that signal so one slow poll is not counted as a failure.
    wrapped.transient = err?.transient === true;
    wrapped.cause = err;
    throw wrapped;
  }

  const out = String(result.stdout ?? "").trim();
  if (result.code === 0) return out;
  if (options.allowNonZeroExit && out) return out;
  const msg = String(result.stderr ?? "").trim() || `command exited with code ${result.code}`;
  throw new Error(
    `SSH to ${targetHost}:${sshPort} failed: ${explainSshFailure(msg, { windows: isWindows })}`
  );
}

export async function sshExec(spark, cmd, options = {}) {
  const timeoutMs =
    Number.isFinite(options.timeoutMs) && options.timeoutMs > 0 ? options.timeoutMs : 10000;

  if (typeof cmd !== "string" || !cmd) {
    throw new Error("SSH command must be a non-empty string");
  }

  // Windows OpenSSH hands the command to cmd.exe or PowerShell, never bash.
  const isWindows = spark?.platform === "windows";

  // Pooled mode: one shared connection per host, one exec channel per poll.
  if (sshMode() === "pool") return sshExecPooled(spark, cmd, options, timeoutMs);

  const { file, args, env, targetHost, multiplex, sshPort } = sshCommandSpec(spark, {
    remoteArgv: remoteArgvFor(spark, cmd),
  });

  const execute = (execArgs) =>
    new Promise((resolve, reject) => {
      const child = execFile(file, execArgs, { timeout: timeoutMs, env, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
        const outcome = sshExecOutcome({
          error: err,
          stdout,
          allowNonZeroExit: options.allowNonZeroExit,
        });
        if (outcome === null) {
          const msg = stderr?.trim() || err?.message || "command failed";
          reject(new Error(`SSH to ${targetHost}:${sshPort} failed: ${explainSshFailure(msg, { windows: isWindows })}`));
        } else {
          resolve(outcome);
        }
      });
      // Windows PowerShell can wait for stdin to close; nothing is ever sent on it.
      if (isWindows) child.stdin?.end();
      // `options.input` travels on stdin only (never argv, never the environment), e.g. a
      // sudo password for one action. Ignored for the multiplex readiness probe.
      else if (typeof options.input === "string" && execArgs === args) {
        child.stdin?.on("error", () => {});
        child.stdin?.end(options.input);
      }
    });

  if (multiplex) {
    const probeArgs = [...args];
    probeArgs[probeArgs.length - 1] = isWindows ? powershellCommand("exit 0") : "true";
    await ensureMultiplexReady(multiplex, () => execute(probeArgs));
  }
  try {
    return await execute(args);
  } catch (err) {
    // The master can die after readiness but before this exec. Never trust
    // cached state after a transport failure; the next caller must re-probe.
    invalidateMultiplex(multiplex);
    throw err;
  }
}

/**
 * Test SSH connectivity to a Spark.
 * Returns { ok: boolean, message: string }
 */
export async function sshTest(spark) {
  try {
    const result = await sshExec(spark, "echo ok");
    return { ok: result === "ok", message: result };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}

/**
 * Test LLM server connectivity on a single port.
 * Returns { ok: boolean, message: string }
 *
 * `port` is required at call sites today (both pass `resolveLlmPort(spark)`).
 * We accept `null`/`undefined` defensively and resolve from `spark.llmPort`
 * so any future caller that forgets the arg can't silently hit port 8888.
 */
export async function llmTest(spark, port) {
  try {
    const host = llmProbeHost(spark);
    if (!isAllowedTargetHost(host)) {
      return { ok: false, message: `Invalid or disallowed LLM host: ${host}` };
    }
    const resolvedPort =
      Number.isInteger(port) && port >= 1 && port <= 65535
        ? port
        : Number(spark?.llmPorts?.[0] || spark?.llmPort) || 8888;
    const url = `http://${host}:${resolvedPort}/v1/models`;
    /** @type {Record<string, string>} */
    const headers = {};
    const apiKey =
      spark?.llmApiKeys?.[String(resolvedPort)] ||
      spark?.llmApiKeys?.[resolvedPort] ||
      null;
    if (apiKey) headers.Authorization = `Bearer ${String(apiKey).trim()}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(3000), headers });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 || res.status === 403) {
      return { ok: false, message: "Auth required (set API key in LLM Settings)" };
    }
    return { ok: res.ok, message: `Model: ${data?.data?.[0]?.id || "unknown"}` };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}

/**
 * Test LLM connectivity on all configured ports.
 * Returns { ok: boolean, ports: { port, ok, message }[] }
 */
export async function llmTestAll(spark) {
  const ports = spark.llmPorts || (spark.llmPort ? [spark.llmPort] : [8888]);
  const results = await Promise.all(
    ports.map(async (port) => {
      const result = await llmTest(spark, port);
      return { port, ...result };
    })
  );
  const allOk = results.every((r) => r.ok);
  return { ok: allOk, ports: results };
}

/**
 * Test ComfyUI connectivity on a single port (GET /system_stats).
 * Returns { ok: boolean, message: string, skipped?: boolean }
 */
export async function comfyTest(spark, port) {
  try {
    const host = llmProbeHost(spark);
    if (!isAllowedTargetHost(host)) {
      return { ok: false, message: `Invalid or disallowed ComfyUI host: ${host}` };
    }
    const resolvedPort =
      Number.isInteger(port) && port >= 1 && port <= 65535
        ? port
        : Number(spark?.comfyPort) || COMFY_PORT;
    const url = `http://${host}:${resolvedPort}/system_stats`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(COMFY_PROBE_TIMEOUT_MS),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      return { ok: false, message: `HTTP ${res.status}` };
    }
    const ver = data?.system?.comfyui_version;
    return {
      ok: true,
      message: ver ? `ComfyUI ${ver}` : "reachable",
    };
  } catch (err) {
    return { ok: false, message: err.message };
  }
}
