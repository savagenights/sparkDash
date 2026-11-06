/**
 * sshPool — ONE persistent ssh2 connection per host, shared by every poller.
 *
 * Why this module exists
 * ----------------------
 * Every collector used to spawn a fresh `ssh` process per poll. Sharing that
 * login through ControlMaster needs Unix-domain sockets, and Windows OpenSSH
 * has none ("getsockname failed: Not a socket"), so on Windows each poll was a
 * full login. Over Wi-Fi those logins are slow enough that healthy Sparks were
 * reported offline.
 *
 * Here a host keeps a single authenticated ssh2 Client, and every command runs
 * as an `exec` channel on it. No login per poll, no sockets, and the same
 * behaviour on Windows, Linux and macOS.
 *
 * Deliberate choices
 * ------------------
 * - One Client per `user@host:port`. Anything else still pays a login per poll.
 * - Lazy connect: the first command for a host opens the connection.
 * - Keepalive catches half-dead links (a dropped Wi-Fi association never sends
 *   a FIN) before a poll hangs on one.
 * - Reconnect backs off exponentially (1s → 30s) plus jitter, with one
 *   in-flight attempt per host, so a flapping link cannot cause a login storm.
 * - Channels are capped per host: sshd's default MaxSessions is 10, and
 *   overshooting gets them refused by the server.
 * - A command timeout closes only that channel. Killing the shared connection
 *   to cancel one slow command would re-login every other poller.
 * - A host is reported offline only after `offlineAfterFailures` consecutive
 *   failed connects. Until then its errors are tagged `transient`, so one slow
 *   poll never flips a healthy host. A command that fails on a live connection
 *   is NOT transient — the host answered, so the caller must see it.
 * - No key material, password or file contents are logged or kept in state.
 *   The identity file is read from config/env at connect time.
 */
import fs from "fs";
import ssh2 from "ssh2";

/** Tunables. `createPool({ defaults })` lets tests run with tiny timings. */
const DEFAULTS = Object.freeze({
  keepaliveInterval: 10000, // ms between keepalive probes
  keepaliveCountMax: 3, // missed probes before ssh2 calls the link dead
  readyTimeout: 15000, // ms allowed for TCP + auth
  maxChannels: 4, // concurrent exec channels per host (sshd MaxSessions is 10)
  reconnectBaseMs: 1000, // first backoff step
  reconnectMaxMs: 30000, // backoff ceiling
  jitterRatio: 0.3, // up to +30%, so hosts do not reconnect in lockstep
  offlineAfterFailures: 2, // consecutive failed connects before "offline"
  defaultTimeoutMs: 30000, // per-command budget
});

/**
 * Accept a bare hostname or a target object, so callers can pass the same
 * shape they already use for the spawn path.
 */
function normalizeTarget(target) {
  if (typeof target === "string") {
    return { host: target, port: 22, user: undefined, identityFile: undefined, password: undefined, agent: undefined };
  }
  const t = target || {};
  return {
    host: t.host,
    port: t.port || 22,
    user: t.user,
    identityFile: t.identityFile,
    password: t.password,
    agent: t.agent,
  };
}

/** Stable pool key. Excludes the key path and password so neither reaches logs. */
function hostKey(target) {
  return `${target.user || "default"}@${target.host}:${target.port}`;
}

/** Default logger: timestamps and no secrets. Swappable so tests stay quiet. */
function defaultLogger(event, key, detail) {
  const stamp = new Date().toISOString();
  console.log(`[sshPool ${stamp}] ${event} ${key}${detail ? ` ${detail}` : ""}`);
}

/**
 * Build an isolated pool. Dependency injection (client factory + logger) is
 * what makes this unit-testable without an SSH server.
 *
 * @param {{ Client?: () => any, logger?: (event: string, key: string, detail?: string) => void, defaults?: object }} [options]
 * @returns {{ exec: (target: any, command: string, options?: { timeoutMs?: number, input?: string, endStdin?: boolean }) => Promise<{ stdout: string, stderr: string, code: number }>, closeAll: () => void, stats: () => object[] }}
 */
export function createPool(options = {}) {
  const cfg = { ...DEFAULTS, ...(options.defaults || {}) };
  const makeClient = options.Client || (() => new ssh2.Client());
  const log = options.logger || defaultLogger;

  /** key -> host state record */
  const hosts = new Map();
  let closed = false;

  /** Fetch (or lazily create) the state record for a target. */
  function getHost(target) {
    const t = normalizeTarget(target);
    if (!t.host) throw new Error("sshPool: a host is required");
    const key = hostKey(t);
    let h = hosts.get(key);
    if (!h) {
      h = {
        key,
        target: t,
        client: null, // established, authenticated Client
        pending: null, // Client mid-handshake (guards against a double connect)
        state: "idle", // idle | connecting | ready | waiting
        attempts: 0, // consecutive failed connect attempts
        backoffMs: cfg.reconnectBaseMs,
        reconnectTimer: null,
        queue: [], // jobs waiting for a live connection / a free channel
        jobs: new Set(), // every unsettled job, so shutdown can fail them all
        active: 0, // exec channels currently open
        online: true, // false only after the grace window is spent
        lastError: null,
        // Lifetime counters, reported by stats() and on shutdown. They are the
        // evidence a soak needs: commands run, commands that failed, redials.
        execs: 0,
        failures: 0,
        reconnects: 0,
      };
      hosts.set(key, h);
      log("host-added", key);
    } else {
      // Refresh auth material; an established connection keeps running as-is.
      h.target = { ...h.target, ...t };
    }
    return h;
  }

  /** Translate a target into ssh2 connection options. Never logged. */
  function connectionOptions(target) {
    const opts = {
      host: target.host,
      port: target.port,
      keepaliveInterval: cfg.keepaliveInterval,
      keepaliveCountMax: cfg.keepaliveCountMax,
      readyTimeout: cfg.readyTimeout,
    };
    if (target.user) opts.username = target.user;
    // Key material is read here, at connect time, from config/env — it is never
    // stored on the host record and never logged.
    if (target.password) opts.password = target.password;
    else if (target.identityFile) opts.privateKey = fs.readFileSync(target.identityFile);
    // Same last resort as `ssh`: ask the running agent for the key.
    else if (target.agent) opts.agent = target.agent;
    return opts;
  }

  /**
   * True while a host is inside its reconnect grace window: not yet declared
   * offline, and not currently holding a working connection.
   */
  function inGrace(h) {
    return h.online && h.state !== "ready" && h.attempts < cfg.offlineAfterFailures;
  }

  /**
   * Build the error a caller sees when a command cannot run.
   *
   * `transient` is true only inside the reconnect grace window, where the pool
   * is redialing on its own and the host is not offline yet. A command that
   * fails on a live connection is NOT transient: the host answered, so the
   * caller must see the failure instead of serving stale data forever.
   * `options.transient` lets the link-loss path say so explicitly.
   */
  function failure(h, message, options = {}) {
    const err = new Error(`sshPool: ${message} (${h.key})`);
    err.transient =
      typeof options.transient === "boolean" ? options.transient : inGrace(h);
    return err;
  }

  /**
   * A command that ran out of time. Deliberately NOT transient: the connection
   * is healthy, so this is a real slow command and the caller should see it.
   * SparkMonitor requires two consecutive liveness failures before it marks a
   * unit offline, so one slow poll cannot flip a healthy host.
   */
  function timeout(h, timeoutMs) {
    return new Error(`sshPool: command timed out after ${timeoutMs}ms (${h.key})`);
  }

  /** Fail everything still queued — a dead attempt must not hold callers. */
  function failQueued(h, message) {
    for (const job of h.queue.splice(0)) settle(h, job, failure(h, message));
  }

  /** Schedule the next connect attempt with exponential backoff + jitter. */
  function scheduleReconnect(h) {
    if (closed || h.reconnectTimer) return; // one in-flight attempt per host
    h.reconnects += 1; // count redials, not polls, so a soak can report them
    const base = Math.min(h.backoffMs, cfg.reconnectMaxMs);
    const wait = base + Math.floor(Math.random() * cfg.jitterRatio * base);
    log("reconnect-scheduled", h.key, `in ${wait}ms`);
    h.reconnectTimer = setTimeout(() => {
      h.reconnectTimer = null;
      h.backoffMs = Math.min(h.backoffMs * 2, cfg.reconnectMaxMs);
      connect(h);
    }, wait);
    // A pending retry must not keep the process alive on shutdown.
    if (typeof h.reconnectTimer.unref === "function") h.reconnectTimer.unref();
  }

  /** Open (or re-open) the shared connection for a host. */
  function connect(h) {
    if (closed || h.state === "connecting" || h.state === "ready") return;
    h.state = "connecting";

    let client;
    try {
      client = makeClient();
    } catch (err) {
      // Cannot even build a client (e.g. ssh2 missing): count it as a failed
      // attempt so the host degrades through the same grace window.
      h.lastError = err;
      h.attempts += 1;
      h.state = "waiting";
      declareOfflineIfSpent(h);
      failQueued(h, "SSH client unavailable");
      scheduleReconnect(h);
      return;
    }

    h.pending = client;
    let becameReady = false;

    client.on("ready", () => {
      becameReady = true;
      h.client = client;
      h.pending = null;
      h.state = "ready";
      h.attempts = 0;
      h.backoffMs = cfg.reconnectBaseMs;
      h.lastError = null;
      if (!h.online) {
        h.online = true;
        log("online", h.key);
      }
      log("connected", h.key);
      drain(h);
    });

    // ssh2 reports a lost link as 'error', then 'end', then 'close'. 'error'
    // only records the cause; the single reconnect path hangs off 'close',
    // which is the one event that always fires.
    client.on("error", (err) => {
      h.lastError = err;
    });

    client.on("close", () => {
      if (h.pending === client) h.pending = null;
      if (h.client === client) h.client = null;
      // Shutting down: drop the reference and stay quiet, no reconnect.
      if (closed) return;
      h.state = "waiting";

      if (becameReady) {
        // An established link dropped. That does not count toward "offline":
        // the reconnect may well succeed, and the host is still the same host.
        log("disconnected", h.key);
        failQueued(h, "connection lost while reconnecting");
      } else {
        h.attempts += 1;
        log("connect-failed", h.key, `attempt=${h.attempts} ${h.lastError ? h.lastError.message : ""}`.trim());
        declareOfflineIfSpent(h);
        failQueued(h, "connection attempt failed");
      }
      scheduleReconnect(h);
    });

    try {
      client.connect(connectionOptions(h.target));
    } catch (err) {
      // Unreadable identity file and friends: record it and let backoff run.
      h.lastError = err;
      log("connect-error", h.key, err.message);
      try {
        client.emit("close");
      } catch {
        /* a client that cannot emit still gets the backoff path */
        h.state = "waiting";
        scheduleReconnect(h);
      }
    }
  }

  /** Flip the host offline once its grace window of failed attempts is spent. */
  function declareOfflineIfSpent(h) {
    if (h.attempts >= cfg.offlineAfterFailures && h.online) {
      h.online = false;
      log("offline", h.key, `after ${h.attempts} failed attempts`);
    }
  }

  /** Resolve or reject a job exactly once, stop its timer, forget it. */
  function settle(h, job, err, result) {
    if (job.settled) return;
    job.settled = true;
    if (err) h.failures += 1;
    if (job.timer) clearTimeout(job.timer);
    h.jobs.delete(job);
    if (err) job.reject(err);
    else job.resolve(result);
  }

  /** Free a channel slot exactly once, then let queued work through. */
  function release(h, job) {
    if (!job.started || job.released) return;
    job.released = true;
    h.active -= 1;
    drain(h);
  }

  /** Start queued jobs while the host has a live client and a free channel. */
  function drain(h) {
    if (closed || h.state !== "ready" || !h.client) return;
    while (h.queue.length > 0 && h.active < cfg.maxChannels) {
      runJob(h, h.queue.shift());
    }
  }

  /** Run one command as an exec channel on the shared client. */
  function runJob(h, job) {
    if (job.settled) return; // timed out while queued
    job.started = true;
    h.active += 1;

    h.client.exec(job.command, (err, channel) => {
      if (err) {
        release(h, job);
        settle(h, job, failure(h, `exec failed: ${err.message}`));
        return;
      }
      if (job.settled) {
        // The deadline fired between dispatch and channel creation.
        try {
          channel.close();
        } catch {
          /* already gone */
        }
        release(h, job);
        return;
      }

      job.channel = channel;
      let stdout = "";
      let stderr = "";
      // The remote process's exit status, when sshd reported one. A dropped
      // connection never sends it, so its absence is the only signal that the
      // output is partial — and that this command must not look successful.
      let exitStatus = null;

      channel.on("exit", (code) => {
        if (typeof code === "number") exitStatus = code;
      });
      channel.on("data", (d) => {
        stdout += d.toString();
      });
      // ssh2 exposes stderr as a separate stream; guard for lightweight fakes.
      if (channel.stderr && typeof channel.stderr.on === "function") {
        channel.stderr.on("data", (d) => {
          stderr += d.toString();
        });
      }
      channel.on("close", (code) => {
        release(h, job);
        const status =
          exitStatus !== null ? exitStatus : typeof code === "number" ? code : null;
        if (status === null) {
          // No exit status: the transport died mid-command. Partial stdout is
          // not a result, and reporting code 0 would mark the unit online with
          // empty data. Transient only while the host is not yet offline.
          settle(
            h,
            job,
            failure(h, "connection lost before the command exited", {
              transient: h.online,
            })
          );
          return;
        }
        settle(h, job, null, { stdout, stderr, code: status });
      });

      // stdin: only when the caller has something to send (a sudo password),
      // plus the Windows case, where PowerShell waits for stdin to close.
      try {
        if (typeof job.input === "string") channel.end(job.input);
        else if (job.endStdin) channel.end();
      } catch {
        /* channel already closed */
      }
    });
  }

  /** Queue a command. The timeout covers queue wait plus execution. */
  function enqueue(h, command, timeoutMs, options) {
    h.execs += 1; // every requested command, whether it runs or times out queued
    return new Promise((resolve, reject) => {
      const job = {
        command,
        resolve,
        reject,
        settled: false,
        started: false,
        released: false,
        channel: null,
        timer: null,
        input: options.input,
        endStdin: Boolean(options.endStdin),
      };

      job.timer = setTimeout(() => {
        // Settle FIRST: closing a channel emits 'close', whose handler would
        // otherwise resolve this command as a success before the reject lands.
        if (!job.channel) {
          // Never dispatched: drop it so it cannot start after its deadline.
          const i = h.queue.indexOf(job);
          if (i !== -1) h.queue.splice(i, 1);
        }
        settle(h, job, timeout(h, timeoutMs));
        if (job.channel) {
          // Close ONLY this channel: the shared connection stays up so every
          // other poller keeps its session.
          try {
            job.channel.close();
          } catch {
            /* channel already closed */
          }
        }
        release(h, job);
      }, timeoutMs);
      // Deliberately NOT unref'd: a command that is still running is real work,
      // so its deadline must keep the event loop alive. An unref'd timer lets
      // Node exit (or cancel a test) before the timeout can fire, which turns
      // "slow command" into "command silently dropped" on an idle process.

      h.queue.push(job);
      h.jobs.add(job);
      if (h.state === "idle") connect(h);
      drain(h);
    });
  }

  /**
   * Public: run a command on the host's shared connection.
   * Resolves `{ stdout, stderr, code }`; rejects with a `.transient` flag while
   * the host is still inside its reconnect grace window.
   */
  async function exec(target, command, options = {}) {
    if (closed) throw new Error("sshPool: pool is closed");
    if (typeof command !== "string" || !command) {
      throw new Error("sshPool: command must be a non-empty string");
    }
    const h = getHost(target);
    const timeoutMs =
      typeof options === "number"
        ? options
        : Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
          ? options.timeoutMs
          : cfg.defaultTimeoutMs;
    return enqueue(h, command, timeoutMs, options);
  }

  /** Public: close every connection and fail anything still queued. */
  function closeAll() {
    closed = true;
    for (const h of hosts.values()) {
      if (h.reconnectTimer) {
        clearTimeout(h.reconnectTimer);
        h.reconnectTimer = null;
      }
      const c = h.client || h.pending;
      if (c && typeof c.end === "function") {
        try {
          c.end();
        } catch {
          /* already closed */
        }
      }
      // Callers must never be left hanging on shutdown.
      failQueued(h, "pool closed");
      for (const job of [...h.jobs]) settle(h, job, new Error("sshPool: pool closed"));
      // One line per host: the totals a soak reads back after the run ends.
      log(
        "summary",
        h.key,
        `execs=${h.execs} failures=${h.failures} reconnects=${h.reconnects} online=${h.online}`
      );
    }
    hosts.clear();
    log("closed", "all");
  }

  /** Public: per-host snapshot for diagnostics. Carries no secrets. */
  function stats() {
    const out = [];
    for (const h of hosts.values()) {
      out.push({
        host: h.key,
        online: h.online,
        state: h.state,
        attempts: h.attempts,
        active: h.active,
        queued: h.queue.length,
        execs: h.execs,
        failures: h.failures,
        reconnects: h.reconnects,
        lastError: h.lastError ? h.lastError.message : null,
      });
    }
    return out;
  }

  return { exec, closeAll, stats };
}

/** Lazily built shared pool, so importing this module costs nothing. */
let _defaultPool = null;

/** The process-wide pool every collector shares. */
export function pool() {
  if (!_defaultPool) _defaultPool = createPool();
  return _defaultPool;
}

/** Close the shared pool, if it was ever created (server shutdown). */
export function closeSshPool() {
  if (_defaultPool) _defaultPool.closeAll();
}
