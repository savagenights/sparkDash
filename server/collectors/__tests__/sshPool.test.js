/**
 * sshPool tests — no SSH server involved. A fake ssh2 Client stands in for the
 * real one, so every behaviour here is deterministic: connection reuse,
 * reconnect backoff, command timeouts, the channel cap, the offline grace
 * window and shutdown.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createPool } from "../sshPool.js";

const TARGET = { host: "unit-a", port: 22, user: "operator" };

/** Let queued promise callbacks and setImmediate work run. */
const tick = () => new Promise((resolve) => setImmediate(resolve));

/** Wait a real (short) delay, for backoff timers in tests. */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A controllable ssh2 Client stand-in. `connect` only records the options; the
 * test decides when (or whether) the client reports `ready`, drops, or fails.
 * Each `exec` hands back a channel the test can drive.
 */
function fakeClients() {
  const clients = [];
  const make = () => {
    const client = new EventEmitter();
    client.connectCalls = [];
    client.execCalls = [];
    client.ended = false;
    client.connect = (opts) => {
      client.connectCalls.push(opts);
    };
    client.exec = (command, cb) => {
      const channel = new EventEmitter();
      channel.stderr = new EventEmitter();
      channel.stdin = null;
      channel.closed = false;
      channel.close = () => {
        if (channel.closed) return;
        channel.closed = true;
        channel.emit("close", 1);
      };
      // The pool ends stdin only when it has data (or on Windows units).
      channel.end = (data) => {
        channel.stdin = data === undefined ? "" : data;
      };
      client.execCalls.push({ command, channel });
      cb(null, channel);
    };
    client.end = () => {
      client.ended = true;
    };
    clients.push(client);
    return client;
  };
  return { clients, make };
}

/** Quiet logger, so test output stays readable. */
const silent = () => {};

test("one connection serves every command for a host", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const runs = [];
  for (const command of ["cat /proc/uptime", "nvidia-smi", "cat /proc/meminfo", "df -h", "free -b"]) {
    runs.push(pool.exec(TARGET, command));
  }
  assert.equal(clients.length, 1, "the first command opened exactly one connection");
  clients[0].emit("ready");
  await tick();
  // The channel cap (4) holds the fifth command until a slot frees.
  assert.equal(clients[0].execCalls.length, 4, "polls run as channels, not logins");

  for (const { channel } of clients[0].execCalls) channel.emit("close", 0);
  await tick();
  assert.equal(clients[0].execCalls.length, 5, "the queued poll follows the freed slot");
  clients[0].execCalls[4].channel.emit("close", 0);
  await Promise.all(runs);
  assert.equal(clients.length, 1, "five polls, one connection");
});

test("a dropped connection reconnects with backoff, one attempt at a time", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({
    Client: make,
    logger: silent,
    defaults: { reconnectBaseMs: 5, reconnectMaxMs: 10, jitterRatio: 0 },
  });

  const first = pool.exec(TARGET, "uptime");
  clients[0].emit("ready");
  await tick();
  clients[0].execCalls[0].channel.emit("close", 0);
  assert.equal((await first).code, 0);

  // Force the link down the way ssh2 reports it: 'error' then 'close'.
  clients[0].emit("error", new Error("link down"));
  clients[0].emit("close");
  await sleep(30);

  assert.equal(clients.length, 2, "one reconnect attempt, not a storm");
  assert.equal(clients[1].connectCalls.length, 1);
  clients[1].emit("ready");

  const second = pool.exec(TARGET, "uptime");
  await tick();
  clients[1].execCalls[0].channel.emit("close", 0);
  assert.equal((await second).code, 0);
  assert.equal(clients.length, 2, "the redial is reused afterwards");
});

test("a command timeout closes only its channel, never the connection", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const slow = pool.exec(TARGET, "nvidia-smi dmon", { timeoutMs: 15 });
  clients[0].emit("ready");
  await tick();
  await assert.rejects(slow, /timed out/);
  assert.equal(clients[0].ended, false, "the shared connection stayed up");
  assert.equal(clients.length, 1, "no re-login to cancel one slow command");

  const fast = pool.exec(TARGET, "uptime", { timeoutMs: 50 });
  await tick();
  clients[0].execCalls[1].channel.emit("close", 0);
  assert.equal((await fast).code, 0, "the next poll still used the same session");
});

test("the channel cap queues extra commands instead of overshooting sshd", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent, defaults: { maxChannels: 1 } });

  const a = pool.exec(TARGET, "gpu");
  clients[0].emit("ready");
  await tick();
  assert.equal(clients[0].execCalls.length, 1);

  const b = pool.exec(TARGET, "cpu");
  await tick();
  assert.equal(clients[0].execCalls.length, 1, "second command waits for a free channel");
  assert.equal(pool.stats()[0].queued, 1);

  clients[0].execCalls[0].channel.emit("close", 0);
  assert.equal((await a).code, 0);
  await tick();
  assert.equal(clients[0].execCalls.length, 2, "the queued command runs when the slot frees");
  clients[0].execCalls[1].channel.emit("close", 0);
  assert.equal((await b).code, 0);
});

test("a host is offline only after the grace window, not on one failure", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({
    Client: make,
    logger: silent,
    defaults: { reconnectBaseMs: 1, reconnectMaxMs: 2, jitterRatio: 0, offlineAfterFailures: 2 },
  });

  const first = pool.exec(TARGET, "uptime");
  clients[0].emit("close"); // never became ready: a failed attempt
  await assert.rejects(first, (err) => err.transient === true);
  assert.equal(pool.stats()[0].online, true, "one failure is still inside the grace window");

  await sleep(20); // let the backoff fire
  assert.equal(clients.length, 2);
  const second = pool.exec(TARGET, "uptime");
  clients[1].emit("close");
  await assert.rejects(second, (err) => err.transient === false);
  assert.equal(pool.stats()[0].online, false, "the second failure spends the grace window");
});

test("a host that comes back is online again and clears its failure count", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({
    Client: make,
    logger: silent,
    defaults: { reconnectBaseMs: 1, reconnectMaxMs: 2, jitterRatio: 0, offlineAfterFailures: 1 },
  });

  const first = pool.exec(TARGET, "uptime");
  clients[0].emit("close");
  await assert.rejects(first);
  assert.equal(pool.stats()[0].online, false);

  await sleep(20);
  clients[1].emit("ready");
  const back = pool.exec(TARGET, "uptime");
  await tick();
  clients[1].execCalls[0].channel.emit("close", 0);
  assert.equal((await back).code, 0);
  assert.equal(pool.stats()[0].online, true);
  assert.equal(pool.stats()[0].attempts, 0);
});

test("shutdown closes every connection and fails whatever is still in flight", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const running = pool.exec(TARGET, "uptime");
  clients[0].emit("ready");
  await tick();
  assert.equal(clients[0].execCalls.length, 1);

  pool.closeAll();
  assert.equal(clients[0].ended, true, "the unit sees its session end");
  await assert.rejects(running, /pool closed/);
  await assert.rejects(pool.exec(TARGET, "uptime"), /pool is closed/);
});

test("stdout, stderr and the exit code come back from the channel", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const run = pool.exec(TARGET, "df -h");
  clients[0].emit("ready");
  await tick();
  const { channel } = clients[0].execCalls[0];
  channel.emit("data", Buffer.from("Filesystem Size\n"));
  channel.stderr.emit("data", Buffer.from("mount warning\n"));
  channel.emit("close", 1);
  assert.deepEqual(await run, {
    stdout: "Filesystem Size\n",
    stderr: "mount warning\n",
    code: 1,
  });
});

test("stdin is only touched when the caller sends something", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const plain = pool.exec(TARGET, "uptime");
  clients[0].emit("ready");
  await tick();
  assert.equal(clients[0].execCalls[0].channel.stdin, null, "no stdin write for a plain command");
  clients[0].execCalls[0].channel.emit("close", 0);
  await plain;

  const sudo = pool.exec(TARGET, "sh -c 'IFS= read -r PW'", { input: "pw\n" });
  await tick();
  assert.equal(clients[0].execCalls[1].channel.stdin, "pw\n");
  clients[0].execCalls[1].channel.emit("close", 0);
  await sudo;

  const windows = pool.exec(TARGET, "exit 0", { endStdin: true });
  await tick();
  assert.equal(clients[0].execCalls[2].channel.stdin, "", "PowerShell needs stdin closed");
  clients[0].execCalls[2].channel.emit("close", 0);
  await windows;
});

test("the pool key separates hosts, users and ports", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const a = pool.exec(TARGET, "uptime");
  const b = pool.exec({ ...TARGET, host: "unit-b" }, "uptime");
  const c = pool.exec({ ...TARGET, port: 2222 }, "uptime");
  assert.equal(clients.length, 3, "three distinct connections");
  for (const client of clients) client.emit("ready");
  await tick();
  for (const client of clients) client.execCalls[0].channel.emit("close", 0);
  await Promise.all([a, b, c]);

  const keys = pool.stats().map((s) => s.host);
  assert.deepEqual(keys.sort(), [
    "operator@unit-a:22",
    "operator@unit-a:2222",
    "operator@unit-b:22",
  ]);
});

/**
 * A channel that closes without an exit status is how ssh2 reports a link that
 * died mid-command. Treating that as code 0 would hand a poller empty stdout and
 * let the monitor mark a unit online with no data.
 */
test("a channel that closes with no exit status is a connection loss, not a success", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const dropped = pool.exec(TARGET, "cat /proc/uptime");
  clients[0].emit("ready");
  await tick();
  const { channel } = clients[0].execCalls[0];
  channel.emit("data", Buffer.from("1234.56 ")); // partial output, then the link dies
  channel.emit("close"); // no exit status: sshd never reported one
  await assert.rejects(dropped, (err) => err.transient === true);
  assert.equal(pool.stats()[0].online, true, "one dropped command is not an offline host");

  // Only the channel died; the shared session still serves the next poll.
  const next = pool.exec(TARGET, "cat /proc/uptime");
  await tick();
  clients[0].execCalls[1].channel.emit("close", 0);
  assert.equal((await next).code, 0);
  assert.equal(clients.length, 1, "no re-login for a dropped channel");
});

/** An exit status reported before `close` is the real one, even if close omits it. */
test("the exit status from the exit event survives a bare close", async () => {
  const { clients, make } = fakeClients();
  const pool = createPool({ Client: make, logger: silent });

  const run = pool.exec(TARGET, "df -h");
  clients[0].emit("ready");
  await tick();
  const { channel } = clients[0].execCalls[0];
  channel.emit("exit", 2);
  channel.emit("close");
  assert.equal((await run).code, 2, "the reported exit code is not lost");
});

/**
 * A host that authenticates but cannot exec is reachable, not offline — and the
 * failure must not be tagged transient, or the monitor would ignore it forever
 * while serving stale readings.
 */
test("an exec failure on a live connection is a real failure, not transient", async () => {
  const client = new EventEmitter();
  client.connect = () => {};
  client.exec = (command, cb) => cb(new Error("session refused by sshd"), null);
  client.end = () => {};
  const pool = createPool({ Client: () => client, logger: silent });

  const run = pool.exec(TARGET, "uptime");
  // Attach the handler before the connection comes up, so the rejection is
  // never unhandled (node:test fails a test on that).
  const settled = run.catch((err) => err);
  client.emit("ready");
  await tick();
  const err = await settled;
  assert.equal(err.transient, false, "a reachable host's command failure is real");
  assert.equal(pool.stats()[0].online, true, "the host answered; only the command failed");
});

/**
 * stats() and the shutdown summary carry the totals a soak reports: commands
 * requested, commands that failed, and redials — no payload, no secrets.
 */
test("stats and shutdown report command, failure and reconnect totals", async () => {
  const { clients, make } = fakeClients();
  const lines = [];
  const pool = createPool({
    Client: make,
    logger: (event, key, detail) => lines.push(`${event} ${key} ${detail || ""}`),
    defaults: { reconnectBaseMs: 20, jitterRatio: 0 }, // deterministic redial
  });

  const first = pool.exec(TARGET, "uptime");
  clients[0].emit("ready");
  await tick();
  clients[0].execCalls[0].channel.emit("close", 0);
  await first;

  // A forced drop schedules exactly one redial; the next command rides the
  // replacement connection rather than opening a second one by itself.
  clients[0].emit("close");
  const during = pool.exec(TARGET, "nvidia-smi");
  await sleep(80); // the first backoff step
  assert.equal(clients.length, 2, "the redial opened a replacement client");
  clients[1].emit("ready");
  await tick();
  clients[1].execCalls[0].channel.emit("close", 0);
  await during;

  const [host] = pool.stats();
  assert.equal(host.execs, 2, "both requested commands are counted");
  assert.equal(host.failures, 0, "both commands ran");
  assert.equal(host.reconnects, 1, "the drop scheduled one redial");

  // Shutdown fails whatever is still in flight, and the summary reports it.
  const inFlight = pool.exec(TARGET, "free -b").catch((err) => err);
  await tick();
  pool.closeAll();
  assert.equal((await inFlight).message, "sshPool: pool closed");
  assert.equal(pool.stats().length, 0, "hosts are forgotten once closed");
  assert.ok(
    lines.some((line) => /summary .*execs=3 failures=1 reconnects=1/.test(line)),
    "shutdown logs one totals line per host"
  );
});
