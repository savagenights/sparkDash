import { beforeEach, test } from "node:test";
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
  sshCommandSpec,
  sshExecOutcome,
  explainSshFailure,
  sshExec,
  sshMode,
  setSshPool,
  closeSshPool,
} from "../ssh.js";
import { decodeClixml } from "../windowsMetrics.js";

beforeEach((t) => {
  for (const name of ["SSH_CONTROL_PERSIST_SECONDS", "SSH_CONTROL_PERSIST", "SSH_IDENTITY_FILE"]) {
    const previous = process.env[name];
    delete process.env[name];
    t.after(() => {
      if (previous === undefined) delete process.env[name];
      else process.env[name] = previous;
    });
  }
});

const controlOptions = (spec) => spec.args.filter((arg) => /^Control/.test(arg));
const controlPath = (spec) => spec.args.find((arg) => arg.startsWith("ControlPath="));

const keySpark = {
  id: "s1",
  lanIp: "192.168.1.143",
  ssh: { host: "192.168.1.143", user: "mia", auth: "key" },
};

test("sshCommandSpec: key auth uses BatchMode and destination after --", () => {
  const spec = sshCommandSpec(keySpark, { remoteArgv: ["echo ok"] });
  assert.equal(spec.file, "ssh");
  assert.equal(spec.targetHost, "192.168.1.143");
  assert.ok(spec.args.includes("BatchMode=yes"));
  const dash = spec.args.indexOf("--");
  assert.ok(dash >= 0);
  assert.equal(spec.args[dash + 1], "mia@192.168.1.143");
  assert.equal(spec.args[dash + 2], "echo ok");
  assert.equal(spec.env.SSHPASS, undefined);
});

test("sshCommandSpec: extraSshArgs land before destination (tunnel flags)", () => {
  const spec = sshCommandSpec(keySpark, {
    extraSshArgs: ["-N", "-L", "127.0.0.1:9:127.0.0.1:8888"],
  });
  const dash = spec.args.indexOf("--");
  const n = spec.args.indexOf("-N");
  const l = spec.args.indexOf("-L");
  assert.ok(n >= 0 && n < dash);
  assert.ok(l >= 0 && l < dash);
  assert.equal(spec.args[l + 1], "127.0.0.1:9:127.0.0.1:8888");
  assert.equal(spec.args[dash + 1], "mia@192.168.1.143");
  assert.equal(spec.args.length, dash + 2);
});

test("sshCommandSpec: missing user throws", () => {
  assert.throws(
    () => sshCommandSpec({ id: "s", lanIp: "192.168.1.1", ssh: { auth: "key" } }),
    /SSH config missing/
  );
});

test("sshCommandSpec: commands use the private socket and persistence from their readiness config", () => {
  const spec = sshCommandSpec(keySpark, { remoteArgv: ["cat /proc/uptime"] });
  const dash = spec.args.indexOf("--");
  const master = spec.args.indexOf("ControlMaster=auto");
  const controlPath = spec.args.find((a) => a.startsWith("ControlPath="));
  const persist = spec.args.find((a) => a.startsWith("ControlPersist="));
  assert.ok(master >= 0 && master < dash);
  // The socket sits in a private sparkdash-ssh-* directory next to the digest.
  const cpValue = controlPath?.slice("ControlPath=".length);
  assert.ok(
    cpValue && /[\\/]sparkdash-ssh-[^\\/]+[\\/][0-9a-f]{24}$/.test(cpValue),
    `controlPath: ${controlPath}`
  );
  assert.ok(!cpValue.includes("%"));
  // The POSIX rules below only apply where Unix sockets exist: /tmp keeps the
  // path inside macOS's 104-byte limit (temporary suffix and NUL included) and
  // the directory is private. Windows has no Unix sockets at all.
  if (process.platform !== "win32") {
    assert.ok(cpValue.startsWith("/tmp/sparkdash-"), `controlPath: ${controlPath}`);
    assert.ok(Buffer.byteLength(cpValue) + 18 <= 104, `control path too long: ${cpValue.length}`);
    assert.equal(fs.statSync(path.dirname(cpValue)).mode & 0o777, 0o700);
  }
  assert.equal(persist, "ControlPersist=60");
  assert.deepEqual(controlOptions(spec), spec.multiplex.args.filter((arg) => /^Control/.test(arg)));
  const next = sshCommandSpec(keySpark, { remoteArgv: ["cat /proc/meminfo"] });
  assert.deepEqual(controlOptions(next), controlOptions(spec));
});

test("sshCommandSpec: SSH port defaults to 22 and a custom port isolates the master", () => {
  const def = sshCommandSpec(keySpark, { remoteArgv: ["echo ok"] });
  const custom = sshCommandSpec(
    { ...keySpark, ssh: { ...keySpark.ssh, port: 2222 } },
    { remoteArgv: ["echo ok"] }
  );
  const portArg = (spec) => {
    const dash = spec.args.indexOf("--");
    const p = spec.args.indexOf("-p");
    assert.ok(p >= 0 && p < dash);
    return spec.args[p + 1];
  };
  assert.equal(portArg(def), "22");
  assert.equal(portArg(custom), "2222");
  assert.equal(custom.sshPort, 2222);
  const controlPath = (spec) => spec.args.find((arg) => arg.startsWith("ControlPath="));
  assert.notEqual(controlPath(def), controlPath(custom));
});

test("sshCommandSpec: multiplex:false opts out (tunnels own their connection)", () => {
  const spec = sshCommandSpec(keySpark, { multiplex: false, extraSshArgs: ["-N"] });
  assert.ok(spec.args.includes("ControlMaster=no"));
  assert.ok(spec.args.includes("ControlPath=none"));
  assert.ok(!spec.args.includes("ControlMaster=auto"));
  assert.equal(spec.multiplex, null);
});

test("sshCommandSpec: documented zero persistence disables both reuse and the readiness probe", () => {
  process.env.SSH_CONTROL_PERSIST_SECONDS = "0";
  process.env.SSH_CONTROL_PERSIST = "300";
  const spec = sshCommandSpec(keySpark);
  assert.deepEqual(controlOptions(spec), ["ControlMaster=no", "ControlPath=none"]);
  assert.equal(spec.multiplex, null);
});

test("sshCommandSpec: configured persistence reaches the actual SSH command", () => {
  process.env.SSH_CONTROL_PERSIST_SECONDS = "120";
  process.env.SSH_CONTROL_PERSIST = "300";
  const spec = sshCommandSpec(keySpark);
  assert.ok(spec.args.includes("ControlPersist=120"));
  assert.equal(spec.multiplex.persistSeconds, 120);
});

test("sshCommandSpec: legacy persistence is a fallback for the documented setting", () => {
  process.env.SSH_CONTROL_PERSIST = "180";
  const spec = sshCommandSpec(keySpark);
  assert.ok(spec.args.includes("ControlPersist=180"));
  assert.equal(spec.multiplex.persistSeconds, 180);
});

test("sshCommandSpec: persistence bounds apply to the command as well as readiness", () => {
  process.env.SSH_CONTROL_PERSIST_SECONDS = "99999";
  const spec = sshCommandSpec(keySpark);
  assert.ok(spec.args.includes("ControlPersist=3600"));
  assert.equal(spec.multiplex.persistSeconds, 3600);
  process.env.SSH_CONTROL_PERSIST_SECONDS = "invalid";
  assert.ok(sshCommandSpec(keySpark).args.includes("ControlPersist=60"));
});

test("sshCommandSpec: changing the key identity changes the socket passed to SSH", () => {
  process.env.SSH_IDENTITY_FILE = "/example/first-key";
  const first = sshCommandSpec(keySpark);
  process.env.SSH_IDENTITY_FILE = "/example/second-key";
  const second = sshCommandSpec(keySpark);
  assert.notEqual(controlPath(first), controlPath(second));
  assert.ok(first.args.includes("/example/first-key"));
  assert.ok(second.args.includes("/example/second-key"));
});

test("sshCommandSpec: password changes select a different socket without exposing the password", (t) => {
  const existsSync = fs.existsSync;
  const statSync = fs.statSync;
  t.mock.method(fs, "existsSync", (p) => p === "/usr/bin/sshpass" || existsSync(p));
  t.mock.method(fs, "statSync", (p) => p === "/usr/bin/sshpass" ? { isFile: () => true } : statSync(p));
  const spark = { ...keySpark, ssh: { ...keySpark.ssh, auth: "pass", password: "test-password-one" } };
  const first = sshCommandSpec(spark);
  const second = sshCommandSpec({ ...spark, ssh: { ...spark.ssh, password: "test-password-two" } });
  assert.equal(first.file, "sshpass");
  assert.equal(first.env.SSHPASS, "test-password-one");
  assert.equal(second.env.SSHPASS, "test-password-two");
  assert.notEqual(controlPath(first), controlPath(second));
  assert.ok(!first.args.join(" ").includes("test-password-one"));
  assert.ok(!second.args.join(" ").includes("test-password-two"));
});

test("sshCommandSpec: different records and authentication modes do not share a socket", (t) => {
  const existsSync = fs.existsSync;
  const statSync = fs.statSync;
  t.mock.method(fs, "existsSync", (p) => p === "/usr/bin/sshpass" || existsSync(p));
  t.mock.method(fs, "statSync", (p) => p === "/usr/bin/sshpass" ? { isFile: () => true } : statSync(p));
  const key = sshCommandSpec(keySpark);
  const otherRecord = sshCommandSpec({ ...keySpark, id: "other-record" });
  const password = sshCommandSpec({ ...keySpark, ssh: { ...keySpark.ssh, auth: "pass", password: "test-only" } });
  assert.notEqual(controlPath(key), controlPath(otherRecord));
  assert.notEqual(controlPath(key), controlPath(password));
});

test("sshCommandSpec: the legacy global switch still disables reuse", () => {
  const moduleUrl = new URL("../ssh.js", import.meta.url).href;
  const script = `
    import { sshCommandSpec } from ${JSON.stringify(moduleUrl)};
    const spec = sshCommandSpec(${JSON.stringify(keySpark)});
    console.log(JSON.stringify({ args: spec.args, multiplex: spec.multiplex }));
  `;
  const spec = JSON.parse(execFileSync(process.execPath, ["--input-type=module", "-e", script], {
    env: { ...process.env, SSH_MULTIPLEX: "0", SSH_CONTROL_PERSIST_SECONDS: "60" },
    encoding: "utf8",
  }));
  assert.deepEqual(controlOptions(spec), ["ControlMaster=no", "ControlPath=none"]);
  assert.equal(spec.multiplex, null);
});

test("sshExecOutcome: a clean command yields trimmed stdout", () => {
  assert.equal(sshExecOutcome({ error: null, stdout: " hi \n" }), "hi");
});

test("sshExecOutcome: nonzero exit keeps output only when the caller opts in", () => {
  const error = Object.assign(new Error("Command failed"), { code: 1 });
  assert.equal(sshExecOutcome({ error, stdout: "df table" }), null);
  assert.equal(sshExecOutcome({ error, stdout: "df table", allowNonZeroExit: true }), "df table");
});

test("sshExecOutcome: timeouts and spawn failures never yield output", () => {
  const killed = Object.assign(new Error("timed out"), { code: null, killed: true });
  assert.equal(sshExecOutcome({ error: killed, stdout: "partial", allowNonZeroExit: true }), null);
  const spawn = Object.assign(new Error("spawn ssh ENOENT"), { code: "ENOENT" });
  assert.equal(sshExecOutcome({ error: spawn, stdout: "partial", allowNonZeroExit: true }), null);
});

test("sshExecOutcome: an opted-in failure with no output still rejects", () => {
  const error = Object.assign(new Error("Permission denied"), { code: 255 });
  assert.equal(sshExecOutcome({ error, stdout: "", allowNonZeroExit: true }), null);
});

test("sshExecOutcome: a transport failure never yields output even with stdout", () => {
  const transport = Object.assign(new Error("Connection closed by remote host"), { code: 255 });
  assert.equal(
    sshExecOutcome({ error: transport, stdout: "partial table", allowNonZeroExit: true }),
    null
  );
});

test("explainSshFailure points Windows hosts at the Windows unit type and leaves other errors alone", () => {
  const win = explainSshFailure("'true' is not recognized as an internal or external command, operable program or batch file.");
  assert.match(win, /Windows/);
  assert.match(win, /Windows PC with an NVIDIA GPU/);
  assert.equal(explainSshFailure("Permission denied (publickey)."), "Permission denied (publickey).");
});

test("a Windows unit's command is sent as an encoded PowerShell argv, others unchanged", async () => {
  const { remoteArgvFor } = await import("../ssh.js");
  const win = remoteArgvFor({ platform: "windows" }, "echo ok");
  assert.equal(win.length, 1);
  assert.match(win[0], /^powershell .*-EncodedCommand [A-Za-z0-9+/=]+$/);
  assert.deepEqual(remoteArgvFor({ platform: "linux" }, "echo ok"), ["echo ok"]);
  assert.deepEqual(remoteArgvFor({}, "echo ok"), ["echo ok"]);
});

test("explainSshFailure names the administrators_authorized_keys file for a refused key on a Windows unit only", () => {
  const denied = "Permission denied (publickey,password,keyboard-interactive).";
  const win = explainSshFailure(denied, { windows: true });
  assert.match(win, /administrators_authorized_keys/);
  assert.match(win, /Administrators and SYSTEM/);
  assert.equal(explainSshFailure(denied), denied);
});

test("decodeClixml returns the PowerShell stream text, and null for plain stderr", () => {
  const clixml =
    '#< CLIXML\n' +
    '<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">' +
    '<S S="Error">Get-CimInstance : Access is denied. _x000D__x000A_</S>' +
    '<S S="Error">At line:1 char:1_x000D__x000A_</S>' +
    '<S S="Debug">noise</S>' +
    '</Objs>';
  assert.equal(decodeClixml(clixml), "Get-CimInstance : Access is denied. At line:1 char:1");
  // Entities and _xNNNN_ escapes come back as characters; &amp; must not re-expand.
  assert.equal(
    decodeClixml('#< CLIXML\n<Objs><S S="Error">a &lt;b&gt; &amp;amp; c_x0009_d</S></Objs>'),
    "a <b> &amp; c d"
  );
  // CLIXML with no stream text at all is still recognised as CLIXML.
  assert.equal(decodeClixml('#< CLIXML\n<Objs><Obj RefId="0"/></Objs>'), "");
  assert.equal(decodeClixml("Permission denied (publickey)."), null);
  assert.equal(decodeClixml(undefined), null);
});

test("explainSshFailure decodes a CLIXML error instead of showing the raw envelope", () => {
  const denied =
    '#< CLIXML\n<Objs><S S="Error">Get-CimInstance : Access is denied. _x000D__x000A_</S></Objs>';
  const shown = explainSshFailure(denied, { windows: true });
  assert.ok(!shown.includes("CLIXML"), shown);
  assert.ok(!shown.includes("<Objs"), shown);
  assert.match(shown, /Access is denied/);
  // The common cause is not in the message itself, so name it.
  assert.match(shown, /WMI\/CIM/);

  // A CLIXML envelope with no message still says something usable.
  const empty = explainSshFailure('#< CLIXML\n<Objs></Objs>', { windows: true });
  assert.ok(!empty.includes("CLIXML"), empty);
  assert.match(empty, /PowerShell reported a failure/);

  // An unrelated PowerShell error is decoded without the WMI hint.
  const other = explainSshFailure(
    '#< CLIXML\n<Objs><S S="Error">nvidia-smi : The term is not recognized._x000D__x000A_</S></Objs>',
    { windows: true }
  );
  assert.match(other, /nvidia-smi/);
  assert.ok(!other.includes("WMI/CIM"), other);

  // Plain stderr keeps its existing handling on every platform.
  assert.equal(explainSshFailure("Permission denied (publickey)."), "Permission denied (publickey).");
});

/**
 * A stand-in pool that records what sshExec asked of it. Lets the routing and
 * result-mapping tests run without an SSH server or a real connection.
 */
function recordingPool(result) {
  const calls = [];
  return {
    calls,
    exec: async (target, command, options) => {
      calls.push({ target, command, options });
      return typeof result === "function" ? result() : result;
    },
    closeAll: () => {},
  };
}

/** Save/restore one env var around a test. */
function keepEnv(t, name) {
  const saved = process.env[name];
  t.after(() => {
    if (saved === undefined) delete process.env[name];
    else process.env[name] = saved;
  });
  return saved;
}

test("sshMode defaults to the pool and honours both opt-outs", (t) => {
  keepEnv(t, "SPARKDASH_SSH_MODE");
  keepEnv(t, "SSH_POOL");
  keepEnv(t, "SSH_MULTIPLEX");
  delete process.env.SPARKDASH_SSH_MODE;
  delete process.env.SSH_POOL;
  delete process.env.SSH_MULTIPLEX;

  assert.equal(sshMode(), "pool", "one persistent connection per unit is the default");
  process.env.SPARKDASH_SSH_MODE = "spawn";
  assert.equal(sshMode(), "spawn");
  process.env.SPARKDASH_SSH_MODE = "POOL";
  assert.equal(sshMode(), "pool");
  delete process.env.SPARKDASH_SSH_MODE;
  process.env.SSH_POOL = "0";
  assert.equal(sshMode(), "spawn", "the legacy opt-out still works");
  delete process.env.SSH_POOL;
  process.env.SSH_MULTIPLEX = "0";
  assert.equal(sshMode(), "spawn", "the documented no-reuse switch also opts out");
});

test("sshExec runs polls on the shared pool and maps the unit's SSH config", async (t) => {
  keepEnv(t, "SSH_IDENTITY_FILE");
  process.env.SSH_IDENTITY_FILE = "/example/key-path";
  const pool = recordingPool({ stdout: "  up 1 day \n", stderr: "", code: 0 });
  setSshPool(pool);

  const spark = { id: "s1", ssh: { host: "10.0.0.5", user: "unit", port: 2222, auth: "key" } };
  assert.equal(await sshExec(spark, "cat /proc/uptime", { timeoutMs: 1234 }), "up 1 day");

  const [call] = pool.calls;
  assert.deepEqual(call.target, {
    host: "10.0.0.5",
    port: 2222,
    user: "unit",
    password: undefined,
    identityFile: "/example/key-path",
    agent: process.env.SSH_AUTH_SOCK,
  });
  assert.equal(call.command, "cat /proc/uptime");
  assert.equal(call.options.timeoutMs, 1234);
  assert.equal(call.options.input, undefined);
  assert.equal(call.options.endStdin, false);
});

test("a Windows unit sends its encoded PowerShell command and closes stdin", async (t) => {
  keepEnv(t, "SSH_IDENTITY_FILE");
  delete process.env.SSH_IDENTITY_FILE;
  const pool = recordingPool({ stdout: "ok", stderr: "", code: 0 });
  setSshPool(pool);

  const spark = { id: "pc", platform: "windows", ssh: { host: "10.0.0.9", user: "pc" } };
  assert.equal(await sshExec(spark, "echo ok"), "ok");
  const [call] = pool.calls;
  assert.match(call.command, /^powershell .*-EncodedCommand [A-Za-z0-9+/=]+$/);
  assert.equal(call.options.endStdin, true, "PowerShell waits for stdin to close");
});

test("sshExec keeps pooled output only when the caller opts into a nonzero exit", async () => {
  const pool = recordingPool({ stdout: "df table\n", stderr: "mount failed\n", code: 1 });
  setSshPool(pool);
  const spark = { id: "s", ssh: { host: "10.0.0.5", user: "unit" } };

  await assert.rejects(sshExec(spark, "df -h"), /mount failed/);
  assert.equal(await sshExec(spark, "df -h", { allowNonZeroExit: true }), "df table");
});

test("a pooled host inside its reconnect grace window reports transient, not offline", async () => {
  const pool = recordingPool(() => {
    const err = new Error("sshPool: connection attempt failed (unit@10.0.0.5:22)");
    err.transient = true;
    throw err;
  });
  setSshPool(pool);
  const spark = { id: "s", ssh: { host: "10.0.0.5", user: "unit" } };

  await assert.rejects(sshExec(spark, "uptime"), (err) => {
    assert.equal(err.transient, true);
    assert.match(err.message, /^SSH to 10\.0\.0\.5:22 failed:/);
    return true;
  });
});

test("spawn mode never touches the pool", async (t) => {
  keepEnv(t, "SPARKDASH_SSH_MODE");
  process.env.SPARKDASH_SSH_MODE = "spawn";
  const pool = recordingPool({ stdout: "the pool was used", stderr: "", code: 0 });
  setSshPool(pool);

  // A unit with no user never reaches ssh: the spec validation refuses first,
  // which is exactly the spawn path's own behaviour.
  await assert.rejects(sshExec({ id: "s", lanIp: "10.0.0.5" }, "uptime"), /SSH config missing/);
  assert.equal(pool.calls.length, 0, "the legacy transport owns this call");
});

test("closeSshPool closes the shared pool", async () => {
  let closed = 0;
  setSshPool({
    exec: async () => ({ stdout: "", stderr: "", code: 0 }),
    closeAll: () => {
      closed += 1;
    },
  });
  await closeSshPool();
  assert.equal(closed, 1);
});
