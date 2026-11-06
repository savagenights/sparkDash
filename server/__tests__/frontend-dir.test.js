import { test } from "node:test";
import { strict as assert } from "node:assert";
import path from "path";
import { resolveFrontendDir } from "../frontendDir.js";

// Expected paths are built with path.join, so this suite passes on Windows too
// (where path.join("/app", "dist") is "\\app\\dist").
const ROOT = "/app";
const hostDir = path.join(ROOT, "dist");
const bakedDir = path.join(ROOT, "dist-baked");
const hostIndex = path.join(hostDir, "index.html");
const bakedIndex = path.join(bakedDir, "index.html");

const has = (...files) => (p) => files.includes(p);

const mtimes = (map) => (p) => map[p];

test("host dist wins when it has an index.html and is not older than the baked copy", () => {
  const both = has(hostIndex, bakedIndex);
  assert.equal(resolveFrontendDir(ROOT, both, mtimes({ [hostIndex]: 200, [bakedIndex]: 100 })), hostDir);
  assert.equal(resolveFrontendDir(ROOT, both, mtimes({ [hostIndex]: 100, [bakedIndex]: 100 })), hostDir);
});

test("a rebuilt image's copy beats an older host build", () => {
  const both = has(hostIndex, bakedIndex);
  const dir = resolveFrontendDir(ROOT, both, mtimes({ [hostIndex]: 100, [bakedIndex]: 200 }));
  assert.equal(dir, bakedDir);
});

test("an unreadable mtime falls back to the host build", () => {
  const both = has(hostIndex, bakedIndex);
  assert.equal(resolveFrontendDir(ROOT, both, () => { throw new Error("EACCES"); }), hostDir);
});

test("an empty bind-mounted dist falls back to the copy baked into the image", () => {
  assert.equal(resolveFrontendDir(ROOT, has(bakedIndex)), bakedDir);
});

test("no build anywhere gives null (the 503 message)", () => {
  assert.equal(resolveFrontendDir(ROOT, has()), null);
});
