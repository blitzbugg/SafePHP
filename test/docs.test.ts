import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";
import { advisoryData } from "../src/core/advisories";
import { fixedVersionsByBranch } from "../src/core/version";

const ROOT = process.cwd();
const read = (file: string): string => fs.readFileSync(path.join(ROOT, file), "utf8");
const readJson = (file: string): Record<string, unknown> =>
  JSON.parse(read(file)) as Record<string, unknown>;

test("README fixed-version table matches the advisory data", () => {
  const rows = new Map<string, string>();
  for (const line of read("README.md").split(/\r?\n/)) {
    const match = /^\|\s*(\d+\.\d+)\s*\|\s*(\d+\.\d+\.\d+)\s*\|\s*$/.exec(line);
    if (match) rows.set(match[1], match[2]);
  }
  assert.deepEqual(Object.fromEntries(rows), fixedVersionsByBranch(advisoryData));
});

test("README names every advisory and the data retrieval date", () => {
  const readme = read("README.md");
  assert.match(readme, new RegExp(advisoryData.retrievedAt));
  for (const advisory of advisoryData.advisories) {
    assert.ok(readme.includes(advisory.id), `README must mention ${advisory.id}`);
  }
});

test("README describes CVE-2026-115560 as an informational RCE, not a configuration advisory", () => {
  const readme = read("README.md");
  assert.match(readme, /CVE-2026-115560[\s\S]{0,500}informational/i);
  assert.doesNotMatch(readme, /configuration advisory/i);
  assert.match(readme, /8\.1 and older are \*\*affected\*\*/i);
});

test("README documents the Composer network path", () => {
  assert.match(read("README.md"), /packagist\.org/);
});

test("PRIVACY.md states what is read, what leaves the machine and what is stored", () => {
  const privacy = read("PRIVACY.md");
  assert.match(privacy, /packagist\.org/);
  assert.match(privacy, /no telemetry/i);
  assert.match(privacy, /never uploaded/i);
  assert.match(privacy, /\.env/);
  assert.match(privacy, /writes no files/i);
});

test("LIMITATIONS.md covers the required caveats", () => {
  const limitations = read("LIMITATIONS.md");
  for (const term of [
    /not the runtime/i,
    /backport/i,
    /line-based/i,
    /\.user\.ini/,
    /not proof of a vulnerability/i,
    /not assessed/i
  ]) {
    assert.match(limitations, term);
  }
});

test("package version matches the changelog", () => {
  const manifest = readJson("package.json") as { version: string };
  const changelog = read("CHANGELOG.md");
  assert.match(changelog, new RegExp(`## ${manifest.version.replace(/\./g, "\\.")}`));
});

test("the test script actually runs tests", () => {
  const manifest = readJson("package.json") as { scripts: Record<string, string> };
  assert.match(manifest.scripts.test, /node --test/);
  assert.match(manifest.scripts.check, /tsc --noEmit/);
});

test("vscode types match the declared engine", () => {
  const manifest = readJson("package.json") as {
    engines: { vscode: string };
    devDependencies: Record<string, string>;
  };
  const engine = manifest.engines.vscode.replace(/^[^\d]*/, "");
  assert.equal(manifest.devDependencies["@types/vscode"], engine);
});

test("packaging declares limited untrusted-workspace support", () => {
  const manifest = readJson("package.json") as {
    capabilities: { untrustedWorkspaces: { supported: string } };
    activationEvents: string[];
  };
  assert.equal(manifest.capabilities.untrustedWorkspaces.supported, "limited");
  assert.ok(manifest.activationEvents.includes("onView:phpSecurityGuard.findings"));
});
