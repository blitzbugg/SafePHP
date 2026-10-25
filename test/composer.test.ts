import { test } from "node:test";
import assert from "node:assert/strict";
import {
  auditArguments,
  auditDependencies,
  buildComposerCandidates,
  parseAuditOutput
} from "../src/core/composer";
import type { ProcessRunner, RunOptions, RunResult } from "../src/core/process";

const SETTINGS = { timeoutMs: 1000 };

function runnerReturning(result: Partial<RunResult>): ProcessRunner {
  return {
    run: async () => ({ stdout: "", stderr: "", code: 0, timedOut: false, ...result })
  };
}

function runnerThrowing(code: string): ProcessRunner {
  return {
    run: async () => {
      throw { code, message: `spawn ${code}` };
    }
  };
}

const ADVISORY_JSON = JSON.stringify({
  advisories: {
    "vendor/pkg": [
      {
        advisoryId: "CVE-2026-111111",
        packageName: "vendor/pkg",
        title: "Remote code execution",
        affectedVersions: "<1.2.3",
        link: "https://example.com/advisory",
        severity: "critical",
        cve: "CVE-2026-111111"
      }
    ]
  },
  abandoned: { "old/pkg": "new/pkg" }
});

test("parses the canonical map-of-arrays audit shape", () => {
  const parsed = parseAuditOutput(ADVISORY_JSON);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.advisories.length, 1);
  const advisory = parsed.advisories[0];
  assert.equal(advisory.packageName, "vendor/pkg");
  assert.equal(advisory.advisoryId, "CVE-2026-111111");
  assert.equal(advisory.severity, "critical");
  assert.equal(advisory.severityPublished, true);
  assert.equal(advisory.link, "https://example.com/advisory");
  assert.equal(parsed.abandoned[0].replacement, "new/pkg");
});

test("parses a flat array audit shape", () => {
  const parsed = parseAuditOutput(
    JSON.stringify({
      advisories: [
        { advisoryId: "GHSA-aaaa", packageName: "vendor/other", title: "X", severity: "moderate" }
      ]
    })
  );
  assert.equal(parsed.ok, true);
  assert.equal(parsed.advisories.length, 1);
  assert.equal(parsed.advisories[0].severity, "medium");
});

test("reports an unpublished severity instead of inventing 'high'", () => {
  const parsed = parseAuditOutput(
    JSON.stringify({
      advisories: { "vendor/pkg": [{ advisoryId: "CVE-2026-222222", title: "X" }] }
    })
  );
  assert.equal(parsed.advisories[0].severity, "medium");
  assert.equal(parsed.advisories[0].severityPublished, false);
});

test("drops non-https advisory links", () => {
  const parsed = parseAuditOutput(
    JSON.stringify({
      advisories: [
        { advisoryId: "CVE-2026-333333", packageName: "p", title: "X", link: "javascript:alert(1)" }
      ]
    })
  );
  assert.equal(parsed.advisories[0].link, undefined);
});

test("reads JSON surrounded by a banner and warnings", () => {
  const stdout = `Composer is operating in a degraded mode.\n${ADVISORY_JSON}\nDone.\n`;
  const parsed = parseAuditOutput(stdout);
  assert.equal(parsed.ok, true);
  assert.equal(parsed.advisories.length, 1);
});

test("deduplicates repeated package advisories", () => {
  const parsed = parseAuditOutput(
    JSON.stringify({
      advisories: [
        { advisoryId: "CVE-2026-444444", packageName: "p", title: "X" },
        { advisoryId: "CVE-2026-444444", packageName: "p", title: "X" }
      ]
    })
  );
  assert.equal(parsed.advisories.length, 1);
});

test("rejects output that is not audit JSON", () => {
  const parsed = parseAuditOutput("Fatal error: something broke");
  assert.equal(parsed.ok, false);
  assert.match(parsed.reason ?? "", /audit JSON/);
});

test("keeps advisories when Composer exits non-zero and writes to stderr", async () => {
  // Regression: composer audit exits 1 when advisories exist, and stderr noise
  // used to corrupt the JSON when stdout and stderr were concatenated.
  const runner = runnerReturning({
    code: 1,
    stdout: ADVISORY_JSON,
    stderr: "Warning: unconstrained dependency\nDeprecation: something\n"
  });
  const outcome = await auditDependencies(
    "/project",
    SETTINGS,
    { platform: "linux", env: {} },
    runner,
    async () => false
  );
  assert.equal(outcome.status, "ok");
  assert.equal(outcome.advisories.length, 1);
});

test("reports an unparseable audit result with the exit status", async () => {
  const runner = runnerReturning({ code: 2, stdout: "resolve error", stderr: "boom" });
  const outcome = await auditDependencies(
    "/project",
    SETTINGS,
    { platform: "linux", env: {} },
    runner,
    async () => false
  );
  assert.equal(outcome.status, "unparsed");
  assert.match(outcome.message ?? "", /status 2/);
});

test("reports a timeout as a failure", async () => {
  const runner = runnerReturning({ code: -1, timedOut: true });
  const outcome = await auditDependencies(
    "/project",
    SETTINGS,
    { platform: "linux", env: {} },
    runner,
    async () => false
  );
  assert.equal(outcome.status, "failed");
  assert.match(outcome.message ?? "", /timed out/);
});

test("retries without version-specific flags when Composer rejects them", async () => {
  const calls: string[][] = [];
  const runner: ProcessRunner = {
    run: async (_command: string, args: string[], _options: RunOptions) => {
      calls.push(args);
      if (args.includes("--locked")) {
        return {
          stdout: "",
          stderr: "The \"--locked\" option does not exist.",
          code: 1,
          timedOut: false
        };
      }
      return { stdout: ADVISORY_JSON, stderr: "", code: 0, timedOut: false };
    }
  };
  const outcome = await auditDependencies(
    "/project",
    SETTINGS,
    { platform: "linux", env: {} },
    runner,
    async () => false
  );
  assert.equal(outcome.status, "ok");
  assert.equal(calls.length, 2);
  assert.ok(!calls[1].includes("--locked"));
});

test("reports not-found when every candidate fails to spawn", async () => {
  const outcome = await auditDependencies(
    "/project",
    SETTINGS,
    { platform: "win32", env: {} },
    runnerThrowing("ENOENT"),
    async () => false
  );
  assert.equal(outcome.status, "not-found");
  assert.ok(outcome.attempts.length > 0);
  assert.match(outcome.message ?? "", /composerPharPath|composerPath/);
});

test("prefers the configured phar launched through php", async () => {
  const candidates = await buildComposerCandidates(
    { ...SETTINGS, composerPharPath: "C:/tools/composer.phar" },
    { platform: "win32", env: {} },
    async target => target === "C:/tools/composer.phar"
  );
  assert.equal(candidates[0].command, "php");
  assert.deepEqual(candidates[0].prefixArgs, ["C:/tools/composer.phar"]);
  assert.equal(candidates[candidates.length - 1].command, "composer");
});

test("never asks for a shell and disables project scripts and plugins", () => {
  const args = auditArguments("/project");
  assert.ok(args.includes("--format=json"));
  assert.ok(args.includes("--no-plugins"));
  assert.ok(args.includes("--no-scripts"));
  assert.ok(args.includes("--locked"));
  assert.equal(args[args.indexOf("--working-dir") + 1], "/project");
});
