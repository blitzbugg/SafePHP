import { test } from "node:test";
import assert from "node:assert/strict";
import { scanWorkspace, type ScanDeps, type ScanSettings } from "../src/core/scan";
import type { DirEntry, ScanFs } from "../src/core/walk";
import type { ProcessRunner, RunResult } from "../src/core/process";
import type { Finding } from "../src/types";

const ROOT = "/ws";

function norm(target: string): string {
  return target.replace(/\\/g, "/").replace(/\/+$/, "");
}

function createFs(
  files: Record<string, string>,
  options: { unreadable?: string[]; sizes?: Record<string, number> } = {}
): ScanFs {
  const contents = new Map<string, string>();
  for (const [key, value] of Object.entries(files)) contents.set(norm(key), value);

  const dirs = new Set<string>([ROOT]);
  for (const key of contents.keys()) {
    let current = key;
    while (current.length > ROOT.length) {
      const index = current.lastIndexOf("/");
      if (index <= 0) break;
      current = current.slice(0, index);
      dirs.add(current);
    }
  }

  const sizes = new Map<string, number>();
  for (const [key, value] of Object.entries(options.sizes ?? {})) sizes.set(norm(key), value);
  const unreadable = new Set((options.unreadable ?? []).map(norm));

  return {
    readdir: async dir => {
      const target = norm(dir);
      if (!dirs.has(target)) throw new Error(`ENOTDIR ${dir}`);
      const children = new Map<string, boolean>();
      for (const candidate of [...contents.keys(), ...dirs]) {
        if (candidate === target) continue;
        if (!candidate.startsWith(`${target}/`)) continue;
        const rest = candidate.slice(target.length + 1);
        if (rest.length === 0) continue;
        const slash = rest.indexOf("/");
        const name = slash === -1 ? rest : rest.slice(0, slash);
        if (!children.has(name)) children.set(name, slash !== -1);
      }
      const entries: DirEntry[] = [...children.entries()].map(([name, isDirectory]) => ({
        name,
        isDirectory: () => isDirectory,
        isFile: () => !isDirectory,
        isSymbolicLink: () => false
      }));
      return entries;
    },
    stat: async target => {
      const key = norm(target);
      return { size: sizes.get(key) ?? contents.get(key)?.length ?? 0 };
    },
    readHead: async (target, maxBytes) => {
      const key = norm(target);
      if (unreadable.has(key)) throw new Error("EACCES");
      const content = contents.get(key);
      if (content === undefined) throw new Error(`ENOENT ${target}`);
      const truncated = content.length > maxBytes;
      return { content: truncated ? content.slice(0, maxBytes) : content, truncated };
    },
    realpath: async target => norm(target)
  };
}

function result(partial: Partial<RunResult>): RunResult {
  return { stdout: "", stderr: "", code: 0, timedOut: false, ...partial };
}

function createRunner(handler: (command: string, args: string[]) => RunResult): ProcessRunner {
  return { run: async (command, args) => handler(command, args) };
}

const neverRunner: ProcessRunner = {
  run: async () => {
    throw new Error("no external process may be started");
  }
};

const BASE: ScanSettings = {
  maxFiles: 100,
  maxFileBytes: 65536,
  sourceHeuristics: true,
  composerAudit: true,
  includeVendor: false,
  phpTimeoutMs: 100,
  composerTimeoutMs: 100
};

function deps(fs: ScanFs, runner: ProcessRunner = neverRunner): ScanDeps {
  return { fs, runner, platform: "linux", env: {} };
}

function find(findings: Finding[], prefix: string): Finding | undefined {
  return findings.find(finding => finding.id.startsWith(prefix));
}

test("reports a Dockerfile image below the fixed release as advisory-backed", async () => {
  const fs = createFs({ "/ws/Dockerfile": "FROM php:8.2.20-fpm\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "IMAGE-VULNERABLE");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
  assert.equal(finding.proof, "advisory");
  assert.deepEqual(finding.advisoryIds, ["CVE-2026-109618", "CVE-2026-109619"]);
  assert.equal(finding.line, 1);
  assert.equal(finding.observation?.kind, "dockerfile");
  assert.equal(finding.observation?.scope, "container-declared");
  assert.equal(finding.observation?.resolution, "exact");
});

test("reports a fixed Dockerfile image as informational, not vulnerable", async () => {
  const fs = createFs({ "/ws/Dockerfile": "FROM php:8.4.27-fpm\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "IMAGE-FIXED");
  assert.ok(finding);
  assert.equal(finding.severity, "info");
  assert.equal(find(scan.findings, "IMAGE-VULNERABLE"), undefined);
});

test("does not invent a patch version for a floating branch tag", async () => {
  const fs = createFs({ "/ws/Dockerfile": "FROM php:8.2-fpm\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "IMAGE-FLOATING");
  assert.ok(finding);
  assert.equal(finding.severity, "low");
  assert.match(finding.message, /floats within the 8\.2 branch/);
  assert.doesNotMatch(finding.message, /8\.2\.0/);
});

test("an uncovered branch is reported and cannot read as safe", async () => {
  const fs = createFs({ "/ws/Dockerfile": "FROM php:8.6.0-fpm\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "IMAGE-UNCOVERED");
  assert.ok(finding);
  assert.equal(finding.severity, "info");
  assert.match(finding.message, /must not be read as safe/);
});

test("an end-of-life image branch is reported as high severity", async () => {
  const fs = createFs({ "/ws/Dockerfile": "FROM php:8.1.31-fpm\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "IMAGE-EOL");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
  assert.match(finding.message, /end-of-life/);
});

test("a commented-out disable does not satisfy the upload-progress mitigation", async () => {
  const fs = createFs({
    "/ws/php.ini": ";session.upload_progress.enabled = 0\nmemory_limit = -1\n"
  });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "CONFIG-UPLOAD-PROGRESS-NOT-DISABLED");
  assert.ok(finding);
  assert.equal(finding.severity, "medium");
  assert.deepEqual(finding.advisoryIds, ["CVE-2026-109619", "CVE-2026-115560"]);
  assert.equal(find(scan.findings, "CONFIG-MEMORY-LIMIT"), undefined);
});

test("an active pre-request disable suppresses the upload-progress finding", async () => {
  const fs = createFs({
    "/ws/php.ini": [
      "session.upload_progress.enabled = 0",
      "memory_limit = -1",
      "post_max_size = 8M"
    ].join("\n")
  });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  assert.equal(find(scan.findings, "CONFIG-UPLOAD-PROGRESS"), undefined);
  assert.equal(find(scan.findings, "CONFIG-MEMORY-LIMIT"), undefined);
  assert.equal(find(scan.findings, "CONFIG-POST-MAX-SIZE"), undefined);
});

test("a .user.ini disable is reported as insufficient for pre-request mitigation", async () => {
  const fs = createFs({ "/ws/.user.ini": "session.upload_progress.enabled = 0\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "CONFIG-UPLOAD-PROGRESS-NOT-DISABLED");
  assert.ok(finding);
  assert.match(finding.message, /\.user\.ini/);
});

test("a finite memory_limit is reported as an unapplied interim control", async () => {
  const fs = createFs({ "/ws/php.ini": "memory_limit = 256M\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "CONFIG-MEMORY-LIMIT");
  assert.ok(finding);
  assert.equal(finding.severity, "low");
  assert.equal(finding.kind, "mitigation");
  assert.match(finding.message, /256M/);
});

test("an oversized post_max_size is reported", async () => {
  const fs = createFs({ "/ws/php.ini": "post_max_size = 64M\nmemory_limit = -1\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "CONFIG-POST-MAX-SIZE");
  assert.ok(finding);
  assert.match(finding.message, /64M/);
});

test("reads FPM pool configuration", async () => {
  const fs = createFs({
    "/ws/php-fpm/pool.d/www.conf": [
      "[www]",
      "php_admin_value[session.upload_progress.enabled] = 0",
      "php_admin_value[memory_limit] = -1"
    ].join("\n")
  });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  assert.equal(find(scan.findings, "CONFIG-UPLOAD-PROGRESS"), undefined);
  assert.equal(find(scan.findings, "CONFIG-MEMORY-LIMIT"), undefined);
});

test("never starts a process in an untrusted workspace", async () => {
  const fs = createFs({
    "/ws/composer.lock": "{\n \"packages\": []\n}\n",
    "/ws/Dockerfile": "FROM php:8.4.27-fpm\n"
  });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs, neverRunner), { allowExecution: false });
  assert.equal(find(scan.findings, "PHP-CLI"), undefined);
  assert.equal(find(scan.findings, "COMPOSER"), undefined);
  assert.ok(scan.summary.skipped.some(item => /not trusted/.test(item)));
});

test("reports a vulnerable local PHP CLI with its SAPI", async () => {
  const runner = createRunner((command, args) => {
    if (command === "php" && args[0] === "-v") {
      return result({ stdout: "PHP 8.2.34 (cli) (built: Jan 1 2026)\n" });
    }
    throw new Error(`unexpected command ${command}`);
  });
  const fs = createFs({});
  const scan = await scanWorkspace(ROOT, { ...BASE, composerAudit: false }, deps(fs, runner), {
    allowExecution: true
  });
  const finding = find(scan.findings, "PHP-CLI-VULNERABLE");
  assert.ok(finding);
  assert.equal(finding.severity, "high");
  assert.equal(finding.observation?.kind, "php-cli");
  assert.equal(finding.observation?.scope, "local-dev");
  assert.equal(finding.observation?.sapi, "cli");
  assert.match(finding.message, /does not establish/);
});

test("maps Composer advisories to findings with the lock-file line", async () => {
  const lock = [
    "{",
    '    "packages": [',
    "        {",
    '            "name": "vendor/pkg",',
    '            "version": "1.0.0"',
    "        }",
    "    ]",
    "}"
  ].join("\n");
  const audit = JSON.stringify({
    advisories: {
      "vendor/pkg": [
        {
          advisoryId: "CVE-2026-123456",
          packageName: "vendor/pkg",
          title: "Remote code execution",
          affectedVersions: "<1.2.3",
          severity: "critical"
        }
      ]
    }
  });
  const runner = createRunner((command, args) => {
    if (command === "php" && args[0] === "-v") {
      return result({ stdout: "PHP 8.4.27 (cli)\n" });
    }
    if (args.includes("audit")) {
      return result({ stdout: audit, stderr: "Warning: noise\n", code: 1 });
    }
    throw new Error(`unexpected command ${command}`);
  });
  const fs = createFs({ "/ws/composer.lock": lock });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs, runner), { allowExecution: true });
  const finding = find(scan.findings, "COMPOSER:vendor/pkg:CVE-2026-123456");
  assert.ok(finding);
  assert.equal(finding.severity, "critical");
  assert.equal(finding.line, 4);
  assert.equal(finding.category, "dependency");
  assert.match(finding.recommendation, /Composer packages only/);
});

test("reports a scan-limit finding only when a matching file is skipped", async () => {
  const fs = createFs({
    "/ws/a/Dockerfile": "FROM php:8.4.27-fpm\n",
    "/ws/a/php.ini": "memory_limit = -1\n",
    "/ws/a/composer.json": '{"require":{"php":"^8.2"}}',
    "/ws/a/README.md": "not a target"
  });
  const limited = await scanWorkspace(ROOT, { ...BASE, maxFiles: 2 }, deps(fs), {
    allowExecution: false
  });
  assert.equal(limited.summary.truncated, true);
  assert.ok(find(limited.findings, "SCAN-LIMIT"));

  const exact = await scanWorkspace(ROOT, { ...BASE, maxFiles: 3 }, deps(fs), {
    allowExecution: false
  });
  assert.equal(exact.summary.truncated, false);
  assert.equal(find(exact.findings, "SCAN-LIMIT"), undefined);
});

test("skips and reports an oversized file instead of analysing a prefix", async () => {
  const fs = createFs({ "/ws/php.ini": "session.upload_progress.enabled = 0\n".repeat(20) });
  const scan = await scanWorkspace(ROOT, { ...BASE, maxFileBytes: 32 }, deps(fs), {
    allowExecution: false
  });
  assert.ok(scan.issues.some(issue => issue.code === "FILE_TOO_LARGE"));
  assert.equal(find(scan.findings, "CONFIG-UPLOAD-PROGRESS"), undefined);
  assert.equal(scan.summary.checkedFiles, 0);
});

test("reports unreadable files", async () => {
  const fs = createFs(
    { "/ws/composer.json": '{"require":{"php":"^8.2"}}' },
    { unreadable: ["/ws/composer.json"] }
  );
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  assert.ok(scan.issues.some(issue => issue.code === "FILE_UNREADABLE"));
});

test("honours the source-heuristic setting", async () => {
  const fs = createFs({ "/ws/a.php": "<?php system($cmd);\n" });
  const enabled = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const heuristic = find(enabled.findings, "php-command-exec");
  assert.ok(heuristic);
  assert.equal(heuristic.proof, "none");
  assert.equal(heuristic.kind, "heuristic");
  assert.equal(heuristic.severity, "medium");

  const disabled = await scanWorkspace(
    ROOT,
    { ...BASE, sourceHeuristics: false },
    deps(fs),
    { allowExecution: false }
  );
  assert.equal(find(disabled.findings, "php-command-exec"), undefined);
});

test("reports a composer.json constraint without treating it as the runtime", async () => {
  const fs = createFs({
    "/ws/composer.json": '{\n  "require": {\n    "php": "^8.1"\n  }\n}\n'
  });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), { allowExecution: false });
  const finding = find(scan.findings, "COMPOSER-CONSTRAINT");
  assert.ok(finding);
  assert.equal(finding.observation?.scope, "declared-constraint");
  assert.match(finding.message, /not the PHP runtime/);
  assert.equal(finding.line, 3);
});

test("stops when the scan is cancelled", async () => {
  const fs = createFs({ "/ws/a.php": "<?php system($cmd);\n" });
  const scan = await scanWorkspace(ROOT, BASE, deps(fs), {
    allowExecution: false,
    runtime: { isCancellationRequested: true }
  });
  assert.equal(scan.summary.cancelled, true);
  assert.equal(scan.summary.checkedFiles, 0);
});
