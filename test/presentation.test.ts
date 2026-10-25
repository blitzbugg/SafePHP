import { test } from "node:test";
import assert from "node:assert/strict";
import {
  countBySeverity,
  diagnosticLevelFor,
  formatReport,
  isSafeExternalUrl,
  sortFindings,
  toDiagnosticData
} from "../src/core/presentation";
import type { Finding, ScanResult } from "../src/types";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "id",
    title: "Title",
    severity: "medium",
    confidence: "low",
    proof: "none",
    kind: "heuristic",
    category: "source",
    message: "Message",
    evidence: "Evidence",
    recommendation: "Do the thing",
    references: [],
    advisoryIds: [],
    ...overrides
  };
}

test("sorts by severity, then file and line", () => {
  const sorted = sortFindings([
    finding({ id: "c", severity: "low", file: "/b", line: 1 }),
    finding({ id: "a", severity: "critical", file: "/z", line: 9 }),
    finding({ id: "b", severity: "critical", file: "/a", line: 2 })
  ]);
  assert.deepEqual(
    sorted.map(item => item.id),
    ["b", "a", "c"]
  );
});

test("counts findings per severity", () => {
  const counts = countBySeverity([
    finding({ severity: "critical" }),
    finding({ severity: "critical" }),
    finding({ severity: "info" })
  ]);
  assert.equal(counts.critical, 2);
  assert.equal(counts.high, 0);
  assert.equal(counts.info, 1);
});

test("never renders a heuristic as an editor error", () => {
  assert.equal(diagnosticLevelFor(finding({ severity: "critical", proof: "none" })), "warning");
  assert.equal(diagnosticLevelFor(finding({ severity: "medium", proof: "none" })), "warning");
  assert.equal(diagnosticLevelFor(finding({ severity: "low", proof: "none" })), "information");
});

test("maps advisory-backed findings to editor severities", () => {
  assert.equal(diagnosticLevelFor(finding({ severity: "critical", proof: "advisory" })), "error");
  assert.equal(diagnosticLevelFor(finding({ severity: "high", proof: "advisory" })), "error");
  assert.equal(diagnosticLevelFor(finding({ severity: "medium", proof: "advisory" })), "warning");
  assert.equal(diagnosticLevelFor(finding({ severity: "info", proof: "advisory" })), "information");
});

test("requires a file and line before producing a diagnostic", () => {
  assert.equal(toDiagnosticData(finding({})), undefined);
  assert.equal(toDiagnosticData(finding({ file: "/a.php" })), undefined);
  const data = toDiagnosticData(finding({ file: "/a.php", line: 12 }));
  assert.ok(data);
  assert.equal(data.line, 12);
  assert.equal(data.level, "warning");
});

test("prefers an advisory id as the diagnostic code", () => {
  const data = toDiagnosticData(
    finding({ file: "/a.php", line: 1, advisoryIds: ["CVE-2026-109618"], proof: "advisory" })
  );
  assert.ok(data);
  assert.equal(data.code, "CVE-2026-109618");
  assert.ok(data.relatedInformation.some(text => /advisory/i.test(text)));
});

test("only accepts https references for external opening", () => {
  assert.equal(isSafeExternalUrl("https://www.php.net/advisory"), true);
  assert.equal(isSafeExternalUrl("http://www.php.net/advisory"), false);
  assert.equal(isSafeExternalUrl("file:///etc/passwd"), false);
  assert.equal(isSafeExternalUrl("javascript:alert(1)"), false);
  assert.equal(isSafeExternalUrl("not a url"), false);
});

test("report states the advisory data date, skipped checks and heuristic limits", () => {
  const result: ScanResult = {
    findings: [
      finding({ id: "h", file: "/a.php", line: 3, severity: "medium", proof: "none" }),
      finding({
        id: "v",
        title: "Vulnerable image",
        severity: "critical",
        proof: "advisory",
        kind: "vulnerability",
        category: "runtime",
        file: "/Dockerfile",
        line: 1,
        advisoryIds: ["CVE-2026-109618"],
        references: ["https://www.php.net/archive/2026.php"]
      })
    ],
    issues: [{ code: "FILE_UNREADABLE", message: "could not read", file: "/b.php" }],
    summary: {
      checkedFiles: 2,
      truncated: false,
      cancelled: false,
      advisoriesRetrievedAt: "2026-10-25",
      skipped: ["Composer audit was not run: no composer.lock was found in the workspace."]
    }
  };
  const report = formatReport(result);
  assert.match(report, /Advisory data retrieved: 2026-10-25/);
  assert.match(report, /heuristic only/i);
  assert.match(report, /Not assessed in this scan/);
  assert.match(report, /FILE_UNREADABLE/);
  assert.match(report, /CVE-2026-109618/);
  assert.match(report, /packagist\.org/);
});
