import { test } from "node:test";
import assert from "node:assert/strict";
import { advisoryData, advisoryDataErrors, validateAdvisoryData } from "../src/core/advisories";

test("bundled advisory data passes validation", () => {
  assert.deepEqual(advisoryDataErrors, []);
  assert.equal(advisoryData.schemaVersion, 2);
  assert.equal(advisoryData.retrievedAt, "2026-10-25");
  assert.equal(advisoryData.advisories.length, 3);
});

test("every advisory has an id, https references and a mitigation", () => {
  for (const advisory of advisoryData.advisories) {
    assert.match(advisory.id, /^CVE-\d{4}-\d+$/);
    assert.ok(advisory.references.length > 0, advisory.id);
    for (const reference of advisory.references) {
      assert.equal(new URL(reference).protocol, "https:", `${advisory.id} reference ${reference}`);
    }
    assert.ok(advisory.mitigations.length > 0, advisory.id);
    assert.ok(advisory.recommendation.length > 0, advisory.id);
  }
});

test("CVE-2026-109618 and CVE-2026-109619 list the verified fixed releases", () => {
  const expected: Record<string, string> = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12"
  };
  for (const id of ["CVE-2026-109618", "CVE-2026-109619"]) {
    const advisory = advisoryData.advisories.find(entry => entry.id === id);
    assert.ok(advisory, id);
    assert.equal(advisory.status, "fixed");
    assert.equal(advisory.severity, "critical");
    assert.equal(advisory.eolBranchesAffected, true);
    assert.deepEqual(
      Object.fromEntries(
        Object.entries(advisory.branches).map(([branch, range]) => [branch, range.fixedIn])
      ),
      expected
    );
  }
});

test("CVE-2026-115560 is an informational RCE, not a configuration advisory", () => {
  const advisory = advisoryData.advisories.find(entry => entry.id === "CVE-2026-115560");
  assert.ok(advisory);
  assert.equal(advisory.category, "runtime");
  assert.equal(advisory.status, "unpatched-informational");
  assert.deepEqual(advisory.branches, {});
  assert.equal(advisory.eolBranchesAffected, false);
  assert.match(advisory.summary, /remote code execution/i);
  assert.ok(advisory.mitigations.some(m => m.directive === "session.upload_progress.enabled"));
});

test("the upload-progress mitigation is documented for both 109619 and 115560", () => {
  for (const id of ["CVE-2026-109619", "CVE-2026-115560"]) {
    const advisory = advisoryData.advisories.find(entry => entry.id === id);
    assert.ok(advisory, id);
    assert.ok(
      advisory.mitigations.some(m => m.directive === "session.upload_progress.enabled" && m.value === "0"),
      id
    );
  }
});

test("validator rejects an unsupported schema version", () => {
  const result = validateAdvisoryData({ schemaVersion: 1, retrievedAt: "2026-10-25", advisories: [] });
  assert.ok(result.errors.some(error => /schemaVersion/.test(error)));
  assert.equal(result.data.advisories.length, 0);
});

test("validator drops non-https references", () => {
  const result = validateAdvisoryData({
    schemaVersion: 2,
    retrievedAt: "2026-10-25",
    advisories: [
      {
        id: "CVE-2026-000001",
        title: "t",
        summary: "s",
        category: "runtime",
        status: "fixed",
        severity: "high",
        branches: { "8.2": { fixedIn: "8.2.35" } },
        eolBranchesAffected: false,
        mitigations: [{ text: "patch" }],
        recommendation: "patch",
        references: ["http://insecure.example/advisory"],
        verifiedAgainst: []
      }
    ]
  });
  assert.ok(result.errors.some(error => /https/.test(error)));
  const advisory = result.data.advisories[0];
  assert.ok(advisory);
  assert.deepEqual(advisory.references, []);
});

test("validator rejects an unparseable fixed version", () => {
  const result = validateAdvisoryData({
    schemaVersion: 2,
    retrievedAt: "2026-10-25",
    advisories: [
      {
        id: "CVE-2026-000002",
        title: "t",
        summary: "s",
        category: "runtime",
        status: "fixed",
        severity: "high",
        branches: { "8.2": { fixedIn: "eight" } },
        eolBranchesAffected: false,
        mitigations: [{ text: "patch" }],
        recommendation: "patch",
        references: ["https://example.com/advisory"],
        verifiedAgainst: []
      }
    ]
  });
  assert.ok(result.errors.some(error => /unparseable "fixedIn"/.test(error)));
});

test("validator rejects a fixed advisory with no branches", () => {
  const result = validateAdvisoryData({
    schemaVersion: 2,
    retrievedAt: "2026-10-25",
    advisories: [
      {
        id: "CVE-2026-000003",
        title: "t",
        summary: "s",
        category: "runtime",
        status: "fixed",
        severity: "high",
        branches: {},
        eolBranchesAffected: false,
        mitigations: [{ text: "patch" }],
        recommendation: "patch",
        references: ["https://example.com/advisory"],
        verifiedAgainst: []
      }
    ]
  });
  assert.ok(result.errors.some(error => /at least one branch/.test(error)));
});

test("validator drops duplicate advisory ids", () => {
  const base = {
    id: "CVE-2026-000004",
    title: "t",
    summary: "s",
    category: "runtime" as const,
    status: "fixed" as const,
    severity: "high" as const,
    branches: { "8.2": { fixedIn: "8.2.35" } },
    eolBranchesAffected: false,
    mitigations: [{ text: "patch" }],
    recommendation: "patch",
    references: ["https://example.com/advisory"],
    verifiedAgainst: []
  };
  const result = validateAdvisoryData({
    schemaVersion: 2,
    retrievedAt: "2026-10-25",
    advisories: [base, base]
  });
  assert.equal(result.data.advisories.length, 1);
  assert.ok(result.errors.some(error => /Duplicate advisory id/.test(error)));
});
