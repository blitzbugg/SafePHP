import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assessVersion,
  compareVersionStrings,
  fixedVersionsByBranch,
  formatVersion,
  isEndOfLifeBranch,
  parseVersion
} from "../src/core/version";
import { advisoryData } from "../src/core/advisories";

function cmp(a: string, b: string): number {
  const result = compareVersionStrings(a, b);
  assert.notEqual(result, undefined, `expected both versions to parse: ${a} / ${b}`);
  return result as number;
}

test("parses an upstream release", () => {
  const version = parseVersion("8.2.35");
  assert.ok(version);
  assert.equal(version.major, 8);
  assert.equal(version.minor, 2);
  assert.equal(version.patch, 35);
  assert.equal(version.hasPatch, true);
  assert.equal(version.prerelease, undefined);
  assert.equal(version.vendorSuffix, undefined);
});

test("records a missing patch level instead of silently assuming one", () => {
  const version = parseVersion("8.2");
  assert.ok(version);
  assert.equal(version.patch, 0);
  assert.equal(version.hasPatch, false);
});

test("parses distribution and vendor suffixes", () => {
  const ubuntu = parseVersion("8.2.35-1+ubuntu22.04.1");
  assert.ok(ubuntu);
  assert.equal(ubuntu.vendorSuffix, "-1+ubuntu22.04.1");
  assert.equal(formatVersion(ubuntu), "8.2.35");

  const debian = parseVersion("8.2.35+deb12u1");
  assert.ok(debian);
  assert.equal(debian.vendorSuffix, "+deb12u1");
  assert.equal(debian.patch, 35);
});

test("parses prereleases with and without a dash", () => {
  for (const input of ["8.4.0RC1", "8.4.0-RC1"]) {
    const version = parseVersion(input);
    assert.ok(version, input);
    assert.equal(version.prerelease?.label, "rc");
    assert.equal(version.prerelease?.number, 1);
  }

  const beta = parseVersion("8.4.0beta2");
  assert.ok(beta);
  assert.equal(beta.prerelease?.label, "beta");
  assert.equal(beta.prerelease?.number, 2);

  const variant = parseVersion("8.4.0RC1-fpm");
  assert.ok(variant);
  assert.equal(variant.prerelease?.label, "rc");
  assert.equal(variant.vendorSuffix, "-fpm");
});

test("rejects input that is not a PHP version", () => {
  for (const input of ["", "latest", "8.2.x", "php", "v8.2.35", "8.2.35 extra.js"]) {
    assert.equal(parseVersion(input), undefined, `should reject ${JSON.stringify(input)}`);
  }
});

test("compares numerically rather than lexicographically", () => {
  assert.equal(cmp("8.10.0", "8.9.9"), 1);
  assert.equal(cmp("8.2.34", "8.2.35"), -1);
  assert.equal(cmp("8.2.35", "8.2.35"), 0);
  assert.equal(cmp("8.2", "8.2.0"), 0);
});

test("orders prereleases before the matching final release", () => {
  assert.equal(cmp("8.4.0RC1", "8.4.0"), -1);
  assert.equal(cmp("8.4.0beta2", "8.4.0RC1"), -1);
  assert.equal(cmp("8.4.0RC2", "8.4.0RC1"), 1);
  assert.equal(cmp("8.4.0alpha1", "8.4.0beta1"), -1);
});

test("returns undefined rather than a bogus ordering for unparseable input", () => {
  assert.equal(compareVersionStrings("8.2.x", "8.2.35"), undefined);
  assert.equal(compareVersionStrings("latest", "8.2.35"), undefined);
});

test("flags the release below the fixed version", () => {
  const assessment = assessVersion("8.2.34", advisoryData);
  assert.equal(assessment.verdict, "vulnerable");
  assert.deepEqual([...assessment.vulnerableAdvisories].sort(), [
    "CVE-2026-109618",
    "CVE-2026-109619"
  ]);
  assert.equal(assessment.fixedIn, "8.2.35");
});

test("treats the fixed release itself as fixed (inclusive boundary)", () => {
  assert.equal(assessVersion("8.2.35", advisoryData).verdict, "fixed");
  assert.equal(assessVersion("8.3.36", advisoryData).verdict, "fixed");
  assert.equal(assessVersion("8.4.27", advisoryData).verdict, "fixed");
  assert.equal(assessVersion("8.5.12", advisoryData).verdict, "fixed");
});

test("treats a prerelease of a fixed branch as vulnerable", () => {
  assert.equal(assessVersion("8.2.35RC1", advisoryData).verdict, "vulnerable");
});

test("marks end-of-life branches as vendor dependent, never safe", () => {
  for (const input of ["7.4.33", "8.0.30", "8.1.31"]) {
    const assessment = assessVersion(input, advisoryData);
    assert.equal(assessment.verdict, "eol-vendor-dependent", input);
    assert.ok(assessment.vulnerableAdvisories.includes("CVE-2026-109618"));
    assert.ok(assessment.notes.some(note => /vendor/i.test(note)));
  }
});

test("marks a branch outside the bundled data as uncovered", () => {
  const assessment = assessVersion("8.6.0", advisoryData);
  assert.equal(assessment.verdict, "uncovered");
  assert.equal(assessment.fixedIn, undefined);
  assert.ok(assessment.notes.some(note => /not assessed/i.test(note)));
});

test("returns unparsed for input it cannot read", () => {
  assert.equal(assessVersion("bookworm", advisoryData).verdict, "unparsed");
});

test("records the vendor-build caveat without downgrading the verdict", () => {
  const assessment = assessVersion("8.2.35-1+ubuntu22.04", advisoryData);
  assert.equal(assessment.verdict, "fixed");
  assert.ok(assessment.notes.some(note => /vendor|distribution/i.test(note)));
});

test("derives fixed versions per branch from advisory data", () => {
  assert.deepEqual(fixedVersionsByBranch(advisoryData), {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12"
  });
});

test("identifies end-of-life branches", () => {
  for (const input of ["7.4.0", "8.0.30", "8.1.31"]) {
    const version = parseVersion(input);
    assert.ok(version);
    assert.equal(isEndOfLifeBranch(version), true, input);
  }
  const supported = parseVersion("8.2.0");
  assert.ok(supported);
  assert.equal(isEndOfLifeBranch(supported), false);
});
