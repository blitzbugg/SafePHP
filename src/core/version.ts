import type { Advisory, AdvisoryData } from "../types";

export interface Prerelease {
  label: string;
  number: number;
}

export interface ParsedVersion {
  raw: string;
  major: number;
  minor: number;
  patch: number;
  /** False when the input stopped at "8.2" or "8". */
  hasPatch: boolean;
  prerelease?: Prerelease;
  /** Vendor/distribution suffix such as "-1+ubuntu22.04" or "+deb12u1". */
  vendorSuffix?: string;
}

const PRERELEASE_LABELS: Array<{ pattern: RegExp; label: string; rank: number }> = [
  { pattern: /^dev/i, label: "dev", rank: 0 },
  { pattern: /^alpha/i, label: "alpha", rank: 1 },
  { pattern: /^beta/i, label: "beta", rank: 2 },
  { pattern: /^rc/i, label: "rc", rank: 3 }
];

function prereleaseRank(label: string): number {
  const found = PRERELEASE_LABELS.find(l => l.label === label);
  return found ? found.rank : 0;
}

function normalizeLabel(raw: string): string {
  return raw.toLowerCase();
}

/**
 * Parse a PHP version string.
 *
 * Accepts upstream releases, prereleases ("8.4.0RC1", "8.4.0-beta2") and
 * distribution/vendor builds ("8.2.35-1+ubuntu22.04", "8.2.35+deb12u1").
 * Returns undefined when the string does not start with a numeric version, so
 * callers can report "unparsed" instead of inventing an ordering.
 */
export function parseVersion(raw: string): ParsedVersion | undefined {
  const input = raw.trim();
  const numeric = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(input);
  if (!numeric) return undefined;

  const major = Number(numeric[1]);
  const minor = Number(numeric[2]);
  const patch = numeric[3] === undefined ? 0 : Number(numeric[3]);
  const hasPatch = numeric[3] !== undefined;

  if (!Number.isFinite(major) || !Number.isFinite(minor) || !Number.isFinite(patch)) {
    return undefined;
  }

  let rest = input.slice(numeric[0].length);
  const parsed: ParsedVersion = { raw: input, major, minor, patch, hasPatch };

  // A prerelease may follow the numeric part directly ("8.4.0RC1") or after a
  // dash ("8.4.0-RC1"). Anything unrecognised after that is a vendor suffix.
  const prereleaseText = /^-?(dev|alpha|beta|rc)(\d*)/i.exec(rest);
  if (prereleaseText) {
    const label = normalizeLabel(prereleaseText[1]);
    parsed.prerelease = { label, number: Number(prereleaseText[2] || 0) };
    rest = rest.slice(prereleaseText[0].length);
  }

  if (rest.length > 0) {
    if (!/^[-+][A-Za-z0-9.+~:_-]+$/.test(rest)) return undefined;
    parsed.vendorSuffix = rest;
  }

  return parsed;
}

export function formatVersion(version: ParsedVersion): string {
  const base = `${version.major}.${version.minor}.${version.patch}`;
  if (!version.prerelease) return base;
  return `${base}-${version.prerelease.label}${version.prerelease.number}`;
}

export function branchOf(version: ParsedVersion): string {
  return `${version.major}.${version.minor}`;
}

function comparePrerelease(a?: Prerelease, b?: Prerelease): number {
  if (!a && !b) return 0;
  // A prerelease sorts before the final release of the same version.
  if (!a) return 1;
  if (!b) return -1;
  const rankA = prereleaseRank(a.label);
  const rankB = prereleaseRank(b.label);
  if (rankA !== rankB) return rankA < rankB ? -1 : 1;
  if (a.number !== b.number) return a.number < b.number ? -1 : 1;
  return 0;
}

/** Numeric comparison of the release core, then prerelease ordering. */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  const core: Array<[number, number]> = [
    [a.major, b.major],
    [a.minor, b.minor],
    [a.patch, b.patch]
  ];
  for (const [left, right] of core) {
    if (left !== right) return left < right ? -1 : 1;
  }
  return comparePrerelease(a.prerelease, b.prerelease);
}

/** Compare two version strings. Returns undefined when either side is unparseable. */
export function compareVersionStrings(a: string, b: string): number | undefined {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return undefined;
  return compareVersions(left, right);
}

export type VersionVerdict =
  | "vulnerable"
  | "fixed"
  | "eol-vendor-dependent"
  | "uncovered"
  | "unparsed";

export interface VersionAssessment {
  verdict: VersionVerdict;
  branch?: string;
  vulnerableAdvisories: string[];
  fixedAdvisories: string[];
  /** Highest fixed release among the advisories that cover this branch. */
  fixedIn?: string;
  notes: string[];
}

/**
 * True for branches the PHP project no longer maintains (8.1 and older), where
 * only a vendor backport can provide a fix.
 */
export function isEndOfLifeBranch(version: ParsedVersion): boolean {
  if (version.major < 8) return true;
  return version.major === 8 && version.minor <= 1;
}

function advisoriesCovering(advisory: Advisory, branch: string): boolean {
  return Object.prototype.hasOwnProperty.call(advisory.branches, branch);
}

/**
 * Classify an observed version against the bundled advisory data.
 *
 * There is deliberately no "safe" verdict: an observation either matches an
 * advisory's affected range, sits at or above a known fixed release for a
 * covered branch, belongs to an end-of-life branch, or is uncovered.
 */
export function assessVersion(raw: string, data: AdvisoryData): VersionAssessment {
  const version = parseVersion(raw);
  if (!version) {
    return {
      verdict: "unparsed",
      vulnerableAdvisories: [],
      fixedAdvisories: [],
      notes: ["The version string could not be parsed, so it was not compared with advisory data."]
    };
  }

  const branch = branchOf(version);
  const notes: string[] = [];
  if (version.vendorSuffix) {
    notes.push(
      `This is a vendor or distribution build (${version.vendorSuffix}); the vendor may have backported the fix without changing the upstream version number.`
    );
  }
  if (version.prerelease) {
    notes.push("This is a prerelease build; upstream fixed releases are compared as final releases.");
  }
  if (!version.hasPatch) {
    notes.push("The observation does not include a patch level, so the exact release is unknown.");
  }

  const withBranchData = data.advisories.filter(a => Object.keys(a.branches).length > 0);
  const relevant = withBranchData.filter(a => advisoriesCovering(a, branch));

  if (relevant.length === 0) {
    if (isEndOfLifeBranch(version) && withBranchData.some(a => a.eolBranchesAffected)) {
      return {
        verdict: "eol-vendor-dependent",
        branch,
        vulnerableAdvisories: withBranchData.filter(a => a.eolBranchesAffected).map(a => a.id),
        fixedAdvisories: [],
        notes: [
          ...notes,
          "The PHP project no longer issues fixes for this branch. Distributions and LTS vendors may provide backported patches; consult the vendor advisory."
        ]
      };
    }
    return {
      verdict: "uncovered",
      branch,
      vulnerableAdvisories: [],
      fixedAdvisories: [],
      notes: [
        ...notes,
        `The bundled advisory data has no affected-range entry for the ${branch} branch, so this version was not assessed.`
      ]
    };
  }

  const vulnerable: string[] = [];
  const fixed: string[] = [];
  let highestFixed: ParsedVersion | undefined;

  for (const advisory of relevant) {
    const entry = advisory.branches[branch];
    const thresholdText = entry.affectedBelow ?? entry.fixedIn;
    const threshold = thresholdText ? parseVersion(thresholdText) : undefined;
    if (!threshold) {
      notes.push(`Advisory ${advisory.id} has an unparseable version range for branch ${branch}.`);
      continue;
    }
    if (compareVersions(version, threshold) < 0) {
      vulnerable.push(advisory.id);
    } else {
      fixed.push(advisory.id);
    }
    if (entry.fixedIn) {
      const fixedVersion = parseVersion(entry.fixedIn);
      if (fixedVersion && (!highestFixed || compareVersions(fixedVersion, highestFixed) > 0)) {
        highestFixed = fixedVersion;
      }
    }
  }

  return {
    verdict: vulnerable.length > 0 ? "vulnerable" : "fixed",
    branch,
    vulnerableAdvisories: vulnerable,
    fixedAdvisories: fixed,
    fixedIn: highestFixed ? formatVersion(highestFixed) : undefined,
    notes
  };
}

/** Fixed releases per branch, derived from the advisory data (never hard-coded). */
export function fixedVersionsByBranch(data: AdvisoryData): Record<string, string> {
  const result: Record<string, string> = {};
  for (const advisory of data.advisories) {
    for (const [branch, entry] of Object.entries(advisory.branches)) {
      if (!entry.fixedIn) continue;
      const existing = result[branch];
      if (!existing) {
        result[branch] = entry.fixedIn;
        continue;
      }
      const existingVersion = parseVersion(existing);
      const candidate = parseVersion(entry.fixedIn);
      if (existingVersion && candidate && compareVersions(candidate, existingVersion) > 0) {
        result[branch] = entry.fixedIn;
      }
    }
  }
  return result;
}
