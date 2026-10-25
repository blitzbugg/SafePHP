import rawData from "../advisories/advisories.json";
import type {
  Advisory,
  AdvisoryBranch,
  AdvisoryData,
  AdvisoryMitigation,
  AdvisoryStatus,
  Severity
} from "../types";
import { parseVersion } from "./version";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const STATUSES: readonly AdvisoryStatus[] = ["fixed", "unpatched-informational", "vendor-dependent"];
const CATEGORIES: readonly Advisory["category"][] = ["runtime", "configuration"];

export interface AdvisoryLoadResult {
  data: AdvisoryData;
  errors: string[];
}

export const EMPTY_ADVISORY_DATA: AdvisoryData = {
  schemaVersion: 2,
  retrievedAt: "unknown",
  advisories: []
};

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every(item => typeof item === "string");
}

/** References are only useful if they can be opened safely. */
export function isSafeReference(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:";
  } catch {
    return false;
  }
}

function readString(record: UnknownRecord, key: string, where: string, errors: string[]): string | undefined {
  const value = record[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    errors.push(`${where}: "${key}" must be a non-empty string.`);
    return undefined;
  }
  return value;
}

function readBranches(value: unknown, where: string, errors: string[]): Record<string, AdvisoryBranch> | undefined {
  if (!isRecord(value)) {
    errors.push(`${where}: "branches" must be an object.`);
    return undefined;
  }
  const branches: Record<string, AdvisoryBranch> = {};
  for (const [branch, entry] of Object.entries(value)) {
    if (!/^\d+\.\d+$/.test(branch)) {
      errors.push(`${where}: branch key "${branch}" must look like "8.4".`);
      continue;
    }
    if (!isRecord(entry)) {
      errors.push(`${where}: branch "${branch}" must be an object.`);
      continue;
    }
    const parsed: AdvisoryBranch = {};
    for (const key of ["affectedBelow", "fixedIn"] as const) {
      const raw = entry[key];
      if (raw === undefined) continue;
      if (typeof raw !== "string" || !parseVersion(raw)) {
        errors.push(`${where}: branch "${branch}" has an unparseable "${key}".`);
        continue;
      }
      parsed[key] = raw;
    }
    if (!parsed.affectedBelow && !parsed.fixedIn) {
      errors.push(`${where}: branch "${branch}" needs "affectedBelow" or "fixedIn".`);
      continue;
    }
    branches[branch] = parsed;
  }
  return branches;
}

function readMitigations(value: unknown, where: string, errors: string[]): AdvisoryMitigation[] {
  if (!Array.isArray(value)) {
    errors.push(`${where}: "mitigations" must be an array.`);
    return [];
  }
  const mitigations: AdvisoryMitigation[] = [];
  value.forEach((entry, index) => {
    if (!isRecord(entry) || typeof entry.text !== "string" || entry.text.trim().length === 0) {
      errors.push(`${where}: mitigations[${index}] needs a "text" string.`);
      return;
    }
    const mitigation: AdvisoryMitigation = { text: entry.text };
    if (typeof entry.directive === "string") mitigation.directive = entry.directive;
    if (typeof entry.value === "string") mitigation.value = entry.value;
    mitigations.push(mitigation);
  });
  return mitigations;
}

function readReferences(value: unknown, where: string, errors: string[]): string[] {
  if (!isStringArray(value)) {
    errors.push(`${where}: "references" must be an array of strings.`);
    return [];
  }
  const safe = value.filter(isSafeReference);
  if (safe.length !== value.length) {
    errors.push(`${where}: only https references are accepted.`);
  }
  return safe;
}

function readAdvisory(value: unknown, index: number, errors: string[]): Advisory | undefined {
  const where = `advisories[${index}]`;
  if (!isRecord(value)) {
    errors.push(`${where}: entry must be an object.`);
    return undefined;
  }

  const id = readString(value, "id", where, errors);
  const title = readString(value, "title", where, errors);
  const summary = readString(value, "summary", where, errors);
  const recommendation = readString(value, "recommendation", where, errors);
  if (!id || !title || !summary || !recommendation) return undefined;

  if (!CATEGORIES.includes(value.category as Advisory["category"])) {
    errors.push(`${where}: "category" must be one of ${CATEGORIES.join(", ")}.`);
    return undefined;
  }
  if (!STATUSES.includes(value.status as AdvisoryStatus)) {
    errors.push(`${where}: "status" must be one of ${STATUSES.join(", ")}.`);
    return undefined;
  }
  if (!SEVERITIES.includes(value.severity as Severity)) {
    errors.push(`${where}: "severity" must be one of ${SEVERITIES.join(", ")}.`);
    return undefined;
  }

  const branches = readBranches(value.branches, where, errors);
  if (!branches) return undefined;

  if (typeof value.eolBranchesAffected !== "boolean") {
    errors.push(`${where}: "eolBranchesAffected" must be a boolean.`);
    return undefined;
  }

  if (value.status === "fixed" && Object.keys(branches).length === 0) {
    errors.push(`${where}: a "fixed" advisory must list at least one branch.`);
    return undefined;
  }

  const references = readReferences(value.references, where, errors);
  if (references.length === 0) {
    errors.push(`${where}: at least one https reference is required.`);
  }

  const verifiedAgainst = isStringArray(value.verifiedAgainst)
    ? value.verifiedAgainst.filter(isSafeReference)
    : [];

  return {
    id,
    aliases: isStringArray(value.aliases) ? value.aliases : [],
    title,
    summary,
    category: value.category as Advisory["category"],
    status: value.status as AdvisoryStatus,
    severity: value.severity as Severity,
    branches,
    eolBranchesAffected: value.eolBranchesAffected,
    preconditions: typeof value.preconditions === "string" ? value.preconditions : undefined,
    mitigations: readMitigations(value.mitigations, where, errors),
    recommendation,
    references,
    verifiedAgainst
  };
}

/**
 * Validate advisory data. Invalid records are dropped and reported; they are
 * never silently coerced into plausible-looking data.
 */
export function validateAdvisoryData(raw: unknown): AdvisoryLoadResult {
  const errors: string[] = [];
  if (!isRecord(raw)) {
    return { data: EMPTY_ADVISORY_DATA, errors: ["Advisory data must be a JSON object."] };
  }
  if (raw.schemaVersion !== 2) {
    errors.push(`Unsupported advisory schemaVersion ${String(raw.schemaVersion)}; expected 2.`);
  }
  if (typeof raw.retrievedAt !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(raw.retrievedAt)) {
    errors.push('"retrievedAt" must be a YYYY-MM-DD date.');
  }
  if (!Array.isArray(raw.advisories)) {
    return { data: EMPTY_ADVISORY_DATA, errors: [...errors, '"advisories" must be an array.'] };
  }

  const advisories: Advisory[] = [];
  raw.advisories.forEach((entry, index) => {
    const advisory = readAdvisory(entry, index, errors);
    if (advisory) advisories.push(advisory);
  });

  const seen = new Set<string>();
  const unique = advisories.filter(advisory => {
    if (seen.has(advisory.id)) {
      errors.push(`Duplicate advisory id "${advisory.id}".`);
      return false;
    }
    seen.add(advisory.id);
    return true;
  });

  return {
    data: {
      schemaVersion: 2,
      retrievedAt: typeof raw.retrievedAt === "string" ? raw.retrievedAt : "unknown",
      advisories: unique
    },
    errors
  };
}

const loaded = validateAdvisoryData(rawData);

/** The bundled advisory data, validated once at module load. */
export const advisoryData: AdvisoryData = loaded.data;
export const advisoryDataErrors: string[] = loaded.errors;

export function advisoryById(id: string): Advisory | undefined {
  return advisoryData.advisories.find(advisory => advisory.id === id);
}
