import * as path from "node:path";
import type { Severity } from "../types";
import { isSpawnFailure, type ProcessRunner } from "./process";

export interface ComposerAdvisory {
  packageName: string;
  advisoryId: string;
  title: string;
  cve?: string;
  affectedVersions?: string;
  link?: string;
  reportedAt?: string;
  severity: Severity;
  /** False when Composer did not publish a severity for this advisory. */
  severityPublished: boolean;
  sources: string[];
}

export interface ComposerAbandoned {
  packageName: string;
  replacement?: string;
}

export type ComposerAuditStatus = "ok" | "failed" | "not-found" | "unparsed";

export interface ComposerAuditOutcome {
  status: ComposerAuditStatus;
  advisories: ComposerAdvisory[];
  abandoned: ComposerAbandoned[];
  lockDir: string;
  attempts: string[];
  message?: string;
  raw?: string;
}

export interface ComposerSettings {
  phpPath?: string;
  composerPath?: string;
  composerPharPath?: string;
  timeoutMs: number;
}

export interface ComposerCandidate {
  command: string;
  prefixArgs: string[];
  display: string;
}

export interface ComposerEnvironment {
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
}

/** Arguments for a full audit. `--no-plugins`/`--no-scripts` keep project code from running. */
export function auditArguments(lockDir: string, mode: "full" | "minimal" = "full"): string[] {
  const base = ["audit", "--format=json", "--no-interaction", "--no-plugins", "--no-scripts"];
  return mode === "full" ? [...base, "--locked", "--working-dir", lockDir] : base;
}

const SAFE_TO_RETRY = new Set(["ENOENT", "EINVAL", "EACCES", "EPERM"]);

/**
 * Build launch candidates in order of preference.
 *
 * On Windows a `composer.bat` shim cannot be spawned without a shell, so the
 * phar invoked through php is the reliable path.
 */
export async function buildComposerCandidates(
  settings: ComposerSettings,
  environment: ComposerEnvironment,
  exists: (target: string) => Promise<boolean>
): Promise<ComposerCandidate[]> {
  const candidates: ComposerCandidate[] = [];
  const php = settings.phpPath?.trim() || "php";
  const seen = new Set<string>();

  const push = (candidate: ComposerCandidate): void => {
    const key = `${candidate.command}\u0000${candidate.prefixArgs.join("\u0000")}`;
    if (seen.has(key)) return;
    seen.add(key);
    candidates.push(candidate);
  };

  const composerPath = settings.composerPath?.trim();
  if (composerPath) {
    push({ command: composerPath, prefixArgs: [], display: composerPath });
  }

  const pharCandidates: string[] = [];
  if (settings.composerPharPath?.trim()) pharCandidates.push(settings.composerPharPath.trim());
  const composerHome = environment.env.COMPOSER_HOME;
  if (composerHome) pharCandidates.push(path.join(composerHome, "composer.phar"));
  const appData = environment.env.APPDATA;
  if (appData) pharCandidates.push(path.join(appData, "Composer", "composer.phar"));
  const home = environment.env.HOME ?? environment.env.USERPROFILE;
  if (home) pharCandidates.push(path.join(home, ".config", "composer", "composer.phar"));

  for (const candidate of pharCandidates) {
    if (await exists(candidate)) {
      push({ command: php, prefixArgs: [candidate], display: `${php} ${candidate}` });
    }
  }

  push({ command: "composer", prefixArgs: [], display: "composer" });

  return candidates;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function mapSeverity(value: unknown): { severity: Severity; published: boolean } {
  if (typeof value !== "string") return { severity: "medium", published: false };
  switch (value.toLowerCase()) {
    case "critical":
      return { severity: "critical", published: true };
    case "high":
      return { severity: "high", published: true };
    case "moderate":
    case "medium":
      return { severity: "medium", published: true };
    case "low":
      return { severity: "low", published: true };
    default:
      return { severity: "medium", published: false };
  }
}

function httpsOnly(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    return new URL(value).protocol === "https:" ? value : undefined;
  } catch {
    return undefined;
  }
}

function readSources(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const sources: string[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) continue;
    if (typeof entry.remoteId === "string") sources.push(entry.remoteId);
  }
  return sources;
}

function normalizeAdvisoryEntry(entry: Record<string, unknown>, packageName: string): ComposerAdvisory | undefined {
  const advisoryId =
    typeof entry.advisoryId === "string"
      ? entry.advisoryId
      : typeof entry.cve === "string"
        ? entry.cve
        : undefined;
  if (!advisoryId) return undefined;

  const severity = mapSeverity(entry.severity);
  const advisory: ComposerAdvisory = {
    packageName,
    advisoryId,
    title: typeof entry.title === "string" ? entry.title : advisoryId,
    severity: severity.severity,
    severityPublished: severity.published,
    sources: readSources(entry.sources)
  };
  const cve = typeof entry.cve === "string" ? entry.cve : undefined;
  if (cve !== undefined) advisory.cve = cve;
  const affected = typeof entry.affectedVersions === "string" ? entry.affectedVersions : undefined;
  if (affected !== undefined) advisory.affectedVersions = affected;
  const link = httpsOnly(entry.link);
  if (link !== undefined) advisory.link = link;
  const reportedAt = typeof entry.reportedAt === "string" ? entry.reportedAt : undefined;
  if (reportedAt !== undefined) advisory.reportedAt = reportedAt;
  return advisory;
}

function normalizeAdvisories(value: unknown): ComposerAdvisory[] {
  const result: ComposerAdvisory[] = [];
  const push = (entry: unknown, fallbackPackage: string | undefined): void => {
    if (!isRecord(entry)) return;
    const packageName =
      typeof entry.packageName === "string" ? entry.packageName : fallbackPackage ?? "unknown package";
    const advisory = normalizeAdvisoryEntry(entry, packageName);
    if (advisory) result.push(advisory);
  };

  if (Array.isArray(value)) {
    for (const entry of value) push(entry, undefined);
    return result;
  }
  if (isRecord(value)) {
    for (const [packageName, entries] of Object.entries(value)) {
      if (Array.isArray(entries)) {
        for (const entry of entries) push(entry, packageName);
      } else {
        push(entries, packageName);
      }
    }
  }
  return result;
}

function dedupeAdvisories(advisories: ComposerAdvisory[]): ComposerAdvisory[] {
  const seen = new Set<string>();
  return advisories.filter(advisory => {
    const key = `${advisory.packageName}\u0000${advisory.advisoryId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeAbandoned(value: unknown): ComposerAbandoned[] {
  if (!isRecord(value)) return [];
  const result: ComposerAbandoned[] = [];
  for (const [packageName, entry] of Object.entries(value)) {
    if (typeof entry === "string" && entry.length > 0) {
      result.push({ packageName, replacement: entry });
    } else {
      result.push({ packageName });
    }
  }
  return result;
}

function payloadCandidates(text: string): string[] {
  const trimmed = text.trim();
  const payloads: string[] = [];
  if (trimmed.startsWith("{")) payloads.push(trimmed);

  const end = trimmed.lastIndexOf("}");
  if (end === -1) return payloads;

  // Collect every slice that starts at a "{" and ends at the last "}": the
  // outermost object that parses is the audit payload, regardless of banners
  // and warnings printed around it.
  for (let index = 0; index < trimmed.length; index += 1) {
    if (trimmed[index] !== "{") continue;
    const slice = trimmed.slice(index, end + 1);
    if (payloads.includes(slice)) continue;
    try {
      JSON.parse(slice);
      payloads.push(slice);
    } catch {
      // Not a complete object from this offset; keep scanning.
    }
  }
  return payloads;
}

export interface ParsedAuditOutput {
  ok: boolean;
  advisories: ComposerAdvisory[];
  abandoned: ComposerAbandoned[];
  reason?: string;
}

/**
 * Parse `composer audit --format=json` output from stdout only.
 *
 * Composer also exits non-zero when advisories are found, so the exit code is
 * never used to decide whether the JSON is meaningful.
 */
export function parseAuditOutput(stdout: string): ParsedAuditOutput {
  if (stdout.trim().length === 0) {
    return { ok: false, advisories: [], abandoned: [], reason: "Composer produced no output." };
  }

  for (const payload of payloadCandidates(stdout)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      continue;
    }
    if (!isRecord(parsed)) continue;
    if (!("advisories" in parsed) && !("abandoned" in parsed)) continue;
    return {
      ok: true,
      advisories: dedupeAdvisories(normalizeAdvisories(parsed.advisories)),
      abandoned: normalizeAbandoned(parsed.abandoned)
    };
  }

  return {
    ok: false,
    advisories: [],
    abandoned: [],
    reason: "Composer output did not contain an audit JSON object."
  };
}

/** Collapse Composer's boxed stderr output into one actionable line. */
function summarizeOutput(stdout: string, stderr: string): string | undefined {
  const text = `${stderr}\n${stdout}`
    .replace(/\u001b\[[0-9;]*m/g, "")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line.length > 0 && !/^[-=\s]+$/.test(line))
    .join(" ");
  if (text.length === 0) return undefined;
  return text.length > 300 ? `${text.slice(0, 300)}...` : text;
}

export async function auditDependencies(
  lockDir: string,
  settings: ComposerSettings,
  environment: ComposerEnvironment,
  runner: ProcessRunner,
  exists: (target: string) => Promise<boolean>
): Promise<ComposerAuditOutcome> {
  const attempts: string[] = [];
  const candidates = await buildComposerCandidates(settings, environment, exists);

  for (const candidate of candidates) {
    const runOnce = async (mode: "full" | "minimal") => {
      const args = [...candidate.prefixArgs, ...auditArguments(lockDir, mode)];
      return runner.run(candidate.command, args, {
        cwd: lockDir,
        timeoutMs: settings.timeoutMs
      });
    };

    try {
      let result = await runOnce("full");
      let parsed = parseAuditOutput(result.stdout);

      const unknownOption = /(option|argument)\s+.*(does not exist|not defined)|unknown option|unrecognized option/i.test(
        `${result.stderr}\n${result.stdout}`
      );
      if ((!parsed.ok || result.code !== 0) && unknownOption) {
        attempts.push(`${candidate.display}: retried without version-specific flags`);
        result = await runOnce("minimal");
        parsed = parseAuditOutput(result.stdout);
      }

      if (result.timedOut) {
        attempts.push(`${candidate.display}: timed out`);
        return {
          status: "failed",
          advisories: [],
          abandoned: [],
          lockDir,
          attempts,
          message: `composer audit timed out in ${lockDir}.`
        };
      }

      if (parsed.ok) {
        attempts.push(`${candidate.display}: exit ${result.code}`);
        return {
          status: "ok",
          advisories: parsed.advisories,
          abandoned: parsed.abandoned,
          lockDir,
          attempts
        };
      }

      const detail = summarizeOutput(result.stdout, result.stderr);
      attempts.push(`${candidate.display}: exit ${result.code}, no audit JSON`);
      return {
        status: "unparsed",
        advisories: [],
        abandoned: [],
        lockDir,
        attempts,
        message: `Composer exited with status ${result.code} and its output could not be read as audit JSON.${detail ? ` Composer said: ${detail}` : ""}`,
        raw: detail ?? "No output."
      };
    } catch (error) {
      if (isSpawnFailure(error)) {
        attempts.push(`${candidate.display}: ${error.code}`);
        if (SAFE_TO_RETRY.has(error.code)) continue;
        return {
          status: "failed",
          advisories: [],
          abandoned: [],
          lockDir,
          attempts,
          message: `Composer could not be started (${error.code}).`
        };
      }
      attempts.push(`${candidate.display}: unexpected error`);
    }
  }

  return {
    status: "not-found",
    advisories: [],
    abandoned: [],
    lockDir,
    attempts,
    message:
      "Composer could not be launched. On Windows a composer.bat shim cannot be started without a shell; configure phpSecurityGuard.composerPharPath or composerPath."
  };
}
