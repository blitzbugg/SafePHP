import * as path from "node:path";
import type {
  Finding,
  ObservationRef,
  ScanIssue,
  ScanResult,
  Severity
} from "../types";
import { advisoryData, advisoryDataErrors } from "./advisories";
import { assessVersion, fixedVersionsByBranch, formatVersion, isEndOfLifeBranch } from "./version";
import { classifyFile, walkWorkspace, type ScanFs } from "./walk";
import { parseDockerfile, type ImageReference } from "./dockerfile";
import { parseCompose } from "./compose";
import {
  detectIniKind,
  isDisabledValue,
  isEnabledValue,
  isUnlimitedMemory,
  parseIni,
  parseIniSize,
  type IniDirective,
  type IniKind
} from "./ini";
import { parseComposerJson } from "./composer-json";
import { probePhpCli, type PhpCliProbe } from "./php-cli";
import { auditDependencies, type ComposerAdvisory, type ComposerAuditOutcome } from "./composer";
import { inspectSource } from "./source-rules";
import type { ProcessRunner } from "./process";

const MAX_LOCKS = 5;
const MAX_REFERENCE = 300;

export interface ScanSettings {
  maxFiles: number;
  maxFileBytes: number;
  sourceHeuristics: boolean;
  composerAudit: boolean;
  includeVendor: boolean;
  phpPath?: string;
  composerPath?: string;
  composerPharPath?: string;
  phpTimeoutMs: number;
  composerTimeoutMs: number;
}

export interface ScanDeps {
  fs: ScanFs;
  runner: ProcessRunner;
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
}

export interface ScanRuntime {
  isCancellationRequested: boolean;
}

export interface ScanOptions {
  /** False in an untrusted workspace: no external process is started. */
  allowExecution: boolean;
  runtime?: ScanRuntime;
  onProgress?: (message: string) => void;
}

interface CollectedImage {
  image: ImageReference;
  file: string;
  kind: "dockerfile" | "compose-image";
}

interface CollectedIni {
  file: string;
  kind: IniKind;
  directives: IniDirective[];
}

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function relativePath(root: string, file: string): string {
  const rel = toPosix(path.relative(root, file));
  return rel.length > 0 ? rel : path.basename(file);
}

function clampText(value: string): string {
  const trimmed = value.trim();
  return trimmed.length > MAX_REFERENCE ? `${trimmed.slice(0, MAX_REFERENCE)}...` : trimmed;
}

function observationFor(
  kind: ObservationRef["kind"],
  scope: ObservationRef["scope"],
  resolution: ObservationRef["resolution"],
  raw: string,
  extra: { file?: string; line?: number; sapi?: string }
): ObservationRef {
  const observation: ObservationRef = { kind, scope, resolution, raw: clampText(raw) };
  if (extra.file !== undefined) observation.file = extra.file;
  if (extra.line !== undefined) observation.line = extra.line;
  if (extra.sapi !== undefined) observation.sapi = extra.sapi;
  return observation;
}

function referencesFor(advisoryIds: string[]): string[] {
  const references = new Set<string>();
  for (const id of advisoryIds) {
    const advisory = advisoryData.advisories.find(entry => entry.id === id);
    for (const reference of advisory?.references ?? []) references.add(reference);
  }
  return [...references];
}

function recommendationFor(advisoryIds: string[], fallback: string): string {
  const recommendations = advisoryData.advisories
    .filter(advisory => advisoryIds.includes(advisory.id))
    .map(advisory => `${advisory.id}: ${advisory.recommendation}`);
  return recommendations.length > 0 ? recommendations.join(" ") : fallback;
}

const FALLBACK_REFERENCE = "https://www.php.net/archive/2026.php";

/** Build findings for one declared container image. */
function findingsForImage(
  item: CollectedImage,
  root: string,
  observedBranches: Set<string>
): Finding[] {
  const { image, file, kind } = item;
  const rel = relativePath(root, file);
  const observation = observationFor(kind, "container-declared", image.resolution, image.raw, {
    file,
    line: image.line
  });
  const location = `${rel}:${image.line}`;

  if (image.version) {
    observedBranches.add(`${image.version.major}.${image.version.minor}`);
  }

  if (image.resolution === "unresolved" || image.resolution === "major-floating") {
    return [
      {
        id: `IMAGE-UNRESOLVED:${rel}:${image.line}`,
        title:
          image.resolution === "major-floating"
            ? "PHP image tag pins only a major version"
            : "PHP image version could not be determined",
        severity: "info",
        confidence: "high",
        proof: "none",
        kind: "unassessed",
        category: "runtime",
        message: `${image.reason ?? "The image reference could not be interpreted."} This is a declaration in ${location}; it is not evidence of the running image.`,
        evidence: clampText(image.raw),
        file,
        line: image.line,
        recommendation:
          "Pin an exact PHP version tag or resolve the tag to an image digest, then compare that version with the advisory.",
        references: [FALLBACK_REFERENCE],
        advisoryIds: [],
        observation
      }
    ];
  }

  if (image.resolution === "branch-floating") {
    const version = image.version;
    const branch = version ? `${version.major}.${version.minor}` : "";
    const fixed = fixedVersionsByBranch(advisoryData)[branch];
    const eol = version ? isEndOfLifeBranch(version) : false;
    const message = [
      image.reason ?? `The tag floats within the ${branch} branch.`,
      `The tag resolves to the newest ${branch}.x at pull time; this scanner cannot tell which patch that is.`,
      eol
        ? "This branch no longer receives upstream fixes; only a vendor backport can address the advisories."
        : fixed
          ? `If the tag currently resolves to ${fixed} or later, the bundled advisories are addressed.`
          : "No fixed release is listed for this branch in the bundled data.",
      "This is a declaration, not the running image."
    ].join(" ");

    return [
      {
        id: `IMAGE-FLOATING:${rel}:${image.line}`,
        title: eol
          ? "PHP image floats on an end-of-life branch"
          : `PHP image tag floats within the ${branch} branch`,
        severity: eol ? "high" : "low",
        confidence: "high",
        proof: eol ? "advisory" : "none",
        kind: "unassessed",
        category: "runtime",
        message,
        evidence: clampText(image.raw),
        file,
        line: image.line,
        recommendation:
          "Pin the exact PHP version and digest in the image reference, rebuild, and verify the resolved digest in your registry.",
        references: eol ? referencesFor(["CVE-2026-109618"]) : [FALLBACK_REFERENCE],
        advisoryIds: eol ? ["CVE-2026-109618", "CVE-2026-109619"] : [],
        observation
      }
    ];
  }

  if (!image.version) {
    return [
      {
        id: `IMAGE-UNPARSED:${rel}:${image.line}`,
        title: "PHP image version could not be compared",
        severity: "info",
        confidence: "high",
        proof: "none",
        kind: "unassessed",
        category: "runtime",
        message: `The image tag in ${location} could not be parsed, so no advisory comparison was made.`,
        evidence: clampText(image.raw),
        file,
        line: image.line,
        recommendation: "Pin an exact PHP version tag and re-run the scan.",
        references: [FALLBACK_REFERENCE],
        advisoryIds: [],
        observation
      }
    ];
  }

  const rendered = formatVersion(image.version);
  const assessed = assessVersion(rendered, advisoryData);
  const notes = assessed.notes.length > 0 ? ` ${assessed.notes.join(" ")}` : "";
  const declared = "This is a declaration in the image configuration, not proof of the running container.";

  switch (assessed.verdict) {
    case "vulnerable": {
      const ids = assessed.vulnerableAdvisories;
      return [
        {
          id: `IMAGE-VULNERABLE:${rel}:${image.line}`,
          title: "PHP image declares a version affected by a critical advisory",
          severity: "critical",
          confidence: "high",
          proof: "advisory",
          kind: "vulnerability",
          category: "runtime",
          message: `The image tag declares PHP ${rendered}. The bundled advisory data lists ${ids.join(", ")} as affecting the ${assessed.branch} branch below ${assessed.fixedIn ?? "the fixed release"}.${notes} ${declared}`,
          evidence: clampText(image.raw),
          file,
          line: image.line,
          recommendation: `${recommendationFor(ids, "Update to a fixed PHP release.")} Rebuild and redeploy from the fixed base image, then verify the running digest.`,
          references: referencesFor(ids),
          advisoryIds: ids,
          observation
        }
      ];
    }
    case "fixed":
      return [
        {
          id: `IMAGE-FIXED:${rel}:${image.line}`,
          title: "PHP image declares a release at or above the fixed version",
          severity: "info",
          confidence: "high",
          proof: "advisory",
          kind: "unassessed",
          category: "runtime",
          message: `The image tag declares PHP ${rendered}, which is at or above the upstream fixed release for the ${assessed.branch} branch.${notes} ${declared} Confirm the image digest actually deployed.`,
          evidence: clampText(image.raw),
          file,
          line: image.line,
          recommendation:
            "Keep the base image and its digest pinned, and re-check the advisory feed for newer releases.",
          references: referencesFor(assessed.fixedAdvisories),
          advisoryIds: assessed.fixedAdvisories,
          observation
        }
      ];
    case "eol-vendor-dependent":
      return [
        {
          id: `IMAGE-EOL:${rel}:${image.line}`,
          title: "PHP image uses an end-of-life branch affected by the advisories",
          severity: "high",
          confidence: "medium",
          proof: "advisory",
          kind: "vulnerability",
          category: "runtime",
          message: `The image tag declares PHP ${rendered}, which is on an end-of-life branch, and the advisories list PHP 8.1 and older as affected.${notes} ${declared}`,
          evidence: clampText(image.raw),
          file,
          line: image.line,
          recommendation:
            "Upgrade to a supported branch, or apply your distribution or LTS vendor backport and verify it with that vendor's advisory. Do not infer safety from the upstream version number alone.",
          references: referencesFor(["CVE-2026-109618", "CVE-2026-109619"]),
          advisoryIds: ["CVE-2026-109618", "CVE-2026-109619"],
          observation
        }
      ];
    case "uncovered":
      return [
        {
          id: `IMAGE-UNCOVERED:${rel}:${image.line}`,
          title: "PHP image version is not covered by the bundled advisory data",
          severity: "info",
          confidence: "low",
          proof: "none",
          kind: "unassessed",
          category: "runtime",
          message: `The image tag declares PHP ${rendered}, and the bundled advisory data has no affected-range entry for the ${assessed.branch} branch. This version was not assessed and must not be read as safe.${notes}`,
          evidence: clampText(image.raw),
          file,
          line: image.line,
          recommendation:
            "Check the PHP project and your vendor for advisories covering this branch, and update the bundled advisory data when a fixed release is published.",
          references: [FALLBACK_REFERENCE],
          advisoryIds: [],
          observation
        }
      ];
    case "unparsed":
    default:
      return [
        {
          id: `IMAGE-UNPARSED:${rel}:${image.line}`,
          title: "PHP image version could not be compared",
          severity: "info",
          confidence: "high",
          proof: "none",
          kind: "unassessed",
          category: "runtime",
          message: `The image tag in ${location} could not be parsed, so no advisory comparison was made.`,
          evidence: clampText(image.raw),
          file,
          line: image.line,
          recommendation: "Pin an exact PHP version tag and re-run the scan.",
          references: [FALLBACK_REFERENCE],
          advisoryIds: [],
          observation
        }
      ];
  }
}

function findingsForPhpCli(probe: PhpCliProbe): Finding[] {
  const base = {
    category: "runtime" as const,
    proof: "none" as const,
    references: [FALLBACK_REFERENCE]
  };

  if (probe.status === "not-found") {
    return [
      {
        ...base,
        id: "PHP-CLI-NOT-FOUND",
        title: "PHP CLI not available",
        severity: "info",
        confidence: "high",
        kind: "unassessed",
        message: `The "${probe.executable}" executable was not found, so no local PHP version was observed.`,
        evidence: `Attempted to run ${probe.executable} -v.`,
        recommendation:
          "If PHP runs in a container or on a server, inspect that environment separately. This extension does not scan remote hosts.",
        advisoryIds: [],
        observation: observationFor("php-cli", "local-dev", "unresolved", `${probe.executable} -v`, {})
      }
    ];
  }

  if (probe.status === "failed" || probe.status === "unparsed") {
    return [
      {
        ...base,
        id: probe.status === "failed" ? "PHP-CLI-FAILED" : "PHP-CLI-UNPARSED",
        title: probe.status === "failed" ? "PHP CLI could not be run" : "PHP CLI version could not be read",
        severity: "medium",
        confidence: "high",
        kind: "unassessed",
        message: `${probe.message ?? "The PHP CLI probe did not produce a usable result."} No version comparison was made.`,
        evidence: clampText(probe.raw ?? `${probe.executable} -v`),
        recommendation:
          "Check the configured phpSecurityGuard.phpPath, or confirm PHP is installed and on the extension host PATH.",
        advisoryIds: [],
        observation: observationFor("php-cli", "local-dev", "unresolved", probe.raw ?? probe.executable, {})
      }
    ];
  }

  if (!probe.version) {
    return [];
  }

  const rendered = formatVersion(probe.version);
  const assessed = assessVersion(rendered, advisoryData);
  const sapi = probe.sapi ?? "unknown";
  const notes = assessed.notes.length > 0 ? ` ${assessed.notes.join(" ")}` : "";
  const scopeNote =
    sapi === "cli"
      ? "This is the development CLI reported by the extension host; it does not establish which version serves the application."
      : `The binary reports the "${sapi}" SAPI, which may be closer to a serving runtime, but it is still only this machine's PHP.`;

  const observation = observationFor("php-cli", "local-dev", "exact", probe.raw ?? rendered, { sapi });

  switch (assessed.verdict) {
    case "vulnerable": {
      const ids = assessed.vulnerableAdvisories;
      return [
        {
          id: "PHP-CLI-VULNERABLE",
          title: "Local PHP CLI is below the upstream fixed release",
          severity: "high",
          confidence: "medium",
          proof: "advisory",
          kind: "vulnerability",
          category: "runtime",
          message: `PHP ${rendered} was reported by ${probe.executable}. The bundled advisory data lists ${ids.join(", ")} as affecting the ${assessed.branch} branch below ${assessed.fixedIn ?? "the fixed release"}.${notes} ${scopeNote}`,
          evidence: `Output of ${probe.executable} -v (${sapi}).`,
          recommendation: `${recommendationFor(ids, "Update PHP to a fixed release.")} ${scopeNote}`,
          references: referencesFor(ids),
          advisoryIds: ids,
          observation
        }
      ];
    }
    case "eol-vendor-dependent":
      return [
        {
          id: "PHP-CLI-EOL",
          title: "Local PHP CLI is on an end-of-life branch",
          severity: "medium",
          confidence: "low",
          proof: "advisory",
          kind: "vulnerability",
          category: "runtime",
          message: `PHP ${rendered} is on an end-of-life branch, and the bundled advisory data lists PHP 8.1 and older as affected.${notes} ${scopeNote}`,
          evidence: `Output of ${probe.executable} -v (${sapi}).`,
          recommendation:
            "Check the operating-system or vendor advisory for backported fixes, and plan a move to a supported PHP release. Do not infer safety or vulnerability from the upstream version alone.",
          references: referencesFor(["CVE-2026-109618", "CVE-2026-109619"]),
          advisoryIds: ["CVE-2026-109618", "CVE-2026-109619"],
          observation
        }
      ];
    case "fixed":
      return [
        {
          id: "PHP-CLI-FIXED",
          title: "Local PHP CLI is at or above the fixed release",
          severity: "info",
          confidence: "high",
          proof: "advisory",
          kind: "unassessed",
          category: "runtime",
          message: `PHP ${rendered} is at or above the upstream fixed release for the ${assessed.branch} branch.${notes} ${scopeNote}`,
          evidence: `Output of ${probe.executable} -v (${sapi}).`,
          recommendation:
            "Keep this installation patched and confirm the version that actually serves web requests.",
          references: referencesFor(assessed.fixedAdvisories),
          advisoryIds: assessed.fixedAdvisories,
          observation
        }
      ];
    case "uncovered":
    default:
      return [
        {
          id: "PHP-CLI-UNCOVERED",
          title: "Local PHP CLI branch is not covered by the bundled advisory data",
          severity: "info",
          confidence: "low",
          proof: "none",
          kind: "unassessed",
          category: "runtime",
          message: `PHP ${rendered} was reported, and the bundled advisory data has no affected-range entry for the ${assessed.branch} branch. This version was not assessed and must not be read as safe.${notes}`,
          evidence: `Output of ${probe.executable} -v (${sapi}).`,
          recommendation:
            "Check the PHP project and vendor advisories for this branch, and update the bundled advisory data when releases are published.",
          references: [FALLBACK_REFERENCE],
          advisoryIds: [],
          observation
        }
      ];
  }
}

function findPackageLine(content: string, packageName: string): number | undefined {
  const needle = `"name": "${packageName}"`;
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const normalized = lines[index].replace(/\s+/g, " ").trim();
    if (normalized.includes(needle)) return index + 1;
  }
  return undefined;
}

function findingsForComposerAdvisory(
  advisory: ComposerAdvisory,
  lockFile: string,
  root: string,
  lockContent: string
): Finding {
  const rel = relativePath(root, lockFile);
  const line = findPackageLine(lockContent, advisory.packageName);
  const detail: Record<string, unknown> = {
    packageName: advisory.packageName,
    advisoryId: advisory.advisoryId
  };
  if (advisory.cve !== undefined) detail.cve = advisory.cve;
  if (advisory.affectedVersions !== undefined) detail.affectedVersions = advisory.affectedVersions;
  if (advisory.reportedAt !== undefined) detail.reportedAt = advisory.reportedAt;
  if (advisory.sources.length > 0) detail.sources = advisory.sources;

  const severityNote = advisory.severityPublished
    ? ""
    : " Composer did not publish a severity for this advisory; the level shown is a placeholder, not an assigned CVSS score.";

  return {
    id: `COMPOSER:${advisory.packageName}:${advisory.advisoryId}`,
    title: `Vulnerable Composer dependency: ${advisory.packageName}`,
    severity: advisory.severity,
    confidence: advisory.severityPublished ? "high" : "medium",
    proof: "advisory",
    kind: "vulnerability",
    category: "dependency",
    message: `${advisory.advisoryId}${advisory.cve ? ` (${advisory.cve})` : ""} affects ${advisory.packageName}${advisory.affectedVersions ? ` (affected versions: ${advisory.affectedVersions})` : ""}. ${advisory.title}.${severityNote}`,
    evidence: `${rel}${line ? `:${line}` : ""}: ${JSON.stringify(detail)}`,
    file: lockFile,
    ...(line !== undefined ? { line } : {}),
    recommendation:
      "Update the package to a version outside the affected range and re-run composer audit. This finding covers Composer packages only; it says nothing about the PHP core runtime.",
    references: advisory.link ? [advisory.link] : ["https://getcomposer.org/doc/03-cli.md#audit"],
    advisoryIds: [advisory.advisoryId],
    observation: observationFor("composer-audit", "declared-constraint", "exact", advisory.advisoryId, {
      file: lockFile
    })
  };
}

function findingsForComposer(
  outcome: ComposerAuditOutcome,
  lockFile: string,
  root: string,
  lockContent: string
): Finding[] {
  const rel = relativePath(root, lockFile);
  const findings: Finding[] = [];

  if (outcome.status === "ok") {
    for (const advisory of outcome.advisories) {
      findings.push(findingsForComposerAdvisory(advisory, lockFile, root, lockContent));
    }
    for (const abandoned of outcome.abandoned) {
      findings.push({
        id: `COMPOSER-ABANDONED:${abandoned.packageName}`,
        title: `Abandoned Composer dependency: ${abandoned.packageName}`,
        severity: "low",
        confidence: "high",
        proof: "advisory",
        kind: "unassessed",
        category: "dependency",
        message: `${abandoned.packageName} is marked abandoned by Composer${abandoned.replacement ? `; suggested replacement: ${abandoned.replacement}` : ""}.`,
        evidence: `${rel}: abandoned package reported by composer audit.`,
        file: lockFile,
        recommendation:
          "Plan a migration to a maintained package. Abandoned packages stop receiving fixes, including security fixes.",
        references: ["https://getcomposer.org/doc/03-cli.md#audit"],
        advisoryIds: []
      });
    }
    if (outcome.advisories.length === 0) {
      findings.push({
        id: `COMPOSER-NO-ADVISORIES:${rel}`,
        title: "Composer audit reported no package advisories",
        severity: "info",
        confidence: "high",
        proof: "advisory",
        kind: "unassessed",
        category: "dependency",
        message: `Composer returned no advisories for ${rel}. This does not assess PHP core runtime vulnerabilities or prove the deployed application is secure.`,
        evidence: `${rel}: ${outcome.attempts.join("; ") || "audit completed"}.`,
        file: lockFile,
        recommendation:
          "Treat this as one input only. Runtime patching, configuration and code review are separate checks.",
        references: ["https://getcomposer.org/doc/03-cli.md#audit"],
        advisoryIds: []
      });
    }
    return findings;
  }

  if (outcome.status === "not-found") {
    return [
      {
        id: `COMPOSER-NOT-LAUNCHED:${rel}`,
        title: "Composer audit could not be started",
        severity: "info",
        confidence: "high",
        proof: "none",
        kind: "unassessed",
        category: "dependency",
        message: `${outcome.message ?? "Composer could not be launched."} Attempts: ${outcome.attempts.join("; ") || "none"}.`,
        evidence: clampText(outcome.message ?? "No Composer executable responded."),
        file: lockFile,
        recommendation:
          "Run `composer audit` manually, or set phpSecurityGuard.composerPath or composerPharPath so the extension can launch it without a shell.",
        references: ["https://getcomposer.org/doc/03-cli.md#audit"],
        advisoryIds: []
      }
    ];
  }

  return [
    {
      id: `COMPOSER-AUDIT-${outcome.status.toUpperCase()}:${rel}`,
      title:
        outcome.status === "unparsed"
          ? "Composer audit returned output this scanner could not read"
          : "Composer audit did not complete",
      severity: "medium",
      confidence: "high",
      proof: "none",
      kind: "unassessed",
      category: "dependency",
      message: `${outcome.message ?? "Composer audit failed."} Attempts: ${outcome.attempts.join("; ") || "none"}.`,
      evidence: clampText(outcome.raw ?? outcome.message ?? "No output."),
      file: lockFile,
      recommendation:
        "Run `composer audit --format=json` manually in the project root and review the result. Dependency auditing is separate from PHP core checks.",
      references: ["https://getcomposer.org/doc/03-cli.md#audit"],
      advisoryIds: []
    }
  ];
}

interface Occurrence {
  name: string;
  value: string;
  file: string;
  line: number;
  kind: IniKind;
}

function preRequest(occurrences: Occurrence[], name: string): Occurrence[] {
  return occurrences.filter(
    occurrence => occurrence.name.toLowerCase() === name && occurrence.kind !== "user-ini"
  );
}

function evaluateConfiguration(
  iniFiles: CollectedIni[],
  observedBranches: Set<string>,
  root: string
): Finding[] {
  const findings: Finding[] = [];
  const occurrences: Occurrence[] = [];
  for (const collected of iniFiles) {
    for (const directive of collected.directives) {
      if (!directive.active) continue;
      occurrences.push({
        name: directive.name,
        value: directive.value,
        file: collected.file,
        line: directive.line,
        kind: collected.kind
      });
    }
  }

  const uploadProgress = "session.upload_progress.enabled";
  const allUpload = occurrences.filter(occurrence => occurrence.name.toLowerCase() === uploadProgress);
  const enabledUpload = preRequest(allUpload, uploadProgress).filter(occurrence =>
    isEnabledValue(occurrence.value)
  );
  const disabledUpload = preRequest(allUpload, uploadProgress).filter(occurrence =>
    isDisabledValue(occurrence.value)
  );
  const userIniDisabled = allUpload.filter(
    occurrence => occurrence.kind === "user-ini" && isDisabledValue(occurrence.value)
  );
  const advisoryIds = ["CVE-2026-109619", "CVE-2026-115560"];
  const fallbackFile = (iniFiles.find(entry => entry.kind !== "user-ini") ?? iniFiles[0])?.file;
  const fallbackLocation = fallbackFile ? { file: fallbackFile, line: 1 } : {};
  const locationKey = (occurrence: { file: string } | undefined): string =>
    occurrence
      ? relativePath(root, occurrence.file)
      : fallbackFile
        ? relativePath(root, fallbackFile)
        : "workspace";

  if (enabledUpload.length > 0) {
    const first = enabledUpload[0];
    findings.push({
      id: `CONFIG-UPLOAD-PROGRESS-ENABLED:${relativePath(root, first.file)}:${first.line}`,
      title: "Session upload progress is enabled",
      severity: "medium",
      confidence: "high",
      proof: "advisory",
      kind: "mitigation",
      category: "configuration",
      message: `${uploadProgress} is set to "${first.value}" in ${relativePath(root, first.file)}. This directive is the documented interim mitigation target for CVE-2026-109619 and CVE-2026-115560. Whether this file is the effective configuration for the web runtime is not established by reading it.`,
      evidence: clampText(`${first.name} = ${first.value}`),
      file: first.file,
      line: first.line,
      recommendation:
        "Set session.upload_progress.enabled=0 in php.ini, an FPM pool or an Apache configuration that takes effect before request parsing, then restart every worker. Do not rely on ini_set() or .user.ini.",
      references: referencesFor(advisoryIds),
      advisoryIds
    });
  } else if (disabledUpload.length === 0) {
    const first = allUpload[0];
    findings.push({
      id: `CONFIG-UPLOAD-PROGRESS-NOT-DISABLED:${locationKey(first)}`,
      title: "Session upload progress is not explicitly disabled",
      severity: "medium",
      confidence: "medium",
      proof: "advisory",
      kind: "mitigation",
      category: "configuration",
      message: [
        `PHP's documented default for ${uploadProgress} is On.`,
        "No active pre-request directive disabling it was found in the inspected configuration files, so the interim mitigation for CVE-2026-109619 and CVE-2026-115560 is not demonstrated.",
        userIniDisabled.length > 0
          ? "A .user.ini entry disables it, but per-request configuration does not apply before request parsing."
          : "",
        "The effective value may be set outside this workspace."
      ]
        .filter(text => text.length > 0)
        .join(" "),
      evidence: first
        ? clampText(`${first.name} = ${first.value}`)
        : clampText(`No ${uploadProgress} directive in inspected files.`),
      ...(first ? { file: first.file, line: first.line } : fallbackLocation),
      recommendation:
        "Confirm the effective setting on the web runtime and set it to 0 in a pre-request context (php.ini, FPM pool or Apache), then restart every worker.",
      references: referencesFor(advisoryIds),
      advisoryIds
    });
  }

  const memory = preRequest(occurrences, "memory_limit");
  const unlimited = memory.some(occurrence => isUnlimitedMemory(occurrence.value));
  if (!unlimited) {
    const first = memory[0];
    findings.push({
      id: `CONFIG-MEMORY-LIMIT:${locationKey(first)}`,
      title: "Interim OOM mitigation for CVE-2026-109618 is not observed",
      severity: "low",
      confidence: "medium",
      proof: "advisory",
      kind: "mitigation",
      category: "configuration",
      message: first
        ? `memory_limit is set to "${first.value}" in ${relativePath(root, first.file)}. The documented interim control for CVE-2026-109618 is memory_limit=-1 in a context applications cannot override.`
        : "No active memory_limit=-1 directive was found in the inspected files. PHP's documented default is 128M, so the interim control for CVE-2026-109618 is not demonstrated.",
      evidence: first ? clampText(`${first.name} = ${first.value}`) : "No memory_limit directive in inspected files.",
      ...(first ? { file: first.file, line: first.line } : fallbackLocation),
      recommendation:
        "Patching is the only complete fix. If you cannot patch immediately, set memory_limit=-1 via php_admin_value and lower post_max_size, then verify no pool or application setting restores a finite limit.",
      references: referencesFor(["CVE-2026-109618"]),
      advisoryIds: ["CVE-2026-109618"]
    });
  }

  const postMax = preRequest(occurrences, "post_max_size")[0];
  const postMaxBytes = postMax ? parseIniSize(postMax.value) : 8 * 1024 * 1024;
  if (postMaxBytes !== undefined && postMaxBytes > 32 * 1024 * 1024) {
    findings.push({
      id: `CONFIG-POST-MAX-SIZE:${locationKey(postMax)}`,
      title: "post_max_size is above the suggested interim limit",
      severity: "low",
      confidence: "medium",
      proof: "advisory",
      kind: "mitigation",
      category: "configuration",
      message: `post_max_size is ${postMax?.value ?? "8M"}. The advisory suggests 8M for applications without uploads and 32M where uploads are required, as an interim control for CVE-2026-109618.`,
      evidence: postMax ? clampText(`${postMax.name} = ${postMax.value}`) : "PHP default post_max_size (8M).",
      ...(postMax ? { file: postMax.file, line: postMax.line } : fallbackLocation),
      recommendation:
        "Lower post_max_size to the smallest value the application needs and keep upload_max_filesize below it. An update is still the only complete fix.",
      references: referencesFor(["CVE-2026-109618"]),
      advisoryIds: ["CVE-2026-109618"]
    });
  }

  if (observedBranches.has("8.5")) {
    const backtraces = preRequest(occurrences, "fatal_error_backtraces");
    const disabled = backtraces.some(occurrence => isDisabledValue(occurrence.value));
    if (!disabled) {
      const first = backtraces[0];
      findings.push({
        id: `CONFIG-FATAL-ERROR-BACKTRACES:${locationKey(first)}`,
        title: "PHP 8.5 interim mitigation fatal_error_backtraces=0 is not observed",
        severity: "low",
        confidence: "medium",
        proof: "advisory",
        kind: "mitigation",
        category: "configuration",
        message: first
          ? `fatal_error_backtraces is set to "${first.value}" in ${relativePath(root, first.file)}. The advisory suggests 0 on PHP 8.5 as an interim control for CVE-2026-109619.`
          : "A PHP 8.5 runtime was observed, but no active fatal_error_backtraces=0 directive was found. The default for this directive depends on the PHP build; verify it directly.",
        evidence: first
          ? clampText(`${first.name} = ${first.value}`)
          : "No fatal_error_backtraces directive in inspected files.",
        ...(first ? { file: first.file, line: first.line } : fallbackLocation),
        recommendation:
          "On PHP 8.5, set fatal_error_backtraces=0 and restart every worker. This blocks the confirmed fatal-backtrace path only, so updating remains necessary.",
        references: referencesFor(["CVE-2026-109619"]),
        advisoryIds: ["CVE-2026-109619"]
      });
    }
  }

  return findings;
}

function findingsForConstraint(
  constraint: { file: string; field: string; constraint: string; line?: number },
  root: string
): Finding {
  const rel = relativePath(root, constraint.file);
  const isPlatform = constraint.field === "config.platform.php";
  return {
    id: `COMPOSER-CONSTRAINT:${constraint.field}:${rel}`,
    title: isPlatform
      ? "composer.json pins a platform PHP version for dependency resolution"
      : "composer.json declares a PHP version constraint",
    severity: "info",
    confidence: "high",
    proof: "none",
    kind: "unassessed",
    category: "runtime",
    message: isPlatform
      ? `config.platform.php is "${constraint.constraint}" in ${rel}. Composer uses this to resolve dependencies; it is not the PHP runtime serving the application.`
      : `require.php is "${constraint.constraint}" in ${rel}. This is a dependency constraint, not the PHP runtime serving the application.`,
    evidence: clampText(`${constraint.field}: ${constraint.constraint}`),
    file: constraint.file,
    ...(constraint.line !== undefined ? { line: constraint.line } : {}),
    recommendation:
      "Check the version reported by the actual web runtime (PHP-FPM, Apache module, container image digest) rather than the Composer constraint.",
    references: [FALLBACK_REFERENCE],
    advisoryIds: [],
    observation: observationFor(
      "composer-constraint",
      "declared-constraint",
      "unresolved",
      `${constraint.field}=${constraint.constraint}`,
      { file: constraint.file, ...(constraint.line !== undefined ? { line: constraint.line } : {}) }
    )
  };
}

function sourceSeverity(ruleSeverity: Severity): Severity {
  const rank: Severity[] = ["critical", "high", "medium", "low", "info"];
  return rank.indexOf(ruleSeverity) < rank.indexOf("medium") ? "medium" : ruleSeverity;
}

/** Run the full local scan. All analysis is read-only. */
export async function scanWorkspace(
  root: string,
  settings: ScanSettings,
  deps: ScanDeps,
  options: ScanOptions
): Promise<ScanResult> {
  const findings: Finding[] = [];
  const issues: ScanIssue[] = [];
  const skipped: string[] = [];
  const images: CollectedImage[] = [];
  const iniFiles: CollectedIni[] = [];
  const lockFiles: Array<{ file: string; content: string }> = [];
  const observedBranches = new Set<string>();
  let checkedFiles = 0;
  let cancelled = false;

  if (advisoryDataErrors.length > 0) {
    findings.push({
      id: "ADVISORY-DATA-INVALID",
      title: "Bundled advisory data failed validation",
      severity: "medium",
      confidence: "high",
      proof: "none",
      kind: "scan-issue",
      category: "scan",
      message: `The bundled advisory data has ${advisoryDataErrors.length} problem(s), so version comparisons may be incomplete: ${advisoryDataErrors.slice(0, 5).join(" ")}`,
      evidence: clampText(advisoryDataErrors.join(" ")),
      recommendation:
        "Fix src/advisories/advisories.json before relying on any version finding. Invalid records are ignored rather than guessed.",
      references: [],
      advisoryIds: []
    });
  }

  const walk = await walkWorkspace(
    root,
    { maxFiles: settings.maxFiles, includeVendor: settings.includeVendor },
    deps.fs
  );
  issues.push(...walk.issues);

  if (walk.truncated) {
    findings.push({
      id: "SCAN-LIMIT",
      title: "Workspace scan reached its file limit",
      severity: "info",
      confidence: "high",
      proof: "none",
      kind: "scan-issue",
      category: "scan",
      message: `Only the first ${settings.maxFiles} matching files were analysed. Files beyond the limit were not assessed.`,
      evidence: "Configured phpSecurityGuard.maxFiles limit reached.",
      recommendation:
        "Increase phpSecurityGuard.maxFiles or scan a smaller workspace. Unscanned files were not assessed.",
      references: [],
      advisoryIds: []
    });
  }

  for (const file of walk.files) {
    if (options.runtime?.isCancellationRequested) {
      cancelled = true;
      break;
    }
    const kind = classifyFile(file);
    if (kind === "unknown") continue;
    if (kind === "composer-lock") {
      let lockContent = "";
      try {
        const read = await deps.fs.readHead(file, settings.maxFileBytes);
        if (!read.truncated) lockContent = read.content;
      } catch {
        // The audit can still run; only the per-package line numbers are lost.
      }
      lockFiles.push({ file, content: lockContent });
      continue;
    }

    let content: string;
    try {
      const read = await deps.fs.readHead(file, settings.maxFileBytes);
      if (read.truncated) {
        issues.push({
          code: "FILE_TOO_LARGE",
          message: `File exceeds phpSecurityGuard.maxFileBytes (${settings.maxFileBytes}) and was not analysed.`,
          file
        });
        continue;
      }
      content = read.content;
    } catch (error) {
      issues.push({
        code: "FILE_UNREADABLE",
        message: `File could not be read: ${error instanceof Error ? error.message : "unknown error"}.`,
        file
      });
      continue;
    }

    checkedFiles += 1;
    options.onProgress?.(relativePath(root, file));

    switch (kind) {
      case "dockerfile": {
        const parsed = parseDockerfile(content);
        for (const issue of parsed.issues) {
          issues.push({ code: "DOCKERFILE_PARSE", message: issue.message, file, line: issue.line });
        }
        for (const image of parsed.images) images.push({ image, file, kind: "dockerfile" });
        break;
      }
      case "compose": {
        const parsed = parseCompose(content);
        for (const image of parsed.images) images.push({ image, file, kind: "compose-image" });
        for (const note of parsed.notes) {
          issues.push({ code: "COMPOSE_PARSE", message: note, file });
        }
        break;
      }
      case "ini": {
        const iniKind = detectIniKind(file);
        if (!iniKind) break;
        const parsed = parseIni(content, iniKind);
        iniFiles.push({ file, kind: iniKind, directives: parsed.directives });
        issues.push(...parsed.issues.map(issue => ({ ...issue, file })));
        break;
      }
      case "composer-json": {
        const parsed = parseComposerJson(content, file);
        issues.push(...parsed.issues);
        for (const constraint of parsed.constraints) {
          findings.push(findingsForConstraint(constraint, root));
        }
        break;
      }
      case "php": {
        if (!settings.sourceHeuristics) break;
        for (const match of inspectSource(content)) {
          const rel = relativePath(root, file);
          findings.push({
            id: `${match.rule.id}:${rel}:${match.line}`,
            title: match.rule.title,
            severity: sourceSeverity(match.rule.severity),
            confidence: match.rule.confidence,
            proof: "none",
            kind: "heuristic",
            category: "source",
            message: `${match.rule.summary} This is a heuristic review candidate, not proof of a vulnerability.`,
            evidence: match.evidence,
            file,
            line: match.line,
            recommendation: `${match.rule.howToVerify} Why it matters: ${match.rule.why}`,
            references: match.rule.references,
            advisoryIds: []
          });
        }
        break;
      }
      default:
        break;
    }
  }

  for (const item of images) {
    findings.push(...findingsForImage(item, root, observedBranches));
  }

  if (options.allowExecution) {
    const probe = await probePhpCli(
      { executable: settings.phpPath, timeoutMs: settings.phpTimeoutMs },
      deps.runner
    );
    findings.push(...findingsForPhpCli(probe));
    if (probe.status === "ok" && probe.version) {
      observedBranches.add(`${probe.version.major}.${probe.version.minor}`);
    }
  } else {
    skipped.push(
      "PHP CLI probe and Composer audit were skipped because the workspace is not trusted. File-content checks still ran."
    );
  }

  if (iniFiles.length > 0) {
    findings.push(...evaluateConfiguration(iniFiles, observedBranches, root));
  } else {
    skipped.push(
      "Configuration checks were not run: no php.ini, conf.d, FPM pool, .user.ini or Apache configuration files were found."
    );
  }

  if (!settings.composerAudit) {
    skipped.push("Composer audit is disabled in settings.");
  } else if (options.allowExecution) {
    if (lockFiles.length === 0) {
      skipped.push("Composer audit was not run: no composer.lock was found in the workspace.");
    } else {
      if (lockFiles.length > MAX_LOCKS) {
        issues.push({
          code: "COMPOSER_LOCKS_LIMITED",
          message: `Only the first ${MAX_LOCKS} composer.lock files were audited; ${lockFiles.length - MAX_LOCKS} were skipped.`
        });
      }
      const exists = async (target: string): Promise<boolean> => {
        try {
          await deps.fs.stat(target);
          return true;
        } catch {
          return false;
        }
      };
      for (const lockFile of lockFiles.slice(0, MAX_LOCKS)) {
        if (options.runtime?.isCancellationRequested) {
          cancelled = true;
          break;
        }
        const outcome = await auditDependencies(
          path.dirname(lockFile.file),
          {
            phpPath: settings.phpPath,
            composerPath: settings.composerPath,
            composerPharPath: settings.composerPharPath,
            timeoutMs: settings.composerTimeoutMs
          },
          { platform: deps.platform, env: deps.env },
          deps.runner,
          exists
        );
        findings.push(...findingsForComposer(outcome, lockFile.file, root, lockFile.content));
      }
    }
  }

  const unique: Finding[] = [];
  const seen = new Set<string>();
  for (const finding of findings) {
    if (seen.has(finding.id)) continue;
    seen.add(finding.id);
    unique.push(finding);
  }

  return {
    findings: unique,
    issues,
    summary: {
      checkedFiles,
      truncated: walk.truncated,
      cancelled,
      advisoriesRetrievedAt: advisoryData.retrievedAt,
      skipped
    }
  };
}
