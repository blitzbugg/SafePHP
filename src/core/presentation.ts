import type { Finding, ScanResult, Severity } from "../types";

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byFile = (a.file ?? "").localeCompare(b.file ?? "");
    if (byFile !== 0) return byFile;
    const byLine = (a.line ?? 0) - (b.line ?? 0);
    if (byLine !== 0) return byLine;
    return a.title.localeCompare(b.title);
  });
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

export type DiagnosticLevel = "error" | "warning" | "information" | "hint";

/**
 * Heuristic findings are capped at "warning": a regex match must not render as
 * an error in the editor.
 */
export function diagnosticLevelFor(finding: Finding): DiagnosticLevel {
  if (finding.proof === "none") {
    return finding.severity === "low" || finding.severity === "info" ? "information" : "warning";
  }
  switch (finding.severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    default:
      return "information";
  }
}

export interface DiagnosticData {
  file: string;
  line: number;
  level: DiagnosticLevel;
  message: string;
  code: string;
  relatedInformation: string[];
}

export function toDiagnosticData(finding: Finding): DiagnosticData | undefined {
  if (!finding.file || !finding.line) return undefined;
  const related = [
    `Recommended action: ${finding.recommendation}`,
    finding.proof === "advisory"
      ? "Backed by published advisory data."
      : "Heuristic only: manual review required, this is not proof of a vulnerability.",
    ...finding.references
  ];
  return {
    file: finding.file,
    line: finding.line,
    level: diagnosticLevelFor(finding),
    message: `${finding.title}. ${finding.message}`.slice(0, 1200),
    code: finding.advisoryIds[0] ?? finding.id,
    relatedInformation: related.filter(text => text.trim().length > 0)
  };
}

export function isSafeExternalUrl(value: string): boolean {
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function describeProof(finding: Finding): string {
  return finding.proof === "advisory"
    ? "advisory-backed"
    : "heuristic only — not proof of a vulnerability";
}

export function formatReport(result: ScanResult): string {
  const lines: string[] = [];
  const counts = countBySeverity(result.findings);
  const { summary } = result;

  lines.push("PHP Security Guard — local scan report");
  lines.push("Triage assistance only. This report cannot certify that a deployment is safe.");
  lines.push("");
  lines.push(`Files analysed: ${summary.checkedFiles}`);
  lines.push(`Advisory data retrieved: ${summary.advisoriesRetrievedAt}`);
  if (summary.truncated) lines.push("The file limit was reached; some files were not analysed.");
  if (summary.cancelled) lines.push("The scan was cancelled before it finished.");
  lines.push(
    `Findings: ${result.findings.length} (critical ${counts.critical}, high ${counts.high}, medium ${counts.medium}, low ${counts.low}, info ${counts.info})`
  );
  lines.push("");
  lines.push("Severity describes potential impact. Confidence describes how sure this scan is.");
  lines.push("Heuristic source findings never prove a vulnerability: verify them by hand.");
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings were reported. Absence of findings is not evidence of security.");
    lines.push("");
  }

  for (const finding of sortFindings(result.findings)) {
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`  Kind: ${finding.kind}; category: ${finding.category}`);
    lines.push(`  Confidence: ${finding.confidence}; proof: ${describeProof(finding)}`);
    if (finding.file) {
      lines.push(`  Location: ${finding.file}${finding.line ? `:${finding.line}` : ""}`);
    }
    if (finding.observation) {
      const observation = finding.observation;
      lines.push(
        `  Observed via: ${observation.kind} (${observation.scope}, ${observation.resolution})${
          observation.sapi ? `, SAPI ${observation.sapi}` : ""
        }`
      );
    }
    lines.push(`  Evidence: ${finding.evidence}`);
    lines.push(`  Detail: ${finding.message}`);
    lines.push(`  Action: ${finding.recommendation}`);
    if (finding.advisoryIds.length > 0) {
      lines.push(`  Advisory IDs: ${finding.advisoryIds.join(", ")}`);
    }
    for (const reference of finding.references) {
      lines.push(`  Reference: ${reference}`);
    }
    lines.push("");
  }

  if (summary.skipped.length > 0) {
    lines.push("Not assessed in this scan");
    for (const item of summary.skipped) lines.push(`  - ${item}`);
    lines.push("");
  }

  if (result.issues.length > 0) {
    lines.push("Scan issues");
    for (const issue of result.issues) {
      lines.push(`  - ${issue.code}: ${issue.message}${issue.file ? ` (${issue.file})` : ""}`);
    }
    lines.push("");
  }

  lines.push("This scan is local and read-only. Composer audit contacts packagist.org; nothing else leaves the machine.");
  return lines.join("\n");
}
