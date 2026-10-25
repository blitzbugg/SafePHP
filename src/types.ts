export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Confidence = "high" | "medium" | "low";

/**
 * How strongly a finding is backed.
 * - "advisory": a published advisory or a documented runtime default states the fact.
 * - "none": a source-code heuristic. It never proves a vulnerability.
 */
export type Proof = "advisory" | "none";

export type FindingKind =
  | "vulnerability"
  | "mitigation"
  | "heuristic"
  | "unassessed"
  | "scan-issue";

export type Category = "runtime" | "configuration" | "dependency" | "source" | "scan";

/** Where a version observation came from. Required on every version-based finding. */
export type ObservationKind =
  | "php-cli"
  | "dockerfile"
  | "compose-image"
  | "ini"
  | "fpm-pool"
  | "apache"
  | "composer-constraint"
  | "composer-audit";

/** What the observation describes. Never conflate a declared constraint with a runtime. */
export type ObservationScope = "local-dev" | "container-declared" | "declared-constraint";

/** How precisely the version could be determined from the input text. */
export type ObservationResolution = "exact" | "branch-floating" | "major-floating" | "unresolved";

export interface ObservationRef {
  kind: ObservationKind;
  scope: ObservationScope;
  resolution: ObservationResolution;
  /** The text actually observed, trimmed for display. */
  raw: string;
  file?: string;
  line?: number;
  /** Server API reported by `php -v`, e.g. "cli" or "fpm-fcgi". */
  sapi?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  proof: Proof;
  kind: FindingKind;
  category: Category;
  message: string;
  evidence: string;
  file?: string;
  line?: number;
  column?: number;
  recommendation: string;
  references: string[];
  advisoryIds: string[];
  observation?: ObservationRef;
}

export interface ScanIssue {
  code: string;
  message: string;
  file?: string;
  line?: number;
}

export interface ScanSummary {
  checkedFiles: number;
  truncated: boolean;
  cancelled: boolean;
  advisoriesRetrievedAt: string;
  /** Checks that were deliberately skipped, with the reason. */
  skipped: string[];
}

export interface ScanResult {
  findings: Finding[];
  issues: ScanIssue[];
  summary: ScanSummary;
}

// ---------------------------------------------------------------------------
// Advisory data (schema v2)
// ---------------------------------------------------------------------------

export type AdvisoryStatus = "fixed" | "unpatched-informational" | "vendor-dependent";

export interface AdvisoryBranch {
  /** Affected when the observed version is strictly below this value. */
  affectedBelow?: string;
  /** The first upstream release that contains the fix. */
  fixedIn?: string;
}

export interface AdvisoryMitigation {
  /** PHP ini directive this mitigation applies to, when it is directive-based. */
  directive?: string;
  /** Representative value, e.g. "0" or "-1". */
  value?: string;
  text: string;
}

export interface Advisory {
  id: string;
  aliases: string[];
  title: string;
  summary: string;
  category: "runtime" | "configuration";
  status: AdvisoryStatus;
  severity: Severity;
  branches: Record<string, AdvisoryBranch>;
  eolBranchesAffected: boolean;
  preconditions?: string;
  mitigations: AdvisoryMitigation[];
  recommendation: string;
  references: string[];
  verifiedAgainst: string[];
}

export interface AdvisoryData {
  schemaVersion: number;
  retrievedAt: string;
  advisories: Advisory[];
}
