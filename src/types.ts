export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  message: string;
  evidence: string;
  file?: string;
  line?: number;
  recommendation: string;
  references: string[];
  category: "runtime" | "dependency" | "source" | "configuration";
}

export interface Advisory {
  id: string;
  title: string;
  category: "runtime" | "configuration";
  summary: string;
  references: string[];
  fixedVersions?: Record<string, string>;
  affectedBefore?: Record<string, string>;
  recommendation: string;
  status: "verified" | "monitor";
}
