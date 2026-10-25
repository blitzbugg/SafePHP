import * as vscode from "vscode";
import * as path from "node:path";
import type { Finding, Severity } from "../types";
import { countBySeverity, SEVERITY_ORDER, sortFindings } from "../core/presentation";

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Information"
};

const ICONS: Record<Severity, string> = {
  critical: "error",
  high: "warning",
  medium: "info",
  low: "circle-outline",
  info: "shield"
};

export class SeverityGroup extends vscode.TreeItem {
  constructor(readonly severity: Severity, count: number) {
    super(`${LABELS[severity]} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.iconPath = new vscode.ThemeIcon(ICONS[severity]);
    this.contextValue = "phpSecurityGuardGroup";
  }
}

export class FindingItem extends vscode.TreeItem {
  constructor(readonly finding: Finding) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    const base = finding.file ? path.basename(finding.file) : finding.category;
    this.description = finding.line ? `${base}:${finding.line}` : base;
    this.tooltip = [
      finding.message,
      `Evidence: ${finding.evidence}`,
      `Action: ${finding.recommendation}`,
      finding.proof === "advisory" ? "Advisory-backed." : "Heuristic only — not proof of a vulnerability."
    ].join("\n\n");
    this.iconPath = new vscode.ThemeIcon(ICONS[finding.severity]);
    this.contextValue = "phpSecurityGuardFinding";
    this.command = {
      command: "phpSecurityGuard.showFinding",
      title: "Show Finding",
      arguments: [finding]
    };
  }
}

export type FindingNode = SeverityGroup | FindingItem;

export class FindingsProvider implements vscode.TreeDataProvider<FindingNode> {
  private findings: Finding[] = [];
  private readonly emitter = new vscode.EventEmitter<FindingNode | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;

  setFindings(findings: Finding[]): void {
    this.findings = sortFindings(findings);
    this.emitter.fire();
  }

  getTreeItem(element: FindingNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingNode): FindingNode[] {
    if (element instanceof SeverityGroup) {
      return this.findings
        .filter(finding => finding.severity === element.severity)
        .map(finding => new FindingItem(finding));
    }
    if (element) return [];

    const counts = countBySeverity(this.findings);
    return SEVERITY_ORDER.filter(severity => counts[severity] > 0).map(
      severity => new SeverityGroup(severity, counts[severity])
    );
  }
}
