import * as vscode from "vscode";
import * as path from "node:path";
import { scanWorkspace } from "./scanner";
import type { Finding } from "./types";

class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
  private readonly emitter = new vscode.EventEmitter<FindingItem | undefined | null | void>();
  readonly onDidChangeTreeData = this.emitter.event;
  private items: FindingItem[] = [];

  setFindings(findings: Finding[]): void {
    this.items = findings.map(f => new FindingItem(f));
    this.emitter.fire();
  }

  getTreeItem(element: FindingItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FindingItem): Thenable<FindingItem[]> {
    if (element) return Promise.resolve([]);
    return Promise.resolve(this.items);
  }
}

class FindingItem extends vscode.TreeItem {
  constructor(readonly finding: Finding) {
    super(`${finding.severity.toUpperCase()}: ${finding.title}`, vscode.TreeItemCollapsibleState.None);
    this.description = finding.file ? `${path.basename(finding.file)}${finding.line ? `:${finding.line}` : ""}` : finding.category;
    this.tooltip = `${finding.message}\n\nEvidence: ${finding.evidence}\n\nAction: ${finding.recommendation}`;
    this.iconPath = new vscode.ThemeIcon(iconFor(finding.severity));
    this.command = {
      command: "phpSecurityGuard.showFinding",
      title: "Show Finding",
      arguments: [finding]
    };
    this.contextValue = "phpSecurityGuardFinding";
  }
}

function iconFor(severity: Finding["severity"]): string {
  switch (severity) {
    case "critical": return "error";
    case "high": return "warning";
    case "medium": return "info";
    case "low": return "circle-outline";
    default: return "shield";
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const provider = new FindingsProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("phpSecurityGuard.findings", provider)
  );

  context.subscriptions.push(vscode.commands.registerCommand("phpSecurityGuard.scanWorkspace", async () => {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders?.length) {
      vscode.window.showWarningMessage("PHP Security Guard: Open a workspace folder first.");
      return;
    }

    const config = vscode.workspace.getConfiguration("phpSecurityGuard");
    const options = {
      maxFiles: config.get<number>("maxFiles", 5000),
      sourceHeuristics: config.get<boolean>("enableSourceHeuristics", true),
      composerAudit: config.get<boolean>("runComposerAudit", true)
    };

    const output = vscode.window.createOutputChannel("PHP Security Guard");
    output.clear();
    output.appendLine("PHP Security Guard — local workspace scan");
    output.appendLine("This is triage assistance, not a certification that a deployment is safe.");
    output.appendLine(`Workspace: ${folders.map(f => f.uri.fsPath).join(", ")}`);
    output.show(true);

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "PHP Security Guard: scanning workspace",
      cancellable: false
    }, async () => {
      const allFindings: Finding[] = [];
      for (const folder of folders) {
        const results = await scanWorkspace(folder.uri.fsPath, options);
        allFindings.push(...results);
      }
      provider.setFindings(allFindings);
      const counts = allFindings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});
      output.appendLine(`Findings: ${allFindings.length}`);
      output.appendLine(JSON.stringify(counts, null, 2));
      for (const f of allFindings) {
        output.appendLine("");
        output.appendLine(`[${f.severity.toUpperCase()}] ${f.title}`);
        output.appendLine(`Category: ${f.category}; confidence: ${f.confidence}`);
        if (f.file) output.appendLine(`Location: ${f.file}${f.line ? `:${f.line}` : ""}`);
        output.appendLine(`Evidence: ${f.evidence}`);
        output.appendLine(`Recommendation: ${f.recommendation}`);
        for (const ref of f.references) output.appendLine(`Reference: ${ref}`);
      }
      vscode.window.showInformationMessage(`PHP Security Guard: ${allFindings.length} finding(s). Review the PHP Security Guard panel and Output.`);
    });
  }));

  context.subscriptions.push(vscode.commands.registerCommand("phpSecurityGuard.showFinding", async (finding: Finding) => {
    const refs = finding.references.join("\n");
    const selection = await vscode.window.showWarningMessage(
      `${finding.title}\n\n${finding.message}\n\nEvidence: ${finding.evidence}\n\nRecommended action: ${finding.recommendation}`,
      { modal: true },
      "Open advisory"
    );
    if (selection === "Open advisory" && finding.references[0]) {
      await vscode.env.openExternal(vscode.Uri.parse(finding.references[0]));
    }
    if (refs) {
      // References are also present in the Output channel for copy/paste.
    }
  }));

  context.subscriptions.push(vscode.commands.registerCommand("phpSecurityGuard.openOfficialAdvisory", async () => {
    await vscode.env.openExternal(vscode.Uri.parse("https://cert.europa.eu/publications/security-advisories/2026-018"));
  }));
}

export function deactivate(): void {}
