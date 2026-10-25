import * as vscode from "vscode";
import type { Finding, ScanResult } from "./types";
import { scanWorkspace, type ScanSettings } from "./core/scan";
import { nodeScanFs } from "./core/walk";
import { nodeProcessRunner } from "./core/process";
import { countBySeverity, formatReport, isSafeExternalUrl, sortFindings } from "./core/presentation";
import { applyDiagnostics } from "./ui/diagnostics";
import { FindingsProvider } from "./ui/tree";

const PHP_TIMEOUT_MS = 5000;
const COMPOSER_TIMEOUT_MS = 30000;

function numberSetting(
  config: vscode.WorkspaceConfiguration,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const raw = config.get<number>(key, fallback);
  if (typeof raw !== "number" || !Number.isFinite(raw)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.floor(raw)));
}

function stringSetting(config: vscode.WorkspaceConfiguration, key: string): string | undefined {
  const raw = config.get<string>(key, "").trim();
  return raw.length > 0 ? raw : undefined;
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("PHP Security Guard");
  const diagnostics = vscode.languages.createDiagnosticCollection("phpSecurityGuard");
  const provider = new FindingsProvider();
  let lastResult: ScanResult | undefined;

  context.subscriptions.push(
    output,
    diagnostics,
    vscode.window.registerTreeDataProvider("phpSecurityGuard.findings", provider)
  );

  const runScan = async (): Promise<void> => {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      void vscode.window.showWarningMessage("PHP Security Guard: open a workspace folder first.");
      return;
    }

    const config = vscode.workspace.getConfiguration("phpSecurityGuard");
    const settings: ScanSettings = {
      maxFiles: numberSetting(config, "maxFiles", 5000, 100, 50000),
      maxFileBytes: numberSetting(config, "maxFileBytes", 1_048_576, 65_536, 16_777_216),
      sourceHeuristics: config.get<boolean>("enableSourceHeuristics", true),
      composerAudit: config.get<boolean>("runComposerAudit", true),
      includeVendor: config.get<boolean>("includeVendor", false),
      phpPath: stringSetting(config, "phpPath"),
      composerPath: stringSetting(config, "composerPath"),
      composerPharPath: stringSetting(config, "composerPharPath"),
      phpTimeoutMs: PHP_TIMEOUT_MS,
      composerTimeoutMs: COMPOSER_TIMEOUT_MS
    };

    const allowExecution = vscode.workspace.isTrusted;

    output.clear();
    output.show(true);
    output.appendLine("PHP Security Guard — local workspace scan");
    output.appendLine("Triage assistance. This does not certify that a deployment is safe.");
    output.appendLine(`Workspace: ${folders.map(folder => folder.uri.fsPath).join(", ")}`);
    if (!allowExecution) {
      output.appendLine(
        "Workspace is not trusted: php and Composer will not be executed. File-content checks only."
      );
    }
    output.appendLine("");

    const aggregated: ScanResult = {
      findings: [],
      issues: [],
      summary: {
        checkedFiles: 0,
        truncated: false,
        cancelled: false,
        advisoriesRetrievedAt: "",
        skipped: []
      }
    };

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "PHP Security Guard: scanning workspace",
        cancellable: true
      },
      async (progress, token) => {
        for (const folder of folders) {
          if (token.isCancellationRequested) {
            aggregated.summary.cancelled = true;
            break;
          }
          progress.report({ message: folder.name });
          try {
            const result = await scanWorkspace(
              folder.uri.fsPath,
              settings,
              {
                fs: nodeScanFs,
                runner: nodeProcessRunner,
                platform: process.platform,
                env: process.env
              },
              {
                allowExecution,
                runtime: token,
                onProgress: message => progress.report({ message })
              }
            );
            aggregated.findings.push(...result.findings);
            aggregated.issues.push(...result.issues);
            aggregated.summary.checkedFiles += result.summary.checkedFiles;
            aggregated.summary.truncated = aggregated.summary.truncated || result.summary.truncated;
            aggregated.summary.cancelled = aggregated.summary.cancelled || result.summary.cancelled;
            aggregated.summary.skipped.push(...result.summary.skipped);
            if (result.summary.advisoriesRetrievedAt.length > 0) {
              aggregated.summary.advisoriesRetrievedAt = result.summary.advisoriesRetrievedAt;
            }
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            aggregated.issues.push({
              code: "SCAN_FAILED",
              message: `The scan failed for ${folder.uri.fsPath}: ${message}`
            });
          }
        }
      }
    );

    aggregated.findings = sortFindings(aggregated.findings);
    aggregated.summary.skipped = [...new Set(aggregated.summary.skipped)];
    lastResult = aggregated;

    provider.setFindings(aggregated.findings);
    applyDiagnostics(diagnostics, aggregated.findings);
    output.append(formatReport(aggregated));

    const counts = countBySeverity(aggregated.findings);
    const summary = `${aggregated.findings.length} finding(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium.`;
    if (aggregated.summary.cancelled) {
      void vscode.window.showInformationMessage(
        `PHP Security Guard: scan cancelled. ${summary} Partial results are shown.`
      );
    } else if (counts.critical + counts.high > 0) {
      void vscode.window.showWarningMessage(`PHP Security Guard: ${summary} Review the findings panel.`);
    } else {
      void vscode.window.showInformationMessage(`PHP Security Guard: ${summary}`);
    }
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("phpSecurityGuard.scanWorkspace", runScan)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("phpSecurityGuard.showReport", async () => {
      if (!lastResult) {
        void vscode.window.showInformationMessage(
          "PHP Security Guard: run a workspace scan first."
        );
        return;
      }
      output.show(true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("phpSecurityGuard.showFinding", async (finding: Finding) => {
      if (!finding) return;

      if (finding.file) {
        try {
          const document = await vscode.workspace.openTextDocument(vscode.Uri.file(finding.file));
          const editor = await vscode.window.showTextDocument(document, { preview: false });
          if (finding.line && document.lineCount > 0) {
            const lineIndex = Math.max(0, Math.min(finding.line - 1, document.lineCount - 1));
            const range = new vscode.Range(
              lineIndex,
              0,
              lineIndex,
              document.lineAt(lineIndex).text.length
            );
            editor.selection = new vscode.Selection(range.start, range.end);
            editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
          }
        } catch {
          void vscode.window.showWarningMessage(
            `PHP Security Guard: could not open ${finding.file}.`
          );
        }
      }

      const reference = finding.references.find(isSafeExternalUrl);
      if (!reference) return;
      const action = "Open reference";
      const selection = await vscode.window.showInformationMessage(finding.title, action);
      if (selection === action) {
        await vscode.env.openExternal(vscode.Uri.parse(reference));
      }
    })
  );
}

export function deactivate(): void {}
