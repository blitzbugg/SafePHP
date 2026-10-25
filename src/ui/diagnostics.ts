import * as vscode from "vscode";
import type { Finding } from "../types";
import { toDiagnosticData, type DiagnosticLevel } from "../core/presentation";

function mapLevel(level: DiagnosticLevel): vscode.DiagnosticSeverity {
  switch (level) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "warning":
      return vscode.DiagnosticSeverity.Warning;
    case "information":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

/** Replace all diagnostics with the findings from the latest scan. */
export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[]
): void {
  collection.clear();
  const byFile = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    const data = toDiagnosticData(finding);
    if (!data) continue;

    const lineIndex = Math.max(0, data.line - 1);
    const range = new vscode.Range(lineIndex, 0, lineIndex, 1000);
    const diagnostic = new vscode.Diagnostic(range, data.message, mapLevel(data.level));
    diagnostic.source = "PHP Security Guard";
    diagnostic.code = data.code;
    diagnostic.relatedInformation = data.relatedInformation.map(
      text =>
        new vscode.DiagnosticRelatedInformation(new vscode.Location(vscode.Uri.file(data.file), range), text)
    );

    const list = byFile.get(data.file) ?? [];
    list.push(diagnostic);
    byFile.set(data.file, list);
  }

  for (const [file, list] of byFile) {
    collection.set(vscode.Uri.file(file), list);
  }
}
