import * as vscode from "vscode";
import type { Finding, ScanResult, Severity } from "../types";
import { countBySeverity } from "../core/presentation";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

const LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--vscode-errorForeground)",
  high: "var(--vscode-editorWarning-foreground)",
  medium: "var(--vscode-charts-yellow)",
  low: "var(--vscode-charts-blue)",
  info: "var(--vscode-descriptionForeground)"
};

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function makeNonce(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let value = "";
  for (let i = 0; i < 32; i += 1) {
    value += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return value;
}

/**
 * Activity Bar dashboard: one glance at the last scan's severity distribution,
 * then the findings themselves, clickable through to the editor.
 */
export class DashboardViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "phpSecurityGuard.dashboard";

  private view: vscode.WebviewView | undefined;
  private result: ScanResult | undefined;
  private scannedAt: Date | undefined;
  private scanning = false;

  constructor(
    private readonly onScanRequested: () => void,
    private readonly onFindingSelected: (finding: Finding) => void
  ) {}

  resolveWebviewView(webviewView: vscode.WebviewView): void {
    this.view = webviewView;
    webviewView.webview.options = { enableScripts: true, localResourceRoots: [] };
    webviewView.webview.html = this.render();
    webviewView.webview.onDidReceiveMessage(message => {
      if (!message || typeof message !== "object") return;
      if (message.type === "scan") {
        this.onScanRequested();
      } else if (message.type === "openFinding" && this.result && typeof message.index === "number") {
        const finding = this.result.findings[message.index];
        if (finding) this.onFindingSelected(finding);
      }
    });
  }

  setScanning(scanning: boolean): void {
    this.scanning = scanning;
    this.refresh();
  }

  setResult(result: ScanResult): void {
    this.result = result;
    this.scannedAt = new Date();
    this.scanning = false;
    this.refresh();
  }

  private refresh(): void {
    if (this.view) this.view.webview.html = this.render();
  }

  private render(): string {
    const nonce = makeNonce();
    const result = this.result;
    const counts = result ? countBySeverity(result.findings) : undefined;
    const total = result ? result.findings.length : 0;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --meter-critical: ${SEVERITY_COLOR.critical};
      --meter-high: ${SEVERITY_COLOR.high};
      --meter-medium: ${SEVERITY_COLOR.medium};
      --meter-low: ${SEVERITY_COLOR.low};
      --meter-info: ${SEVERITY_COLOR.info};
    }
    body {
      margin: 0;
      padding: 0 14px 20px;
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: transparent;
    }
    .eyebrow {
      margin: 14px 0 2px;
      font-size: 10px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--vscode-descriptionForeground);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 14px;
      font-weight: 600;
    }
    button.scan {
      display: block;
      width: 100%;
      padding: 7px 0;
      border: none;
      border-radius: 2px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      font: inherit;
      font-weight: 600;
      cursor: pointer;
    }
    button.scan:hover { background: var(--vscode-button-hoverBackground); }
    button.scan:disabled { opacity: 0.6; cursor: default; }
    button.scan:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: 2px; }
    .meter {
      display: flex;
      height: 4px;
      margin: 16px 0 8px;
      border-radius: 2px;
      overflow: hidden;
      background: var(--vscode-widget-border);
    }
    .meter span { display: block; height: 100%; }
    .counts {
      display: flex;
      flex-wrap: wrap;
      gap: 4px 14px;
      margin-bottom: 4px;
      font-variant-numeric: tabular-nums;
    }
    .count { display: inline-flex; align-items: center; gap: 5px; font-size: 12px; }
    .dot { width: 7px; height: 7px; border-radius: 50%; }
    .meta { margin: 6px 0 0; font-size: 11px; color: var(--vscode-descriptionForeground); }
    .findings { list-style: none; margin: 14px 0 0; padding: 0; }
    .findings li { border-top: 1px solid var(--vscode-widget-border); }
    .findings button {
      display: flex;
      align-items: baseline;
      gap: 8px;
      width: 100%;
      padding: 7px 2px;
      border: none;
      background: none;
      color: inherit;
      font: inherit;
      text-align: left;
      cursor: pointer;
    }
    .findings button:hover { background: var(--vscode-list-hoverBackground); }
    .findings button:focus-visible { outline: 1px solid var(--vscode-focusBorder); outline-offset: -1px; }
    .findings .title { flex: 1; font-size: 12px; line-height: 1.35; }
    .findings .where {
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
      white-space: nowrap;
    }
    .empty {
      margin: 18px 0 0;
      font-size: 12px;
      line-height: 1.5;
      color: var(--vscode-descriptionForeground);
    }
    .disclaimer {
      margin: 18px 0 0;
      padding-top: 10px;
      border-top: 1px solid var(--vscode-widget-border);
      font-size: 11px;
      line-height: 1.5;
      color: var(--vscode-descriptionForeground);
    }
  </style>
</head>
<body>
  <p class="eyebrow">local · read-only</p>
  <h1>PHP Security Guard</h1>
  <button class="scan" id="scan" ${this.scanning ? "disabled" : ""}>${this.scanning ? "Scanning…" : "Scan workspace"}</button>
  ${
    result && counts
      ? `<div class="meter" role="img" aria-label="Severity distribution: ${SEVERITIES.map(
          severity => `${counts[severity]} ${LABELS[severity]}`
        ).join(", ")}">
      ${SEVERITIES.filter(severity => counts[severity] > 0)
        .map(
          severity =>
            `<span style="width:${((counts[severity] / Math.max(total, 1)) * 100).toFixed(1)}%; background:var(--meter-${severity})"></span>`
        )
        .join("")}
    </div>
    <div class="counts">
      ${SEVERITIES.filter(severity => counts[severity] > 0)
        .map(
          severity =>
            `<span class="count"><span class="dot" style="background:var(--meter-${severity})"></span>${counts[severity]} ${LABELS[severity]}</span>`
        )
        .join("")}
    </div>
    <p class="meta">${total} finding${total === 1 ? "" : "s"} · ${result.summary.checkedFiles} file${
            result.summary.checkedFiles === 1 ? "" : "s"
          } analysed${this.scannedAt ? ` · ${this.scannedAt.toLocaleTimeString()}` : ""}${
            result.summary.cancelled ? " · cancelled early" : ""
          }</p>
    ${
      total === 0
        ? `<p class="empty">No findings reported. Absence of findings is not evidence of security: this scan cannot certify a deployment as safe.</p>`
        : `<ul class="findings">
      ${result.findings
        .slice(0, 12)
        .map((finding, index) => {
          const where = finding.file
            ? `${finding.file.split(/[\\/]/).pop() ?? finding.file}${finding.line ? `:${finding.line}` : ""}`
            : LABELS[finding.severity];
          return `<li><button data-finding="${index}" title="${escapeHtml(finding.message)}">
            <span class="dot" style="background:var(--meter-${finding.severity})"></span>
            <span class="title">${escapeHtml(finding.title)}</span>
            <span class="where">${escapeHtml(where)}</span>
          </button></li>`;
        })
        .join("")}
    </ul>
    ${total > 12 ? `<p class="meta">+ ${total - 12} more in the Explorer findings panel.</p>` : ""}`
    }`
      : `<p class="empty">No scan yet. Open a PHP workspace and scan it to see runtime, configuration, Composer and source findings here.</p>`
  }
  <p class="disclaimer">Heuristic findings are review candidates, not proof of a vulnerability. Composer audit contacts packagist.org with package names and versions; nothing else leaves this machine.</p>
  <script nonce="${nonce}">
    const vscode = acquireVsCodeApi();
    document.getElementById("scan").addEventListener("click", () => vscode.postMessage({ type: "scan" }));
    document.querySelectorAll("[data-finding]").forEach(button => {
      button.addEventListener("click", () => {
        vscode.postMessage({ type: "openFinding", index: Number(button.getAttribute("data-finding")) });
      });
    });
  </script>
</body>
</html>`;
  }
}
