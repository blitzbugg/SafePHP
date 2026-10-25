import * as fs from "node:fs/promises";
import * as path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "./types";

const execFileAsync = promisify(execFile);
const IGNORE_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", "coverage",
  ".next", ".cache", ".idea", ".vscode", "out"
]);

const PHP2SHELL_REFS = [
  "https://www.php.net/archive/2026.php#2026-10-20-1",
  "https://cert.europa.eu/publications/security-advisories/2026-018"
];

function compareVersions(a: string, b: string): number {
  const aa = a.split(".").map(Number);
  const bb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(aa.length, bb.length); i++) {
    const av = aa[i] ?? 0;
    const bv = bb[i] ?? 0;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return 0;
}

function parsePhpVersion(output: string): string | undefined {
  const match = output.match(/PHP\s+(\d+\.\d+\.\d+)/i);
  return match?.[1];
}

export async function scanWorkspace(
  root: string,
  options: { maxFiles: number; sourceHeuristics: boolean; composerAudit: boolean }
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files: string[] = [];
  let truncated = false;

  async function walk(dir: string): Promise<void> {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= options.maxFiles) {
        truncated = true;
        return;
      }
      if (entry.name.startsWith(".") && entry.isDirectory()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) await walk(full);
      } else if (
        entry.isFile() &&
        /^(composer\.json|composer\.lock|Dockerfile(?:\..*)?|docker-compose(?:\..*)?\.ya?ml|compose\.ya?ml|php\.ini(?:\.production)?|\.user\.ini|.*\.php)$/i.test(entry.name)
      ) {
        files.push(full);
      }
      if (truncated) return;
    }
  }

  await walk(root);

  if (truncated) {
    findings.push({
      id: "SCAN-LIMIT",
      title: "Workspace scan reached its file limit",
      severity: "info",
      confidence: "high",
      message: `Only the first ${options.maxFiles} matching files were considered.`,
      evidence: "Configured maxFiles limit reached.",
      recommendation: "Increase phpSecurityGuard.maxFiles or scan a smaller workspace. Unscanned files were not assessed.",
      references: [],
      category: "configuration"
    });
  }

  // Inspect version declarations and configuration text. These are clues, not proof
  // of the version/configuration actually used by a production web server.
  const seenRuntimeFiles = new Set<string>();
  for (const file of files) {
    const base = path.basename(file).toLowerCase();
    let content: string;
    try {
      content = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }

    if (/^(dockerfile|docker-compose.*\.ya?ml|compose\.ya?ml)$/.test(base)) {
      const lines = content.split(/\r?\n/);
      lines.forEach((line, index) => {
        const match = line.match(/^\s*FROM\s+(?:--platform=\S+\s+)?(?:\S*\/)?php:(\d+\.\d+(?:\.\d+)?)(?:[-@].*)?\s*$/i);
        if (!match) return;
        const version = match[1].split(".").length === 2 ? `${match[1]}.0` : match[1];
        const fixed = fixedVersionFor(version);
        if (fixed && compareVersions(version, fixed) < 0) {
          findings.push({
            id: `PHP2SHELL-IMAGE-${path.basename(file)}-${index + 1}`,
            title: "PHP container image may use a vulnerable upstream version",
            severity: "critical",
            confidence: "medium",
            message: `Image reference declares PHP ${match[1]}; this is below the upstream fixed release ${fixed} for its branch.`,
            evidence: line.trim(),
            file,
            line: index + 1,
            recommendation: "Update to a vendor-fixed image and rebuild/redeploy. Verify distro/vendor backports and the actual running image before concluding exposure.",
            references: PHP2SHELL_REFS,
            category: "runtime"
          });
        } else if (!fixed) {
          findings.push({
            id: `PHP-IMAGE-REVIEW-${index + 1}-${path.basename(file)}`,
            title: "Review PHP container image version",
            severity: "high",
            confidence: "low",
            message: `Could not confidently compare PHP image version ${match[1]} against the supported branch data.`,
            evidence: line.trim(),
            file,
            line: index + 1,
            recommendation: "Check the image publisher's security advisory and confirm the running image digest/version.",
            references: PHP2SHELL_REFS,
            category: "runtime"
          });
        }
      });
    }

    if (/^(php\.ini(?:\.production)?|\.user\.ini)$/.test(base) || /fpm|apache|httpd/i.test(base)) {
      seenRuntimeFiles.add(file);
      const lines = content.split(/\r?\n/);
      let found = false;
      lines.forEach((line, index) => {
        if (/^\s*[;#]?\s*session\.upload_progress\.enabled\s*=\s*(0|Off|false)\b/i.test(line)) {
          found = true;
        }
        if (/^\s*session\.upload_progress\.enabled\s*=\s*(1|On|true)\b/i.test(line)) {
          findings.push({
            id: `CVE-2026-115560-${path.basename(file)}-${index + 1}`,
            title: "Session upload progress appears enabled",
            severity: "high",
            confidence: "medium",
            message: "This file contains an enabled session.upload_progress setting. It may not be the effective configuration for the web runtime.",
            evidence: line.trim(),
            file,
            line: index + 1,
            recommendation: "Verify the effective server configuration. The advisory recommends disabling session.upload_progress.enabled and restarting all relevant workers.",
            references: ["https://cert.europa.eu/publications/security-advisories/2026-018"],
            category: "configuration"
          });
        }
      });
      if (!found && /php\.ini|\.user\.ini/.test(base)) {
        findings.push({
          id: `CVE-2026-115560-UNKNOWN-${path.basename(file)}`,
          title: "Session upload-progress setting not confirmed",
          severity: "medium",
          confidence: "low",
          message: "No explicit disabled setting was found in this inspected file; PHP defaults, included configuration, and runtime overrides may differ.",
          evidence: path.relative(root, file),
          file,
          recommendation: "Confirm the effective web-runtime setting using server-level configuration and the current official advisory.",
          references: ["https://cert.europa.eu/publications/security-advisories/2026-018"],
          category: "configuration"
        });
      }
    }

    if (options.sourceHeuristics && file.toLowerCase().endsWith(".php")) {
      inspectPhpSource(file, content, findings);
    }
  }

  // CLI version is useful evidence, but may differ from PHP-FPM/Apache in production.
  try {
    const { stdout, stderr } = await execFileAsync("php", ["-v"], { timeout: 3000, windowsHide: true });
    const version = parsePhpVersion(`${stdout}\n${stderr}`);
    if (version) {
      const fixed = fixedVersionFor(version);
      if (fixed && compareVersions(version, fixed) < 0) {
        findings.push({
          id: "PHP2SHELL-LOCAL-CLI",
          title: "Local PHP CLI is below the upstream fixed release",
          severity: "critical",
          confidence: "high",
          message: `Detected local PHP CLI ${version}; upstream fixed release for this branch is ${fixed}.`,
          evidence: "Output from `php -v` on this development machine.",
          recommendation: "Update the relevant PHP installation. This result does not prove which version your web server runs; check PHP-FPM/Apache/container runtime and vendor backports.",
          references: PHP2SHELL_REFS,
          category: "runtime"
        });
      } else if (!fixed && compareVersions(version, "8.2.0") < 0) {
        findings.push({
          id: "PHP2SHELL-LOCAL-LEGACY",
          title: "Legacy PHP CLI requires vendor-specific verification",
          severity: "high",
          confidence: "low",
          message: `Detected PHP CLI ${version}, which is outside the upstream branches represented by this prototype's fixed-version table.`,
          evidence: "Output from `php -v` on this development machine.",
          recommendation: "Do not infer vulnerability or safety from this prototype's version table. Check the operating-system or vendor advisory for backported fixes, and plan a move to a supported PHP release.",
          references: PHP2SHELL_REFS,
          category: "runtime"
        });
      } else {
        findings.push({
          id: "PHP-RUNTIME-INFO",
          title: "Local PHP CLI version detected",
          severity: "info",
          confidence: "high",
          message: `Detected local PHP CLI ${version}.`,
          evidence: "Output from `php -v` on this development machine.",
          recommendation: "Compare this with the actual web-serving runtime and your vendor's security status. A version-only check cannot certify a deployment as safe.",
          references: PHP2SHELL_REFS,
          category: "runtime"
        });
      }
    }
  } catch {
    findings.push({
      id: "PHP-CLI-NOT-FOUND",
      title: "PHP CLI not available",
      severity: "info",
      confidence: "high",
      message: "The `php` executable was not found or could not be run.",
      evidence: "Attempted `php -v` locally; no runtime version was obtained.",
      recommendation: "If PHP is installed in a container or remote host, inspect that environment separately. This extension does not scan remote hosts.",
      references: [],
      category: "runtime"
    });
  }

  if (options.composerAudit && files.some(f => path.basename(f) === "composer.lock")) {
    try {
      const { stdout } = await execFileAsync("composer", ["audit", "--format=json"], {
        cwd: root,
        timeout: 20000,
        windowsHide: true,
        maxBuffer: 5 * 1024 * 1024
      });
      addComposerAuditFindings(stdout, findings);
    } catch (error: unknown) {
      const output = extractExecOutput(error);
      if (output) {
        addComposerAuditFindings(output, findings);
      } else {
        findings.push({
          id: "COMPOSER-AUDIT-FAILED",
          title: "Composer audit could not complete",
          severity: "info",
          confidence: "high",
          message: "Composer audit was unavailable, timed out, or failed.",
          evidence: "The extension did not obtain a valid Composer audit JSON report.",
          recommendation: "Run `composer audit` manually in the project root and review the result. Dependency audit results do not assess the PHP core runtime.",
          references: ["https://getcomposer.org/doc/03-cli.md#audit"],
          category: "dependency"
        });
      }
    }
  }

  return dedupeFindings(findings);
}

function fixedVersionFor(version: string): string | undefined {
  const [major, minor] = version.split(".").map(Number);
  const branch = `${major}.${minor}`;
  const fixed: Record<string, string> = {
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12"
  };
  return fixed[branch];
}

function inspectPhpSource(file: string, content: string, findings: Finding[]): void {
  const lines = content.split(/\r?\n/);
  const patterns: Array<{ regex: RegExp; id: string; title: string; severity: Finding["severity"]; recommendation: string }> = [
    {
      regex: /\b(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$/,
      id: "PHP-CMD-REVIEW",
      title: "Review command execution with a variable argument",
      severity: "high",
      recommendation: "Trace whether untrusted input reaches this argument. Prefer avoiding shell commands; if required, use safe argument handling and strict allowlists. This heuristic does not prove exploitability."
    },
    {
      regex: /\b(?:unserialize)\s*\(\s*\$/,
      id: "PHP-UNSERIALIZE-REVIEW",
      title: "Review unserialize() with a variable argument",
      severity: "high",
      recommendation: "Determine whether the serialized input is attacker-controlled. Avoid unserialize() on untrusted data; consider JSON or a strict schema."
    },
    {
      regex: /\b(?:include|include_once|require|require_once)\s*\(\s*\$/,
      id: "PHP-FILE-INCLUDE-REVIEW",
      title: "Review dynamic file inclusion",
      severity: "high",
      recommendation: "Ensure the path cannot be controlled by untrusted input. Prefer fixed mappings and allowlists."
    },
    {
      regex: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\].{0,120}\b(?:query|exec|system|shell_exec|passthru|unserialize)\s*\(/i,
      id: "PHP-TAINT-REVIEW",
      title: "Review user-input flow to a sensitive operation",
      severity: "medium",
      recommendation: "Trace input validation and data flow manually. This same-line heuristic can miss flows across statements and can also produce false positives."
    }
  ];

  lines.forEach((line, index) => {
    for (const pattern of patterns) {
      if (!pattern.regex.test(line)) continue;
      findings.push({
        id: `${pattern.id}-${path.basename(file)}-${index + 1}`,
        title: pattern.title,
        severity: pattern.severity,
        confidence: "low",
        message: "Potentially risky source pattern found; manual data-flow review is required.",
        evidence: line.trim().slice(0, 500),
        file,
        line: index + 1,
        recommendation: pattern.recommendation,
        references: ["https://www.php.net/manual/en/security.php"],
        category: "source"
      });
    }
  });
}

function addComposerAuditFindings(raw: string, findings: Finding[]): void {
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    findings.push({
      id: "COMPOSER-AUDIT-INVALID-JSON",
      title: "Composer audit returned unrecognized output",
      severity: "info",
      confidence: "high",
      message: "The audit output could not be parsed as JSON.",
      evidence: raw.slice(0, 300),
      recommendation: "Run `composer audit` manually and review its output.",
      references: ["https://getcomposer.org/doc/03-cli.md#audit"],
      category: "dependency"
    });
    return;
  }

  const advisories = Array.isArray(parsed.advisories)
    ? parsed.advisories
    : Object.values(parsed.advisories ?? {}).flat() as any[];

  if (advisories.length === 0) {
    findings.push({
      id: "COMPOSER-AUDIT-NO-ADVISORIES",
      title: "Composer audit reported no package advisories",
      severity: "info",
      confidence: "high",
      message: "No package advisories were returned by Composer for this audit.",
      evidence: "Composer audit JSON contained no advisories.",
      recommendation: "This does not assess PHP core runtime vulnerabilities or prove that the deployed application is secure.",
      references: ["https://getcomposer.org/doc/03-cli.md#audit"],
      category: "dependency"
    });
    return;
  }

  for (const item of advisories) {
    const name = String(item.packageName ?? item.package ?? "Unknown package");
    const advisoryId = String(item.advisoryId ?? item.cve ?? item.title ?? "Composer advisory");
    findings.push({
      id: `COMPOSER-${advisoryId}-${name}`,
      title: `Composer advisory: ${name}`,
      severity: "high",
      confidence: "high",
      message: `${advisoryId}: ${String(item.title ?? item.advisoryId ?? "Review the Composer advisory details")}`,
      evidence: JSON.stringify({
        packageName: name,
        affectedVersions: item.affectedVersions,
        link: item.link,
        cve: item.cve
      }),
      recommendation: "Review the Composer audit details and update to a fixed compatible dependency version.",
      references: [String(item.link ?? "https://getcomposer.org/doc/03-cli.md#audit")],
      category: "dependency"
    });
  }
}

function extractExecOutput(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const e = error as { stdout?: unknown; stderr?: unknown };
  const out = [e.stdout, e.stderr].filter((x): x is string => typeof x === "string" && x.length > 0);
  return out.join("\n") || undefined;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.id}:${f.file ?? ""}:${f.line ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
