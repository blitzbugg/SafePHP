import type { ScanIssue } from "../types";

export type IniKind = "php-ini" | "user-ini" | "fpm-pool" | "apache";

export interface IniDirective {
  name: string;
  value: string;
  line: number;
  /** False for commented-out directives: they document nothing about the effective value. */
  active: boolean;
  kind: IniKind;
}

export interface IniParseResult {
  directives: IniDirective[];
  issues: ScanIssue[];
}

/** Identify which PHP configuration surface a file belongs to. */
export function detectIniKind(filePath: string): IniKind | undefined {
  const normalized = filePath.replace(/\\/g, "/");
  const base = normalized.split("/").pop()?.toLowerCase() ?? "";
  if (base === ".user.ini") return "user-ini";
  if (/^php\.ini([-.].+)?$/.test(base)) return "php-ini";
  if (base.endsWith(".ini") && /(^|\/)conf\.d(\/|$)/i.test(normalized)) return "php-ini";
  if (base.endsWith(".conf") && /(^|\/)pool\.d(\/|$)/i.test(normalized)) return "fpm-pool";
  if (base === "httpd.conf" || base === "apache2.conf") return "apache";
  if (base.endsWith(".conf") && /(apache|httpd)/i.test(normalized)) return "apache";
  return undefined;
}

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function stripInlineComment(value: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index];
    if (char === "'" && !inDouble) inSingle = !inSingle;
    else if (char === '"' && !inSingle) inDouble = !inDouble;
    else if (!inSingle && !inDouble && (char === ";" || char === "#")) {
      return value.slice(0, index).trim();
    }
  }
  return value.trim();
}

interface Extracted {
  name: string;
  value: string;
}

function extractDirective(body: string): Extracted | undefined {
  // FPM pool / bracketed Apache value: php_admin_value[name] = value
  const bracketed = /^php_(?:admin_)?(?:value|flag)\s*\[([^\]]+)\]\s*(?:=\s*)?(.*)$/i.exec(body);
  if (bracketed) {
    return { name: bracketed[1].trim(), value: bracketed[2] };
  }
  // Apache space-separated form: php_admin_value name value
  const spaced = /^php_(?:admin_)?(?:value|flag)\s+(\S+)\s+(.*)$/i.exec(body);
  if (spaced) {
    return { name: spaced[1].trim(), value: spaced[2] };
  }
  // php.ini key = value
  const keyValue = /^([A-Za-z0-9_.\-[\]]+)\s*=\s*(.*)$/.exec(body);
  if (keyValue) {
    return { name: keyValue[1].trim(), value: keyValue[2] };
  }
  return undefined;
}

/**
 * Parse a PHP configuration file.
 *
 * Commented-out directives are returned with `active: false` so callers can see
 * that the setting was mentioned without treating it as configured.
 */
export function parseIni(content: string, kind: IniKind): IniParseResult {
  const directives: IniDirective[] = [];
  const issues: ScanIssue[] = [];

  content.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.length === 0) return;

    const commented = trimmed.startsWith(";") || trimmed.startsWith("#");
    const body = commented ? trimmed.slice(1).trim() : trimmed;
    if (body.length === 0) return;
    if (/^\[[^\]]*\]$/.test(body)) return;

    const extracted = extractDirective(body);
    if (!extracted) return;

    const value = unquote(stripInlineComment(extracted.value));
    directives.push({
      name: extracted.name,
      value,
      line: index + 1,
      active: !commented,
      kind
    });
  });

  return { directives, issues };
}

const FALSEY = new Set(["0", "off", "false", "no", "none", ""]);
const TRUTHY = new Set(["1", "on", "true", "yes"]);

export function isDisabledValue(value: string): boolean {
  return FALSEY.has(value.trim().toLowerCase());
}

export function isEnabledValue(value: string): boolean {
  return TRUTHY.has(value.trim().toLowerCase());
}

const SIZE_UNITS: Record<string, number> = {
  "": 1,
  K: 1024,
  M: 1024 * 1024,
  G: 1024 * 1024 * 1024
};

/** Parse a php.ini shorthand size such as "8M" or "1G". Returns undefined if unknown. */
export function parseIniSize(value: string): number | undefined {
  const match = /^(\d+)\s*([KMG]?)B?$/i.exec(value.trim());
  if (!match) return undefined;
  const unit = SIZE_UNITS[match[2].toUpperCase()];
  return Number(match[1]) * unit;
}

export function isUnlimitedMemory(value: string): boolean {
  const trimmed = value.trim().toLowerCase();
  return trimmed === "-1" || trimmed === "unlimited" || trimmed === "infinite";
}
