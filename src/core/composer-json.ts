import type { ScanIssue } from "../types";

export interface ComposerConstraint {
  file: string;
  field: "require.php" | "config.platform.php";
  constraint: string;
  line?: number;
}

export interface ComposerJsonResult {
  constraints: ComposerConstraint[];
  issues: ScanIssue[];
}

function findLine(content: string, key: string): number | undefined {
  const pattern = new RegExp(`"${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\s*:`);
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    if (pattern.test(lines[index])) return index + 1;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Extract PHP version constraints from composer.json.
 *
 * These are dependency-resolution declarations. They are never treated as the
 * runtime version: a project can declare ^8.1 and be served by PHP 7.4.
 */
export function parseComposerJson(content: string, file: string): ComposerJsonResult {
  const constraints: ComposerConstraint[] = [];
  const issues: ScanIssue[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    issues.push({
      code: "COMPOSER_JSON_INVALID",
      message: `composer.json could not be parsed: ${error instanceof Error ? error.message : "unknown error"}.`,
      file
    });
    return { constraints, issues };
  }

  if (!isRecord(parsed)) {
    issues.push({ code: "COMPOSER_JSON_INVALID", message: "composer.json is not a JSON object.", file });
    return { constraints, issues };
  }

  const require = isRecord(parsed.require) ? parsed.require : undefined;
  if (require && typeof require.php === "string") {
    constraints.push({
      file,
      field: "require.php",
      constraint: require.php,
      line: findLine(content, "php")
    });
  }

  const config = isRecord(parsed.config) ? parsed.config : undefined;
  const platform = config && isRecord(config.platform) ? config.platform : undefined;
  if (platform && typeof platform.php === "string") {
    constraints.push({
      file,
      field: "config.platform.php",
      constraint: platform.php,
      line: findLine(content, "php")
    });
  }

  return { constraints, issues };
}
