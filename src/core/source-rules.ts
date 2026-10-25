import type { Confidence, Severity } from "../types";

export interface SourceRule {
  id: string;
  title: string;
  summary: string;
  /** Heuristic rules are capped at "medium" severity by construction. */
  severity: Severity;
  confidence: Confidence;
  why: string;
  howToVerify: string;
  references: string[];
  test: (line: string) => boolean;
}

const MANUAL = "https://www.php.net/manual/en";

/**
 * Line-based PHP rules.
 *
 * These are heuristics: they identify code worth a manual review and never
 * prove that a vulnerability exists. Method calls (`$pdo->exec`) are excluded
 * from command-execution matching, and comment-only lines are skipped.
 *
 * Limitation: strings are not masked, so a pattern inside a string literal can
 * still match.
 */
export const SOURCE_RULES: SourceRule[] = [
  {
    id: "php-command-exec",
    title: "Command execution with a non-literal argument",
    summary:
      "A process-execution function is called with a variable or expression rather than a fixed string.",
    severity: "medium",
    confidence: "low",
    why: "If an attacker controls any part of the command, this can become remote command execution.",
    howToVerify:
      "Trace the argument back to its source. Prefer avoiding shell commands; otherwise use a fixed executable with an argument array and a strict allowlist.",
    references: [`${MANUAL}/function.exec.php`, `${MANUAL}/security.php`],
    test: line => /(?<![>\w:])(?:exec|system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$[A-Za-z_]/.test(line)
  },
  {
    id: "php-unserialize",
    title: "unserialize() with a non-literal argument",
    summary: "unserialize() is called on a variable instead of a trusted literal.",
    severity: "medium",
    confidence: "low",
    why: "Unserialising attacker-controlled data can trigger object injection and dangerous magic methods.",
    howToVerify:
      "Check whether the serialised data can come from a request, cookie, cache or database written by users. Prefer JSON with an explicit schema.",
    references: [`${MANUAL}/function.unserialize.php`],
    test: line => /(?<![>\w:])unserialize\s*\(\s*\$[A-Za-z_]/.test(line)
  },
  {
    id: "php-dynamic-include",
    title: "Dynamic file inclusion",
    summary: "include/require is given a variable path, with or without parentheses.",
    severity: "medium",
    confidence: "low",
    why: "A user-influenced include path can load attacker-controlled files (local or remote file inclusion).",
    howToVerify: "Confirm the path cannot be influenced by request data. Prefer a fixed map from identifiers to files.",
    references: [`${MANUAL}/function.include.php`],
    test: line => /(?<![>\w:])(?:include|include_once|require|require_once)\s*\(?\s*\$[A-Za-z_]/.test(line)
  },
  {
    id: "php-eval",
    title: "eval() with a non-literal argument",
    summary: "eval() is called with a variable rather than a fixed string.",
    severity: "medium",
    confidence: "low",
    why: "eval() executes arbitrary PHP; any influence over its argument is code execution.",
    howToVerify: "Establish whether the argument can be influenced by input. Remove eval() where possible.",
    references: [`${MANUAL}/function.eval.php`],
    test: line => /(?<![>\w:])eval\s*\(\s*\$[A-Za-z_]/.test(line)
  },
  {
    id: "php-assert-string",
    title: "assert() with a non-literal argument",
    summary: "assert() is called with a variable; older PHP versions evaluate string assertions as code.",
    severity: "medium",
    confidence: "low",
    why: "String assertions were evaluated as PHP code before PHP 8, and dynamic assertions are easy to misuse.",
    howToVerify: "Confirm the code does not rely on string evaluation and that the argument is not attacker-influenced.",
    references: [`${MANUAL}/function.assert.php`],
    test: line => /(?<![>\w:])assert\s*\(\s*\$[A-Za-z_]/.test(line)
  },
  {
    id: "php-callable-from-input",
    title: "Function call built from request input",
    summary: "A request value is used directly as a callable.",
    severity: "medium",
    confidence: "low",
    why: "Calling a function named by user input can reach dangerous functions such as system() or eval().",
    howToVerify: "Replace dynamic dispatch with an allowlist of permitted operations.",
    references: [`${MANUAL}/security.php`],
    test: line => /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/.test(line)
  },
  {
    id: "php-extract-superglobal",
    title: "extract() on request data",
    summary: "extract() is called with a superglobal, creating variables from user-controlled keys.",
    severity: "medium",
    confidence: "low",
    why: "extract() can overwrite local variables and bypass assumptions about where values came from.",
    howToVerify: "Check which variables can be overwritten; prefer explicit assignments.",
    references: [`${MANUAL}/function.extract.php`],
    test: line => /(?<![>\w:])extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/.test(line)
  },
  {
    id: "php-preg-replace-e",
    title: "preg_replace() with the /e modifier",
    summary: "The pattern uses the /e modifier, which evaluated the replacement as PHP code.",
    severity: "medium",
    confidence: "low",
    why: "The /e modifier executes the replacement string as code and was removed in PHP 7.",
    howToVerify: "Confirm the code is reachable on a supported PHP version and replace it with preg_replace_callback().",
    references: [`${MANUAL}/function.preg-replace.php`],
    test: line => /preg_replace\s*\(\s*['"][^'"]*\/[a-zA-Z]*e[a-zA-Z]*['"]/.test(line)
  },
  {
    id: "php-sql-concat",
    title: "SQL statement built with request data",
    summary: "A query is executed on the same line as a superglobal, suggesting string-built SQL.",
    severity: "medium",
    confidence: "low",
    why: "Concatenating input into SQL is the classic injection pattern.",
    howToVerify: "Check whether the value is bound as a parameter. Prefer prepared statements everywhere.",
    references: [`${MANUAL}/mysqli.query.php`, `${MANUAL}/security.database.sql-injection.php`],
    test: line =>
      (/\$_(?:GET|POST|REQUEST|COOKIE)[^;]{0,160}(?:->query|->prepare|->exec|mysqli_query|mysql_query)\s*\(/.test(line) ||
        /(?:->query|->prepare|mysqli_query|mysql_query)\s*\([^;]{0,160}\$_(?:GET|POST|REQUEST|COOKIE)/.test(line))
  },
  {
    id: "php-echo-input",
    title: "Request data written to output",
    summary: "A superglobal is echoed or printed, suggesting unescaped output.",
    severity: "medium",
    confidence: "low",
    why: "Printing request data without context-aware escaping enables cross-site scripting.",
    howToVerify: "Check for htmlspecialchars() with ENT_QUOTES and the correct encoding, or a templating engine with auto-escaping.",
    references: [`${MANUAL}/function.htmlspecialchars.php`],
    test: line => /\b(?:echo|print|printf|print_r|var_dump)\b[^;]{0,100}\$_(?:GET|POST|REQUEST|COOKIE|SERVER)/.test(line)
  },
  {
    id: "php-header-location-input",
    title: "Redirect target built from input",
    summary: "A Location header is concatenated with a variable.",
    severity: "medium",
    confidence: "low",
    why: "An attacker-influenced redirect target enables open redirects and, in some flows, token leakage.",
    howToVerify: "Confirm the target is validated against an allowlist of internal paths or hosts.",
    references: [`${MANUAL}/function.header.php`],
    test: line => /header\s*\(\s*['"]Location:[^'"]*['"]\s*\.\s*\$/.test(line)
  },
  {
    id: "php-ssrf-input",
    title: "Remote request to a variable URL",
    summary: "A URL-fetching function is called with request data.",
    severity: "medium",
    confidence: "low",
    why: "Fetching an attacker-chosen URL enables server-side request forgery against internal services.",
    howToVerify: "Check for scheme/host allowlisting and blocked private address ranges.",
    references: [`${MANUAL}/function.file-get-contents.php`],
    test: line =>
      /(?<![>\w:])(?:file_get_contents|fopen|readfile|curl_init)\s*\(\s*\$_/.test(line) ||
      /CURLOPT_URL\s*,\s*\$_/.test(line)
  },
  {
    id: "php-weak-password-hash",
    title: "Fast hash used near a password",
    summary: "md5() or sha1() appears on a line that also mentions a password.",
    severity: "medium",
    confidence: "low",
    why: "Fast hashes are unsuitable for password storage and are cheap to brute-force.",
    howToVerify: "Confirm the value is a password. Use password_hash() with PASSWORD_DEFAULT and password_verify().",
    references: [`${MANUAL}/function.password-hash.php`],
    test: line => /(?:md5|sha1)\s*\(/.test(line) && /\bpassword\b/i.test(line)
  },
  {
    id: "php-weak-random-token",
    title: "Non-cryptographic randomness near a token",
    summary: "rand(), mt_rand() or uniqid() appears on a line that mentions a token or secret.",
    severity: "medium",
    confidence: "low",
    why: "Predictable values are unsuitable for security tokens, nonces and password resets.",
    howToVerify: "Confirm the value is security-sensitive. Use random_bytes() or random_int().",
    references: [`${MANUAL}/function.random-bytes.php`],
    test: line =>
      /(?<![>\w:])(?:rand|mt_rand|uniqid)\s*\(/.test(line) &&
      /\b(?:token|nonce|csrf|secret|password|salt|reset)\b/i.test(line)
  },
  {
    id: "php-phpinfo",
    title: "phpinfo() left in code",
    summary: "phpinfo() exposes configuration and environment details.",
    severity: "low",
    confidence: "medium",
    why: "phpinfo() discloses paths, extensions and configuration that help an attacker.",
    howToVerify: "Confirm the call is not reachable in production, or remove it.",
    references: [`${MANUAL}/function.phpinfo.php`],
    test: line => /(?<![>\w:])phpinfo\s*\(/.test(line)
  }
];

export interface SourceMatch {
  rule: SourceRule;
  line: number;
  evidence: string;
}

const MAX_EVIDENCE = 300;

const SECRET_ASSIGNMENT = /\b(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key)\b(\s*=\s*)(["'])[^"']*\3/gi;

/** Keep obvious inline credentials out of the output channel and issue reports. */
export function redactSecrets(text: string): string {
  return text.replace(
    SECRET_ASSIGNMENT,
    (_match, name: string, separator: string, quote: string) =>
      `${name}${separator}${quote}[redacted]${quote}`
  );
}

function isCommentOnly(trimmed: string): boolean {
  return (
    trimmed.startsWith("//") ||
    trimmed.startsWith("#") ||
    trimmed.startsWith("*") ||
    trimmed.startsWith("/*") ||
    trimmed.startsWith("*/")
  );
}

/** Inspect PHP source text and return review candidates. */
export function inspectSource(content: string, rules: SourceRule[] = SOURCE_RULES): SourceMatch[] {
  const matches: SourceMatch[] = [];
  content.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim();
    if (trimmed.length === 0 || isCommentOnly(trimmed)) return;
    for (const rule of rules) {
      if (!rule.test(line)) continue;
      matches.push({
        rule,
        line: index + 1,
        evidence: redactSecrets(trimmed).slice(0, MAX_EVIDENCE)
      });
    }
  });
  return matches;
}
