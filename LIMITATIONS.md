# Limitations

Read this before acting on a report, and before treating a clean scan as good news.

## Version observations are not the runtime

- `php -v` reports the CLI binary that the **extension host** can find. PHP-FPM, Apache
  `mod_php`, php-cgi, FrankenPHP, LiteSpeed and containers may all run something else.
- A `Dockerfile` or Compose `image:` line is a **declaration**. The running container may
  use a different digest, or a base image rebuilt by someone else.
- A `composer.json` constraint (`require.php`, `config.platform.php`) is a
  **dependency-resolution declaration**. It does not describe the runtime, and
  `config.platform.php` exists specifically to mask the real platform from Composer.
- This extension does not scan remote hosts, registries, Kubernetes clusters or CI
  runners.

Every finding names its observation source so these differences stay visible.

## Configuration text is not the effective configuration

- Reading `php.ini` does not prove what the web SAPI loaded. Included files, `Scan this
  dir`, FPM pool overrides, Apache `<Directory>` blocks, container entrypoints and
  environment-driven ini files can all change the result.
- `.user.ini` and `ini_set()` are applied **per request**. PHP's guidance for
  CVE-2026-109619 explicitly says they are not sufficient for a pre-parse mitigation, and
  this scanner does not accept a `.user.ini` disable as satisfying it.
- Directive ordering across files is not resolved. The scanner reports what it observed
  and, where it matters, says that the effective value is unproven.
- Defaults are used only where PHP documents them (for example
  `session.upload_progress.enabled` defaults to On, `memory_limit` to 128M).

## Vendor builds and backports

- Distributions and LTS vendors backport fixes without changing the upstream version.
  A `-1+ubuntu22.04` or `+deb12u1` build may be patched while looking older, or unpatched
  while looking newer.
- For PHP 8.1 and older the tool reports *vendor dependent*, never safe and never fixed.
  PHP published minimal source backports for 7.4, 8.0 and 8.1; only your vendor can tell
  you whether your package includes them.
- Prereleases (`RC`, `beta`, `alpha`) are compared as older than the matching final
  release. They are not fixed releases.

## Advisory data is a snapshot

- Data is bundled with the extension and stamped with a `retrievedAt` date. It is not
  refreshed automatically, because the extension makes no network request for advisories.
- Uncovered branches are reported as *not assessed*. That is not a statement that they
  are safe.
- Only the advisories listed in the README are modelled. Other PHP core, SAPIs, extension
  or library vulnerabilities are out of scope.

## Composer auditing

- Covers Composer packages only. It says nothing about PHP core, web-server modules,
  JavaScript dependencies or OS packages.
- Requires a `composer.lock`. Without Composer installed — or on Windows with only a
  `composer.bat` shim, which cannot be launched without a shell — the audit is reported as
  not run, with the candidates that were tried.
- Composer must reach packagist.org. Offline runs fail and are reported.
- Advisories without a published severity are shown at `medium` with an explicit note;
  the severity is a placeholder, not an assigned CVSS score.
- Abandoned packages are reported separately and are not vulnerabilities.

## Source rules are heuristics

- Matching is **line-based**. There is no parsing, no data-flow analysis and no
  interprocedural tracking, so multi-statement and cross-file flows are missed.
- Request-to-sink rules only fire when both ends appear on the same line.
- Strings are not masked, so a pattern inside a string literal can still match. Lines
  that consist only of a comment are skipped, but trailing comments are not.
- Method calls such as `$pdo->exec()` are excluded from command-execution matching, but
  other dynamic dispatch can still produce false positives.
- A match is a **review prompt**, not proof of a vulnerability, and it is capped at
  `medium` severity for that reason.
- No suppression mechanism exists. Findings are shown as observed; if a pattern is
  acceptable in your codebase, record that decision in your own review process rather than
  expecting the scanner to hide it.

## Coverage limits

- `vendor`, `node_modules`, `dist`, `build`, `coverage`, `.git` and similar directories
  are skipped by default. `vendor` can be enabled.
- Symbolic links are skipped, not followed, which keeps the scan inside the workspace but
  means linked source is not analysed. Skips are counted and reported.
- Files larger than `phpSecurityGuard.maxFileBytes` are skipped and reported rather than
  partially analysed.
- `phpSecurityGuard.maxFiles` caps the number of analysable files. Reaching it produces a
  finding so the gap is visible.
- Unreadable files and directories are reported, not silently ignored.

## Composer files and untrusted workspaces

- In an untrusted workspace, no external process runs. Runtime and Composer checks are
  listed as skipped.
- Composer plugins and project scripts are disabled during audit. A project that requires
  a plugin for its audit output will be reported as not run rather than executed.

## What this tool is not

Not a SAST engine, not a patch-management system, not an incident-response tool, not a
compliance certificate, and not a substitute for the official advisories or your vendor's
security notices. It does not exploit, validate or confirm any vulnerability.
