# Changelog

## 0.2.0 — 2026-10-25

Correctness release. The detection core was rebuilt around validated advisory data and
tested behaviour.

### Fixed

- **Advisory data is now actually used.** `src/advisories/advisories.json` was never
  imported; fixed versions were duplicated in code. The JSON is now the single source of
  truth, validated at load, with https-only references and a `retrievedAt` date.
- **CVE-2026-115560 reclassified.** It is an unpatched, informational PHP core RCE that
  requires an unusual session serialiser setup — not a "configuration advisory". The
  upload-progress check now cites it together with CVE-2026-109619, whose interim
  mitigation is the same directive.
- **Composer audit works on Windows.** A `composer.bat` shim cannot be spawned without a
  shell and used to fail every time. The extension now resolves a phar through `php`,
  then falls back through `composerPath` and `composer`, and reports what it tried.
- **Advisories are no longer lost when audit exits non-zero.** `composer audit` exits
  non-zero when it finds advisories; output parsing now reads stdout only instead of
  concatenating stdout and stderr, and tolerates banners and warnings.
- **Version matching is sound.** Numeric parsing no longer turns unparseable input into
  "newer than fixed". Prereleases, distribution suffixes and missing patch levels are
  modelled, and an unreadable version is reported as unparsed instead of passing quietly.
- **Floating Docker tags are separated from exact versions.** `php:8.2-fpm` is reported as
  an unpinned branch tag, not as PHP 8.2.0. Digest-only, `latest` and `ARG`-interpolated
  tags are reported instead of being silently dropped.
- **Compose images are parsed.** Compose files were matched by the walker but their
  `image:` keys were never read.
- **Comment-only ini lines no longer count as configuration.** A commented-out
  `session.upload_progress.enabled = 0` used to suppress the warning; only active
  directives count, and a `.user.ini` disable is explicitly treated as insufficient for a
  pre-parse mitigation.
- **Unknown versions no longer read as safe.** Branches outside the bundled data are
  reported as uncovered, and PHP 8.1 and older as vendor dependent.
- **Source rules over-claimed.** `$pdo->exec()` matched command execution; `include $x;`
  without parentheses was missed; every heuristic was reported at `high`. Rules are now
  capped at `medium`, method calls are excluded, and findings say they are heuristics.
- **Scan gaps are visible.** Unreadable files, skipped symlinks, oversized files and the
  file limit are reported; the limit is only claimed when a matching file was skipped.

### Added

- Editor diagnostics for every finding that has a file and line, with advisory-backed
  findings mapped to errors and heuristics never above warnings.
- Findings tree grouped by severity, with navigation to the exact line.
- Per-finding observation source (`php-cli`, `dockerfile`, `compose-image`, `ini`,
  `fpm-pool`, `apache`, `composer-constraint`, `composer-audit`) and a
  `local-dev`/`container-declared`/`declared-constraint` scope on version findings.
- Advisory-grounded configuration checks: upload progress, `memory_limit`,
  `post_max_size`, and `fatal_error_backtraces` on PHP 8.5.
- Trust gating: no external process runs in an untrusted workspace.
- 127 unit and integration tests (`node:test`), including regression tests for the
  Composer exit-code path and the commented-ini suppression.

### Changed

- Settings: added `maxFileBytes`, `includeVendor`, `phpPath`, `composerPath`,
  `composerPharPath`.
- `@types/vscode` pinned to 1.90.0 to match the declared engine.
- Removed the unused "Open advisory" command and the empty `problemMatcher`.
- Scans are cancellable and report a partial result when cancelled.
