# PHP Security Guard

A local-first VS Code extension prototype for triaging PHP security issues.

## Scope

- Checks the local PHP CLI version when available.
- Inspects common Docker/PHP configuration files for runtime and session-upload-progress clues.
- Runs `composer audit --format=json` when enabled and a `composer.lock` exists.
- Flags a few conservative PHP source patterns for **manual review**.
- Presents findings in a VS Code Explorer panel and Output channel.

## Important limitations

This is an early prototype, not a complete SAST engine and not a guarantee that a deployment is secure.

- A local `php -v` result may not match PHP-FPM, Apache `mod_php`, a container, or production.
- A version declaration in a Dockerfile is not proof of the currently deployed image.
- Linux distributions and commercial vendors may backport security fixes without changing the upstream version in the usual way. Verify vendor advisories.
- The source-pattern checks are intentionally simple heuristics. They can miss vulnerabilities and produce false positives.
- Composer audit checks PHP package advisories, not PHP core runtime vulnerabilities.
- Configuration text inspection does not establish the effective configuration used before request parsing.
- This extension does not send source code to a service, scan remote hosts, exploit targets, or modify project files.

## Build and run

Requirements: Node.js 20+ and npm. VS Code is needed to run the extension host.

```bash
npm install
npm run compile
```

Open this folder in VS Code, press `F5`, then in the Extension Development Host run:

`PHP Security Guard: Scan Workspace`

To package it locally, install `@vscode/vsce` and run `vsce package`.

## Initial PHP2Shell advisory data

The initial data covers CVE-2026-109618 and CVE-2026-109619 using the PHP project's October 2026 fixed releases:

- PHP 8.2.35
- PHP 8.3.36
- PHP 8.4.27
- PHP 8.5.12

This branch-based comparison is only a triage signal. For PHP 8.1 and earlier, and for vendor-maintained builds, consult the relevant vendor's security advisory. Never interpret an unknown version as safe.

The advisory data also tracks CVE-2026-115560 as a configuration advisory. Confirm current official release status before relying on this rule.

Primary references:

- https://www.php.net/archive/2026.php#2026-10-20-1
- https://cert.europa.eu/publications/security-advisories/2026-018
- https://getcomposer.org/doc/03-cli.md#audit

## Roadmap

1. Add automated unit tests for version parsing, vendor backports and advisory-data validation.
2. Add language-server diagnostics with exact source ranges and severity mappings.
3. Replace source regex heuristics with integration to a maintained PHP analyzer (Psalm or PHPStan rules) and a carefully reviewed ruleset.
4. Add a signed/versioned advisory feed with provenance and freshness metadata.
5. Add platform-specific container and package-manager inventory checks.
6. Add Eclipse/NetBeans adapters only after the analysis core is independently tested.

## Responsible use

Use only on workspaces and systems you are authorized to assess. Do not use this tool as evidence that an internet-facing server is patched. During an active incident, follow the official advisory and patch/contain the affected deployment before relying on new tooling.
