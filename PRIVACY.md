# Privacy

PHP Security Guard is local-first and read-only. This document describes exactly what it
reads, what leaves the machine and what it stores.

## What the extension reads

Only files inside the opened workspace, and only those matching its analyser set:

- `*.php`
- `composer.json`, `composer.lock`
- `Dockerfile` and `Dockerfile.*`
- `docker-compose*.yml`, `compose*.yml` (and `.yaml`)
- `php.ini`, `php.ini-*`, `conf.d/*.ini`, `pool.d/*.conf`, `.user.ini`, `httpd.conf`,
  `apache2.conf`

It does **not** read `.env` files, `auth.json`, SSH keys, cloud credential files, browser
data or anything outside the workspace. Symbolic links are skipped rather than followed,
so the scan cannot leave the workspace through a link.

## What leaves the machine

There is exactly one network path:

**`composer audit`** — when enabled, a `composer.lock` exists and the workspace is
trusted. Composer contacts packagist.org (or the package repositories configured in your
Composer setup) and asks which advisories apply to the installed package names and
versions. That request contains dependency metadata, not your source code. It is the
same request `composer audit` makes when you run it yourself. Disable it with
`phpSecurityGuard.runComposerAudit: false`.

Nothing else makes a network request. There is no telemetry, analytics, crash reporting
or update check in this extension. Advisory data is bundled with the extension and is not
fetched at runtime.

`php -v` runs locally and produces no network traffic.

Workspace files, source code, findings and configuration are never uploaded.

## What is executed

- `php -v` — only the version flag. Workspace files are never executed.
- `composer audit ...` — with `--no-plugins` and `--no-scripts`, so project-defined
  plugins and scripts do not run. Arguments are passed as a fixed array with
  `shell: false`; no workspace string is interpreted by a shell.

Both are skipped entirely in an untrusted workspace.

## What is stored

The extension writes no files, no cache and no database. Findings live in memory and are
shown in the Explorer panel, the Problems list and an Output channel that VS Code owns.

The Output channel contains analysed file paths, evidence lines and recommendations. It
survives until the window closes and can be copied by you. Evidence is trimmed and
obvious inline credential assignments (`password = "..."`) are redacted, but treat the
report as sensitive: it can reveal file layout and code snippets.

Diagnostics are cleared and replaced on every scan and are disposed when the extension
deactivates.

## Third parties

- PHP advisory facts: php.net, CERT-EU, CISA (bundled at build time).
- Composer advisories: packagist.org, queried at scan time by Composer itself.

Neither receives your source code.

## Removing data

Nothing is persisted by the extension, so there is nothing to delete. Uninstalling the
extension removes its code; Composer's own cache under `COMPOSER_HOME` is managed by
Composer, not by this extension.
