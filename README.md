# PHP Security Guard

Local-first security checks for PHP projects inside VS Code. It reports what it can
observe about PHP runtime versions, advisory-relevant configuration, Composer
dependencies and a small set of risky source patterns — with the source of every
observation named.

This is a triage tool. It cannot certify that a deployment is safe.

## What it does

| Check | What it reads | What it does **not** do |
| --- | --- | --- |
| PHP version observations | `php -v`, `Dockerfile` `FROM`, Compose `image:`, `composer.json` constraints | It does not prove which PHP serves production |
| Configuration | `php.ini`, `conf.d/*.ini`, FPM `pool.d/*.conf`, `.user.ini`, Apache config | It does not prove the *effective* configuration |
| Composer advisories | `composer audit --format=json --locked` | It does not cover PHP core vulnerabilities |
| Source review candidates | Line-based PHP rules | It does not prove a vulnerability |

Every version finding carries an observation like `local-dev`, `container-declared`
or `declared-constraint`, so a `composer.json` constraint is never presented as the
runtime version.

## Supported advisory data

Bundled data, retrieved **2026-10-25**:

| Branch | First fixed release |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

Covered advisories:

- **CVE-2026-109618** (GHSA-w8hw-w9fx-j79w) — PHP core RCE via out-of-memory request cleanup.
- **CVE-2026-109619** (GHSA-6wmf-4rv5-p3rp) — PHP core RCE via stale request global state.
- **CVE-2026-115560** — an additional PHP core RCE disclosed on 23 October 2026. PHP
  published an **informational** advisory: it requires upload progress to stay enabled
  together with an unusual session serialiser configuration, and PHP considers the risk
  unlikely. No out-of-band fix was issued; PHP recommends disabling session upload
  progress until the next regular bugfix release. This is **not** a configuration-only
  advisory.

PHP 8.1 and older are **affected** per the advisories. Those branches no longer receive
upstream fixes; PHP published minimal source backports for 7.4, 8.0 and 8.1, and some
distributions and LTS vendors provide backported packages. This tool therefore reports
those versions as *vendor dependent* — never as safe.

Sources: [PHP news archive](https://www.php.net/archive/2026.php),
[CERT-EU 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/),
[CISA alert 2026-10-21](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching).

## How to read a finding

Each finding states:

- **Severity** — potential impact if the finding is real (`critical` … `info`).
- **Confidence** — how sure this scanner is about *this observation*.
- **Proof** — `advisory-backed` or `heuristic only`.
- **Observed via** — `php-cli`, `dockerfile`, `compose-image`, `ini`, `fpm-pool`,
  `apache`, `composer-constraint` or `composer-audit`.
- Evidence, file and line, remediation and references.

Heuristic source findings are capped at `medium` severity and never appear as editor
errors. They are review prompts, not proof.

An `uncovered` verdict means the bundled data has no entry for that branch. It is
explicitly **not** a clean bill of health.

## Commands and settings

- **PHP Security Guard: Scan Workspace** — also available from the view title.
- **PHP Security Guard: Show Last Report** — reopens the output channel.

| Setting | Default | Purpose |
| --- | --- | --- |
| `phpSecurityGuard.enableSourceHeuristics` | `true` | Line-based source review candidates |
| `phpSecurityGuard.runComposerAudit` | `true` | Run `composer audit` when a lock file exists |
| `phpSecurityGuard.maxFiles` | `5000` | Hard cap on analysed files |
| `phpSecurityGuard.maxFileBytes` | `1048576` | Files larger than this are skipped and reported |
| `phpSecurityGuard.includeVendor` | `false` | Analyse `vendor/` as well |
| `phpSecurityGuard.phpPath` | `""` | Path to the `php` executable (default: PATH) |
| `phpSecurityGuard.composerPath` | `""` | Path to a Composer executable |
| `phpSecurityGuard.composerPharPath` | `""` | Path to `composer.phar`, launched through PHP |

### Windows and Composer

A `composer.bat` shim cannot be launched without a shell, and this extension never uses
one. On Windows, set `phpSecurityGuard.composerPharPath` (or `composerPath` pointing at a
real executable). The scan reports which candidates it tried when Composer cannot start.

### Untrusted workspaces

In an untrusted workspace the extension still reads files, but **never executes** `php`
or Composer. The report lists the skipped checks.

## Privacy

Local and read-only. No telemetry. The one network path is `composer audit`, which asks
packagist.org about installed packages. See [PRIVACY.md](PRIVACY.md) for the exact data
flows.

## Requirements

- VS Code 1.90 or newer.
- Node.js 22+ and npm to build from source and run the test suite (the extension
  itself runs on VS Code's extension host).
- PHP and Composer are optional; without them the corresponding checks are reported as
  not run rather than silently dropped.

## Development

```bash
npm install
npm run check   # tsc --noEmit
npm test        # compiles tests and runs node --test
npm run compile # build to out/
```

Open the folder in VS Code and press `F5`, then run **PHP Security Guard: Scan
Workspace** in the Extension Development Host.

Advisory data lives in [src/advisories/advisories.json](src/advisories/advisories.json).
It is validated at load time and is the only source of fixed versions; tests enforce
schema, https-only references and README consistency.

## Limitations

Read [LIMITATIONS.md](LIMITATIONS.md) before using this in an incident or an audit. In
short: a CLI version is not the web runtime, a declared image is not the running image,
text configuration is not the effective configuration, vendor backports are not
adjudicated, and line-based heuristics miss cross-statement flows.

## Roadmap

1. Optional signed advisory feed with provenance, replacing the bundled snapshot.
2. Extension-host integration tests via `@vscode/test-electron`.
3. Integration with a maintained PHP analyser for data-flow checks.

## Responsible use

Use only on workspaces and systems you are authorised to assess. Do not treat a clean
report as evidence that an internet-facing server is patched.
