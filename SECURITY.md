# Security Policy

This project is a security tool in active development. It reports observations; it does
not certify that a deployment is safe.

## Reporting a vulnerability

Do not publish secrets, exploit payloads against third-party systems, or sensitive server
reports in public issues. Open a private security advisory through the repository's GitHub
Security tab when private reporting is enabled. Until then, contact the maintainers
privately through a verified repository channel.

## In scope

- Code execution introduced by the extension (for example shell interpolation, unsafe
  argument construction, or a path that executes workspace content).
- Reading files outside the workspace, following symlinks out of it, or ignoring
  `maxFileBytes`/`maxFiles` in a way that creates denial of service.
- Misleading detection behaviour that could cause a user to believe a vulnerable runtime
  is fixed, or a fixed runtime is vulnerable.
- Incorrect advisory identifiers, affected ranges, fixed versions or mitigation guidance.
- Secret leakage through diagnostics, the output channel or the packaged extension.

## Out of scope

- Vulnerabilities in PHP, Composer, VS Code or third-party packages themselves.
- Results that are explicitly labelled heuristic, unassessed or vendor dependent.
- Findings that depend on a runtime the extension cannot observe (the scanner says so).

## How findings are handled

- Advisory facts are verified against php.net, CERT-EU and CISA before being added; every
  record records its references and the date it was retrieved.
- A report that a heuristic rule is noisy is a bug report, not a security report, unless it
  causes a false "safe" conclusion.
- Fixed versions are never hard-coded outside `src/advisories/advisories.json`, and tests
  enforce schema and README consistency.

## Limitations

This tool is not a replacement for patch management, a full static analyser, incident
response or vendor advisories. See [LIMITATIONS.md](LIMITATIONS.md).
