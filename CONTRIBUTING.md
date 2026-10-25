# Contributing

Contributions that improve correctness are especially welcome.

- Include authoritative sources for vulnerability and fixed-version claims.
- Add tests for every detection rule and edge case.
- Label heuristic findings as potential/review-needed unless exploitability is established.
- Do not treat `composer.json` constraints as the deployed PHP runtime.
- Account for distribution/vendor backports.
- Never add exploit code or remote scanning without a documented, authorized test design.
- Keep default behavior local-first and read-only.
