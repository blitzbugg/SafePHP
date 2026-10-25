# Contributing

Contributions that improve correctness are especially welcome.

## Rules that are not negotiable

- **No shell.** External processes use `execFile` with a fixed argument vector and
  `shell: false`. Never interpolate workspace text into a command string.
- **No execution of workspace code.** The only allowed invocations are `php -v` and
  `composer audit` with `--no-plugins --no-scripts`.
- **No silent suppression.** If a check cannot decide, emit an explicit `unassessed`,
  `uncovered` or `unparsed` finding. Never turn missing data into "safe".
- **No invented advisory data.** Identifiers, affected ranges, fixed versions and
  mitigation text must come from an authoritative source, and the record must list it.
- **No severity inflation.** Heuristic rules stay at `medium` or below and carry
  `proof: "none"`.

## Adding or updating an advisory

1. Confirm the facts against php.net and at least one national CERT or vendor advisory.
2. Edit `src/advisories/advisories.json` only. Do not hard-code versions anywhere else.
3. Update `retrievedAt` and the README table; `test/docs.test.ts` fails if they disagree.
4. Add or update a test in `test/advisories.test.ts` for the new range or status.
5. If the advisory needs a configuration check, cite the directive in `mitigations` and
   add the check to `src/core/scan.ts` with a test.

## Development

```bash
npm install
npm run check   # tsc --noEmit
npm test        # tsc -p tsconfig.test.json && node --test
```

Requirements for a pull request:

- `npm run check` and `npm test` pass, with no skipped tests and no weakened assertions.
- `src/core/**` does not import `vscode`; pure logic stays testable under Node.
- Every detection rule and parser branch has a positive and a negative test.
- New filesystem or process behaviour goes through the injectable interfaces in
  `src/core/walk.ts` and `src/core/process.ts` so it can be tested without touching disk
  or spawning processes.

## Style

- TypeScript strict mode; avoid `any` in new code.
- Findings must carry: id, title, severity, confidence, proof, kind, category, message,
  evidence, location when available, recommendation, references and advisory ids.
- User-facing text states what was observed and what remains unproven.

## Responsible behaviour

Never add exploit code, remote scanning or payload generation. Do not add features that
upload source code or run project scripts.
