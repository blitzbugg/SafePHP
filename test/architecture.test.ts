import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as path from "node:path";

function sourceFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...sourceFiles(full));
    else if (entry.name.endsWith(".ts")) files.push(full);
  }
  return files;
}

const SRC = path.join(process.cwd(), "src");

test("core modules never import the vscode API", () => {
  for (const file of sourceFiles(path.join(SRC, "core"))) {
    const content = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(content, /from\s+["']vscode["']/, path.relative(SRC, file));
  }
});

test("the codebase never enables a shell", () => {
  for (const file of sourceFiles(SRC)) {
    const content = fs.readFileSync(file, "utf8");
    const relative = path.relative(SRC, file);
    assert.doesNotMatch(content, /shell:\s*true/, relative);
    // Only the shell-capable `exec` helper is forbidden; execFile is the safe API.
    assert.doesNotMatch(
      content,
      /import\s*\{[^}]*\bexec\b[^}]*\}\s*from\s*["'](?:node:)?child_process["']/,
      relative
    );
    assert.doesNotMatch(content, /require\(["'](?:node:)?child_process["']\)\.exec\(/, relative);
  }
});

test("process execution is limited to execFile with a fixed argument vector", () => {
  const processFile = fs.readFileSync(path.join(SRC, "core", "process.ts"), "utf8");
  assert.match(processFile, /execFile\(/);
  assert.doesNotMatch(processFile, /execFileSync/);
});

test("no code path opens a file for writing", () => {
  for (const file of sourceFiles(SRC)) {
    const content = fs.readFileSync(file, "utf8");
    assert.doesNotMatch(content, /writeFile|appendFile|createWriteStream/, path.relative(SRC, file));
  }
});
