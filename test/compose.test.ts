import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCompose } from "../src/core/compose";

const FILE = [
  "services:",
  "  app:",
  "    build: .",
  "    image: php:8.2.34-fpm",
  "  worker:",
  "    image: 'php:8.2-fpm'",
  "  db:",
  "    image: mysql:8.0",
  "  cache:",
  '    image: "php:latest"  # floating',
  ""
].join("\n");

test("finds PHP images and records their line numbers", () => {
  const result = parseCompose(FILE);
  assert.deepEqual(
    result.images.map(image => image.line),
    [4, 6, 10]
  );
  assert.equal(result.images[0].resolution, "exact");
  assert.equal(result.images[0].version?.patch, 34);
  assert.equal(result.images[1].resolution, "branch-floating");
  assert.equal(result.images[1].tag, "8.2-fpm");
  assert.equal(result.images[2].resolution, "unresolved");
});

test("ignores non-PHP images and build keys", () => {
  const result = parseCompose(FILE);
  assert.ok(result.images.every(image => image.name.endsWith("php")));
  assert.equal(result.images.length, 3);
});

test("strips an inline YAML comment after whitespace", () => {
  const result = parseCompose("services:\n  app:\n    image: php:8.2.34 # pinned\n");
  assert.equal(result.images[0].tag, "8.2.34");
  assert.equal(result.images[0].resolution, "exact");
});

test("reports an image key with no value", () => {
  const result = parseCompose("services:\n  app:\n    image:\n");
  assert.equal(result.images.length, 0);
  assert.equal(result.notes.length, 1);
});

test("does not treat a digest # as a comment", () => {
  const result = parseCompose("services:\n  app:\n    image: php@sha256:abc#def\n");
  assert.equal(result.images.length, 1);
  assert.equal(result.images[0].resolution, "unresolved");
});
