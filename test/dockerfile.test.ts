import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDockerfile, parseImageReference } from "../src/core/dockerfile";

test("parses an exact PHP image with a variant suffix", () => {
  const parsed = parseImageReference("php:8.2.34-fpm", 1);
  assert.ok(parsed);
  assert.equal(parsed.resolution, "exact");
  assert.equal(parsed.version?.major, 8);
  assert.equal(parsed.version?.minor, 2);
  assert.equal(parsed.version?.patch, 34);
  assert.equal(parsed.variant, "fpm");
});

test("parses an exact image through a registry prefix", () => {
  const parsed = parseImageReference("docker.io/library/php:8.3.35-cli", 1);
  assert.ok(parsed);
  assert.equal(parsed.resolution, "exact");
  assert.equal(parsed.tag, "8.3.35-cli");
});

test("marks a branch tag as floating rather than inventing a patch version", () => {
  const parsed = parseImageReference("php:8.2-fpm", 1);
  assert.ok(parsed);
  assert.equal(parsed.resolution, "branch-floating");
  assert.equal(parsed.version?.patch, 0);
  assert.match(parsed.reason ?? "", /floats/);
});

test("marks a major-only tag as major floating", () => {
  const parsed = parseImageReference("php:8", 1);
  assert.ok(parsed);
  assert.equal(parsed.resolution, "major-floating");
});

test("reports unresolved references instead of dropping them", () => {
  for (const reference of ["php", "php:latest", "php@sha256:abcdef", "php:bookworm"]) {
    const parsed = parseImageReference(reference, 1);
    assert.ok(parsed, reference);
    assert.equal(parsed.resolution, "unresolved", reference);
    assert.ok((parsed.reason ?? "").length > 0, reference);
  }
});

test("parses a prerelease tag", () => {
  const parsed = parseImageReference("php:8.4.0RC1-fpm", 1);
  assert.ok(parsed);
  assert.equal(parsed.resolution, "exact");
  assert.equal(parsed.version?.prerelease?.label, "rc");
});

test("ignores images that are not PHP", () => {
  assert.equal(parseImageReference("nginx:1.27", 1), undefined);
  assert.equal(parseImageReference("mysql:8.0", 1), undefined);
});

test("parses platform flags and stage names", () => {
  const result = parseDockerfile(
    ["FROM --platform=linux/amd64 php:8.4.27-apache AS app", "RUN echo hi"].join("\n")
  );
  assert.equal(result.images.length, 1);
  assert.equal(result.images[0].resolution, "exact");
  assert.equal(result.images[0].stage, "app");
  assert.equal(result.images[0].line, 1);
});

test("expands ARG defaults before parsing the tag", () => {
  const result = parseDockerfile(
    ["ARG PHP_VERSION=8.2.34", "FROM php:${PHP_VERSION}-fpm"].join("\n")
  );
  assert.equal(result.images.length, 1);
  assert.equal(result.images[0].resolution, "exact");
  assert.equal(result.images[0].version?.patch, 34);
  assert.equal(result.images[0].raw, "php:${PHP_VERSION}-fpm");
});

test("reports an unresolved ARG instead of silently ignoring the FROM", () => {
  const result = parseDockerfile(["ARG PHP_VERSION", "FROM php:${PHP_VERSION}-fpm"].join("\n"));
  assert.equal(result.images.length, 1);
  assert.equal(result.images[0].resolution, "unresolved");
  assert.match(result.images[0].reason ?? "", /build argument/i);
});

test("handles multi-stage builds", () => {
  const result = parseDockerfile(
    ["FROM php:8.1.31-cli AS build", "RUN true", "FROM php:8.4.27-fpm"].join("\n")
  );
  assert.equal(result.images.length, 2);
  assert.equal(result.images[0].version?.minor, 1);
  assert.equal(result.images[1].stage, undefined);
  assert.equal(result.images[1].line, 3);
});

test("ignores commented FROM lines", () => {
  const result = parseDockerfile("# FROM php:8.2.0-fpm\nFROM php:8.4.27-fpm");
  assert.equal(result.images.length, 1);
  assert.equal(result.images[0].line, 2);
});
