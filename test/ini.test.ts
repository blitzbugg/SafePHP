import { test } from "node:test";
import assert from "node:assert/strict";
import {
  detectIniKind,
  isDisabledValue,
  isEnabledValue,
  isUnlimitedMemory,
  parseIni,
  parseIniSize
} from "../src/core/ini";

test("detects configuration file kinds", () => {
  assert.equal(detectIniKind("/app/php.ini"), "php-ini");
  assert.equal(detectIniKind("/app/php.ini-production"), "php-ini");
  assert.equal(detectIniKind("/app/.user.ini"), "user-ini");
  assert.equal(detectIniKind("/usr/local/etc/php/conf.d/99-custom.ini"), "php-ini");
  assert.equal(detectIniKind("/etc/php/8.2/fpm/pool.d/www.conf"), "fpm-pool");
  assert.equal(detectIniKind("/etc/apache2/apache2.conf"), "apache");
  assert.equal(detectIniKind("/etc/httpd/httpd.conf"), "apache");
  assert.equal(detectIniKind("/app/config/random.conf"), undefined);
  assert.equal(detectIniKind("/app/readme.md"), undefined);
});

test("a commented-out directive is never treated as configured", () => {
  const result = parseIni(
    [";session.upload_progress.enabled = 0", "#session.upload_progress.enabled = 0"].join("\n"),
    "php-ini"
  );
  assert.equal(result.directives.length, 2);
  assert.ok(result.directives.every(directive => directive.active === false));
});

test("an active directive is captured with its value and line", () => {
  const result = parseIni("session.upload_progress.enabled = 0", "php-ini");
  assert.equal(result.directives.length, 1);
  assert.equal(result.directives[0].name, "session.upload_progress.enabled");
  assert.equal(result.directives[0].value, "0");
  assert.equal(result.directives[0].line, 1);
  assert.equal(result.directives[0].active, true);
});

test("strips inline comments and surrounding quotes", () => {
  const result = parseIni(
    ['memory_limit = 128M ; production default', 'session.name = "PHPSESSID"'].join("\n"),
    "php-ini"
  );
  assert.equal(result.directives[0].value, "128M");
  assert.equal(result.directives[1].value, "PHPSESSID");
});

test("reads FPM pool php_admin_value directives", () => {
  const result = parseIni(
    ["[www]", "php_admin_value[session.upload_progress.enabled] = 0", "php_admin_value[memory_limit] = -1"].join(
      "\n"
    ),
    "fpm-pool"
  );
  assert.equal(result.directives.length, 2);
  assert.equal(result.directives[0].name, "session.upload_progress.enabled");
  assert.equal(result.directives[0].value, "0");
  assert.equal(result.directives[1].name, "memory_limit");
});

test("reads Apache php_admin_value directives", () => {
  const result = parseIni(
    ["<IfModule mod_php.c>", "php_admin_value session.upload_progress.enabled 0", "</IfModule>"].join("\n"),
    "apache"
  );
  assert.equal(result.directives.length, 1);
  assert.equal(result.directives[0].name, "session.upload_progress.enabled");
  assert.equal(result.directives[0].value, "0");
});

test("ignores sections and non-directive lines", () => {
  const result = parseIni(["[www]", "listen = /run/php.sock", "pm = dynamic"].join("\n"), "fpm-pool");
  assert.deepEqual(
    result.directives.map(directive => directive.name),
    ["listen", "pm"]
  );
});

test("interprets boolean ini values", () => {
  for (const value of ["0", "Off", "false", "no", ""]) {
    assert.equal(isDisabledValue(value), true, value);
  }
  for (const value of ["1", "On", "true", "yes"]) {
    assert.equal(isEnabledValue(value), true, value);
  }
  assert.equal(isDisabledValue("On"), false);
  assert.equal(isEnabledValue("Off"), false);
});

test("parses ini size shorthand", () => {
  assert.equal(parseIniSize("8M"), 8 * 1024 * 1024);
  assert.equal(parseIniSize("1G"), 1024 * 1024 * 1024);
  assert.equal(parseIniSize("512K"), 512 * 1024);
  assert.equal(parseIniSize("1024"), 1024);
  assert.equal(parseIniSize("lots"), undefined);
  assert.equal(parseIniSize("-1"), undefined);
});

test("recognises an unlimited memory limit", () => {
  assert.equal(isUnlimitedMemory("-1"), true);
  assert.equal(isUnlimitedMemory("unlimited"), true);
  assert.equal(isUnlimitedMemory("128M"), false);
});
