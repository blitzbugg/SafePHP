import { test } from "node:test";
import assert from "node:assert/strict";
import { inspectSource, SOURCE_RULES } from "../src/core/source-rules";

const ids = (source: string): string[] => inspectSource(source).map(match => match.rule.id);

test("rule ids are unique and every rule is capped at medium severity", () => {
  const seen = new Set<string>();
  for (const rule of SOURCE_RULES) {
    assert.ok(!seen.has(rule.id), `duplicate rule id ${rule.id}`);
    seen.add(rule.id);
    assert.ok(
      ["medium", "low", "info"].includes(rule.severity),
      `${rule.id} must not claim high or critical severity`
    );
    assert.ok(rule.references.every(reference => reference.startsWith("https://")), rule.id);
    assert.ok(rule.howToVerify.length > 0, rule.id);
  }
});

test("detects command execution with a variable argument", () => {
  assert.deepEqual(ids("<?php system($cmd);"), ["php-command-exec"]);
  assert.deepEqual(ids("<?php $out = shell_exec($userInput);"), ["php-command-exec"]);
});

test("does not confuse PDO or Redis method calls with command execution", () => {
  assert.deepEqual(ids("<?php $pdo->exec($sql);"), []);
  assert.deepEqual(ids("<?php $redis::exec($command);"), []);
  assert.deepEqual(ids("<?php $pdo->exec('DELETE FROM t');"), []);
});

test("ignores command execution with a literal argument", () => {
  assert.deepEqual(ids("<?php exec('ls -la');"), []);
});

test("detects dynamic includes with and without parentheses", () => {
  assert.deepEqual(ids("<?php include($page);"), ["php-dynamic-include"]);
  assert.deepEqual(ids("<?php require_once $page;"), ["php-dynamic-include"]);
  assert.deepEqual(ids("<?php require_once __DIR__ . '/boot.php';"), []);
});

test("detects unserialize and eval on variables", () => {
  assert.deepEqual(ids("<?php $data = unserialize($input);"), ["php-unserialize"]);
  assert.deepEqual(ids("<?php eval($code);"), ["php-eval"]);
  assert.deepEqual(ids("<?php unserialize('a:0:{}');"), []);
});

test("detects functions called from request input", () => {
  assert.deepEqual(ids("<?php $_GET['action']();"), ["php-callable-from-input"]);
});

test("detects extract on superglobals", () => {
  assert.deepEqual(ids("<?php extract($_POST);"), ["php-extract-superglobal"]);
});

test("detects the removed preg_replace /e modifier", () => {
  assert.deepEqual(ids("<?php preg_replace('/x/e', $replacement, $subject);"), [
    "php-preg-replace-e"
  ]);
  assert.deepEqual(ids("<?php preg_replace('/x/', 'y', $subject);"), []);
});

test("detects SQL built with request data in both orders", () => {
  assert.ok(ids("<?php mysqli_query($db, \"SELECT * FROM t WHERE id=\" . $_GET['id']);").includes("php-sql-concat"));
  assert.ok(ids("<?php $db->query(\"SELECT * FROM t WHERE id=\".$_GET['id']);").includes("php-sql-concat"));
  assert.deepEqual(ids("<?php $db->query('SELECT 1');"), []);
});

test("detects echoed request data and input-built redirects", () => {
  assert.ok(ids("<?php echo $_GET['name'];").includes("php-echo-input"));
  assert.ok(ids("<?php header('Location: ' . $next);").includes("php-header-location-input"));
});

test("detects remote fetches from request input", () => {
  assert.ok(ids("<?php $body = file_get_contents($_GET['url']);").includes("php-ssrf-input"));
  assert.ok(ids("<?php curl_setopt($ch, CURLOPT_URL, $_POST['url']);").includes("php-ssrf-input"));
});

test("requires password context for weak hash findings", () => {
  assert.ok(ids("<?php $hash = md5($password);").includes("php-weak-password-hash"));
  assert.deepEqual(ids("<?php $checksum = md5($fileContents);"), []);
});

test("requires token context for weak randomness findings", () => {
  assert.ok(ids("<?php $token = mt_rand();").includes("php-weak-random-token"));
  assert.deepEqual(ids("<?php $roll = mt_rand(1, 6);"), []);
});

test("detects phpinfo", () => {
  assert.deepEqual(ids("<?php phpinfo();"), ["php-phpinfo"]);
});

test("skips comment-only lines", () => {
  assert.deepEqual(ids("// system($cmd);"), []);
  assert.deepEqual(ids("# exec($cmd);"), []);
  assert.deepEqual(ids(" * system($cmd);"), []);
});

test("reports one-based line numbers and trims long evidence", () => {
  const source = [
    "<?php",
    "$a = 1;",
    "system($cmd);"
  ].join("\n");
  const matches = inspectSource(source);
  assert.equal(matches[0].line, 3);
  assert.ok(matches[0].evidence.length <= 300);

  const long = `<?php system($${"a".repeat(400)});`;
  const longMatches = inspectSource(long);
  assert.ok(longMatches[0].evidence.length <= 300);
});
