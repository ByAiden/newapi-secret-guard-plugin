import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fakeSecrets, applyPatch, streamThrough, chunked, generator, rand, ALNUM } from "./helpers.mjs";
import { meta, ingress, reply, validateConfig } from "../plugin.js";

const S = fakeSecrets();
const BUILT_IN_IDS = Object.keys(meta.configSchema.properties.actions.properties);

function ctx(config = {}, extra = {}) {
  return { stage: "ingress", format: "openai", path: "/v1/chat/completions", model: "gpt-4o-mini", attempt: 0, instance: { id: "rp_test", name: "test" }, config, ...extra };
}

function chat(content, extra = {}) {
  return { model: "gpt-4o-mini", stream: false, messages: [{ role: "user", content }], ...extra };
}

function run(body, config, extra) {
  const before = JSON.stringify(body);
  const result = ingress(ctx(config, extra), { body });
  assert.equal(JSON.stringify(body), before, "ingress must not mutate the body");
  return result;
}

// No result may carry a secret: not in findings, messages or notices.
function assertNoLeak(result, secrets) {
  const serialized = JSON.stringify({ ...result, effects: undefined });
  for (const secret of secrets) assert.ok(!serialized.includes(secret), "result leaks a secret");
}

function patched(body, result) {
  assert.equal(result.action, "continue");
  const patch = result.effects.find((effect) => effect.type === "json.patch");
  return patch ? applyPatch(body, patch.ops) : body;
}

test("meta is a plain JSON literal with the market key and version", () => {
  const source = readFileSync(new URL("../plugin.js", import.meta.url), "utf8");
  const block = source.slice(source.indexOf("export const meta = ") + "export const meta = ".length, source.indexOf("\n};\n") + 2);
  assert.deepEqual(JSON.parse(block), meta);
  assert.match(meta.key, /^[a-z0-9-]+_secret_guard$/);
  assert.equal(meta.version, "1.0.0");
  assert.equal(meta.apiVersion, 1);
  for (const text of [meta.description.en, meta.description.zh]) assert.ok(text.length > 0);
  for (const id of BUILT_IN_IDS) {
    const field = meta.configSchema.properties.actions.properties[id];
    assert.deepEqual(field.enum, ["block", "mask", "log", "off"]);
    assert.equal(field.enumTitles.length, 4);
  }
  for (const marker of ["TERM_", "{{SECRET", "{{PERSON", "{{EMAIL", "__PLUGIN", "__SAMPLE"]) assert.ok(!source.includes(marker), marker);
});

test("schema defaults behave like an empty config", () => {
  const defaults = { actions: {} };
  for (const [name, field] of Object.entries(meta.configSchema.properties)) if (name !== "actions") defaults[name] = field.default;
  for (const [id, field] of Object.entries(meta.configSchema.properties.actions.properties)) defaults.actions[id] = field.default;
  for (const value of Object.values(S)) {
    const body = chat("value " + value + " end");
    assert.deepEqual(run(body, defaults), run(body, {}));
  }
});

const BLOCKED = [
  ["openai_api_key", S.openai_api_key],
  ["openai_api_key", S.openai_legacy],
  ["anthropic_api_key", S.anthropic_api_key],
  ["google_api_key", S.google_api_key],
  ["google_api_key", S.google_client_secret],
  ["github_token", S.github_token],
  ["github_token", S.github_pat],
  ["gitlab_token", S.gitlab_token],
  ["slack_token", S.slack_token],
  ["slack_token", S.slack_webhook],
  ["stripe_live_key", S.stripe_live_key],
  ["other_api_token", S.other_api_token],
  ["private_key", S.private_key],
];

for (const [id, secret] of BLOCKED) {
  test("blocks " + id + " by default (" + secret.slice(0, 6) + ")", () => {
    const result = run(chat("Why does this fail?\nkey: " + secret + "\nthanks"));
    assert.equal(result.action, "reject");
    assert.equal(result.code, "secret_guard.blocked");
    assert.equal(result.ruleId, id);
    assert.ok(result.message.includes(id));
    assert.equal(result.findings[0].category, id);
    assert.match(result.findings[0].rule, new RegExp("^" + id.replace(".", "\\.") + ":[0-9a-f]{8}$"));
    assertNoLeak(result, [secret, secret.slice(-16)]);
  });
}

test("masks AWS key pairs: the ID by default, and blocks the secret next to it", () => {
  const masked = run(chat("id " + S.aws_access_key_id + " only"));
  const body = patched(chat("id " + S.aws_access_key_id + " only"), masked);
  assert.equal(body.messages[0].content, "id [REDACTED:aws_access_key_id] only");
  const pair = run(chat("[default]\naws_access_key_id = " + S.aws_access_key_id + "\naws_secret_access_key = " + S.aws_secret_access_key + "\n"));
  assert.equal(pair.action, "reject");
  assert.equal(pair.ruleId, "aws_secret_access_key");
  // Next to the ID, without a key name.
  const near = run(chat(S.aws_access_key_id + " " + S.aws_secret_access_key));
  assert.equal(near.action, "reject");
  // By key name alone.
  const named = run(chat('AWS_SECRET_ACCESS_KEY="' + S.aws_secret_access_key + '"'));
  assert.equal(named.ruleId, "aws_secret_access_key");
});

test("AWS pairing ignores hex digests and the documentation example", () => {
  const sha = rand(40, "0123456789abcdef");
  const result = run(chat("id " + S.aws_access_key_id + " commit " + sha));
  assert.equal(result.action, "continue");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].category, "aws_access_key_id");
  const example = run(chat("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
  assert.deepEqual(example, { action: "continue", effects: [], findings: [] });
});

test("Alibaba Cloud and Tencent Cloud pairs", () => {
  const ali = run(chat("AccessKeyId: " + S.alibaba_access_key_id + "\nAccessKeySecret: " + S.alibaba_access_key_secret));
  assert.equal(ali.action, "reject");
  assert.equal(ali.ruleId, "alibaba_access_key_secret");
  assert.ok(ali.findings.some((f) => f.category === "alibaba_access_key_id"));
  const tc = run(chat("SecretId=" + S.tencent_secret_id + " SecretKey=" + S.tencent_secret_key));
  assert.equal(tc.action, "reject");
  assert.equal(tc.ruleId, "tencent_secret_key");
  const idOnly = run(chat("my id is " + S.alibaba_access_key_id));
  assert.equal(patched(chat("my id is " + S.alibaba_access_key_id), idOnly).messages[0].content, "my id is [REDACTED:alibaba_access_key_id]");
  const tcId = run(chat("SecretId " + S.tencent_secret_id));
  assert.equal(tcId.findings[0].category, "tencent_secret_id");
});

test("masks JWTs, database passwords and sk- keys by default", () => {
  const text = "Bearer " + S.jwt + " and postgres://app:" + S.db_password + "@db.internal:5432/app and " + S.generic_sk_key;
  const body = chat(text);
  const result = run(body);
  const after = patched(body, result);
  assert.equal(after.messages[0].content, "Bearer [REDACTED:jwt] and postgres://app:[REDACTED:db_connection_string]@db.internal:5432/app and [REDACTED:generic_sk_key]");
  assert.deepEqual(result.notice, { en: "Credentials in the request were masked before it was sent", zh: "请求中的密钥已在发送前遮盖" });
  assert.deepEqual(result.findings.map((f) => f.category).sort(), ["db_connection_string", "generic_sk_key", "jwt"]);
  assertNoLeak(result, [S.jwt, S.db_password, S.generic_sk_key]);
});

test("database URLs of several engines; placeholder passwords pass", () => {
  for (const scheme of ["postgresql", "mysql", "mongodb+srv", "redis", "rediss", "amqps", "jdbc:postgresql", "postgresql+psycopg"]) {
    const body = chat("url " + scheme + "://u:" + S.db_password + "@h.example.net/db");
    assert.equal(patched(body, run(body)).messages[0].content, "url " + scheme + "://u:[REDACTED:db_connection_string]@h.example.net/db", scheme);
  }
  const redis = chat("redis://:" + S.db_password + "@cache:6379/0");
  assert.equal(patched(redis, run(redis)).messages[0].content, "redis://:[REDACTED:db_connection_string]@cache:6379/0");
  for (const text of [
    "postgres://user:password@localhost:5432/db",
    "mysql://root:${DB_PASSWORD}@db/app",
    "mongodb://admin:<password>@cluster0.example.net",
    "amqp://guest:guest@localhost:5672",
    "postgres://app:****@db/app",
    "see https://user:pass@example.com/path",
  ]) {
    assert.deepEqual(run(chat(text)), { action: "continue", effects: [], findings: [] }, text);
  }
});

test("placeholders, prose and documentation tokens are not secrets", () => {
  const jwtio = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  for (const text of [
    "Set OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx in your shell",
    "export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "Use your key: sk-ant-api03-your-api-key-here-and-more-text-to-reach-the-length",
    "the sk-proj-something-very-long-and-descriptive-name-of-a-project is fine",
    "token " + jwtio,
    "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
    "a UUID 3f2b8c1e-9d4a-4e7b-8c2d-1a2b3c4d5e6f and a sha " + rand(40, "0123456789abcdef"),
    "password = os.environ.get(\"DB_PASSWORD\")",
    "token: getToken()",
    "const password = hashedPassword;",
    "[media:0] is an image",
  ]) {
    const result = run(chat(text));
    assert.equal(result.action, "continue", text);
    assert.equal(result.effects.length, 0, text);
    assert.equal(result.findings.filter((f) => f.category !== "generic_assignment").length, 0, text);
  }
});

test("ignorePlaceholders off reports placeholder-shaped keys", () => {
  const result = run(chat("postgres://user:password@localhost/db"), { ignorePlaceholders: false });
  assert.equal(result.findings[0].category, "db_connection_string");
});

test("generic assignments are log only by default and gated by entropy", () => {
  const body = chat('config: password = "' + S.generic_value + '"');
  const logged = run(body);
  assert.equal(logged.action, "continue");
  assert.deepEqual(logged.effects, []);
  assert.equal(logged.findings[0].category, "generic_assignment");
  const masked = run(body, { actions: { generic_assignment: "mask" } });
  assert.equal(patched(body, masked).messages[0].content, 'config: password = "[REDACTED:generic_assignment]"');
  assert.equal(run(chat("password: aaaabbbbcccc")).findings.length, 0);
  // Low-entropy values pass; the threshold is capped by what the value length can reach.
  assert.equal(run(chat('password = "aaaabbbb1111cccc"')).findings.length, 0);
  assert.equal(run(chat('password = "Summer2024x"'), { genericMinEntropy: 6 }).findings.length, 1);
  // JSON style.
  assert.equal(run(chat('{"client_secret": "' + S.generic_value + '"}')).findings[0].category, "generic_assignment");
});

test("per-detector actions: off, log, mask and block", () => {
  const body = chat("key " + S.github_token);
  assert.deepEqual(run(body, { actions: { github_token: "off" } }), { action: "continue", effects: [], findings: [] });
  const logged = run(body, { actions: { github_token: "log" } });
  assert.deepEqual(logged.effects, []);
  assert.equal(logged.findings[0].count, 1);
  assert.equal(patched(body, run(body, { actions: { github_token: "mask" } })).messages[0].content, "key [REDACTED:github_token]");
  assert.equal(run(chat("Bearer " + S.jwt), { actions: { jwt: "block" } }).action, "reject");
});

test("allowlist: exact values and prefixes", () => {
  const body = chat("a " + S.github_token + " b " + S.generic_sk_key);
  assert.equal(run(body, { allowlist: S.github_token + "\n# comment\n\n" }).action, "continue");
  const prefixed = run(body, { allowlist: "ghp_*\n" + S.generic_sk_key.slice(0, 10) + "*" });
  assert.deepEqual(prefixed, { action: "continue", effects: [], findings: [] });
  const testKey = "sk" + "_test_" + rand(24);
  assert.equal(run(chat(testKey)).action, "continue");
});

test("fingerprints identify the same secret without revealing it", () => {
  const a = run(chat("x " + S.github_token + " y " + S.github_token));
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0].count, 2);
  const b = run(chat(S.github_token), { fingerprints: false });
  assert.equal(b.findings[0].rule, "github_token");
  assert.equal(a.findings[0].rule, "github_token:" + globalThis.utils.sha256(S.github_token).slice(0, 8));
});

test("custom detectors with groups, case flags and validation", () => {
  const token = "acme_" + rand(32);
  const config = { customDetectors: [{ name: "acme", pattern: "\\bacme_[A-Za-z0-9]{32}\\b", action: "mask" }] };
  assert.equal(patched(chat("t=" + token), run(chat("t=" + token), config)).messages[0].content, "t=[REDACTED:custom.acme]");
  const grouped = { customDetectors: [{ name: "emp", pattern: "(?i)employee id: (\\d{6})", action: "mask" }] };
  assert.equal(patched(chat("EMPLOYEE ID: 123456."), run(chat("EMPLOYEE ID: 123456."), grouped)).messages[0].content, "EMPLOYEE ID: [REDACTED:custom.emp].");
  const blocked = run(chat("code INT-" + rand(10)), { customDetectors: [{ name: "int", pattern: "int-[a-z0-9]{10}", caseInsensitive: true }] });
  assert.equal(blocked.action, "reject");
  assert.equal(blocked.ruleId, "custom.int");
  assert.throws(() => validateConfig({ customDetectors: [{ name: "bad", pattern: "(" }] }), /invalid regular expression/);
  assert.throws(() => validateConfig({ customDetectors: [{ name: "empty", pattern: "a*" }] }), /matches empty text/);
  assert.throws(() => validateConfig({ customDetectors: [{ name: "x", pattern: "a" }, { name: "x", pattern: "b" }] }), /more than once/);
  assert.throws(() => validateConfig({ allowlist: Array.from({ length: 1001 }, (_, i) => "v" + i).join("\n") }), /1000/);
  validateConfig({});
  validateConfig(undefined);
});

test("rejection message names detectors and never the secret", () => {
  const result = run(chat(S.github_token + " " + S.stripe_live_key), { message: "Blocked: {detectors}." });
  assert.equal(result.message, "Blocked: github_token, stripe_live_key.");
});

test("guarded members are never searched or changed", () => {
  const body = { model: "gpt-4o-mini", stream: true, size: S.generic_sk_key, n: 1, messages: [{ role: "user", content: "hello there friend" }] };
  assert.deepEqual(run(body), { action: "continue", effects: [], findings: [] });
  const mj = { action: "IMAGINE", customId: S.generic_sk_key, content: S.generic_sk_key, prompt: "x " + S.generic_sk_key };
  const result = run(mj, {}, { format: "mj_proxy" });
  assert.deepEqual(result.effects[0].ops.map((op) => op.path), ["/prompt"]);
});

test("multimodal parts: only text strings change, media placeholders stay", () => {
  const body = {
    model: "gpt-4o",
    messages: [
      { role: "system", content: "You are helpful." },
      { role: "user", content: [{ type: "text", text: "read " + S.generic_sk_key }, { type: "image_url", image_url: { url: "[media:0]" } }] },
    ],
  };
  const result = run(body);
  assert.deepEqual(result.effects[0].ops, [{ op: "replace", path: "/messages/1/content/0/text", value: "read [REDACTED:generic_sk_key]" }]);
  // A string that holds a media reference cannot take a patch: rejected.
  const mixed = run(chat("[media:0] " + S.generic_sk_key));
  assert.equal(mixed.action, "reject");
});

test("Responses, Claude, Gemini, tool calls and form bodies", () => {
  const responses = { model: "gpt-4.1", instructions: "Use " + S.generic_sk_key, input: [{ role: "user", content: [{ type: "input_text", text: "db postgres://a:" + S.db_password + "@h/d" }] }, { type: "function_call_output", call_id: "c1", output: "{\"token\":\"" + S.jwt + "\"}" }] };
  const r = patched(responses, run(responses, {}, { format: "openai_responses" }));
  assert.equal(r.instructions, "Use [REDACTED:generic_sk_key]");
  assert.equal(r.input[0].content[0].text, "db postgres://a:[REDACTED:db_connection_string]@h/d");
  assert.equal(r.input[1].output, "{\"token\":\"[REDACTED:jwt]\"}");
  const claude = { model: "claude-sonnet-4", max_tokens: 100, system: [{ type: "text", text: "key " + S.generic_sk_key }], messages: [{ role: "user", content: [{ type: "text", text: "hi there friend" }, { type: "image", source: { type: "base64", media_type: "image/png", data: "[media:0]" } }] }] };
  const c = patched(claude, run(claude, {}, { format: "claude" }));
  assert.equal(c.system[0].text, "key [REDACTED:generic_sk_key]");
  assert.equal(c.messages[0].content[1].source.data, "[media:0]");
  const gemini = { contents: [{ role: "user", parts: [{ text: "token " + S.jwt }, { inlineData: { mimeType: "image/png", data: "[media:0]" } }] }], generationConfig: { candidateCount: 1 } };
  const g = patched(gemini, run(gemini, {}, { format: "gemini" }));
  assert.equal(g.contents[0].parts[0].text, "token [REDACTED:jwt]");
  const tools = chat("ok", { messages: [{ role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "login", arguments: JSON.stringify({ key: S.github_token }) } }] }] });
  assert.equal(run(tools).ruleId, "github_token");
  const form = { prompt: "draw " + S.generic_sk_key, n: "1", tags: ["a", "x " + S.generic_sk_key] };
  const f = run(form, {}, { format: "openai_image" });
  assert.deepEqual(f.effects[0].ops.map((op) => op.path), ["/prompt", "/tags/1"]);
  assert.ok(f.effects[0].ops.every((op) => op.op === "replace" && typeof op.value === "string"));
});

test("JSON-escaped private keys inside a pasted service account file", () => {
  const sa = JSON.stringify({ type: "service_account", private_key: S.private_key.replace(/-----BEGIN RSA/, "-----BEGIN").replace(/END RSA/, "END") });
  const result = run(chat("my credentials: " + sa));
  assert.equal(result.ruleId, "private_key");
  const partial = run(chat("-----BEGIN OPENSSH PRIVATE KEY-----\n" + rand(70) + "\n" + rand(70)));
  assert.equal(partial.ruleId, "private_key");
  const masked = run(chat("k " + S.private_key + " done"), { actions: { private_key: "mask" } });
  assert.equal(patched(chat("k " + S.private_key + " done"), masked).messages[0].content, "k [REDACTED:private_key] done");
});

test("the scan budget counts unchecked text", () => {
  const big = "word ".repeat(4000);
  const result = run({ messages: [{ role: "user", content: big }, { role: "user", content: big + S.github_token }] }, { maxScanChars: 20005 });
  assert.equal(result.action, "continue");
  assert.deepEqual(result.findings, [{ rule: "scan_limit", category: "unscanned", count: 1 }]);
});

test("more than 512 masked fields reject instead of sending secrets", () => {
  const messages = Array.from({ length: 513 }, () => ({ role: "user", content: "k " + S.generic_sk_key }));
  const result = run({ model: "m", messages });
  assert.equal(result.action, "reject");
  assert.equal(result.code, "secret_guard.too_many_secrets");
});

test("attached text files are masked; unreadable ones with secrets reject", () => {
  const files = {
    "[media:0]": { kind: "document", mime: "text/plain", rewritable: true, text: "API=" + S.generic_sk_key, truncated: false },
    "[media:1]": { kind: "document", mime: "application/pdf", text: "nothing here", truncated: false },
  };
  globalThis.utils.attachments = () => Object.entries(files).map(([ref, f]) => ({ ref, kind: f.kind, mime: f.mime, path: "/x", rewritable: f.rewritable }));
  globalThis.utils.mediaText = (ref) => ({ text: files[ref].text, truncated: files[ref].truncated });
  try {
    const body = chat("see file");
    const result = run(body, { scanFiles: true });
    assert.deepEqual(result.effects, [{ type: "media.text", media: 0, text: "API=[REDACTED:generic_sk_key]" }]);
    assert.deepEqual(run(body).effects, []);
    files["[media:1]"].text = "token " + S.generic_sk_key;
    assert.equal(run(body, { scanFiles: true }).code, "secret_guard.file_blocked");
    files["[media:1]"].text = "token " + S.github_token;
    const blocked = run(body, { scanFiles: true });
    assert.equal(blocked.code, "secret_guard.file_blocked");
    assert.equal(blocked.ruleId, "github_token");
  } finally {
    delete globalThis.utils.attachments;
    delete globalThis.utils.mediaText;
  }
});

test("reply: non-stream answers are masked, follow mode stops, log and off", () => {
  const text = "Here is your key " + S.github_token + " and url postgres://a:" + S.db_password + "@h/d.";
  const res = { stream: false, outputs: [{ index: 0, text, offset: 0, final: true }] };
  const masked = reply(ctx(), res);
  assert.equal(masked.action, "continue");
  assert.equal(masked.hold, 0);
  assert.deepEqual(masked.mask.map((m) => text.slice(m.start, m.end)), [S.github_token, S.db_password]);
  assert.deepEqual(masked.notice, { en: "Credentials in the answer were masked", zh: "回答中的密钥已遮盖" });
  assertNoLeak(masked, [S.github_token, S.db_password]);
  const stopped = reply(ctx({ replyMode: "follow" }), res);
  assert.equal(stopped.action, "stop");
  assert.equal(stopped.code, "secret_guard.reply_blocked");
  const logged = reply(ctx({ replyMode: "log" }), res);
  assert.deepEqual(logged.mask, []);
  assert.equal(logged.findings.length, 2);
  assert.deepEqual(reply(ctx({ replyMode: "off" }), res), { action: "pass" });
  const allOff = {};
  for (const id of BUILT_IN_IDS) allOff[id] = "off";
  assert.deepEqual(reply(ctx({ actions: allOff }), res), { action: "pass" });
  // Detectors set to log only are not masked in answers either.
  const logOnly = reply(ctx({ actions: { github_token: "log" } }), res);
  assert.equal(logOnly.mask.length, 1);
  assert.equal(logOnly.findings.length, 2);
});

test("reply: several outputs keep their own indexes", () => {
  const res = { stream: false, outputs: [{ index: 0, text: "clean answer here", offset: 0, final: true }, { index: 1, text: "k " + S.generic_sk_key, offset: 0, final: true }] };
  const result = reply(ctx(), res);
  assert.deepEqual(result.mask, [{ index: 1, start: 2, end: 2 + S.generic_sk_key.length, category: "generic_sk_key" }]);
});

test("reply: secrets split across stream chunks are masked whole", () => {
  const secrets = [S.github_token, S.openai_api_key, S.jwt, S.generic_sk_key, S.anthropic_api_key];
  const text = "Sure. First " + secrets.join(" then ") + " and finally postgres://svc:" + S.db_password + "@db:5432/x done. " + "Some trailing words. ".repeat(5);
  for (const max of [1, 3, 7, 16, 33, 80, 400]) {
    const { out, stopped } = streamThrough(reply, ctx(), chunked(text, max, generator(max).next));
    assert.equal(stopped, null);
    for (const secret of secrets.concat([S.db_password])) {
      for (let i = 0; i + 12 <= secret.length; i += 6) assert.ok(!out.includes(secret.slice(i, i + 12)), "fragment leaked with chunk size " + max);
    }
    assert.equal(out.split("***").length - 1, 6, "six masks with chunk size " + max);
    assert.ok(out.endsWith("Some trailing words. "));
    assert.ok(out.startsWith("Sure. First ***"));
  }
});

test("reply: randomized streams never release a secret fragment", () => {
  const words = ["the", "config", "value:", "use", "then", "and", "url", "key=", "\n", "token", "is", "ok."];
  for (let seed = 1; seed <= 40; seed++) {
    const g = generator(seed);
    const local = fakeSecrets(g.rand);
    const pool = [local.github_token, local.openai_api_key, local.jwt, local.generic_sk_key, local.slack_token, local.private_key, "mongodb+srv://svc:" + local.db_password + "@c0.example.net/db"];
    const used = [];
    let text = "";
    for (let i = 0; i < 30; i++) {
      if (g.next() < 0.2) {
        const secret = pool[Math.floor(g.next() * pool.length)];
        used.push(secret);
        text += secret + (g.next() < 0.5 ? " " : "\n");
      } else {
        text += words[Math.floor(g.next() * words.length)] + " ";
      }
    }
    const { out } = streamThrough(reply, ctx(), chunked(text, 1 + Math.floor(g.next() * 60), g.next));
    for (const secret of used) {
      const core = secret.startsWith("mongodb") ? local.db_password : secret;
      for (let i = 0; i + 12 <= core.length; i += 4) assert.ok(!out.includes(core.slice(i, i + 12)), "seed " + seed + " leaked a fragment");
    }
  }
});

test("reply: a private key streamed line by line is masked whole", () => {
  const text = "Your key:\n" + S.private_key + "\nKeep it safe.";
  for (const max of [5, 40]) {
    const { out } = streamThrough(reply, ctx(), chunked(text, max, generator(3).next));
    assert.equal(out, "Your key:\n***\nKeep it safe.");
  }
  const { stopped } = streamThrough(reply, ctx({ replyMode: "follow" }), chunked(text, 20));
  assert.equal(stopped.code, "secret_guard.reply_blocked");
});

test("reply: a clean stream comes through unchanged with a small hold", () => {
  const text = "Plain answer without any credentials, just words and numbers 12345. ".repeat(20);
  const holds = [];
  const wrapped = (c, res) => {
    const result = reply(c, res);
    holds.push(result.hold);
    return result;
  };
  const { out } = streamThrough(wrapped, ctx(), chunked(text, 30));
  assert.equal(out, text);
  assert.ok(Math.max(...holds) <= 64 + 16, "hold stays near one word plus context");
});

test("performance: 2 MB of adversarial text scans quickly", () => {
  const { rand: r } = generator(99);
  let text = "";
  while (text.length < 2000000) text += "sk- eyJ" + r(30) + " postgres://a:b " + r(20) + "-eyJ ghp_ AKIA password= ";
  const start = performance.now();
  const result = run(chat(text));
  const elapsed = performance.now() - start;
  assert.equal(result.action, "continue");
  assert.ok(elapsed < 3000, "took " + elapsed + " ms");
  const replyStart = performance.now();
  reply(ctx(), { stream: false, outputs: [{ index: 0, text, offset: 0, final: true }] });
  assert.ok(performance.now() - replyStart < 3000);
});

test("findings stay within host limits", () => {
  const values = Array.from({ length: 80 }, () => "sk" + "-" + rand(48));
  const result = run(chat(values.join(" ")));
  assert.ok(result.findings.length <= 64);
  for (const finding of result.findings) assert.ok(finding.rule.length <= 256 && Number.isInteger(finding.count));
  assert.ok(/^[a-z0-9_.-]{1,64}$/.test("secret_guard.too_many_secrets"));
});

test("samples are masked by the default config", () => {
  for (const sample of meta.samples) {
    const result = ingress(ctx(), { body: sample.body });
    assert.equal(result.action, "continue");
    assert.equal(result.effects.length, 1);
    const answer = reply(ctx(), { stream: false, outputs: [{ index: 0, text: sample.reply, offset: 0, final: true }] });
    assert.ok(answer.mask.length >= 1);
  }
  assert.ok(ALNUM.length === 62);
});
