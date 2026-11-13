// Builds test/golden.json for the host fixture runner:
//   node test/golden.gen.mjs
//   new-api plugin test plugin.js --fixture test/golden.json
// Expected values come from running the plugin in Node; the host replays the
// same calls in its own JavaScript engine and regular expressions. Each fake
// secret is written with one character as a JSON \u escape, so the file holds
// no scanner-matchable token while the host still decodes the real value.
import { writeFileSync } from "node:fs";
import { fakeSecrets, generator, rand } from "./helpers.mjs";
import { ingress, reply, validateConfig } from "../plugin.js";

const S = fakeSecrets(generator(4242).rand);

function ctx(config = {}, extra = {}) {
  return { stage: "ingress", format: "openai", path: "/v1/chat/completions", model: "gpt-4o-mini", attempt: 0, instance: { id: "rp_golden", name: "golden" }, config, ...extra };
}
function chat(content) {
  return { model: "gpt-4o-mini", messages: [{ role: "user", content }] };
}

const cases = [];
function addIngress(name, body, config = {}, extra = {}) {
  const args = [ctx(config, extra), { body }];
  cases.push({ name, hook: "ingress", args, expected: ingress(...structuredClone(args)) });
}
function addReply(name, res, config = {}) {
  const args = [ctx(config, { stage: "reply" }), res];
  cases.push({ name, hook: "reply", args, expected: reply(...structuredClone(args)) });
}
function addConfigError(name, config, message) {
  try {
    validateConfig(config);
  } catch (error) {
    if (!error.message.includes(message)) throw error;
    cases.push({ name, hook: "validateConfig", args: [config], expectedError: message });
    return;
  }
  throw new Error(name + ": expected an error");
}

for (const key of ["openai_api_key", "openai_legacy", "anthropic_api_key", "google_api_key", "google_client_secret", "github_token", "github_pat", "gitlab_token", "slack_token", "slack_webhook", "stripe_live_key", "other_api_token", "private_key"]) {
  addIngress("blocks " + key, chat("Why does this fail?\nkey: " + S[key] + "\nthanks"));
}
addIngress("masks IDs, JWT, database password and sk- key", chat(
  "id " + S.aws_access_key_id + " ali " + S.alibaba_access_key_id + " tc " + S.tencent_secret_id +
  " Bearer " + S.jwt + " url postgres://app:" + S.db_password + "@db.internal:5432/app key " + S.generic_sk_key,
));
addIngress("AWS pair is blocked", chat("aws_access_key_id = " + S.aws_access_key_id + "\naws_secret_access_key = " + S.aws_secret_access_key));
addIngress("AWS secret next to its ID", chat(S.aws_access_key_id + " " + S.aws_secret_access_key));
addIngress("Alibaba Cloud pair is blocked", chat("AccessKeyId: " + S.alibaba_access_key_id + "\nAccessKeySecret: " + S.alibaba_access_key_secret));
addIngress("Tencent Cloud pair is blocked", chat("SecretId=" + S.tencent_secret_id + " SecretKey=" + S.tencent_secret_key));
addIngress("placeholders pass", {
  model: "m",
  messages: [
    { role: "user", content: "Set OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
    { role: "user", content: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" },
    { role: "user", content: "postgres://user:password@localhost:5432/db and amqp://guest:guest@localhost" },
    { role: "user", content: "the sk-proj-something-very-long-and-descriptive-name-of-a-project" },
    { role: "user", content: "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" },
    { role: "user", content: "commit " + rand(40, "0123456789abcdef") + " next to AKIAIOSFODNN7EXAMPLE" },
  ],
});
addIngress("assignment is log only", chat('password = "' + S.generic_value + '"'));
addIngress("assignment masked when set", chat('password = "' + S.generic_value + '"'), { actions: { generic_assignment: "mask" } });
addIngress("detector off", chat("k " + S.github_token), { actions: { github_token: "off" } });
addIngress("allowlist prefix", chat("k " + S.github_token + " " + S.generic_sk_key), { allowlist: "ghp_*\n" + S.generic_sk_key });
addIngress("custom detector with group and (?i)", chat("EMPLOYEE ID: 123456 and acme_" + rand(32)), {
  customDetectors: [
    { name: "emp", pattern: "(?i)employee id: (\\d{6})", action: "mask" },
    { name: "acme", pattern: "\\bacme_[A-Za-z0-9]{32}\\b", action: "mask" },
  ],
});
addIngress("custom message", chat(S.github_token + " " + S.stripe_live_key), { message: "Blocked: {detectors}." });
addIngress("multimodal chat", {
  model: "gpt-4o",
  stream: true,
  messages: [{ role: "user", content: [{ type: "text", text: "read " + S.generic_sk_key }, { type: "image_url", image_url: { url: "[media:0]" } }] }],
});
addIngress("responses body", { model: "gpt-4.1", instructions: "Use " + S.generic_sk_key, input: [{ type: "function_call_output", call_id: "c1", output: "{\"token\":\"" + S.jwt + "\"}" }] }, {}, { format: "openai_responses" });
addIngress("claude body", { model: "claude-sonnet-4", max_tokens: 64, system: [{ type: "text", text: "key " + S.generic_sk_key }], messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "[media:0]" } }] }] }, {}, { format: "claude" });
addIngress("gemini body", { contents: [{ role: "user", parts: [{ text: "token " + S.jwt }] }], generationConfig: { candidateCount: 1 } }, {}, { format: "gemini" });
addIngress("form body", { prompt: "draw " + S.generic_sk_key, n: "1" }, {}, { format: "openai_image" });
addIngress("service account JSON", chat("creds " + JSON.stringify({ type: "service_account", private_key: S.private_key })));
addIngress("media reference beside a secret", chat("[media:0] " + S.generic_sk_key));
addIngress("guarded members", { model: "m", size: S.generic_sk_key, messages: [{ role: "user", content: "hello there friend" }] });

const answer = "Here is your key " + S.github_token + " and url postgres://a:" + S.db_password + "@h/d.";
addReply("answer masked", { stream: false, outputs: [{ index: 0, text: answer, offset: 0, final: true }] });
addReply("answer stopped in follow mode", { stream: false, outputs: [{ index: 0, text: answer, offset: 0, final: true }] }, { replyMode: "follow" });
addReply("answer off", { stream: false, outputs: [{ index: 0, text: answer, offset: 0, final: true }] }, { replyMode: "off" });
addReply("stream holds a growing key", { stream: true, outputs: [{ index: 0, text: "Sure, here it is: " + S.generic_sk_key.slice(0, 20), offset: 0, final: false }] });
addReply("stream masks a finished key and holds the tail", { stream: true, outputs: [{ index: 0, text: "Key " + S.generic_sk_key + " is set. Next we configure the database connection for the service " + "postgres://svc:" + S.db_password.slice(0, 8), offset: 0, final: false }] });
addReply("stream holds an open private key", { stream: true, outputs: [{ index: 0, text: "Key:\n" + S.private_key.slice(0, 300), offset: 0, final: false }] });

addConfigError("invalid custom regex", { customDetectors: [{ name: "bad", pattern: "(" }] }, "invalid regular expression");
addConfigError("custom regex matching empty text", { customDetectors: [{ name: "empty", pattern: "a*" }] }, "matches empty text");

// Escape one character of every fake secret in the written JSON.
let json = JSON.stringify({ cases }, null, 2);
const escape = (value) => value.slice(0, 2) + "\\u" + value.charCodeAt(2).toString(16).padStart(4, "0") + value.slice(3);
for (const [key, value] of Object.entries(S)) {
  if (key === "private_key") continue;
  json = json.split(value).join(escape(value));
}
json = json.split("-----BEGIN RSA PRIVATE").join("-----B\\u0045GIN RSA PRIVATE");
for (const [key, value] of Object.entries(S)) {
  if (key !== "private_key" && json.includes(value)) throw new Error("raw secret left in fixture: " + key);
}
if (JSON.stringify(JSON.parse(json)) !== JSON.stringify({ cases })) throw new Error("escaping changed the fixture");
writeFileSync(new URL("./golden.json", import.meta.url), json + "\n");
console.log("cases", cases.length);
