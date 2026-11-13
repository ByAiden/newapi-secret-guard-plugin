// Shared test helpers. Every credential used by the tests is fake and built
// at runtime from a seeded generator, so no secret-shaped literal sits in the
// repository for scanners to flag.
import { createHash } from "node:crypto";

globalThis.utils = {
  sha256(value) {
    return createHash("sha256").update(String(value), "utf8").digest("hex");
  },
};

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
export const ALNUM = UPPER + LOWER + DIGITS;
export const BASE64 = ALNUM + "+/";
export const B32 = UPPER + "234567";

// mulberry32: deterministic, so failures reproduce.
export function generator(seed) {
  let state = seed >>> 0;
  function next() {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  // Random text of the alphabet that always mixes cases and digits when the
  // alphabet has them, as real keys do.
  function rand(length, alphabet = ALNUM) {
    for (;;) {
      let out = "";
      for (let i = 0; i < length; i++) out += alphabet[Math.floor(next() * alphabet.length)];
      const needsMix = alphabet.includes("a") && alphabet.includes("A") && alphabet.includes("0") && length >= 12;
      if (!needsMix || (/[a-z]/.test(out) && /[A-Z]/.test(out) && /\d/.test(out) && !/(.)\1{5}/.test(out))) return out;
    }
  }
  return { next, rand };
}

const { rand } = generator(20261113);
export { rand };

function b64url(object) {
  return Buffer.from(JSON.stringify(object)).toString("base64url");
}

// One fake value per detector, joined from pieces at runtime.
export function fakeSecrets(r = rand) {
  const dash = "-";
  const under = "_";
  return {
    openai_api_key: "sk" + dash + "proj" + dash + r(48) + "T3Blbk" + "FJ" + r(48),
    openai_legacy: "sk" + dash + r(20) + "T3Blbk" + "FJ" + r(20),
    anthropic_api_key: "sk" + dash + "ant" + dash + "api03" + dash + r(93, ALNUM + "_-") + "AA",
    google_api_key: "AI" + "za" + "Sy" + r(33, ALNUM + "_-"),
    google_client_secret: "GOC" + "SPX" + dash + r(28),
    aws_access_key_id: "AK" + "IA" + r(16, B32),
    aws_secret_access_key: r(40, BASE64),
    github_token: "gh" + "p" + under + r(36),
    github_pat: "github" + under + "pat" + under + r(22) + under + r(59),
    gitlab_token: "gl" + "pat" + dash + r(20),
    slack_token: "xo" + "xb" + dash + r(12, DIGITS) + dash + r(13, DIGITS) + dash + r(24),
    slack_webhook: "https://hooks.slack.com/services/T" + r(10, UPPER + DIGITS) + "/B" + r(10, UPPER + DIGITS) + "/" + r(24),
    stripe_live_key: "sk" + under + "live" + under + r(99),
    other_api_token: "hf" + under + r(34),
    alibaba_access_key_id: "LT" + "AI" + r(20),
    alibaba_access_key_secret: r(30),
    tencent_secret_id: "AK" + "ID" + r(32),
    tencent_secret_key: r(32),
    jwt: b64url({ alg: "HS256", typ: "JWT" }) + "." + b64url({ sub: "u-" + r(6), iat: 1700000000 }) + "." + r(43, ALNUM + "_-"),
    db_password: r(18),
    generic_sk_key: "sk" + dash + r(48),
    generic_value: r(24, ALNUM + "!#%^&"),
    private_key:
      "-----BEGIN " + "RSA PRIVATE " + "KEY-----\n" +
      Array.from({ length: 12 }, () => r(64, BASE64)).join("\n") +
      "\n" + r(20, BASE64) + "==\n-----END RSA PRIVATE " + "KEY-----",
  };
}

// Applies RFC 6902 replace operations, the only ones the plugin emits.
export function applyPatch(body, ops) {
  const copy = structuredClone(body);
  for (const op of ops) {
    if (op.op !== "replace") throw new Error("unexpected op " + op.op);
    const keys = op.path.split("/").slice(1).map((k) => k.replace(/~1/g, "/").replace(/~0/g, "~"));
    let parent = copy;
    for (const key of keys.slice(0, -1)) parent = parent[key];
    const last = keys[keys.length - 1];
    if (!(last in parent)) throw new Error("replace of a missing member " + op.path);
    parent[last] = op.value;
  }
  return copy;
}

// Simulates the host's reply pipeline for one streamed output: the first call
// on the first text, then each time 32 or more code units arrived, then a
// final call. Masks past the cut are dropped and the held text comes back,
// as releaseReply does in new-api.
export function streamThrough(reply, ctx, chunks) {
  let held = "";
  let pending = "";
  let offset = 0;
  let out = "";
  let called = false;
  let passed = false;
  let stopped = null;
  const findings = [];
  const call = (final) => {
    const text = held + pending;
    pending = "";
    if (passed) {
      out += text;
      held = "";
      return;
    }
    const result = reply(ctx, { stream: true, outputs: [{ index: 0, text, offset, final }] });
    if (result.action === "pass") {
      passed = true;
      out += text;
      held = "";
      return;
    }
    if (result.action === "stop") {
      stopped = result;
      return;
    }
    if (result.hold < 0 || result.hold > 8192) throw new Error("hold out of range " + result.hold);
    findings.push(...(result.findings || []));
    const masks = (result.mask || []).slice().sort((a, b) => a.start - b.start);
    let cut = final ? text.length : Math.max(0, text.length - result.hold);
    for (const mask of masks) if (mask.start < cut && cut < mask.end) cut = mask.end;
    let released = "";
    let from = 0;
    for (const mask of masks) {
      if (mask.end > cut) break;
      released += text.slice(from, mask.start) + "***";
      from = mask.end;
    }
    released += text.slice(from, cut);
    out += released;
    offset += cut;
    held = text.slice(cut);
  };
  for (const chunk of chunks) {
    if (stopped) break;
    pending += chunk;
    if (!called || pending.length >= 32) {
      call(false);
      called = true;
    }
  }
  if (!stopped) call(true);
  return { out, stopped, findings };
}

// Splits text into chunks of 1 to max code units.
export function chunked(text, max, r = generator(7).next) {
  const chunks = [];
  for (let i = 0; i < text.length; ) {
    const size = 1 + Math.floor(r() * max);
    chunks.push(text.slice(i, i + size));
    i += size;
  }
  return chunks;
}
