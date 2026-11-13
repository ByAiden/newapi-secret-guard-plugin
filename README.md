---
locale: en
translations:
  zh-CN: README.zh-CN.md
---

# Secret Guard

**English** | [简体中文](README.zh-CN.md)

A request processing plugin that keeps credentials out of model traffic. It finds API keys, access tokens, private keys and passwords that users paste into prompts and either rejects the request or masks each secret before the request is sent upstream. It also checks model answers, so a model that repeats a secret from its context does not hand it back in clear text.

- High-confidence secrets (vendor keys with a known prefix, private key blocks, cloud secret keys next to their key ID) are blocked by default.
- Identifiers and tokens that are often pasted on purpose (key IDs, JWTs, database URL passwords, `sk-` keys of OpenAI-compatible services) are masked by default.
- Random-looking values after `password=`, `secret:` and similar names are only logged by default.
- Every detector can be set to block, mask, log only or off; values can be allowlisted; custom regular expressions add detectors.
- Logs never contain a secret: findings carry the detector name and, optionally, the first 8 hex digits of the secret's SHA-256.

Requires new-api v1.0.0-rc.50 or later (request processing plugins). The plugin has no channel part: it is not a channel type and needs no vendor account or key.

## Compared with the built-in Request redaction

New API ships a built-in request processing plugin, Request redaction, whose `api_key` type replaces key-like strings with a single regular expression. Secret Guard is meant for gateways that need more than that:

- 19 dedicated detectors, including private key blocks, AWS, Alibaba Cloud and Tencent Cloud key pairs, database connection strings with passwords, decodable JWTs and vendor tokens.
- A per-detector action: block the request, mask the value, or log only. Request redaction can only replace.
- Logs carry the detector name and an optional short fingerprint, never the secret itself.
- An allowlist, placeholder and documentation-example skipping, and custom detectors.

Both can run on the same gateway. If you only need simple masking of personal data and generic keys, the built-in plugin is enough.

## Install

1. In the admin console open the plugin page and install the plugin from the community market, or upload `plugin.js`.
2. Switch the plugin on. The plugin master switch only affects task and provider channels; request processing runs whenever an enabled instance matches.

## Add an instance

Instances live in the request plugin settings. Each instance is one configured use of the plugin, with its own settings:

- Global: runs on every request. Use this for a gateway-wide policy.
- Groups: runs only for requests of the listed user groups, for example a stricter policy for a `team` group.
- Models: limits the instance to the listed models, as the client names them; leave empty for every model.
- Channel binding: a channel lists instance IDs in its request plugin setting, and those instances run only on that channel, on the body built for its upstream. Use this to guard only the channels that leave your network.

Instances run in that order: global, then group, then channel-bound. Several instances of this plugin may run with different settings, for example a global log-only instance and a blocking instance for one group.

Each instance checks the request once at ingress, before the request is priced, so a blocked request is neither charged nor sent. A channel-bound instance checks the body built for that channel on each channel attempt. The answer check runs on the attempt that produced the answer.

## Detectors

| Detector | Matches | Default |
| --- | --- | --- |
| `private_key` | PEM private key blocks: RSA, EC, DSA, OpenSSH, PKCS#8, encrypted and PGP, also when JSON-escaped (a pasted service account file) or cut off before the END line | block |
| `openai_api_key` | OpenAI project, service account and admin keys, and legacy user keys | block |
| `anthropic_api_key` | Anthropic API, admin and OAuth keys | block |
| `google_api_key` | Google API keys, OAuth client secrets and OAuth access tokens | block |
| `aws_access_key_id` | AWS access key IDs (AKIA, ASIA, ABIA, ACCA) | mask |
| `aws_secret_access_key` | 40-character AWS secret keys next to an access key ID, or after a name such as `aws_secret_access_key` | block |
| `github_token` | GitHub personal, OAuth, app, refresh and fine-grained tokens | block |
| `gitlab_token` | GitLab personal, deploy, runner, trigger and other prefixed tokens | block |
| `slack_token` | Slack bot, user, app and configuration tokens and incoming webhook URLs | block |
| `stripe_live_key` | Stripe live secret and restricted keys and webhook signing secrets; test keys are not reported | block |
| `other_api_token` | Hugging Face, xAI, Groq, npm, PyPI and SendGrid tokens | block |
| `alibaba_access_key_id` | Alibaba Cloud AccessKey IDs (LTAI) | mask |
| `alibaba_access_key_secret` | 30-character AccessKey secrets next to an AccessKey ID or after a name such as `AccessKeySecret` | block |
| `tencent_secret_id` | Tencent Cloud SecretIds (AKID) | mask |
| `tencent_secret_key` | 32-character SecretKeys next to a SecretId or after a name such as `TENCENTCLOUD_SECRET_KEY` | block |
| `jwt` | Signed JSON Web Tokens whose header and payload decode to JSON objects | mask |
| `db_connection_string` | The password of PostgreSQL, MySQL, MariaDB, MongoDB, Redis, AMQP, SQL Server, ClickHouse, CockroachDB and JDBC URLs with `user:password@` | mask |
| `generic_sk_key` | Other `sk-` keys of 32 to 64 letters and digits, as many OpenAI-compatible services and gateways issue | mask |
| `generic_assignment` | Random-looking values after `password`, `secret`, `api_key`, `access_token`, `client_secret`, `private_key` or `token` followed by `=` or `:` | log |

Every detector requires a known prefix or structure plus a shape check: random-looking characters, the right length, a JWT that decodes, a private key body of at least 64 base64 characters, a cloud secret with all three character classes and high entropy. Where a database URL is found only its password is masked, so the rest of the URL still helps the model.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| Detector actions | see the table above | Per detector: Block rejects the request; Mask replaces the secret with `[REDACTED:detector_name]` before the request is sent; Log only records a finding and sends the request unchanged; Off skips the detector. |
| Answer check | Mask | Mask: every detector that is not off or log only is masked in answers, as `***`. Follow: detector actions apply, and a Block detector stops the answer. Log only: answers are only recorded. Off: answers are not checked. |
| Allowlist | empty | One value per line that is never treated as a secret. End a line with `*` to allow a prefix, for example `sk_test_*`. Lines starting with `#` are comments. At most 1000 entries. The value compared is the masked part: the key itself, or the password of a database URL. |
| Ignore placeholders and documentation examples | on | Skips values such as `xxxx`, `your-api-key`, `${DB_PASSWORD}`, `user:password@`, AWS keys containing `EXAMPLE` and the jwt.io sample token. Turn off to report them too. |
| Custom detectors | none | Up to 20 regular expressions, each with a name (lowercase letters, digits, `.`, `-`, `_`), an action and an option to ignore letter case. A leading `(?i)` also ignores case. With a capturing group, only the first group is the secret. Patterns that do not compile or that match empty text are refused when the instance is saved. |
| Minimum entropy of assignment values | 3.5 | Shannon entropy in bits per character a `generic_assignment` value must reach. Short values cannot reach a high entropy, so the threshold is capped at log2(length) - 0.5. |
| Check attached documents | off | Also reads text, PDF and DOCX files of the request through the host. A plain text file read whole is masked in place; a PDF, DOCX or truncated file that holds a secret to mask rejects the request, because the host cannot rewrite it. |
| Text checked per request | 2,000,000 characters | Strings past this amount are not checked and are recorded as finding `scan_limit` with category `unscanned`. |
| Record fingerprints | on | Adds the first 8 hex digits of each secret's SHA-256 to the finding's rule name in the administrator log, for example `github_token:1a2b3c4d`, so the same leaked secret can be recognized across requests. |
| Rejection message | see below | The message the client gets when a request is blocked; `{detectors}` is replaced with the detector names. The host appends `(code: secret_guard.blocked)`. |

The default rejection message is: "The request contains what looks like a credential ({detectors}). Remove it or replace it with a placeholder and try again."

## What clients and logs see

- A blocked request answers HTTP 400 with error code `request_rejected` and the rejection message. It is not priced, charged or sent to another channel.
- A masked request goes upstream with each secret replaced by `[REDACTED:detector_name]`; the user's log shows a notice that credentials were masked.
- In an answer, each masked secret becomes `***` (the host's fixed mask text). In Follow mode a blocking detector stops the answer: a non-stream answer becomes HTTP 400 `response_rejected`, a stream ends with an error event. Usage is billed as the host bills a stopped answer.
- The user's log record lists findings by category and count. The administrator steps add the rule names, with fingerprints when enabled. No log, message or notice contains a matched value.

Example: a user sends `Bearer` followed by a JWT and a PostgreSQL URL with a password. The upstream receives `Bearer [REDACTED:jwt]` and `postgres://app:[REDACTED:db_connection_string]@db.internal:5432/app`, and the user's log shows the findings `jwt` and `db_connection_string`, one each.

## Design choices

- Failure behavior: the plugin does not declare `optional`. If a hook fails (for example, a custom regular expression runs into the 5 second hook limit), the request fails with HTTP 500 `request_plugin_failed` instead of going out unchecked. A security filter that silently stops filtering is worse than an error. Keep custom patterns simple and bounded.
- Where it checks: requests are checked at the `ingress` stage, so a blocked request is never priced or charged and a masked body is what every later stage, retry and channel sees. The plugin does not check `egress`: a channel's own parameter override may add credentials on purpose, such as an upstream key in the body.
- What it reads: every string of the JSON body, including system prompts, tool definitions, tool call arguments and tool results, except the members the host guards (`model`, `stream`, `stream_options`, `n`, `generationConfig`, `size`, `quality`, `resolution`, `seconds`, `duration`, `service_tier`, and `action`, `customId` and `content` on Midjourney submissions). Inline images and files are never passed to the plugin.
- Streams: the answer check keeps back the last word of each output plus up to 64 characters before it, so a key split across chunks is masked whole. Clean answers are delayed by about one word.
- Performance: every pattern starts with a literal prefix and every repetition is bounded, and each detector first runs a cheap prefix test. A 1.5 MB request took about 0.3 s end to end on a test gateway.

## Limits

- Answers are checked on Chat Completions, Responses, Claude Messages and Gemini generateContent, streamed or not, and on Responses WebSocket and Realtime text. Reasoning text, tool call arguments, refusals and Chat Completions content given as parts are not checked by the host. Images, audio, embeddings, rerank and task results are not checked.
- Requests are checked on every endpoint the host passes to request processing; binary and URL-encoded bodies, audio input and file contents (unless Check attached documents is on) are not.
- A private key longer than 8192 characters in a streamed answer may be released in part before its END line arrives; a key cut off at the end of an answer is masked to the end of its base64 lines.
- Masks in answers are always `***`; the replacement text cannot be chosen there.
- A request that needs more than 512 fields masked is rejected with code `secret_guard.too_many_secrets`, because the host takes at most 512 patch operations.
- A string that holds both a secret to mask and an inline media reference is rejected, because the host cannot patch such a value.

## False positives and false negatives

False positives, and how to handle them:

- Test or sample keys of a known prefix: add them to the allowlist (`sk_test_*`, a whole key, or a prefix).
- Documentation values are skipped while Ignore placeholders is on. A real secret that happens to contain `example`, `xxxx`, a run of six equal characters or `1234567890` is skipped too.
- `jwt` and `generic_sk_key` also match short-lived or self-issued tokens that users share on purpose; they mask rather than block by default.
- `generic_assignment` reports code such as `password = "Summer2024!"` in a unit test; it is log only by default. Identifiers, dotted names and function calls (`hashedPassword`, `os.environ.get(...)`) are not reported.
- 40-character base64 strings near an AWS key ID, or 30 and 32 character alphanumeric strings near an Alibaba or Tencent key ID, are treated as secret keys when they mix upper case, lower case and digits. Hex digests are not.

False negatives, and what is not covered:

- Secrets without a known prefix or structure: passwords in prose, session cookies, vendor keys not listed above. Use custom detectors or `generic_assignment`.
- Secrets split by spaces or line breaks, encoded (base64, URL encoding beyond the URL itself) or spelled out by the user.
- Cloud secret keys far (more than 256 characters) from their key ID and not after a known name.
- Database URLs whose password contains an unencoded `@` or `/`, and passwords given as query parameters.
- Text past the per-request limit, files when Check attached documents is off, the second part of a truncated file, and the outputs the host does not pass to the answer check.
