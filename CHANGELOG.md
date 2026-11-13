---
changelogVersion: 1
plugin: byaiden_secret_guard
version: 1.0.0
locale: "en"
translations:
  zh-CN: CHANGELOG.zh-CN.md
---

# Changelog

## [1.0.0]

### Added

- Request check at the ingress stage that finds credentials in every string of the JSON body (chat, Responses, Claude, Gemini, task and form bodies, tool calls and tool results) and blocks the request, masks each secret as `[REDACTED:detector_name]` before it is sent, or only logs it.
- Nineteen detectors with prefix and shape checks: private key blocks, OpenAI, Anthropic, Google, GitHub, GitLab, Slack, Stripe live, Hugging Face, xAI, Groq, npm, PyPI and SendGrid tokens, AWS, Alibaba Cloud and Tencent Cloud key pairs, JWTs, database URL passwords, `sk-` keys and entropy-gated password and secret assignments.
- Answer check on Chat Completions, Responses, Claude Messages and Gemini answers, streamed or not, that masks secrets a model repeats, or stops the answer in Follow mode, holding back only the last word of a stream.
- Settings for each detector's action, the answer check mode, an allowlist of exact values and prefixes, placeholder and documentation example skipping, custom regular expression detectors, the assignment entropy threshold, attached document checks, the per-request text limit, SHA-256 fingerprints in administrator logs and the rejection message.
