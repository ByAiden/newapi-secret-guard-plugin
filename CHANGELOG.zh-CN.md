---
changelogVersion: 1
plugin: byaiden_secret_guard
version: 1.0.0
locale: "zh-CN"
---

# Changelog

## [1.0.0]

### Added

- 在 ingress 阶段检查请求：识别 JSON 请求体中所有字符串里的密钥（对话、Responses、Claude、Gemini、任务和表单请求体，以及工具调用和工具结果），按设置拒绝请求、在发送前把每个密钥遮盖为 `[REDACTED:检测器名]`，或仅记录。
- 十九个带前缀和形态检查的检测器：私钥块，OpenAI、Anthropic、Google、GitHub、GitLab、Slack、Stripe 正式环境、Hugging Face、xAI、Groq、npm、PyPI 和 SendGrid 令牌，AWS、阿里云和腾讯云密钥对，JWT，数据库连接串密码，`sk-` 密钥，以及按熵过滤的密码和密钥赋值。
- 回答检查：覆盖 Chat Completions、Responses、Claude Messages 和 Gemini 的流式与非流式回答，遮盖模型复述的密钥，或在「按检测器处理方式」模式下停止回答；流式回答只保留最后一个词。
- 设置项：每个检测器的处理方式、回答检查模式、精确值和前缀白名单、跳过占位符和文档示例、自定义正则检测器、赋值内容的熵阈值、附带文档检查、每个请求的检查量、管理员日志中的 SHA-256 指纹以及拒绝提示。
