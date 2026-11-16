// Secret Guard: a request processing plugin for new-api that finds
// credentials in prompts and model answers. A request that carries a
// high-confidence secret is rejected, or the secret is masked before the
// request is sent upstream; the same detectors mask secrets in answers.
// Matched text is never logged: findings carry the detector name and, when
// enabled, the first 8 hex digits of the secret's SHA-256.

export const meta = {
  "apiVersion": 1,
  "key": "byaiden_secret_guard",
  "name": "Secret Guard",
  "version": "1.0.1",
  "author": { "name": "ByAiden", "url": "https://github.com/ByAiden" },
  "description": {
    "en": "Blocks or masks API keys, tokens, private keys and passwords in requests and model answers",
    "zh": "拦截或遮盖请求和模型回答中的 API 密钥、令牌、私钥和密码"
  },
  "configSchema": {
    "type": "object",
    "properties": {
      "actions": {
        "type": "object",
        "title": { "en": "Detector actions", "zh": "检测器处理方式" },
        "description": { "en": "What happens when a detector finds a secret in a request", "zh": "检测器在请求中发现密钥时的处理方式" },
        "properties": {
          "private_key": { "type": "string", "title": { "en": "Private key blocks", "zh": "私钥块" }, "description": { "en": "PEM private keys: RSA, EC, DSA, OpenSSH, PKCS#8, encrypted and PGP", "zh": "PEM 私钥：RSA、EC、DSA、OpenSSH、PKCS#8、加密私钥和 PGP" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "openai_api_key": { "type": "string", "title": { "en": "OpenAI API keys", "zh": "OpenAI API 密钥" }, "description": { "en": "Project, service account, admin and legacy user keys", "zh": "项目、服务账号、管理员和旧版用户密钥" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "anthropic_api_key": { "type": "string", "title": { "en": "Anthropic API keys", "zh": "Anthropic API 密钥" }, "description": { "en": "API, admin and OAuth keys", "zh": "API、管理员和 OAuth 密钥" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "google_api_key": { "type": "string", "title": { "en": "Google credentials", "zh": "Google 凭据" }, "description": { "en": "API keys, OAuth client secrets and OAuth access tokens", "zh": "API 密钥、OAuth 客户端密钥和 OAuth 访问令牌" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "aws_access_key_id": { "type": "string", "title": { "en": "AWS access key IDs", "zh": "AWS 访问密钥 ID" }, "description": { "en": "The public half of an AWS key pair", "zh": "AWS 密钥对中公开的部分" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "aws_secret_access_key": { "type": "string", "title": { "en": "AWS secret access keys", "zh": "AWS 秘密访问密钥" }, "description": { "en": "Found next to an access key ID or after an AWS secret key name", "zh": "出现在访问密钥 ID 附近或 AWS 密钥变量名之后时识别" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "github_token": { "type": "string", "title": { "en": "GitHub tokens", "zh": "GitHub 令牌" }, "description": { "en": "Personal, OAuth, app and refresh tokens", "zh": "个人、OAuth、应用和刷新令牌" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "gitlab_token": { "type": "string", "title": { "en": "GitLab tokens", "zh": "GitLab 令牌" }, "description": { "en": "Personal, deploy, runner, trigger and other prefixed tokens", "zh": "个人、部署、Runner、触发器等带前缀的令牌" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "slack_token": { "type": "string", "title": { "en": "Slack tokens and webhooks", "zh": "Slack 令牌和 Webhook" }, "description": { "en": "Bot, user, app and configuration tokens and incoming webhook URLs", "zh": "机器人、用户、应用和配置令牌以及传入 Webhook 地址" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "stripe_live_key": { "type": "string", "title": { "en": "Stripe live keys", "zh": "Stripe 正式密钥" }, "description": { "en": "Live secret and restricted keys and webhook signing secrets", "zh": "正式环境的私密密钥、受限密钥和 Webhook 签名密钥" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "other_api_token": { "type": "string", "title": { "en": "Other vendor tokens", "zh": "其他厂商令牌" }, "description": { "en": "Hugging Face, xAI, Groq, npm, PyPI and SendGrid tokens", "zh": "Hugging Face、xAI、Groq、npm、PyPI 和 SendGrid 令牌" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "alibaba_access_key_id": { "type": "string", "title": { "en": "Alibaba Cloud AccessKey IDs", "zh": "阿里云 AccessKey ID" }, "description": { "en": "The public half of an Alibaba Cloud AccessKey pair", "zh": "阿里云 AccessKey 中公开的部分" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "alibaba_access_key_secret": { "type": "string", "title": { "en": "Alibaba Cloud AccessKey secrets", "zh": "阿里云 AccessKey Secret" }, "description": { "en": "Found next to an AccessKey ID or after an AccessKey secret name", "zh": "出现在 AccessKey ID 附近或 AccessKey Secret 变量名之后时识别" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "tencent_secret_id": { "type": "string", "title": { "en": "Tencent Cloud SecretIds", "zh": "腾讯云 SecretId" }, "description": { "en": "The public half of a Tencent Cloud API key", "zh": "腾讯云 API 密钥中公开的部分" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "tencent_secret_key": { "type": "string", "title": { "en": "Tencent Cloud SecretKeys", "zh": "腾讯云 SecretKey" }, "description": { "en": "Found next to a SecretId or after a Tencent Cloud secret key name", "zh": "出现在 SecretId 附近或腾讯云 SecretKey 变量名之后时识别" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
          "jwt": { "type": "string", "title": { "en": "JSON Web Tokens", "zh": "JSON Web Token" }, "description": { "en": "Signed tokens whose header and payload decode to JSON", "zh": "头部和载荷可解码为 JSON 的已签名令牌" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "db_connection_string": { "type": "string", "title": { "en": "Database URL passwords", "zh": "数据库连接串密码" }, "description": { "en": "The password of a PostgreSQL, MySQL, MongoDB, Redis, AMQP or SQL Server URL", "zh": "PostgreSQL、MySQL、MongoDB、Redis、AMQP 或 SQL Server 连接串中的密码" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "generic_sk_key": { "type": "string", "title": { "en": "Other sk- keys", "zh": "其他 sk- 密钥" }, "description": { "en": "Keys of the sk- shape used by many OpenAI-compatible services", "zh": "众多 OpenAI 兼容服务使用的 sk- 形式密钥" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "mask" },
          "generic_assignment": { "type": "string", "title": { "en": "Password and secret assignments", "zh": "密码和密钥赋值" }, "description": { "en": "Random-looking values after names such as password, secret or api_key", "zh": "password、secret、api_key 等名称之后看起来随机的值" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "log" }
        }
      },
      "replyMode": {
        "type": "string",
        "title": { "en": "Answer check", "zh": "回答检查" },
        "description": { "en": "How secrets in model answers are handled", "zh": "模型回答中出现密钥时的处理方式" },
        "enum": ["mask", "follow", "log", "off"],
        "enumTitles": [
          { "en": "Mask every detector that is not off or log only", "zh": "遮盖所有未关闭且非仅记录的检测器" },
          { "en": "Follow detector actions, block stops the answer", "zh": "按检测器处理方式，拦截时停止回答" },
          { "en": "Log only", "zh": "仅记录" },
          { "en": "Off", "zh": "关闭" }
        ],
        "default": "mask"
      },
      "allowlist": {
        "type": "string",
        "format": "textarea",
        "title": { "en": "Allowlist", "zh": "白名单" },
        "description": { "en": "One value per line that is never treated as a secret; end a line with * to allow a prefix", "zh": "每行一个永不视为密钥的值；以 * 结尾表示前缀匹配" },
        "default": "",
        "maxLength": 20000,
        "examples": ["sk_test_*\nAKIAIOSFODNN7EXAMPLE"]
      },
      "ignorePlaceholders": {
        "type": "boolean",
        "title": { "en": "Ignore placeholders and documentation examples", "zh": "忽略占位符和文档示例" },
        "description": { "en": "Skip values such as xxxx, your-api-key, EXAMPLE keys and the jwt.io sample token", "zh": "跳过 xxxx、your-api-key、EXAMPLE 示例密钥和 jwt.io 示例令牌等值" },
        "default": true
      },
      "customDetectors": {
        "type": "array",
        "title": { "en": "Custom detectors", "zh": "自定义检测器" },
        "description": { "en": "Regular expressions checked after the built-in detectors", "zh": "在内置检测器之后检查的正则表达式" },
        "default": [],
        "maxItems": 20,
        "items": {
          "type": "object",
          "title": { "en": "Detector", "zh": "检测器" },
          "required": ["name", "pattern"],
          "properties": {
            "name": { "type": "string", "title": { "en": "Name", "zh": "名称" }, "description": { "en": "Lowercase letters, digits, dot, dash and underscore; shown in logs", "zh": "小写字母、数字、点、短横线和下划线，显示在日志中" }, "pattern": "^[a-z0-9_.-]{1,48}$", "examples": ["internal_token"] },
            "pattern": { "type": "string", "format": "regex", "title": { "en": "Regular expression", "zh": "正则表达式" }, "description": { "en": "With a capturing group only the first group is treated as the secret", "zh": "含捕获组时只把第一个捕获组视为密钥" }, "minLength": 1, "maxLength": 1024, "examples": ["\\bacme_[A-Za-z0-9]{32}\\b"] },
            "action": { "type": "string", "title": { "en": "Action", "zh": "处理方式" }, "enum": ["block", "mask", "log", "off"], "enumTitles": [{ "en": "Block", "zh": "拦截" }, { "en": "Mask", "zh": "遮盖" }, { "en": "Log only", "zh": "仅记录" }, { "en": "Off", "zh": "关闭" }], "default": "block" },
            "caseInsensitive": { "type": "boolean", "title": { "en": "Ignore letter case", "zh": "忽略大小写" }, "default": false }
          }
        }
      },
      "genericMinEntropy": {
        "type": "number",
        "title": { "en": "Minimum entropy of assignment values", "zh": "赋值内容的最小熵" },
        "description": { "en": "Shannon entropy in bits per character a password or secret value must reach", "zh": "密码或密钥值需要达到的每字符香农熵（比特）" },
        "minimum": 2,
        "maximum": 6,
        "default": 3.5
      },
      "scanFiles": {
        "type": "boolean",
        "title": { "en": "Check attached documents", "zh": "检查附带的文档" },
        "description": { "en": "Also read text, PDF and DOCX files of the request; plain text files can be masked, others are rejected", "zh": "同时读取请求附带的文本、PDF 和 DOCX 文件；纯文本文件可遮盖，其余文件含密钥时拒绝" },
        "default": false
      },
      "maxScanChars": {
        "type": "integer",
        "title": { "en": "Text checked per request", "zh": "每个请求检查的文本量" },
        "description": { "en": "Text past this amount is not checked and is counted as unscanned", "zh": "超出部分不检查，并记为未检查" },
        "unit": "character",
        "minimum": 10000,
        "maximum": 16000000,
        "default": 2000000
      },
      "fingerprints": {
        "type": "boolean",
        "title": { "en": "Record fingerprints", "zh": "记录指纹" },
        "description": { "en": "Add the first 8 hex digits of each secret's SHA-256 to the rule name in the administrator log", "zh": "在管理员日志的规则名中附加每个密钥 SHA-256 的前 8 位十六进制" },
        "default": true
      },
      "message": {
        "type": "string",
        "title": { "en": "Rejection message", "zh": "拒绝提示" },
        "description": { "en": "Shown to the client when a request is blocked; {detectors} lists the detector names", "zh": "请求被拦截时返回给客户端；{detectors} 会替换为检测器名称" },
        "minLength": 1,
        "maxLength": 200,
        "default": "The request contains what looks like a credential ({detectors}). Remove it or replace it with a placeholder and try again."
      }
    }
  },
  "samples": [
    {
      "name": { "en": "Database URL and access token", "zh": "数据库连接串和访问令牌" },
      "lang": "en",
      "format": "openai",
      "body": {
        "model": "gpt-4o-mini",
        "messages": [
          { "role": "user", "content": "My service fails to start. It reads DATABASE_URL=postgres://orders:Kq7vX2pLm9Rt4@db.internal:5432/orders and calls the API with the header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwfQ.Qm9ndXNTaWduYXR1cmVGb3JEb2NzT25seTA5ODc2NTQz . What should I check first?" }
        ]
      },
      "reply": "First confirm that postgres://orders:Kq7vX2pLm9Rt4@db.internal:5432/orders is reachable from the service, then check that the token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTQyIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwfQ.Qm9ndXNTaWduYXR1cmVGb3JEb2NzT25seTA5ODc2NTQz has not expired."
    },
    {
      "name": { "en": "Database URL", "zh": "数据库连接串" },
      "lang": "zh",
      "format": "openai",
      "body": {
        "model": "gpt-4o-mini",
        "messages": [
          { "role": "user", "content": "帮我看看这段配置为什么连不上：DATABASE_URL=mysql://shop:Wb3nH8sYc5Fd1@10.0.0.5:3306/shop" }
        ]
      },
      "reply": "请先确认 mysql://shop:Wb3nH8sYc5Fd1@10.0.0.5:3306/shop 中的主机和端口可以从应用所在机器访问。"
    }
  ]
};

const ACTIONS = ["block", "mask", "log", "off"];
const DEFAULT_ACTIONS = {
  private_key: "block",
  openai_api_key: "block",
  anthropic_api_key: "block",
  google_api_key: "block",
  aws_access_key_id: "mask",
  aws_secret_access_key: "block",
  github_token: "block",
  gitlab_token: "block",
  slack_token: "block",
  stripe_live_key: "block",
  other_api_token: "block",
  alibaba_access_key_id: "mask",
  alibaba_access_key_secret: "block",
  tencent_secret_id: "mask",
  tencent_secret_key: "block",
  jwt: "mask",
  db_connection_string: "mask",
  generic_sk_key: "mask",
  generic_assignment: "log",
};
const DEFAULT_MESSAGE =
  "The request contains what looks like a credential ({detectors}). Remove it or replace it with a placeholder and try again.";
const DEFAULTS = {
  replyMode: "mask",
  allowlist: "",
  ignorePlaceholders: true,
  customDetectors: [],
  genericMinEntropy: 3.5,
  scanFiles: false,
  maxScanChars: 2000000,
  fingerprints: true,
  message: DEFAULT_MESSAGE,
};

const REJECT_CODE = "secret_guard.blocked";
const FILE_REJECT_CODE = "secret_guard.file_blocked";
const LIMIT_REJECT_CODE = "secret_guard.too_many_secrets";
const REPLY_STOP_CODE = "secret_guard.reply_blocked";
const REPLY_STOP_MESSAGE = "The answer was stopped because it contained what looks like a credential.";
const REQUEST_NOTICE = { en: "Credentials in the request were masked before it was sent", zh: "请求中的密钥已在发送前遮盖" };
const REPLY_NOTICE = { en: "Credentials in the answer were masked", zh: "回答中的密钥已遮盖" };

// Host limits on one result.
const MAX_PATCH_OPS = 512;
const MAX_FINDINGS = 64;
const MAX_MASKS = 1024;
const MAX_HOLD = 8192;
// Text kept before the last word of a streamed answer, so that a key name
// such as aws_secret_access_key stays next to the value that follows it.
const HOLD_CONTEXT = 64;
// Strings shorter than this hold no secret any detector reports.
const MIN_TEXT = 12;
const MEDIA_PLACEHOLDER = /^\[media:\d+\]$/;
const MEDIA_REF = /\[media:\d+\]/;

// Members the host guards: ingress keeps model and stream, a late ingress
// also keeps the billing members, and a Midjourney submission keeps action,
// customId and content. Secrets are never searched there.
const GUARDED_KEYS = [
  "model", "stream", "stream_options", "n", "generationConfig", "size", "quality",
  "resolution", "seconds", "duration", "service_tier",
];
const MJ_GUARDED_KEYS = ["action", "customId", "content"];

// ---------------------------------------------------------------------------
// Value checks

function hasDigit(value) {
  return /\d/.test(value);
}

function charClasses(value) {
  return (/[a-z]/.test(value) ? 1 : 0) + (/[A-Z]/.test(value) ? 1 : 0) + (/\d/.test(value) ? 1 : 0) + (/[^A-Za-z0-9]/.test(value) ? 1 : 0);
}

function distinctChars(value) {
  return new Set(value).size;
}

// Shannon entropy in bits per character.
function entropy(value) {
  if (value.length === 0) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let total = 0;
  for (const ch of value) total++;
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / total;
    bits -= p * Math.log2(p);
  }
  return bits;
}

const PLACEHOLDER_WORDS = [
  "example", "placeholder", "your_", "your-", "yourkey", "yourtoken", "yoursecret", "dummy", "sample",
  "redacted", "xxxx", "****", "...", "1234567890", "abcdefghij", "changeme", "insert",
];

// Documentation values and obvious stand-ins: EXAMPLE keys, your-api-key,
// runs of one character, ascending sequences, template variables.
function looksPlaceholder(value) {
  const lower = value.toLowerCase();
  for (const word of PLACEHOLDER_WORDS) if (lower.includes(word)) return true;
  if (/(.)\1{5}/.test(value)) return true;
  if (/^[$%{<[]/.test(value) || /[{}<>]/.test(value)) return true;
  return false;
}

// Strips a vendor prefix such as sk-, ghp_, sk-ant-api03-, github_pat_ or
// sk_live_ so that shape checks look at the random part.
function tokenBody(value) {
  return value.replace(/^[A-Za-z]{2,10}\d{0,2}[-_](?:[a-z]{2,8}\d{0,3}[-_])?(?:pat_)?/, "");
}

// A vendor token's random part: digits, or both letter cases, and enough
// different characters. Prose such as sk-something-long fails.
function randomToken(value, cfg) {
  const body = tokenBody(value);
  if (cfg.ignorePlaceholders && looksPlaceholder(body)) return false;
  if (!(hasDigit(body) || (/[a-z]/.test(body) && /[A-Z]/.test(body)))) return false;
  return distinctChars(body) >= Math.min(10, Math.floor(body.length / 2));
}

function notPlaceholder(value, cfg) {
  return !(cfg.ignorePlaceholders && looksPlaceholder(value));
}

// A paired cloud secret is base64 or alphanumeric noise: all three character
// classes and high entropy, which keeps out hex digests and words.
function strongSecret(value, cfg) {
  if (cfg.ignorePlaceholders && looksPlaceholder(value)) return false;
  return /[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value) && entropy(value) >= 3.5;
}

// ---------------------------------------------------------------------------
// Finders. Each one appends {start, end, value} spans of text; end is
// exclusive and the span is what gets masked. Every pattern starts with a
// literal and every quantifier is bounded, so the work stays linear in the
// text length.

// regexFinder runs a global regex. With group, the secret is that capturing
// group, which the pattern places at the end of its match.
function regexFinder(regex, options) {
  const opts = options || {};
  return function (text, cfg, out) {
    for (const match of text.matchAll(regex)) {
      let value = match[0];
      let start = match.index;
      if (opts.group) {
        const group = match[opts.group];
        if (!group) continue;
        start = match.index + match[0].length - group.length;
        value = group;
      }
      if (opts.trim) value = value.replace(opts.trim, "");
      if (value === "") continue;
      if (opts.valid && !opts.valid(value, cfg, match)) continue;
      out.push({ start: start, end: start + value.length, value: value });
    }
  };
}

const PEM_BEGIN = /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/g;
const PEM_MAX_BODY = 16384;

function isPemBodyChar(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || (code >= 48 && code <= 57) ||
    code === 43 || code === 47 || code === 61 || code === 10 || code === 13 || code === 92;
}

// A PEM private key block, up to its END line. A block cut off before its END
// line still counts, up to the end of its base64 lines, so that a partial
// paste is caught too. A header without at least 64 base64 characters after
// it, as in "-----BEGIN PRIVATE KEY----- ...", is not a key.
function findPem(text, cfg, out) {
  for (const match of text.matchAll(PEM_BEGIN)) {
    const start = match.index;
    const bodyStart = start + match[0].length;
    let bodyEnd;
    let end;
    const endIndex = text.indexOf("-----END ", bodyStart);
    if (endIndex >= 0 && endIndex - bodyStart <= PEM_MAX_BODY) {
      bodyEnd = endIndex;
      const close = text.indexOf("-----", endIndex + 9);
      end = close >= 0 && close - endIndex <= 64 ? close + 5 : endIndex + 9;
    } else {
      let i = bodyStart;
      while (i < text.length && i - bodyStart < PEM_MAX_BODY && isPemBodyChar(text.charCodeAt(i))) i++;
      bodyEnd = i;
      end = i;
    }
    const body = text.slice(bodyStart, bodyEnd).replace(/\\[nr]/g, "");
    const base64 = body.match(/[A-Za-z0-9+/=]/g);
    if (!base64 || base64.length < 64) continue;
    if (cfg.ignorePlaceholders && looksPlaceholder(body.replace(/\s+/g, ""))) continue;
    out.push({ start: start, end: end, value: text.slice(start, end) });
  }
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// Decodes base64url into a string of byte values; null when it is not
// base64url. Multi-byte UTF-8 stays as single bytes, which JSON.parse
// accepts inside strings.
function base64UrlDecode(value) {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (let i = 0; i < value.length; i++) {
    const digit = B64URL.indexOf(value[i]);
    if (digit < 0) return null;
    buffer = ((buffer << 6) | digit) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }
  return out;
}

function decodeJsonObject(segment) {
  const decoded = base64UrlDecode(segment);
  if (decoded === null) return null;
  try {
    const value = JSON.parse(decoded);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch (error) {
    return null;
  }
}

// A signed JWT: the header decodes to a JSON object with alg, the payload to
// a JSON object, and the signature is present. The jwt.io sample token is a
// documentation example.
function validJwt(value, cfg) {
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  const header = decodeJsonObject(parts[0]);
  if (!header || typeof header.alg !== "string" || header.alg.toLowerCase() === "none") return false;
  const payload = decodeJsonObject(parts[1]);
  if (!payload) return false;
  if (cfg.ignorePlaceholders && payload.sub === "1234567890" && payload.name === "John Doe") return false;
  return true;
}

const DB_PLACEHOLDER_PASSWORDS = [
  "password", "passwd", "pass", "pwd", "secret", "changeme", "change_me", "pw", "mypassword", "my_password",
  "yourpassword", "your_password", "your-password", "dbpassword", "db_password", "user_password", "password123",
  "example", "test", "admin", "root", "postgres", "mysql", "redis", "guest", "foobar", "foo", "bar",
];

// The password of a connection URL. Template variables, masked values and
// the stand-ins of documentation, such as user:password@ or guest:guest@,
// are not secrets.
function validDbPassword(value, cfg, match) {
  if (!cfg.ignorePlaceholders) return true;
  const lower = value.toLowerCase();
  if (DB_PLACEHOLDER_PASSWORDS.includes(lower)) return false;
  if (/^[*xX.•]+$/.test(value) || /^[$%{<[]/.test(value)) return false;
  const user = match[1] || "";
  if (user !== "" && user === value) return false;
  return !looksPlaceholder(value);
}

// Values after password=, secret: and similar names. Identifiers, dotted
// names and calls are code, not secrets; short values need fewer bits per
// character because they cannot reach a high entropy.
function validAssignment(value, cfg) {
  if (cfg.ignorePlaceholders && looksPlaceholder(value)) return false;
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) && !hasDigit(value)) return false;
  if (/^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(value)) return false;
  if (/^(?:true|false|null|none|undefined|required|optional|string)$/i.test(value)) return false;
  if (value.startsWith("[REDACTED")) return false;
  if (charClasses(value) < 2) return false;
  const threshold = Math.min(cfg.genericMinEntropy, Math.log2(value.length) - 0.5);
  return entropy(value) >= threshold;
}

// pairFinder finds a cloud secret by a key name before it, or as a random
// value of the secret's length near the matching key ID.
function pairFinder(keywordRegex, idRegex, candidateRegex, idPrefix) {
  return function (text, cfg, out) {
    for (const match of text.matchAll(keywordRegex)) {
      const value = match[1];
      if (!value) continue;
      const start = match.index + match[0].length - value.length;
      if (randomToken(value, cfg)) out.push({ start: start, end: start + value.length, value: value });
    }
    for (const id of text.matchAll(idRegex)) {
      const from = Math.max(0, id.index - 256);
      const window = text.slice(from, Math.min(text.length, id.index + id[0].length + 256));
      for (const candidate of window.matchAll(candidateRegex)) {
        const value = candidate[0];
        if (value.startsWith(idPrefix) || !strongSecret(value, cfg)) continue;
        const start = from + candidate.index;
        out.push({ start: start, end: start + value.length, value: value });
      }
    }
  };
}

// Built-in detectors in priority order: when two spans overlap, the one that
// starts first wins, and at the same start the earlier detector. pre is a
// cheap test that skips the detector on text that cannot hold its secret.
const BUILT_INS = [
  {
    id: "private_key",
    pre: /-----BEGIN [A-Z ]{0,24}PRIVATE KEY/,
    find: findPem,
  },
  {
    id: "anthropic_api_key",
    pre: /sk-ant-/,
    find: regexFinder(/\bsk-ant-[a-z]{2,8}\d{0,3}-[A-Za-z0-9_-]{32,400}/g, { valid: randomToken }),
  },
  {
    id: "openai_api_key",
    pre: /sk-(?:proj|svcacct|admin)-|T3BlbkFJ/,
    find: regexFinder(/\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,400}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, { valid: randomToken }),
  },
  {
    id: "google_api_key",
    pre: /AIza|GOCSPX-|ya29\./,
    find: regexFinder(/\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])|\bGOCSPX-[0-9A-Za-z_-]{28}(?![0-9A-Za-z_-])|\bya29\.[0-9A-Za-z_-]{30,2048}/g, { valid: randomToken }),
  },
  {
    id: "github_token",
    pre: /gh[pousr]_|github_pat_/,
    find: regexFinder(/\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{50,251})(?![A-Za-z0-9_])/g, { valid: randomToken }),
  },
  {
    id: "gitlab_token",
    pre: /gl(?:pat|dt|rt|ptt|ft|soat|cbt|imt|agent|oas|ffct|cst|wt)-/,
    find: regexFinder(/\b(?:glpat|gldt|glrt|glptt|glft|glsoat|glcbt|glimt|glagent|gloas|glffct|glcst|glwt)-[A-Za-z0-9_.-]{20,300}/g, { trim: /[.-]+$/, valid: randomToken }),
  },
  {
    id: "slack_token",
    pre: /xox[abposre]-|xapp-|hooks\.slack\.com/,
    find: regexFinder(/\bxox[abposre]-[A-Za-z0-9-]{10,250}|\bxapp-\d-[A-Za-z0-9-]{20,250}|https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/-]{20,250}/g, {
      trim: /-+$/,
      valid: function (value, cfg) {
        return hasDigit(value) && notPlaceholder(value.replace(/^https:\/\/hooks\.slack\.com\//, ""), cfg);
      },
    }),
  },
  {
    id: "stripe_live_key",
    pre: /_live_|whsec_/,
    find: regexFinder(/\b(?:sk|rk)_live_[A-Za-z0-9]{20,247}\b|\bwhsec_[A-Za-z0-9+\/]{32,100}={0,2}/g, { valid: randomToken }),
  },
  {
    id: "other_api_token",
    pre: /hf_|xai-|gsk_|npm_|pypi-|SG\./,
    find: regexFinder(/\bhf_[A-Za-z0-9]{30,40}\b|\bxai-[A-Za-z0-9]{60,100}\b|\bgsk_[A-Za-z0-9]{48,56}\b|\bnpm_[A-Za-z0-9]{36}\b|\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,300}|\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g, { valid: randomToken }),
  },
  {
    id: "aws_access_key_id",
    pre: /A(?:KIA|SIA|BIA|CCA)/,
    find: regexFinder(/\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g, { valid: notPlaceholder }),
  },
  {
    id: "aws_secret_access_key",
    pre: /secret|A(?:KIA|SIA|BIA|CCA)/i,
    find: pairFinder(
      /(?:aws_?secret_?access_?key|aws_?secret_?key|aws_?secret|secret_?access_?key)["']?[ \t]*(?:=|:|=>)[ \t]*["']?([A-Za-z0-9\/+]{40})(?![A-Za-z0-9\/+=])/gi,
      /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g,
      /(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+]{40}(?![A-Za-z0-9\/+=])/g,
      "AKIA",
    ),
  },
  {
    id: "alibaba_access_key_id",
    pre: /LTAI/,
    find: regexFinder(/\bLTAI[A-Za-z0-9]{12,20}\b/g, { valid: randomToken }),
  },
  {
    id: "alibaba_access_key_secret",
    pre: /secret|LTAI/i,
    find: pairFinder(
      /(?:access_?key_?secret|alibaba_?cloud_?access_?key_?secret|alicloud_?secret_?key|aliyun_?secret(?:_?key)?)["']?[ \t]*(?:=|:|=>)[ \t]*["']?([A-Za-z0-9]{30})(?![A-Za-z0-9])/gi,
      /\bLTAI[A-Za-z0-9]{12,20}\b/g,
      /(?<![A-Za-z0-9])[A-Za-z0-9]{30}(?![A-Za-z0-9])/g,
      "LTAI",
    ),
  },
  {
    id: "tencent_secret_id",
    pre: /AKID/,
    find: regexFinder(/\bAKID[A-Za-z0-9]{32}\b/g, { valid: randomToken }),
  },
  {
    id: "tencent_secret_key",
    pre: /tencent|tc_?secret|AKID/i,
    find: pairFinder(
      /(?:tencentcloud_?secret_?key|tencent_?(?:cloud_?)?secret_?key|tc_?secret_?key)["']?[ \t]*(?:=|:|=>)[ \t]*["']?([A-Za-z0-9]{32})(?![A-Za-z0-9])/gi,
      /\bAKID[A-Za-z0-9]{32}\b/g,
      /(?<![A-Za-z0-9])[A-Za-z0-9]{32}(?![A-Za-z0-9])/g,
      "AKID",
    ),
  },
  {
    id: "jwt",
    pre: /eyJ/,
    find: regexFinder(/\beyJ[A-Za-z0-9_-]{8,1024}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{16,1024}/g, { valid: validJwt }),
  },
  {
    id: "db_connection_string",
    pre: /:\/\/[^\s@]{0,400}@/,
    find: regexFinder(
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse|cockroachdb|jdbc:[a-z]{2,16})(?:\+[a-z0-9]{1,16})?:\/\/([^\s:\/@'"`<>]{0,128}):([^\s\/@'"`<>]{1,256})(?=@[A-Za-z0-9\[._-])/gi,
      { group: 2, valid: validDbPassword },
    ),
  },
  {
    id: "generic_sk_key",
    pre: /sk-/,
    find: regexFinder(/\bsk-[A-Za-z0-9]{32,64}(?![A-Za-z0-9_-])/g, {
      valid: function (value, cfg) {
        return hasDigit(value.slice(3)) && randomToken(value, cfg);
      },
    }),
  },
  {
    id: "generic_assignment",
    pre: /pass|pwd|secret|key|token/i,
    find: regexFinder(
      /(?:^|[^A-Za-z0-9_])(?:pass(?:word|wd)?|pwd|secret(?:[_-]?key)?|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|token)["']?[ \t]*(?:=|:|=>)[ \t]*["']?([^\s"'`,;()<>{}\[\]]{8,128})/gi,
      { group: 1, valid: validAssignment },
    ),
  },
];

const BUILT_IN_IDS = BUILT_INS.map(function (detector) {
  return detector.id;
});

// ---------------------------------------------------------------------------
// Config

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// The host fills in the schema defaults; this repeats them so that a dry run
// or a fixture with a partial config behaves the same.
function resolveConfig(raw) {
  const config = isObject(raw) ? raw : {};
  const cfg = {};
  for (const name of Object.keys(DEFAULTS)) cfg[name] = config[name] === undefined ? DEFAULTS[name] : config[name];
  const actions = isObject(config.actions) ? config.actions : {};
  cfg.actions = {};
  for (const id of BUILT_IN_IDS) cfg.actions[id] = ACTIONS.includes(actions[id]) ? actions[id] : DEFAULT_ACTIONS[id];
  if (typeof cfg.genericMinEntropy !== "number") cfg.genericMinEntropy = DEFAULTS.genericMinEntropy;
  if (typeof cfg.maxScanChars !== "number" || cfg.maxScanChars <= 0) cfg.maxScanChars = DEFAULTS.maxScanChars;
  if (typeof cfg.message !== "string" || cfg.message === "") cfg.message = DEFAULT_MESSAGE;
  cfg.allow = parseAllowlist(cfg.allowlist);
  return cfg;
}

function parseAllowlist(text) {
  const exact = new Set();
  const prefixes = [];
  if (typeof text !== "string") return { exact: exact, prefixes: prefixes };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    if (line.endsWith("*")) {
      const prefix = line.slice(0, -1);
      if (prefix !== "") prefixes.push(prefix);
    } else {
      exact.add(line);
    }
  }
  return { exact: exact, prefixes: prefixes };
}

function allowed(cfg, value) {
  if (cfg.allow.exact.has(value)) return true;
  for (const prefix of cfg.allow.prefixes) if (value.startsWith(prefix)) return true;
  return false;
}

// Go-style patterns often start with (?i); JavaScript takes it as a flag.
function compileCustom(detector, index) {
  const name = detector.name;
  let source = detector.pattern;
  let flags = "g";
  if (detector.caseInsensitive === true) flags = "gi";
  if (source.startsWith("(?i)")) {
    source = source.slice(4);
    flags = "gi";
  }
  let regex;
  try {
    regex = new RegExp(source, flags);
  } catch (error) {
    throw new Error('Custom detector "' + name + '" has an invalid regular expression');
  }
  if (new RegExp(source, flags.replace("g", "")).test("")) {
    throw new Error('Custom detector "' + name + '" matches empty text');
  }
  return regex;
}

function customDetectors(cfg) {
  const list = Array.isArray(cfg.customDetectors) ? cfg.customDetectors : [];
  const detectors = [];
  const names = new Set();
  for (let i = 0; i < list.length; i++) {
    const item = list[i];
    if (!isObject(item) || typeof item.pattern !== "string" || item.pattern === "") continue;
    const name = typeof item.name === "string" && /^[a-z0-9_.-]{1,48}$/.test(item.name) ? item.name : "rule-" + (i + 1);
    if (names.has(name)) throw new Error('Custom detector name "' + name + '" is used more than once');
    names.add(name);
    const regex = compileCustom({ name: name, pattern: item.pattern, caseInsensitive: item.caseInsensitive }, i);
    detectors.push({
      id: "custom." + name,
      action: ACTIONS.includes(item.action) ? item.action : "block",
      find: function (text, c, out) {
        for (const match of text.matchAll(regex)) {
          if (match[0] === "") continue;
          let start = match.index;
          let value = match[0];
          if (match.length > 1 && typeof match[1] === "string" && match[1] !== "") {
            const offset = match[0].indexOf(match[1]);
            if (offset >= 0) {
              start = match.index + offset;
              value = match[1];
            }
          }
          out.push({ start: start, end: start + value.length, value: value });
        }
      },
    });
  }
  return detectors;
}

// activeDetectors lists the detectors to run with the action each takes.
// mapAction turns a request action into the action of the current check.
function activeDetectors(cfg, mapAction) {
  const list = [];
  for (const detector of BUILT_INS) {
    const action = mapAction(cfg.actions[detector.id]);
    if (action !== "off") list.push({ id: detector.id, pre: detector.pre, find: detector.find, action: action });
  }
  for (const detector of customDetectors(cfg)) {
    const action = mapAction(detector.action);
    if (action !== "off") list.push({ id: detector.id, pre: null, find: detector.find, action: action });
  }
  return list;
}

function sameAction(action) {
  return action;
}

// Runs when an instance is saved, so a custom detector that cannot compile or
// matches empty text is refused there instead of failing every request.
export function validateConfig(config) {
  const cfg = resolveConfig(config || {});
  customDetectors(cfg);
  if (cfg.allow.exact.size + cfg.allow.prefixes.length > 1000) throw new Error("The allowlist holds more than 1000 entries");
}

// ---------------------------------------------------------------------------
// Scanning

// scan returns the secrets of text as non-overlapping spans with their
// detector and action, in text order. Allowlisted values are dropped.
function scan(text, detectors, cfg) {
  const hits = [];
  for (let order = 0; order < detectors.length; order++) {
    const detector = detectors[order];
    if (detector.pre && !detector.pre.test(text)) continue;
    const spans = [];
    detector.find(text, cfg, spans);
    for (const span of spans) {
      if (allowed(cfg, span.value)) continue;
      hits.push({ start: span.start, end: span.end, value: span.value, id: detector.id, action: detector.action, order: order });
    }
  }
  hits.sort(function (a, b) {
    return a.start - b.start || a.order - b.order || b.end - a.end;
  });
  const kept = [];
  let lastEnd = -1;
  for (const hit of hits) {
    if (hit.start < lastEnd) continue;
    kept.push(hit);
    lastEnd = hit.end;
  }
  return kept;
}

function maskText(text, hits) {
  let result = "";
  let cursor = 0;
  for (const hit of hits) {
    result += text.slice(cursor, hit.start) + "[REDACTED:" + hit.id + "]";
    cursor = hit.end;
  }
  return result + text.slice(cursor);
}

function fingerprint(value) {
  if (typeof utils === "undefined" || typeof utils.sha256 !== "function") return "";
  return String(utils.sha256(value)).slice(0, 8);
}

// Findings name the detector, and with fingerprints on, the first 8 hex
// digits of the secret's SHA-256 in the rule: enough to tell whether the
// same secret comes back, never enough to recover it.
function Findings(cfg) {
  this.cfg = cfg;
  this.map = new Map();
}

Findings.prototype.add = function (hit) {
  let rule = hit.id;
  if (this.cfg.fingerprints) {
    const fp = fingerprint(hit.value);
    if (fp !== "") rule = hit.id + ":" + fp;
  }
  const entry = this.map.get(rule);
  if (entry) entry.count++;
  else this.map.set(rule, { rule: rule, category: hit.id, count: 1 });
};

Findings.prototype.addCount = function (rule, category, count) {
  const entry = this.map.get(rule);
  if (entry) entry.count += count;
  else this.map.set(rule, { rule: rule, category: category, count: count });
};

Findings.prototype.list = function () {
  return Array.from(this.map.values()).slice(0, MAX_FINDINGS);
};

function escapePointer(key) {
  return String(key).replace(/~/g, "~0").replace(/\//g, "~1");
}

// collectStrings lists every string of the body with its JSON Pointer, skipping
// guarded members and media placeholders, within the character budget.
function collectStrings(body, format) {
  const fields = [];
  const guarded = new Set(format === "mj_proxy" ? GUARDED_KEYS.concat(MJ_GUARDED_KEYS) : GUARDED_KEYS);
  const stack = [];
  // Members are visited in sorted order, as the host passes them without the
  // json-order capability, so results are the same on every host.
  if (isObject(body)) {
    const keys = Object.keys(body).sort();
    for (let i = keys.length - 1; i >= 0; i--) {
      if (!guarded.has(keys[i])) stack.push({ path: "/" + escapePointer(keys[i]), value: body[keys[i]], depth: 1 });
    }
  } else if (Array.isArray(body)) {
    for (let i = body.length - 1; i >= 0; i--) stack.push({ path: "/" + i, value: body[i], depth: 1 });
  }
  while (stack.length > 0) {
    const item = stack.pop();
    const value = item.value;
    if (typeof value === "string") {
      if (value.length >= MIN_TEXT && !MEDIA_PLACEHOLDER.test(value)) fields.push({ path: item.path, text: value });
    } else if (item.depth < 64 && Array.isArray(value)) {
      for (let i = value.length - 1; i >= 0; i--) stack.push({ path: item.path + "/" + i, value: value[i], depth: item.depth + 1 });
    } else if (item.depth < 64 && isObject(value)) {
      const keys = Object.keys(value).sort();
      for (let i = keys.length - 1; i >= 0; i--) {
        stack.push({ path: item.path + "/" + escapePointer(keys[i]), value: value[keys[i]], depth: item.depth + 1 });
      }
    }
  }
  return fields;
}

function rejectMessage(cfg, ids) {
  const names = Array.from(new Set(ids)).join(", ");
  return cfg.message.split("{detectors}").join(names).slice(0, 256);
}

// Text files of the request, when enabled. A plain text file the host read
// whole takes the masked text; any other file holding a secret to mask, such
// as a PDF, cannot be rewritten and the request is rejected.
function scanAttachments(cfg, detectors, findings, effects, budget) {
  if (typeof utils === "undefined" || typeof utils.attachments !== "function") return null;
  for (const attachment of utils.attachments()) {
    if (!attachment || !attachment.ref || attachment.kind !== "document") continue;
    if (budget.left <= 0) {
      findings.addCount("scan_limit", "unscanned", 1);
      continue;
    }
    const read = utils.mediaText(attachment.ref, { maxChars: Math.max(1, Math.min(131072, budget.left)) });
    if (!read || typeof read.text !== "string") continue;
    budget.left -= read.text.length;
    if (read.truncated) findings.addCount("file_truncated", "unscanned", 1);
    const hits = scan(read.text, detectors, cfg);
    if (hits.length === 0) continue;
    for (const hit of hits) findings.add(hit);
    const blocking = hits.filter(function (hit) {
      return hit.action === "block";
    });
    if (blocking.length > 0) return { code: FILE_REJECT_CODE, ids: blocking.map((hit) => hit.id) };
    const masked = hits.filter(function (hit) {
      return hit.action === "mask";
    });
    if (masked.length === 0) continue;
    if (attachment.rewritable !== true || read.truncated) return { code: FILE_REJECT_CODE, ids: masked.map((hit) => hit.id) };
    effects.push({ type: "media.text", media: Number(attachment.ref.slice(7, -1)), text: maskText(read.text, masked) });
  }
  return null;
}

// ingress checks the client's body once per request, or the upstream body
// when a channel binds the instance. A block action rejects the request
// before it is priced or sent; mask replaces each secret with
// [REDACTED:<detector>]; log only records the finding.
export function ingress(ctx, req) {
  const cfg = resolveConfig(ctx && ctx.config);
  const detectors = activeDetectors(cfg, sameAction);
  if (detectors.length === 0) return { action: "continue" };
  const findings = new Findings(cfg);
  const fields = collectStrings(req && req.body, ctx && ctx.format);
  const budget = { left: cfg.maxScanChars };
  const ops = [];
  const blocked = [];
  let unscanned = 0;
  let masked = 0;
  for (const field of fields) {
    if (budget.left < field.text.length) {
      unscanned++;
      continue;
    }
    budget.left -= field.text.length;
    const hits = scan(field.text, detectors, cfg);
    if (hits.length === 0) continue;
    const toMask = [];
    for (const hit of hits) {
      findings.add(hit);
      if (hit.action === "block") blocked.push(hit.id);
      else if (hit.action === "mask") toMask.push(hit);
    }
    if (toMask.length > 0) {
      const text = maskText(field.text, toMask);
      // A json.patch value must not hold a media reference.
      if (MEDIA_REF.test(text)) blocked.push(toMask[0].id);
      else ops.push({ op: "replace", path: field.path, value: text });
      masked += toMask.length;
    }
  }
  if (unscanned > 0) findings.addCount("scan_limit", "unscanned", unscanned);
  if (blocked.length > 0) {
    return { action: "reject", code: REJECT_CODE, message: rejectMessage(cfg, blocked), ruleId: blocked[0], findings: findings.list() };
  }
  // The host takes at most 512 patch operations: past that the request
  // cannot be masked and is rejected rather than sent with secrets.
  if (ops.length > MAX_PATCH_OPS) {
    return { action: "reject", code: LIMIT_REJECT_CODE, message: rejectMessage(cfg, [ops.length + " masked fields"]), findings: findings.list() };
  }
  const effects = ops.length > 0 ? [{ type: "json.patch", ops: ops }] : [];
  if (cfg.scanFiles === true) {
    const fileReject = scanAttachments(cfg, detectors, findings, effects, budget);
    if (fileReject) {
      return { action: "reject", code: fileReject.code, message: rejectMessage(cfg, fileReject.ids), ruleId: fileReject.ids[0], findings: findings.list() };
    }
  }
  const result = { action: "continue", effects: effects, findings: findings.list() };
  if (effects.length > 0) result.notice = REQUEST_NOTICE;
  return result;
}

// ---------------------------------------------------------------------------
// Answers

function replyMapper(mode) {
  return function (action) {
    if (action === "off") return "off";
    if (mode === "log") return "log";
    if (mode === "mask") return action === "log" ? "log" : "mask";
    return action;
  };
}

function isSpace(code) {
  return code === 32 || code === 9 || code === 10 || code === 13 || code === 12 || code === 11 || code === 0xa0 || code === 0x3000;
}

// releasePoint is where a streamed, unfinished output may be cut: before its
// last word and the context in front of it, before an open private key block,
// and before any secret that reaches past that point and may still grow.
// The cut always falls at the start of a word: a word cut in two would leave
// the next call a secret without the prefix that identifies it, such as a
// database URL without its scheme.
function releasePoint(text, hits) {
  const limit = Math.max(0, text.length - MAX_HOLD);
  const wordStart = function (pos) {
    while (pos > limit && !isSpace(text.charCodeAt(pos - 1))) pos--;
    return pos;
  };
  let release = wordStart(Math.max(limit, wordStart(text.length) - HOLD_CONTEXT));
  const begin = text.lastIndexOf("-----BEGIN ");
  if (begin >= 0 && begin < release && text.indexOf("-----END ", begin) < 0 && /PRIVATE KEY/.test(text.slice(begin, begin + 64))) {
    release = wordStart(Math.max(limit, begin));
  }
  for (const hit of hits) {
    if (hit.end > release && hit.start < release) release = wordStart(Math.max(limit, hit.start));
  }
  return release;
}

// reply checks the model's answer. In a stream each output keeps back its
// last word, so a key split across chunks is masked whole once it is
// complete. Masked spans become *** (the host's fixed mask text).
export function reply(ctx, res) {
  const cfg = resolveConfig(ctx && ctx.config);
  if (cfg.replyMode === "off") return { action: "pass" };
  const detectors = activeDetectors(cfg, replyMapper(cfg.replyMode));
  if (detectors.length === 0) return { action: "pass" };
  const outputs = res && Array.isArray(res.outputs) ? res.outputs : [];
  const stream = !!(res && res.stream);
  const findings = new Findings(cfg);
  const plans = [];
  let hold = 0;
  for (const output of outputs) {
    const text = typeof output.text === "string" ? output.text : "";
    if (text === "") continue;
    const hits = text.length > cfg.maxScanChars ? scan(text.slice(0, cfg.maxScanChars), detectors, cfg) : scan(text, detectors, cfg);
    let release = text.length;
    if (stream && output.final !== true) {
      release = releasePoint(text, hits);
      hold = Math.max(hold, text.length - release);
    }
    plans.push({ output: output, hits: hits, release: release });
  }
  const mask = [];
  const stopped = [];
  for (const plan of plans) {
    for (const hit of plan.hits) {
      // A secret that may still grow waits for the next call, unless it is
      // to stop the answer: its matched part already is a secret.
      if (hit.end > plan.release && hit.action !== "block") continue;
      findings.add(hit);
      if (hit.action === "block") stopped.push(hit.id);
      else if (hit.action === "mask" && mask.length < MAX_MASKS) {
        mask.push({ index: plan.output.index, start: hit.start, end: hit.end, category: hit.id });
      }
    }
  }
  if (stopped.length > 0) {
    return { action: "stop", code: REPLY_STOP_CODE, message: REPLY_STOP_MESSAGE, findings: findings.list() };
  }
  const result = { action: "continue", mask: mask, hold: stream ? Math.min(MAX_HOLD, hold) : 0, findings: findings.list() };
  if (mask.length > 0) result.notice = REPLY_NOTICE;
  return result;
}
