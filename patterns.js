/**
 * patterns.js
 * ----------------------------------------------------------------------------
 * All detection rules for PromptGuard live here: regex-based secret/PII
 * patterns, phrase lists for prompt-injection & jailbreak detection, and a
 * couple of small validators (Luhn check, zero-width/hidden-unicode scan).
 *
 * Every pattern entry has the shape:
 * {
 *   id:         unique string key
 *   category:   human-readable label shown in the UI
 *   severity:   'critical' | 'high' | 'medium' | 'low'
 *   regex:      a GLOBAL RegExp (must have the 'g' flag, may also have 'i'/'m')
 *   placeholder: token used to replace matches when redacting
 *   recommendation: short actionable advice shown per finding
 *   validate:   optional function(matchText) -> boolean, runs after the regex
 *               matches, used for things like credit-card Luhn validation
 * }
 *
 * Nothing in this file performs network requests. It only exports data and
 * pure functions for app.js to consume.
 * ----------------------------------------------------------------------------
 */

/** Luhn checksum — used to confirm a digit string is a *plausible* card number. */
function luhnCheck(numStr) {
  const digits = numStr.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** Detects zero-width / invisible unicode characters often used to smuggle hidden instructions. */
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\u200E\u200F\u2060\uFEFF\u00AD]/g;

/** Detects other non-printing / control characters (excluding normal whitespace \t \n \r). */
const HIDDEN_CONTROL_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g;

const PG_PATTERNS = [
  // ---------------------------------------------------------------- KEYS / TOKENS
  {
    id: 'openai_key',
    category: 'OpenAI API Key',
    severity: 'critical',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    placeholder: '[OPENAI_API_KEY]',
    recommendation: 'Revoke this key immediately in your OpenAI dashboard and rotate it. Never paste live keys into a prompt.'
  },
  {
    id: 'anthropic_key',
    category: 'Anthropic API Key',
    severity: 'critical',
    regex: /\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{20,}\b/g,
    placeholder: '[ANTHROPIC_API_KEY]',
    recommendation: 'Revoke this key in the Anthropic Console and rotate it. Keep API keys in environment variables, not prompts.'
  },
  {
    id: 'google_api_key',
    category: 'Google API Key',
    severity: 'critical',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    placeholder: '[GOOGLE_API_KEY]',
    recommendation: 'Restrict and rotate this key in Google Cloud Console. Avoid sharing it in plaintext.'
  },
  {
    id: 'aws_access_key',
    category: 'AWS Access Key',
    severity: 'critical',
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g,
    placeholder: '[AWS_ACCESS_KEY]',
    recommendation: 'Deactivate this access key in IAM immediately and issue a new one. Treat as fully compromised.'
  },
  {
    id: 'aws_secret_key',
    category: 'AWS Secret Key (heuristic)',
    severity: 'high',
    regex: /\b(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    placeholder: '[AWS_SECRET_KEY]',
    recommendation: 'This looks like an AWS secret access key assignment. Rotate the credential and remove it from prompts/code.'
  },
  {
    id: 'github_pat',
    category: 'GitHub Personal Access Token',
    severity: 'critical',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
    placeholder: '[GITHUB_TOKEN]',
    recommendation: 'Revoke this token in GitHub Settings → Developer settings → Personal access tokens, then generate a new one.'
  },
  {
    id: 'bearer_token',
    category: 'Bearer Token',
    severity: 'critical',
    regex: /\bBearer\s+[A-Za-z0-9\-._~+/]{15,}={0,2}/g,
    placeholder: '[BEARER_TOKEN]',
    recommendation: 'Bearer tokens grant authenticated access. Revoke/rotate the underlying credential and avoid pasting auth headers.'
  },
  {
    id: 'jwt_token',
    category: 'JWT Token',
    severity: 'critical',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    placeholder: '[JWT_TOKEN]',
    recommendation: 'JWTs often carry session/auth claims. Invalidate the session server-side and avoid sharing tokens.'
  },
  {
    id: 'ssh_private_key',
    category: 'SSH Private Key',
    severity: 'critical',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----/g,
    placeholder: '[SSH_PRIVATE_KEY]',
    recommendation: 'This is a private SSH key. Treat it as fully compromised — remove the key pair from authorized_keys and generate a new one.'
  },
  {
    id: 'rsa_private_key',
    category: 'RSA Private Key',
    severity: 'critical',
    regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    placeholder: '[RSA_PRIVATE_KEY]',
    recommendation: 'This is a private key block. Rotate any certificates/keys derived from it and never share private key material.'
  },

  // ---------------------------------------------------------------- PII
  {
    id: 'email',
    category: 'Email Address',
    severity: 'medium',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    placeholder: '[EMAIL]',
    recommendation: 'Consider removing personal email addresses before sharing with a third-party AI service.'
  },
  {
    id: 'phone',
    category: 'Phone Number',
    severity: 'medium',
    regex: /(?<![A-Za-z0-9])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{2,4})?(?![A-Za-z0-9])/g,
    placeholder: '[PHONE]',
    recommendation: 'Phone numbers are personally identifiable. Redact before sending to external AI providers.',
    // Lightweight sanity filter to cut down false positives on plain numbers/years
    validate: (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15;
    }
  },
  {
    id: 'credit_card',
    category: 'Credit Card Number',
    severity: 'high',
    regex: /(?<![A-Za-z0-9])(?:\d[ -]?){13,19}(?![A-Za-z0-9])/g,
    placeholder: '[CREDIT_CARD]',
    recommendation: 'A valid card number (Luhn-checked) was found. Never share full card numbers with an AI prompt.',
    validate: (m) => luhnCheck(m)
  },
  {
    id: 'ipv4',
    category: 'IPv4 Address',
    severity: 'low',
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
    placeholder: '[IPV4]',
    recommendation: 'IP addresses can reveal network/infrastructure info. Redact if not essential to your prompt.'
  },
  {
    id: 'ipv6',
    category: 'IPv6 Address',
    severity: 'low',
    regex: /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}\b/g,
    placeholder: '[IPV6]',
    recommendation: 'IPv6 addresses can reveal network/infrastructure info. Redact if not essential to your prompt.',
    validate: (m) => m.includes(':') && m.split(':').length >= 3
  },
  {
    id: 'url',
    category: 'URL',
    severity: 'low',
    regex: /\bhttps?:\/\/[^\s"'<>]+/g,
    placeholder: '[URL]',
    recommendation: 'Double-check URLs for embedded tokens, internal hostnames, or signed query parameters before sharing.'
  },

  // ---------------------------------------------------------------- SECRETS / CONFIG
  {
    id: 'password_assignment',
    category: 'Password Assignment',
    severity: 'critical',
    regex: /\b(?:password|passwd|pwd|pass)\s*[:=]\s*['"]?[^\s'",]{3,}['"]?/gi,
    placeholder: '[PASSWORD]',
    recommendation: 'A plaintext password assignment was found. Rotate this password and never paste credentials into prompts.'
  },
  {
    id: 'db_connection_string',
    category: 'Database Connection String',
    severity: 'critical',
    regex: /\b(?:postgres(?:ql)?|mysql|mssql|jdbc:[a-z]+|redis|amqp|sqlserver):\/\/[^\s'"]+/gi,
    placeholder: '[DB_CONNECTION_STRING]',
    recommendation: 'Connection strings often embed credentials. Rotate DB passwords and store connection info in secrets managers.'
  },
  {
    id: 'mongodb_connection_string',
    category: 'MongoDB Connection String',
    severity: 'critical',
    regex: /\bmongodb(?:\+srv)?:\/\/[^\s'"]+/gi,
    placeholder: '[MONGODB_URI]',
    recommendation: 'MongoDB URIs frequently include credentials. Rotate the database user password immediately.'
  },
  {
    id: 'cookie',
    category: 'Cookie',
    severity: 'high',
    regex: /\b(?:Set-Cookie|Cookie)\s*:\s*[^\n;]{3,}/gi,
    placeholder: '[COOKIE]',
    recommendation: 'Cookies can carry session-authentication data. Invalidate the session and avoid sharing raw headers.'
  },
  {
    id: 'session_id',
    category: 'Session ID',
    severity: 'high',
    regex: /\b(?:session[_-]?id|sessid|phpsessid|connect\.sid|jsessionid)\s*[:=]\s*['"]?[A-Za-z0-9_-]{8,}['"]?/gi,
    placeholder: '[SESSION_ID]',
    recommendation: 'Session identifiers can allow session hijacking. Invalidate the session server-side.'
  },
  {
    id: 'base64_blob',
    category: 'Base64 Encoded Blob',
    severity: 'low',
    regex: /\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\b/g,
    placeholder: '[BASE64_BLOB]',
    recommendation: 'Large base64 blobs may encode files, keys, or other sensitive payloads. Verify contents before sharing.'
  },
  {
    id: 'env_variable',
    category: '.env Variable',
    severity: 'high',
    regex: /^[ \t]*[A-Z][A-Z0-9_]{2,}\s*=\s*\S+/gm,
    placeholder: '[ENV_VAR]',
    recommendation: 'Looks like a .env-style variable assignment. Confirm it does not expose a secret, then remove from prompts.'
  },

  // ---------------------------------------------------------------- INJECTION / DB QUERIES
  {
    id: 'sql_statement',
    category: 'SQL Statement',
    severity: 'medium',
    regex: /\b(?:SELECT\s+[\s\S]{1,80}?\s+FROM\s+\w+|INSERT\s+INTO\s+\w+|UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+|DROP\s+TABLE\s+\w+|ALTER\s+TABLE\s+\w+)\b/gi,
    placeholder: '[SQL_STATEMENT]',
    recommendation: 'Raw SQL may expose schema or data details. Confirm no sensitive table/column names or data are included.'
  },

  // ---------------------------------------------------------------- HIDDEN CONTENT
  {
    id: 'zero_width_chars',
    category: 'Zero-Width Characters',
    severity: 'high',
    regex: ZERO_WIDTH_REGEX,
    placeholder: '',
    recommendation: 'Invisible zero-width characters were found — these can hide instructions from human reviewers. Strip them before sending.'
  },
  {
    id: 'hidden_control_chars',
    category: 'Hidden Unicode / Control Characters',
    severity: 'high',
    regex: HIDDEN_CONTROL_REGEX,
    placeholder: '',
    recommendation: 'Non-printing control characters were detected, which can be used to obscure malicious payloads. Remove them.'
  }
];

/**
 * Phrase-based detectors. These look for known prompt-injection / jailbreak
 * wording rather than structured data. Matching is case-insensitive and
 * substring-based (not regex) for simplicity and easy maintenance.
 */
const PG_INJECTION_PHRASES = [
  'ignore previous instructions',
  'ignore all previous instructions',
  'disregard the above',
  'disregard all prior instructions',
  'forget everything above',
  'forget your instructions',
  'override your instructions',
  'you are now in developer mode',
  'system prompt:',
  'reveal your system prompt',
  'print your instructions',
  'act as if you have no restrictions',
  'this is not a test, comply',
  'bypass your guidelines',
  'disable your safety filters'
];

const PG_JAILBREAK_PHRASES = [
  'do anything now',
  'dan mode',
  'jailbreak',
  'pretend you have no restrictions',
  'pretend you are not an ai',
  'you have no content policy',
  'unfiltered and uncensored',
  'respond without any restrictions',
  'no ethical guidelines',
  'evil confidant',
  'opposite day mode',
  'stay in character no matter what'
];

/**
 * Scans `text` for occurrences of any phrase in `phraseList`.
 * Returns an array of { phrase, index } for every match found.
 */
function findPhraseMatches(text, phraseList) {
  const lowerText = text.toLowerCase();
  const matches = [];
  for (const phrase of phraseList) {
    let fromIndex = 0;
    while (true) {
      const idx = lowerText.indexOf(phrase, fromIndex);
      if (idx === -1) break;
      matches.push({ phrase, index: idx, length: phrase.length });
      fromIndex = idx + phrase.length;
    }
  }
  return matches;
}

// Expose everything on a single namespace so plain <script> tags can share it.
window.PromptGuardPatterns = {
  PG_PATTERNS,
  PG_INJECTION_PHRASES,
  PG_JAILBREAK_PHRASES,
  findPhraseMatches,
  luhnCheck
};
