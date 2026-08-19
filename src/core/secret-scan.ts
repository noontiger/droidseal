// Shared secret scanner. Shape-specific tokens are high-confidence; generic
// assignments must also pass value-only entropy and placeholder filters.
import type { FindingConfidence } from "./types.ts"

export interface SecretHit {
  code: string
  label: string
  confidence: FindingConfidence
  // Redacted preview of the matched value (never the full secret).
  preview: string
}

interface SecretPattern {
  code: string
  label: string
  regex: RegExp
  confidence: FindingConfidence
  // When set, entropy is calculated from this capture group, not the key name.
  valueGroup?: number
  minEntropy?: number
}

// Well-known credential shapes. Ordered most-specific first so labelling is stable.
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { code: "PRIVATE_KEY_PEM", label: "PEM 私钥块", regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/, confidence: "confirmed" },
  { code: "AWS_ACCESS_KEY", label: "AWS Access Key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, confidence: "high" },
  { code: "GOOGLE_API_KEY", label: "Google API Key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/, confidence: "high" },
  { code: "GITHUB_TOKEN", label: "GitHub Token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b/, confidence: "high" },
  { code: "SLACK_TOKEN", label: "Slack Token", regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, confidence: "high" },
  { code: "STRIPE_KEY", label: "Stripe 密钥", regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b/, confidence: "high" },
  { code: "JWT", label: "JWT", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, confidence: "high" },
  { code: "BEARER_TOKEN", label: "Bearer Token", regex: /\bBearer\s+[0-9A-Za-z._-]{20,}\b/, confidence: "high" },
  {
    code: "GENERIC_CREDENTIAL",
    label: "疑似硬编码凭据赋值",
    regex: /(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']?([0-9A-Za-z._\-+/]{12,})["']?/i,
    confidence: "medium",
    valueGroup: 1,
    minEntropy: 3.3,
  },
]

// Shannon entropy in bits/char. Empty string returns 0.
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0
  const counts = new Map<string, number>()
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / value.length
    entropy -= p * Math.log2(p)
  }
  return entropy
}

function redact(match: string): string {
  const trimmed = match.length > 48 ? `${match.slice(0, 24)}…${match.slice(-8)}` : match
  if (trimmed.length <= 8) return `${trimmed.slice(0, 2)}****`
  return `${trimmed.slice(0, 6)}****${trimmed.slice(-2)}`
}

function looksLikePlaceholder(value: string): boolean {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, "")
  if (/^(?:example|sample|dummy|test|testing|changeme|replace(?:me)?|your\w*|todo|undefined|null|password|secret|apikey|token|x+|0+|1+)$/.test(normalized)) {
    return true
  }
  return new Set(normalized).size < 4
}

// De-duplicates by (code, preview). Generic assignments are intentionally held
// to a stronger threshold than provider-specific token formats.
export function scanStringsForSecrets(strings: Iterable<string>): SecretHit[] {
  const seen = new Set<string>()
  const hits: SecretHit[] = []
  for (const value of strings) {
    if (typeof value !== "string" || value.length < 8) continue
    for (const pattern of SECRET_PATTERNS) {
      const match = pattern.regex.exec(value)
      if (!match) continue
      const candidate = pattern.valueGroup === undefined ? match[0] : (match[pattern.valueGroup] ?? "")
      if (pattern.valueGroup !== undefined && looksLikePlaceholder(candidate)) continue
      if (pattern.minEntropy !== undefined && shannonEntropy(candidate) < pattern.minEntropy) continue
      const preview = redact(candidate)
      const key = `${pattern.code}:${preview}`
      if (seen.has(key)) continue
      seen.add(key)
      hits.push({ code: pattern.code, label: pattern.label, confidence: pattern.confidence, preview })
    }
  }
  return hits
}
export function strongestSecretConfidence(hits: readonly SecretHit[]): FindingConfidence {
  if (hits.some((hit) => hit.confidence === "confirmed")) return "confirmed"
  if (hits.some((hit) => hit.confidence === "high")) return "high"
  if (hits.some((hit) => hit.confidence === "medium")) return "medium"
  return "low"
}


// True when the string is an unambiguous embedded private key (PEM header).
export function containsPrivateKey(value: string): boolean {
  return SECRET_PATTERNS[0]!.regex.test(value)
}
