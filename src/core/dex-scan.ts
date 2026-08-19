// Pure-TypeScript DEX string-pool scanner. No external dependencies.
//
// Scope: parse only the DEX string pool (string_ids -> string_data_item). Type
// descriptors, class names, method names and string literals are all interned in
// that pool supports useful triage without a full disassembler. Strict rules
// require corroborating API/action/value strings and attach evidence confidence;
// operands that the pool cannot recover are not guessed.

import type { Finding } from "./types.ts"
import { scanStringsForSecrets, strongestSecretConfidence } from "./secret-scan.ts"
import { scanCodeStrings, pendingIntentImmutableFinding } from "./code-heuristics.ts"

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a] // "dex\n"
const STRING_IDS_SIZE_OFFSET = 0x38
const STRING_IDS_OFF_OFFSET = 0x3c

export interface DexStrings {
  strings: string[]
  truncated: boolean
}

function readUleb128(bytes: Uint8Array, start: number): { value: number; next: number } {
  let result = 0
  let shift = 0
  let index = start
  while (index < bytes.length) {
    const byte = bytes[index]!
    result |= (byte & 0x7f) << shift
    index += 1
    if ((byte & 0x80) === 0) break
    shift += 7
    if (shift > 28) break
  }
  return { value: result >>> 0, next: index }
}

// Extract the string pool of a DEX buffer. Throws when the buffer is not a DEX
// container (bad magic / too small). Individual malformed entries are skipped and
// flip `truncated` so callers can degrade gracefully.
export function extractDexStrings(bytes: Uint8Array, maxStrings = 200_000): DexStrings {
  if (bytes.length < 0x70) throw new Error("dex too small")
  for (let i = 0; i < DEX_MAGIC.length; i += 1) {
    if (bytes[i] !== DEX_MAGIC[i]) throw new Error("not a dex file")
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const stringIdsSize = view.getUint32(STRING_IDS_SIZE_OFFSET, true)
  const stringIdsOff = view.getUint32(STRING_IDS_OFF_OFFSET, true)
  const decoder = new TextDecoder("utf-8", { fatal: false })
  const strings: string[] = []
  let truncated = false

  const count = Math.min(stringIdsSize, maxStrings)
  if (stringIdsSize > maxStrings) truncated = true

  for (let i = 0; i < count; i += 1) {
    const idOffset = stringIdsOff + i * 4
    if (idOffset + 4 > bytes.length) {
      truncated = true
      break
    }
    const dataOffset = view.getUint32(idOffset, true)
    if (dataOffset >= bytes.length) {
      truncated = true
      continue
    }
    // Skip the ULEB128 utf16 length prefix, then read MUTF-8 bytes until the NUL
    // terminator. A genuine embedded NUL is encoded as 0xC0 0x80, never a bare 0x00.
    const { next } = readUleb128(bytes, dataOffset)
    let end = next
    while (end < bytes.length && bytes[end] !== 0x00) end += 1
    strings.push(decoder.decode(bytes.subarray(next, end)))
  }
  return { strings, truncated }
}

// Known third-party SDK package descriptor prefixes for the SBOM inventory (Tier3-J).
const SDK_PREFIXES: ReadonlyArray<{ prefix: string; name: string }> = [
  { prefix: "Lcom/google/firebase/", name: "Google Firebase" },
  { prefix: "Lcom/google/android/gms/", name: "Google Play Services" },
  { prefix: "Lcom/facebook/", name: "Facebook SDK" },
  { prefix: "Lcom/umeng/", name: "友盟 Umeng" },
  { prefix: "Lcom/bytedance/", name: "字节跳动 ByteDance" },
  { prefix: "Lcom/tencent/", name: "腾讯 Tencent" },
  { prefix: "Lcom/alipay/", name: "支付宝 Alipay" },
  { prefix: "Lcom/amap/api/", name: "高德地图 AMap" },
  { prefix: "Lcom/baidu/", name: "百度 Baidu" },
  { prefix: "Lcom/squareup/okhttp", name: "OkHttp" },
  { prefix: "Lretrofit2/", name: "Retrofit" },
  { prefix: "Lcom/bumptech/glide/", name: "Glide" },
  { prefix: "Lio/reactivex/", name: "RxJava" },
  { prefix: "Lcom/appsflyer/", name: "AppsFlyer" },
  { prefix: "Lcom/adjust/sdk/", name: "Adjust" },
]

// Best-effort third-party SDK detection from type descriptors. Returns display names.
export function detectSdkPackages(strings: Iterable<string>): string[] {
  const found = new Set<string>()
  for (const value of strings) {
    if (value.length === 0 || value.charCodeAt(0) !== 0x4c /* 'L' */) continue
    for (const sdk of SDK_PREFIXES) {
      if (value.startsWith(sdk.prefix)) found.add(sdk.name)
    }
  }
  return [...found].sort()
}

// Scan the combined string pool of one or more DEX files for heuristic risks.
export function scanDex(strings: string[]): Finding[] {
  const findings: Finding[] = []

  const secretHits = scanStringsForSecrets(strings)
  if (secretHits.length > 0) {
    findings.push({
      severity: secretHits.some((hit) => hit.confidence === "confirmed" || hit.confidence === "high") ? "high" : "medium",
      confidence: strongestSecretConfidence(secretHits),
      code: "DEX_HARDCODED_SECRET",
      title: "DEX 中疑似硬编码密钥/凭据",
      detail:
        "为什么：在 DEX 字符串池中发现通过格式、长度、值域与熵阈值校验的密钥/令牌候选；通用赋值仅按中等置信度报告。所以：任何解包 APK 的人都能提取真实凭据。请先按脱敏证据定位，确认后立即轮换：" +
        secretHits.map((hit) => `${hit.label}(${hit.preview})`).join("、") + "。",
      recommendation: "将密钥移出客户端，改由服务端保管或使用短期令牌；已泄露的凭据立即轮换。",
      evidence: secretHits.map((hit) => `${hit.code}:${hit.preview}`).join(", "),
    })
  }

  // Shared heuristic catalog (Web crypto/TLS/WebView/data-storage/component/runtime).
  findings.push(...scanCodeStrings(strings, "DEX"))

  // Cross-correlation checks that need two signals at once.
  findings.push(...pendingIntentImmutableFinding("DEX", strings))

  let hasSecureRandom = false
  let hasInsecureRandom = false
  for (const value of strings) {
    if (value === "Ljava/security/SecureRandom;") hasSecureRandom = true
    if (value === "Ljava/util/Random;") hasInsecureRandom = true
  }
  if (hasInsecureRandom && !hasSecureRandom) {
    findings.push({
      severity: "info",
      confidence: "low",
      code: "DEX_WEAK_RANDOM",
      title: "DEX 引用了 java.util.Random，用途无法从字符串池确认",
      detail:
        "为什么：字符串池含 Ljava/util/Random; 但 DEX 字符串池不能还原它的具体调用点和用途；这不是已确认漏洞。只有用于密钥、令牌、验证码或盐值时才构成可预测风险。",
      recommendation: "所有安全敏感的随机数改用 java.security.SecureRandom。",
      evidence: "Ljava/util/Random;",
    })
  }

  return findings
}
