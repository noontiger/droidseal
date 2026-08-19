// Deep signing analysis. Pure functions that parse `apksigner verify --verbose --print-certs`
// and `keytool -printcert -jarfile` text output, then derive security findings. No I/O.

import type { Finding } from "./types.ts"

export interface SigningSchemes {
  v1: boolean
  v2: boolean
  v3: boolean
  v4: boolean
}

export interface CertInfo {
  dn?: string
  sha256?: string
  keyAlgorithm?: string
  keySize?: number
  signatureAlgorithm?: string
  validFrom?: Date
  validUntil?: Date
}

function schemeFlag(stdout: string, version: number): boolean {
  const match = new RegExp(`Verified using v${version} scheme[^\\n]*:\\s*(true|false)`, "i").exec(stdout)
  return match?.[1]?.toLowerCase() === "true"
}

// Parse apksigner verbose output for scheme flags and (as a fallback) per-signer cert basics.
export function analyzeApksignerVerbose(stdout: string): { schemes: SigningSchemes; certs: CertInfo[] } {
  const schemes: SigningSchemes = {
    v1: schemeFlag(stdout, 1),
    v2: schemeFlag(stdout, 2),
    v3: schemeFlag(stdout, 3),
    v4: schemeFlag(stdout, 4),
  }
  const bySigner = new Map<string, CertInfo>()
  const ensure = (id: string): CertInfo => {
    let cert = bySigner.get(id)
    if (!cert) {
      cert = {}
      bySigner.set(id, cert)
    }
    return cert
  }
  const lines = stdout.split(/\r?\n/)
  for (const line of lines) {
    const dn = /Signer\s+#(\d+)\s+certificate DN:\s*(.+)$/i.exec(line)
    if (dn) {
      ensure(dn[1]!).dn = dn[2]!.trim()
      continue
    }
    const sha = /Signer\s+#(\d+)\s+certificate SHA-256 digest:\s*([0-9a-f]+)/i.exec(line)
    if (sha) {
      ensure(sha[1]!).sha256 = sha[2]!.toLowerCase()
      continue
    }
    const algo = /Signer\s+#(\d+)\s+key algorithm:\s*(\w+)/i.exec(line)
    if (algo) {
      ensure(algo[1]!).keyAlgorithm = algo[2]!.toUpperCase()
      continue
    }
    const size = /Signer\s+#(\d+)\s+key size \(bits\):\s*(\d+)/i.exec(line)
    if (size) {
      ensure(size[1]!).keySize = Number.parseInt(size[2]!, 10)
    }
  }
  return { schemes, certs: [...bySigner.values()] }
}

// Parse `keytool -printcert -jarfile <apk>` output, which is richer than apksigner:
// it carries validity dates, signature algorithm and key size per signer.
export function analyzeCertPrint(stdout: string): CertInfo[] {
  const certs: CertInfo[] = []
  // Split into per-signer blocks; "Owner:" reliably starts a certificate section.
  const blocks = stdout.split(/(?=^Owner:)/m).filter((block) => /^Owner:/m.test(block))
  for (const block of blocks) {
    const cert: CertInfo = {}
    const owner = /^Owner:\s*(.+)$/m.exec(block)?.[1]?.trim()
    if (owner) cert.dn = owner
    const validity = /Valid from:\s*(.+?)\s+until:\s*(.+)$/m.exec(block)
    if (validity) {
      const from = new Date(validity[1]!.trim())
      const until = new Date(validity[2]!.trim())
      if (!Number.isNaN(from.getTime())) cert.validFrom = from
      if (!Number.isNaN(until.getTime())) cert.validUntil = until
    }
    const sha256 = /SHA256:\s*([0-9A-Fa-f:]+)/.exec(block)?.[1]
    if (sha256) cert.sha256 = sha256.replaceAll(":", "").toLowerCase()
    const sigAlgo = /Signature algorithm name:\s*(.+)$/m.exec(block)?.[1]?.trim()
    if (sigAlgo) cert.signatureAlgorithm = sigAlgo
    const keyAlgo = /Subject Public Key Algorithm:\s*(?:(\d+)-bit\s+)?(\w+)/m.exec(block)
    if (keyAlgo) {
      if (keyAlgo[1]) cert.keySize = Number.parseInt(keyAlgo[1], 10)
      cert.keyAlgorithm = keyAlgo[2]!.toUpperCase()
    }
    certs.push(cert)
  }
  return certs
}

const WEAK_SIGNATURE_ALGORITHMS = [/\bMD5\b/i, /\bSHA1with/i, /\bMD2\b/i]
const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000

export interface SigningFindingInput {
  schemes: SigningSchemes
  certs: CertInfo[]
  minSdk?: number | undefined
  now: Date
}

// Derive signing-depth findings. Pure: `now` is injected for deterministic tests.
export function buildSigningFindings(input: SigningFindingInput): Finding[] {
  const { schemes, certs, minSdk, now } = input
  const findings: Finding[] = []

  if (!schemes.v2 && !schemes.v3) {
    findings.push({
      severity: "medium",
      code: "SIGNING_SCHEME_V2V3_MISSING",
      title: "缺少 APK Signature Scheme v2/v3",
      detail: "仅有 v1(JAR) 签名而无 v2/v3 全文件签名，无法获得整包完整性保护，安装与更新校验更弱。",
      recommendation: "启用 v2/v3 签名（apksigner 默认支持），确保 signingConfig 未禁用较新方案。",
      evidence: `v1=${schemes.v1} v2=${schemes.v2} v3=${schemes.v3}`,
    })
    if (schemes.v1 && (minSdk === undefined || minSdk < 24)) {
      findings.push({
        severity: "high",
        code: "SIGNING_V1_ONLY_JANUS",
        title: "仅 v1 签名且兼容旧系统，存在 Janus 漏洞面",
        detail: `仅使用 v1(JAR) 签名，且 minSdk=${minSdk ?? "未知"}（<24）。在 Android 5.0–6.0 上 v1-only 签名易受 Janus（CVE-2017-13156）攻击，可在不破坏签名的情况下篡改 DEX。`,
        recommendation: "启用 v2/v3 签名方案；如需支持 <24 设备，v2+v1 组合可缓解 Janus。",
        evidence: `minSdk=${minSdk ?? "未知"}`,
      })
    }
  }

  for (const cert of certs) {
    const who = cert.dn ?? "(未知签名者)"
    if (cert.dn && /CN=Android Debug/i.test(cert.dn)) {
      findings.push({
        severity: "critical",
        code: "SIGNING_DEBUG_CERTIFICATE",
        title: "使用 Android 调试证书签名",
        detail: `签名证书为 Android 调试证书（${cert.dn}）。调试证书私钥公开、人人可复制，等同于未签名，绝不能用于发布。`,
        recommendation: "改用受保护的正式发布 keystore 重新签名，并将调试证书排除出发布流程。",
        evidence: cert.dn,
      })
    }
    if (cert.validUntil && cert.validUntil.getTime() < now.getTime()) {
      findings.push({
        severity: "high",
        code: "SIGNING_CERT_EXPIRED",
        title: "签名证书已过期",
        detail: `签名者 ${who} 的证书已于 ${cert.validUntil.toISOString().slice(0, 10)} 过期。过期证书会阻碍新设备安装与后续更新。`,
        recommendation: "使用有效期充足的证书重新签名；对已发布应用需保持相同签名身份以支持升级。",
        evidence: cert.validUntil.toISOString(),
      })
    } else if (cert.validUntil && cert.validUntil.getTime() - now.getTime() < NINETY_DAYS_MS) {
      findings.push({
        severity: "low",
        code: "SIGNING_CERT_EXPIRING_SOON",
        title: "签名证书即将过期（<90 天）",
        detail: `签名者 ${who} 的证书将于 ${cert.validUntil.toISOString().slice(0, 10)} 过期，不足 90 天。`,
        recommendation: "提前规划证书轮换；注意更换签名身份会影响已发布应用的升级安装。",
        evidence: cert.validUntil.toISOString(),
      })
    }
    const weakKey = cert.keyAlgorithm === "RSA" && cert.keySize !== undefined && cert.keySize < 2048
    const weakSig = cert.signatureAlgorithm
      ? WEAK_SIGNATURE_ALGORITHMS.some((re) => re.test(cert.signatureAlgorithm!))
      : false
    if (weakKey || weakSig) {
      findings.push({
        severity: "medium",
        code: "SIGNING_WEAK_KEY",
        title: "签名密钥或签名算法强度不足",
        detail:
          `签名者 ${who}` +
          (weakKey ? ` 使用 ${cert.keySize}-bit RSA 密钥（<2048）` : "") +
          (weakSig ? `${weakKey ? "，且" : " "}使用弱签名算法 ${cert.signatureAlgorithm}` : "") +
          "。弱密钥/弱哈希会降低签名抗伪造能力。",
        recommendation: "改用 ≥2048-bit RSA（或 EC P-256）与 SHA-256 及以上签名算法重新生成签名。",
        evidence: `${cert.keyAlgorithm ?? "?"} ${cert.keySize ?? "?"}bit ${cert.signatureAlgorithm ?? ""}`.trim(),
      })
    }
  }

  const fingerprints = certs.map((cert) => cert.sha256).filter((value): value is string => Boolean(value))
  if (fingerprints.length > 0) {
    findings.push({
      severity: "info",
      code: "SIGNING_CERT_FINGERPRINT",
      title: "签名证书 SHA-256 指纹（供证书固定/校验）",
      detail: `已提取签名证书 SHA-256 指纹，可用于服务端签名校验或 App Links assetlinks.json：${fingerprints.join("、")}。`,
      recommendation: "如做签名固定，将该指纹纳入服务端校验或 CI 校验，并保留轮换预案。",
      evidence: fingerprints.join(", ").slice(0, 300),
    })
  }

  return findings
}
