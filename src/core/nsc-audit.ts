// Pure-TypeScript Network Security Config (NSC) auditor for source projects.
// Operates on the plaintext res/xml/*.xml referenced by the manifest. Regex-based
// (no XML dependency); heuristic but sufficient for the common misconfigurations.

import type { Finding } from "./types.ts"

interface PinSet {
  raw: string
  pinCount: number
  expiration?: string
}

function extractPinSets(xml: string): PinSet[] {
  const sets: PinSet[] = []
  const re = /<pin-set\b([^>]*)>([\s\S]*?)<\/pin-set>/g
  let match: RegExpExecArray | null
  while ((match = re.exec(xml)) !== null) {
    const attrs = match[1] ?? ""
    const body = match[2] ?? ""
    const pinCount = (body.match(/<pin\b/g) ?? []).length
    const expiration = /expiration\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1]
    const set: PinSet = { raw: match[0], pinCount }
    if (expiration) set.expiration = expiration
    sets.push(set)
  }
  // Self-closing pin-set with no body is meaningless; also capture empty declarations.
  return sets
}

// Audit one Network Security Config XML document.
export function auditNetworkSecurityConfig(
  xml: string,
  evidence?: string,
  now: Date = new Date(),
): Finding[] {
  const findings: Finding[] = []

  if (/cleartextTrafficPermitted\s*=\s*["']true["']/.test(xml)) {
    findings.push({
      severity: "high",
      code: "NSC_CLEARTEXT_PERMITTED",
      title: "网络安全配置显式允许明文流量",
      detail:
        "为什么：NSC 中 cleartextTrafficPermitted=\"true\"。所以：对应作用域内的 HTTP 明文流量被允许，数据可被窃听/篡改。开发者需自行确认：是否仅为个别必需域名开启。",
      recommendation: "移除全局 cleartext 允许；确需的域名放入最小化 domain-config，长期迁移到 HTTPS。",
      ...(evidence ? { evidence } : {}),
    })
  }

  if (/<certificates\b[^>]*\bsrc\s*=\s*["']user["']/.test(xml)) {
    findings.push({
      severity: "medium",
      code: "NSC_TRUSTS_USER_CA",
      title: "网络安全配置信任用户安装的 CA",
      detail:
        "为什么：trust-anchors 含 <certificates src=\"user\"/>。所以：应用会信任用户/设备中安装的 CA，便于抓包代理与中间人，削弱 TLS 保护。开发者需自行确认：是否仅用于调试且不进入 release。",
      recommendation: "release 配置只信任 system CA；调试信任放在 debug-overrides 且不随发布构建打包。",
      ...(evidence ? { evidence } : {}),
    })
  }

  if (/<debug-overrides\b/.test(xml)) {
    findings.push({
      severity: "low",
      code: "NSC_DEBUG_OVERRIDES_PRESENT",
      title: "网络安全配置包含 debug-overrides",
      detail:
        "为什么：存在 <debug-overrides>。所以：其内容仅在 android:debuggable=true 时生效，release 通常安全；但需确认没有误把宽松信任放到 base/domain-config。",
      recommendation: "确认调试专用的信任锚仅位于 debug-overrides，release 构建 debuggable=false。",
      ...(evidence ? { evidence } : {}),
    })
  }

  const pinSets = extractPinSets(xml)
  if (pinSets.length === 0) {
    findings.push({
      severity: "info",
      code: "NSC_NO_PINNING",
      title: "网络安全配置未使用证书固定",
      detail:
        "为什么：NSC 中未发现 <pin-set>。所以：这是可选加固，缺失并非漏洞；若为高价值通信可考虑固定。开发者需自行权衡：固定带来的运维成本与备份/轮换风险。",
      recommendation: "如需固定，务必配置备份 pin 与 expiration，并准备轮换/失效方案，避免锁死用户。",
      ...(evidence ? { evidence } : {}),
    })
  } else {
    for (const set of pinSets) {
      const expired = set.expiration ? new Date(set.expiration).getTime() < now.getTime() : false
      if (set.pinCount < 2 || expired) {
        findings.push({
          severity: "medium",
          code: "NSC_PINNING_WEAK",
          title: "证书固定配置存在风险",
          detail:
            (set.pinCount < 2 ? "只配置了单个 pin，缺少备份 pin：证书轮换或密钥丢失时会导致所有客户端无法连接。" : "") +
            (expired ? `pin-set 的 expiration=${set.expiration} 已过期：过期后固定失效，等同未固定。` : ""),
          recommendation: "至少配置一个备份 pin（下一轮证书/中间 CA 的公钥摘要），并设置合理且可维护的 expiration。",
          ...(evidence ? { evidence } : {}),
        })
      }
    }
  }

  return findings
}
