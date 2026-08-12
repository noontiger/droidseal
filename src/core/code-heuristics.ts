// Shared string-pattern heuristic catalog for DroidSeal's static code audit.
//
// The same rules are applied to two different string corpora:
//   - the DEX string pool (descriptors + literals, see dex-scan.ts)
//   - app-module Java/Kotlin source text (see project-audit.ts)
// The catalog supplies candidate patterns; strict source/DEX evidence gates at
// the bottom of this file decide whether a finding is emitted. Source requires
// concrete calls/values, while DEX requires corroborating API/action signals.
//
// Findings are emitted with code `${codePrefix}_${rule.suffix}` so the DEX and
// SOURCE scans reuse identical rules without code collisions. PendingIntent is
// checked at individual source call sites because DEX strings lose flag operands.

import type { Finding } from "./types.ts"

export interface CodeHeuristicRule {
  suffix: string
  severity: Finding["severity"]
  title: string
  detail: string
  recommendation: string
  regex: RegExp
}

// Cut a small, single-line window around the first regex match for evidence.
function snippetAround(text: string, index: number, length: number, window = 60): string {
  const start = Math.max(0, index - window)
  const end = Math.min(text.length, index + length + window)
  let out = text.slice(start, end).replace(/\s+/g, " ").trim()
  if (out.length > 200) out = out.slice(0, 200)
  return out
}

export const CODE_HEURISTIC_RULES: readonly CodeHeuristicRule[] = [
  // --- Category 4: WebView deep configuration ---
  {
    suffix: "WEBVIEW_JS_BRIDGE",
    severity: "medium",
    title: "代码引用了 WebView JS 桥或宽松文件访问",
    detail:
      "为什么：代码中出现 addJavascriptInterface 或 @JavascriptInterface，可能把原生能力暴露给网页；setAllowUniversalAccessFromFileURLs / setAllowFileAccessFromFileURLs 会放宽 file:// 跨源访问。所以：若加载不可信内容，恶意页面可调用原生接口或读取本地文件。开发者需自行确认：桥接口是否最小化、加载内容是否完全可信。",
    recommendation: "仅对可信内容启用 JS 桥并用 @JavascriptInterface 限定方法；关闭 setAllowUniversalAccessFromFileURLs 等宽松设置。",
    regex: /addJavascriptInterface|@JavascriptInterface|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs/,
  },
  {
    suffix: "WEBVIEW_JS_ENABLED",
    severity: "low",
    title: "WebView 启用了 JavaScript",
    detail:
      "为什么：检测到 setJavaScriptEnabled / javaScriptEnabled=true。所以：开启 JS 后若加载任意外部或用户可控内容，XSS 可直接执行原生能力。开发者需自行确认：开启 JS 的 WebView 是否只加载完全可信内容，并配合 CSP。",
    recommendation: "只对可信前端启用 JS；对不可信内容保持 JS 关闭，并配置基于 nonce/hash 的 CSP。",
    regex: /javaScriptEnabled/i,
  },
  {
    suffix: "WEBVIEW_FILE_ACCESS",
    severity: "medium",
    title: "WebView 允许访问本地文件",
    detail:
      "为什么：检测到 setAllowFileAccess 等放宽 WebView 对本地文件访问的设置。所以：结合 file:// 加载或 JS 桥，可能读取应用私有目录或沙箱外文件。开发者需自行确认：是否确实需要文件访问、访问范围是否可控。",
    recommendation: "默认关闭 setAllowFileAccess；确需时用显式路径白名单，避免暴露敏感目录。",
    regex: /setAllowFileAccess/i,
  },
  {
    suffix: "WEBVIEW_MIXED_CONTENT",
    severity: "medium",
    title: "WebView 允许混合内容（HTTP 资源）",
    detail:
      "为什么：检测到 setMixedContentMode / MIXED_CONTENT_ALWAYS_ALLOW 等，HTTPS 页面可加载 HTTP 子资源。所以：中间人可在 HTTPS 页面注入明文内容，削弱 TLS 保护。开发者需自行确认：是否确有遗留 HTTP 资源需要加载。",
    recommendation: "使用 MIXED_CONTENT_NEVER_ALLOW（默认），将所有子资源迁移到 HTTPS。",
    regex: /setMixedContentMode|MIXED_CONTENT_ALWAYS_ALLOW|MIXED_CONTENT_COMPATIBILITY_MODE/i,
  },
  {
    suffix: "WEBVIEW_DOM_STORAGE",
    severity: "low",
    title: "WebView 启用了 DOM Storage",
    detail:
      "为什么：检测到 setDomStorageEnabled / domStorageEnabled=true。所以：localStorage/sessionStorage 可能持久化令牌或敏感数据，且 WebView 默认不加密该存储。开发者需自行确认：是否有敏感数据落入 DOM Storage。",
    recommendation: "仅在必需时开启 DOM Storage，避免在其中存放令牌；退出时清理。",
    regex: /domStorageEnabled/i,
  },
  {
    suffix: "WEBVIEW_FILE_URL_LOAD",
    severity: "medium",
    title: "WebView 通过 loadUrl 加载 file:// 地址",
    detail:
      "为什么：检测到 loadUrl(\"file://...\") 或加载 android_asset/android_res/sdcard 路径。所以：若路径片段来自不可信输入，可能发生本地文件泄露或路径穿越。开发者需自行确认：file:// 加载来源是否完全受控。",
    recommendation: "避免用不可信数据拼接 file:// 路径；优先用 loadUrl 加载可信 https 或使用 WebViewAssetLoader 做受控映射。",
    regex: /loadUrl\s*\([^)]*["']file:|file:\/\/\/(?:android_asset|android_res|sdcard)/i,
  },

  // --- Category 6: crypto / TLS ---
  {
    suffix: "WEAK_CRYPTO",
    severity: "medium",
    title: "疑似使用弱加密/弱分组模式",
    detail:
      "为什么：代码中出现 DES/RC4/Blowfish 或 ECB 模式的字符串（启发式，可能来自第三方库或误报）。这些算法在现代密码学中已不安全，ECB 会泄露明文模式。所以：若用于保护敏感数据存在被破解风险。开发者需自行确认：这些字符串是否用于真实加密路径。",
    recommendation: "改用 AES-GCM 等经过验证的算法与分组模式；密钥通过 Android Keystore 管理。",
    regex: /(?:\b(?:DESede|DES|RC4|RC2|Blowfish)\b|(?:AES|DES|DESede)\/ECB|\/ECB\/|\bECB\b)/,
  },
  {
    suffix: "WEAK_HASH",
    severity: "low",
    title: "疑似使用弱摘要算法（MD5/SHA-1）",
    detail:
      "为什么：代码中出现 MD5 或 SHA-1 字符串（启发式，可能用于校验或非安全场景）。所以：若用于密码摘要、签名或完整性校验，MD5/SHA-1 已被证明不够安全。开发者需自行确认：是否用于安全敏感场景。",
    recommendation: "密码/完整性场景改用 SHA-256 及以上或带盐的慢哈希（如 scrypt/PBKDF2/Argon2）。",
    regex: /\bMD5\b|\bSHA-?1\b/,
  },
  {
    suffix: "INSECURE_TLS",
    severity: "high",
    title: "疑似存在不安全的 TLS/证书校验",
    detail:
      "为什么：代码中出现自定义主机名校验或信任所有证书的迹象（如 ALLOW_ALL_HOSTNAME_VERIFIER、TrustAll、空实现 checkServerTrusted）。所以：可能关闭了服务器证书/主机名校验，导致中间人攻击。开发者需自行确认：TrustManager/HostnameVerifier 是否被弱化。",
    recommendation: "移除信任所有证书的实现，使用平台默认校验；如需固定证书用 Network Security Config 并保留备份 pin 与轮换方案。",
    regex: /ALLOW_ALL_HOSTNAME_VERIFIER|setHostnameVerifier|NullHostnameVerifier|TrustAll|checkServerTrusted/,
  },

  // --- Category 7: dynamic code loading / runtime exec ---
  {
    suffix: "DYNAMIC_CODE_LOADING",
    severity: "medium",
    title: "引用动态代码加载类",
    detail:
      "为什么：发现 DexClassLoader/PathClassLoader/InMemoryDexClassLoader 等动态加载类引用。所以：若从外部存储或网络加载可执行代码，存在被替换/注入的风险；也是加壳/热更新常见特征。开发者需自行确认：加载源是否可信且完整性受校验。",
    recommendation: "仅从应用私有目录加载并做完整性校验；避免从外部可写位置加载 DEX/JAR。",
    regex: /DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader/i,
  },
  {
    suffix: "RUNTIME_EXEC",
    severity: "low",
    title: "引用运行时进程执行",
    detail:
      "为什么：源码中定位到 exec/ProcessBuilder 构造调用，或 DEX 同时出现运行时类与执行动作信号。所以：若命令拼接不可信输入或调用 shell，会形成命令注入/提权面。开发者需确认参数是否固定且可控。",
    recommendation: "避免执行外部命令；确需时使用固定参数数组，绝不拼接不可信输入。",
    regex: /Runtime\.getRuntime|ProcessBuilder|Ljava\/lang\/Runtime;|Ljava\/lang\/ProcessBuilder;/i,
  },

  // --- Category 2: data storage ---
  {
    suffix: "DATA_MODE_WORLD",
    severity: "high",
    title: "使用了全局可读/可写文件模式",
    detail:
      "为什么：检测到 MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE。所以：标记为全局可读写的文件任何应用都能读写，敏感配置/数据可被其他应用窃取或篡改。开发者需自行确认：是否仍依赖该废弃 API。",
    recommendation: "移除 MODE_WORLD_* 用法，改用 ContentProvider（带权限）或应用私有存储 + 签名级共享。",
    regex: /MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/,
  },

  // --- Category 3: component / IPC ---
  {
    suffix: "COMPONENT_INTENT_SCHEME",
    severity: "medium",
    title: "使用 Intent Scheme 解析（Intent.parseUri）",
    detail:
      "为什么：检测到 Intent.parseUri(..., Intent.URI_INTENT_SCHEME) 等按 scheme 解析 Intent 的用法。所以：若对不可信输入调用，可能实现 Intent 注入、越权调起组件或钓鱼。开发者需自行确认：解析来源是否可信且做了严格白名单。",
    recommendation: "对 parseUri 的输入做 scheme/host/action 白名单与权限校验；避免直接把外部字符串当作 Intent 解析。",
    regex: /Intent\.parseUri|URI_INTENT_SCHEME/i,
  },

  // --- Category 5: runtime self-protection (presence = positive signal) ---
  {
    suffix: "RUNTIME_ROOT_DETECTION",
    severity: "info",
    title: "检测到 Root 环境检测代码",
    detail:
      "为什么：代码中出现 RootBeer / Magisk / su 路径 / root 工具包等字符串。所以：应用内置了 Root 环境检测，是运行时自我保护（反-root）的正向信号。开发者可据此确认：检测触发后的处置逻辑是否足够（退出/限制敏感功能）。",
    recommendation: "保留并强化 root 检测；注意检测可被绕过，应作为纵深防御的一环而非唯一保障。",
    regex: /RootBeer|com\.scottyab|Magisk|\/sbin\/su|\/system\/bin\/su|Superuser\.apk|rootTools/i,
  },
  {
    suffix: "RUNTIME_DEBUGGER_DETECTION",
    severity: "info",
    title: "检测到调试器检测代码",
    detail:
      "为什么：代码中出现 isDebuggerConnected / android.os.Debug 等字符串。所以：应用内置了调试器检测，是反调试自我保护的正向信号。开发者可确认：检测到调试后的响应（退出/降级）是否到位。",
    recommendation: "保留调试器检测并配合完整性校验；注意反调试可被绕过，属纵深防御。",
    regex: /isDebuggerConnected|android\.os\.Debug/i,
  },
  {
    suffix: "RUNTIME_INTEGRITY_ATTESTATION",
    severity: "info",
    title: "检测到完整性/设备 attestation 调用",
    detail:
      "为什么：代码中出现 SafetyNet / Play Integrity / IntegrityManager 等字符串。所以：应用调用了平台完整性证明，是反篡改/反伪造的正向信号。开发者可确认：attestation 失败后的处置逻辑是否健全。",
    recommendation: "基于 attestation 结果做服务端风控；密钥与风控决策留在服务端，避免只做客户端提示。",
    regex: /SafetyNet|attestation|PlayIntegrity|IntegrityManager|integrityToken/i,
  },
  {
    suffix: "RUNTIME_FLAG_SECURE",
    severity: "info",
    title: "检测到防截屏（FLAG_SECURE）设置",
    detail:
      "为什么：代码中出现 FLAG_SECURE / LayoutParams.FLAG_SECURE。所以：应用对敏感界面禁用了系统截屏/录屏，是防敏感信息泄露的正向信号。开发者可确认：是否覆盖所有敏感页面。",
    recommendation: "在登录、令牌展示等敏感界面统一设置 FLAG_SECURE。",
    regex: /FLAG_SECURE|LayoutParams\.FLAG_SECURE/i,
  },

  // --- Category 7 (native) / presence ---
  {
    suffix: "NATIVE_JNI",
    severity: "info",
    title: "检测到 JNI / Native 代码加载",
    detail:
      "为什么：代码中出现 System.loadLibrary / JNI_OnLoad / RegisterNatives。所以：应用包含 Native 层，需额外关注 .so 加固（NX/RELRO/Canary）与 JNI 桥的输入校验。开发者可结合 SO 扫描结果确认 Native 层防护。",
    recommendation: "为 .so 启用栈保护/RELRO/PIE 与符号剥离；对 JNI 导出函数做调用方与参数校验。",
    regex: /System\.loadLibrary|JNI_OnLoad|RegisterNatives/i,
  },

  // --- Category 10: other sensitive capabilities (presence) ---
  {
    suffix: "OTHER_ACCESSIBILITY_SERVICE",
    severity: "info",
    title: "引用无障碍服务（AccessibilityService）",
    detail:
      "为什么：代码中出现 BIND_ACCESSIBILITY_SERVICE / AccessibilityService。所以：无障碍服务权限极高，可被滥用读取屏幕与输入；若无必要属多余攻击面。开发者需自行确认：是否确实需要、权限获取是否最小化。",
    recommendation: "仅在确有必要时使用无障碍服务，并明确告知用户用途；避免请求全局无障碍权限。",
    regex: /BIND_ACCESSIBILITY_SERVICE|AccessibilityService/i,
  },
  {
    suffix: "OTHER_DEVICE_ADMIN",
    severity: "info",
    title: "引用设备管理器（DeviceAdmin）",
    detail:
      "为什么：代码中出现 DeviceAdminReceiver / DevicePolicyManager / BIND_DEVICE_ADMIN。所以：设备管理器权限可强制锁屏、清除数据等，属高权限能力。开发者需自行确认：业务是否确实需要、激活流程是否受控。",
    recommendation: "仅在 MDM/企业场景使用设备管理器，并对激活做明确用户确认与说明。",
    regex: /DeviceAdminReceiver|BIND_DEVICE_ADMIN|DevicePolicyManager/i,
  },
  {
    suffix: "OTHER_VPN",
    severity: "info",
    title: "引用 VPN 服务（VpnService）",
    detail:
      "为什么：代码中出现 VpnService。所以：应用可建立系统级 VPN 隧道，属敏感网络能力。开发者需自行确认：是否为预期功能、隧道流量是否被妥善保护。",
    recommendation: "仅在确有代理/隧道需求时使用 VpnService，并清晰告知用户；避免静默劫持全部流量。",
    regex: /VpnService|VpnServiceBuilder/i,
  },
  {
    suffix: "OTHER_BIOMETRIC",
    severity: "info",
    title: "引用生物识别认证（Biometric）",
    detail:
      "为什么：代码中出现 BiometricPrompt / androidx.biometric。所以：应用使用平台生物识别做身份验证，是较安全的本地认证方式（需配合 CryptoObject 才具加密绑定）。开发者可确认：是否用 CryptoObject 绑定密钥以防止绕过。",
    recommendation: "用 BiometricPrompt + BiometricPrompt.CryptoObject（Keystore 密钥）做加密绑定，避免仅做“是否通过”判断。",
    regex: /BiometricPrompt|BiometricManager|androidx\.biometric/i,
  },
]

// The DEX string pool loses call-site operands (for example a boolean passed to
// a WebSettings setter). Strict mode therefore requires corroborating API and
// value signals instead of treating every class or method name as a vulnerability.
function corpusHas(corpus: readonly string[], regex: RegExp): boolean {
  return corpus.some((value) => regex.test(value))
}

function firstMatch(value: string, patterns: readonly RegExp[]): RegExpExecArray | null {
  for (const pattern of patterns) {
    const match = pattern.exec(value)
    if (match) return match
  }
  return null
}

function preciseRuleMatch(
  suffix: string,
  value: string,
  corpus: readonly string[],
  sourceMode: boolean,
  fallback: RegExp,
): RegExpExecArray | null {
  switch (suffix) {
    case "WEBVIEW_JS_BRIDGE":
      return sourceMode
        ? firstMatch(value, [
            /addJavascriptInterface|@JavascriptInterface/,
            /setAllow(?:UniversalAccess|FileAccess)FromFileURLs\s*\(\s*true\s*\)/i,
          ])
        : /addJavascriptInterface|JavascriptInterface/.exec(value)
    case "WEBVIEW_JS_ENABLED":
      return sourceMode
        ? /(?:setJavaScriptEnabled\s*\(\s*true\s*\)|javaScriptEnabled\s*=\s*true)/i.exec(value)
        : null
    case "WEBVIEW_FILE_ACCESS":
      return sourceMode
        ? /(?:setAllowFileAccess\s*\(\s*true\s*\)|allowFileAccess\s*=\s*true)/i.exec(value)
        : null
    case "WEBVIEW_MIXED_CONTENT":
      return /MIXED_CONTENT_(?:ALWAYS_ALLOW|COMPATIBILITY_MODE)/i.exec(value)
    case "WEBVIEW_DOM_STORAGE":
      return sourceMode
        ? /(?:setDomStorageEnabled\s*\(\s*true\s*\)|domStorageEnabled\s*=\s*true)/i.exec(value)
        : null
    case "WEAK_CRYPTO": {
      if (sourceMode) {
        return /Cipher\s*\.\s*getInstance\s*\(\s*["'][^"']*(?:(?:DESede|DES|RC4|RC2|Blowfish)|\/ECB(?:\/|["']))[^"']*["']/i.exec(value)
      }
      return corpusHas(corpus, /Ljavax\/crypto\/Cipher;/) ? fallback.exec(value) : null
    }
    case "WEAK_HASH": {
      if (sourceMode) {
        return /MessageDigest\s*\.\s*getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']/i.exec(value)
      }
      return corpusHas(corpus, /Ljava\/security\/MessageDigest;/) ? fallback.exec(value) : null
    }
    case "INSECURE_TLS":
      return firstMatch(value, [
        /ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|TrustAll(?:Certs?|Manager|Certificates)?/i,
        /HostnameVerifier\s*\{[^}]{0,180}(?:->\s*true|return\s+true)/is,
        /verify\s*\([^)]*\)\s*(?:=|\{)[^}]{0,180}\breturn\s+true/is,
        /checkServerTrusted\s*\([^)]*\)\s*\{\s*\}/is,
      ])
    case "DYNAMIC_CODE_LOADING": {
      if (sourceMode) return /(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader)\s*\(/i.exec(value)
      const hasExternalCodeSource = corpusHas(corpus, /(?:https?:\/\/|\/sdcard\/|externalStorage|\.dex\b|\.jar\b)/i)
      return hasExternalCodeSource ? fallback.exec(value) : null
    }
    case "RUNTIME_EXEC": {
      if (sourceMode) return /(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|new\s+ProcessBuilder\s*\()/i.exec(value)
      const hasExecution = corpusHas(corpus, /^(?:exec|start)$/) || corpusHas(corpus, /(?:\/system\/(?:bin\/sh|xbin\/su)|\bsu\s+-c\b)/i)
      return hasExecution ? fallback.exec(value) : null
    }
    default:
      return fallback.exec(value)
  }
}

function confidenceFor(codePrefix: string, severity: Finding["severity"]): NonNullable<Finding["confidence"]> {
  if (severity === "info") return codePrefix === "SOURCE" ? "high" : "medium"
  return codePrefix === "SOURCE" ? "high" : "medium"
}

// Run every rule in strict-evidence mode. One finding is emitted per rule and
// only after the source/DEX-specific evidence gate above has passed.
export function scanCodeStrings(strings: Iterable<string>, codePrefix: string): Finding[] {
  const corpus = [...strings].filter((value) => value.length > 0)
  const findings: Finding[] = []
  const seen = new Set<string>()
  const sourceMode = codePrefix === "SOURCE"
  for (const value of corpus) {
    for (const rule of CODE_HEURISTIC_RULES) {
      const code = `${codePrefix}_${rule.suffix}`
      if (seen.has(code)) continue
      const match = preciseRuleMatch(rule.suffix, value, corpus, sourceMode, rule.regex)
      if (!match) continue
      seen.add(code)
      findings.push({
        severity: rule.severity,
        confidence: confidenceFor(codePrefix, rule.severity),
        code,
        title: rule.title,
        detail: rule.detail,
        recommendation: rule.recommendation,
        evidence: snippetAround(value, match.index, match[0].length),
      })
    }
  }
  return findings
}

function callTextAt(source: string, openParen: number): string | undefined {
  let depth = 0
  let quote = ""
  for (let index = openParen; index < source.length && index < openParen + 1_200; index += 1) {
    const char = source[index]!
    const previous = source[index - 1]
    if (quote) {
      if (char === quote && previous !== "\\") quote = ""
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      continue
    }
    if (char === "(") depth += 1
    if (char === ")") {
      depth -= 1
      if (depth === 0) return source.slice(openParen + 1, index)
    }
  }
  return undefined
}

function topLevelArguments(call: string): string[] {
  const args: string[] = []
  let start = 0
  let depth = 0
  let quote = ""
  for (let index = 0; index < call.length; index += 1) {
    const char = call[index]!
    const previous = call[index - 1]
    if (quote) {
      if (char === quote && previous !== "\\") quote = ""
      continue
    }
    if (char === '"' || char === "'") quote = char
    else if ("([{".includes(char)) depth += 1
    else if (")]}".includes(char)) depth -= 1
    else if (char === "," && depth === 0) {
      args.push(call.slice(start, index).trim())
      start = index + 1
    }
  }
  args.push(call.slice(start).trim())
  return args
}

function flagsDefinitelyLackMutability(flags: string): boolean {
  if (/FLAG_(?:IMMUTABLE|MUTABLE)/.test(flags)) return false
  if (/^(?:0|0x0+)$/i.test(flags.trim())) return true
  const withoutKnownFlags = flags
    .replace(/(?:PendingIntent\s*\.\s*)?FLAG_(?:ONE_SHOT|NO_CREATE|CANCEL_CURRENT|UPDATE_CURRENT)/g, "")
    .replace(/\b(?:or)\b|[|()+\s]|0x0+|\b0\b/gi, "")
  return withoutKnownFlags.length === 0
}

// Source calls are checked one by one. DEX strings do not retain the flags
// operand, so strict mode deliberately emits no DEX-level vulnerability here.
export function pendingIntentImmutableFinding(codePrefix: string, strings: Iterable<string>): Finding[] {
  if (codePrefix !== "SOURCE") return []
  for (const source of strings) {
    const callPattern = /PendingIntent\s*\.\s*(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\(/g
    let match: RegExpExecArray | null
    while ((match = callPattern.exec(source)) !== null) {
      const openParen = source.indexOf("(", match.index)
      const call = callTextAt(source, openParen)
      if (call === undefined) continue
      const args = topLevelArguments(call)
      if (args.length < 4) continue
      const flags = args.at(-1) ?? ""
      if (!flagsDefinitelyLackMutability(flags)) continue
      return [{
        severity: "medium",
        confidence: "high",
        code: `${codePrefix}_PENDING_INTENT_NO_MUTABILITY_FLAG`,
        title: "PendingIntent 调用点缺少显式可变性标志",
        detail:
          "为什么：已定位到具体 PendingIntent 创建调用，其 flags 参数可确定只含 0 或旧式控制标志，未包含 FLAG_IMMUTABLE/FLAG_MUTABLE。所以：在需要显式可变性的平台版本上可能产生兼容问题，也可能扩大 Intent 被填充或修改的风险。",
        recommendation: "默认加入 PendingIntent.FLAG_IMMUTABLE；仅在 RemoteInput 等确需外部修改的调用点使用 FLAG_MUTABLE，并限制 Intent 目标与输入。",
        evidence: snippetAround(source, match.index, match[0].length + call.length + 1),
      }]
    }
  }
  return []
}
