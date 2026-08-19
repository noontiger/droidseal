import path from "node:path"
import { readdir, readFile, stat } from "node:fs/promises"
import {
  buildMinSdkFinding,
  classifyCsp,
  clipboardFinding,
  cspFindings,
  detectClipboardPlugin,
  metaDataSecretFindings,
} from "./apk-audit.ts"
import { auditBackupPolicy, auditBackupRulesXml } from "./backup-rules-audit.ts"
import { buildPermissionFindings, type CustomPermission } from "./permissions-catalog.ts"
import { auditNetworkSecurityConfig } from "./nsc-audit.ts"
import { scanCodeStrings, pendingIntentImmutableFinding } from "./code-heuristics.ts"
import { scanStringsForSecrets, strongestSecretConfidence } from "./secret-scan.ts"
import { auditR8Rules, type R8AppModule } from "./r8-rules-audit.ts"
import { collectGradleSoftwareComponents } from "./gradle-components.ts"
import { auditSigningMaterials } from "./signing-material-audit.ts"
import { analyzeSignatureSelfChecks, type SignatureSourceFile } from "./signature-self-check.ts"
import {
  analyzeWebViewDebugging,
  type WebViewDebugSourceFile,
} from "./webview-debug-audit.ts"
import type { Finding, SecurityAudit, SignatureSelfCheckEvidence } from "./types.ts"

const SKIP_DIRECTORIES = new Set([".git", ".gradle", ".idea", "build", "node_modules", "dist", "out"])

export async function findFiles(root: string, predicate: (relativePath: string) => boolean): Promise<string[]> {
  const results: string[] = []
  const queue: Array<{ directory: string; depth: number }> = [{ directory: root, depth: 0 }]
  while (queue.length > 0) {
    const current = queue.shift()
    if (!current || current.depth > 12) continue
    let entries
    try {
      entries = await readdir(current.directory, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const absolute = path.join(current.directory, entry.name)
      const relative = path.relative(root, absolute).replaceAll("\\", "/")
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) queue.push({ directory: absolute, depth: current.depth + 1 })
      } else if (predicate(relative)) {
        results.push(absolute)
      }
    }
  }
  return results
}

function extractReleaseBlocks(source: string): string {
  const starts = [
    /\brelease\s*\{/g,
    /\bgetByName\s*\(\s*["']release["']\s*\)\s*\{/g,
    /\bcreate\s*\(\s*["']release["']\s*\)\s*\{/g,
  ]
  const blocks: string[] = []
  for (const expression of starts) {
    for (const match of source.matchAll(expression)) {
      const open = source.indexOf("{", match.index)
      if (open < 0) continue
      let depth = 0
      for (let index = open; index < source.length; index += 1) {
        const char = source[index]
        if (char === "{") depth += 1
        if (char === "}") depth -= 1
        if (depth === 0) {
          blocks.push(source.slice(open + 1, index))
          break
        }
      }
    }
  }
  return blocks.join("\n")
}

function releaseBlockHasMinify(release: string): boolean {
  return (
    /\bisMinifyEnabled\s*=\s*true\b/.test(release) ||
    /\bminifyEnabled\s*(?:=\s*)?true\b/.test(release) ||
    /\boptimization\s*\{[\s\S]*?\benable\s*=\s*true\b/.test(release)
  )
}

function auditGradle(relativePath: string, source: string): Finding[] {
  const findings: Finding[] = []
  const release = extractReleaseBlocks(source)
  if (!release) return findings

  const minifyEnabled = releaseBlockHasMinify(release)
  const shrinkResources =
    /\bisShrinkResources\s*=\s*true\b/.test(release) ||
    /\bshrinkResources\s*(?:=\s*)?true\b/.test(release) ||
    /\boptimization\s*\{[\s\S]*?\benable\s*=\s*true\b/.test(release)

  if (!minifyEnabled) {
    findings.push({
      severity: "high",
      code: "R8_MINIFICATION_NOT_CONFIRMED",
      title: "未确认 release 启用 R8 代码优化/混淆",
      detail: `${relativePath} 的 release 块中未发现 minify/optimization enable。`,
      recommendation: "在 release 构建中启用 R8，并回归测试反射、序列化与 JNI 路径。",
      evidence: relativePath,
    })
  }
  if (!shrinkResources) {
    findings.push({
      severity: "medium",
      code: "RESOURCE_SHRINKING_NOT_CONFIRMED",
      title: "未确认 release 启用资源优化",
      detail: `${relativePath} 的 release 块中未发现 shrinkResources/optimization enable。`,
      recommendation: "与代码优化一起启用资源优化，检查动态资源引用并配置 keep 规则。",
      evidence: relativePath,
    })
  }
  if (minifyEnabled && !/proguard-android-optimize\.txt/.test(release) && !/\boptimization\s*\{/.test(release)) {
    findings.push({
      severity: "low",
      code: "R8_OPTIMIZED_DEFAULT_RULES_NOT_CONFIRMED",
      title: "未确认使用优化版默认 R8 规则",
      detail: "检测到代码混淆，但未发现 proguard-android-optimize.txt。",
      recommendation: "确认当前 AGP 配置使用推荐的优化规则，并验证启动与关键业务路径。",
      evidence: relativePath,
    })
  }
  if (/\bdebuggable\s*(?:=\s*)?true\b/.test(release) || /\bisDebuggable\s*=\s*true\b/.test(release)) {
    findings.push({
      severity: "critical",
      code: "RELEASE_DEBUGGABLE",
      title: "release 构建显式允许调试",
      detail: "调试开关会降低对动态调试与运行时数据的保护。",
      recommendation: "将 release 的 debuggable/isDebuggable 设置为 false。",
      evidence: relativePath,
    })
  }
  if (/(?:storePassword|keyPassword)\s*(?:=|\s)\s*["'][^"']+["']/.test(source)) {
    findings.push({
      severity: "critical",
      code: "SIGNING_SECRET_IN_BUILD_SCRIPT",
      title: "构建脚本可能包含明文签名密码",
      detail: "检测到 storePassword/keyPassword 的字符串字面量。任何能读到该脚本（含 git 历史）的人都能提取签名密码，导致二次打包风险。",
      recommendation:
        "把密码移出构建脚本和仓库：优先使用 CI secret/环境变量；如必须使用属性文件，应放在仓库外的受控路径并限制 ACL，signingConfig 只读取外部值，例如 System.getenv('RELEASE_STORE_PASSWORD')。因明文一旦进过版本库即视为已泄露，建议用 keytool -genkeypair 生成新 keystore 轮换（会改变签名身份、影响已发布应用的升级安装；未发布可安全轮换）。注：DroidSeal 自身的签名密码仅驻留本次进程内存，绝不写入报告或磁盘。",
      evidence: relativePath,
    })
  }
  return findings
}

// Scan a source AndroidManifest.xml for components declared android:exported="true" without an
// android:permission guard that are not the launcher entry — those are an unnecessary exposure.
function auditSourceExportedComponents(relativePath: string, source: string): Finding[] {
  const findings: Finding[] = []
  const unprotected: string[] = []
  const browsableUnprotected: string[] = []
  const deeplinkNoAutoVerify: string[] = []
  const customTaskAffinity: string[] = []
  const packageName = /<manifest\b[^>]*\bpackage\s*=\s*["']([^"']+)["']/.exec(source)?.[1]
  const tagRe = /<(activity|activity-alias|service|receiver|provider)\b([^>]*?)(\/?)>/g
  let match: RegExpExecArray | null
  while ((match = tagRe.exec(source)) !== null) {
    const tag = match[1]!
    const attrs = match[2] ?? ""
    const selfClosing = match[3] === "/"
    if (!/android:exported\s*=\s*["']true["']/.test(attrs)) continue
    const hasPermission = /android:permission\s*=\s*["']/.test(attrs)
    const name = /android:name\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1] ?? `<${tag}>`
    const taskAffinity = /android:taskAffinity\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1]

    let body = ""
    if (!selfClosing) {
      const closeIndex = source.indexOf(`</${tag}>`, tagRe.lastIndex)
      body = closeIndex >= 0 ? source.slice(tagRe.lastIndex, closeIndex) : ""
    }
    const isLauncher =
      (tag === "activity" || tag === "activity-alias") &&
      /android\.intent\.action\.MAIN/.test(body) &&
      /android\.intent\.category\.LAUNCHER/.test(body)

    if (!hasPermission && !isLauncher) unprotected.push(name)

    if ((tag === "activity" || tag === "activity-alias") && !hasPermission) {
      const hasBrowsable = /android\.intent\.category\.BROWSABLE/.test(body)
      if (hasBrowsable) browsableUnprotected.push(name)
      const hasHttpScheme = /android:scheme\s*=\s*["']https?["']/.test(body)
      const autoVerify = /android:autoVerify\s*=\s*["']true["']/.test(attrs)
      if (hasHttpScheme && !autoVerify) deeplinkNoAutoVerify.push(name)
    }

    if (
      taskAffinity &&
      taskAffinity.length > 0 &&
      taskAffinity !== packageName &&
      !hasPermission &&
      !isLauncher
    ) {
      customTaskAffinity.push(`${name}(${taskAffinity})`)
    }
  }

  if (unprotected.length > 0) {
    findings.push({
      severity: "medium",
      code: "SOURCE_EXPORTED_COMPONENT_UNPROTECTED",
      title: "源码 Manifest 声明了无权限保护的导出组件",
      detail:
        "为什么：以下组件在 Manifest 中 android:exported=\"true\" 且未声明 android:permission，也不是 launcher 入口，任意第三方应用/ADB 都可向其发送 Intent。所以：可能被越权调用、组件劫持或用于数据泄露。开发者需自行：确认它们确实需要跨应用暴露；否则设为 exported=false，或以 signature 级 android:permission 保护。" +
        `无保护导出组件：${unprotected.join("、")}。`,
      recommendation: "对不需要跨应用调用的组件设置 android:exported=\"false\"；确需导出的加 signature 级 android:permission 并做调用方校验。",
      evidence: relativePath,
    })
  }
  if (browsableUnprotected.length > 0) {
    findings.push({
      severity: "medium",
      code: "SOURCE_BROWSABLE_EXPORTED_ACTIVITY",
      title: "源码 Manifest 存在可被浏览器唤起且无权限保护的导出 Activity",
      detail:
        "以下 Activity 带 BROWSABLE 分类且 exported=true、无 android:permission，网页/其他应用可直接构造链接唤起并传入参数，是深链参数注入与未授权跳转的常见入口：" +
        `${browsableUnprotected.join("、")}。`,
      recommendation: "对 BROWSABLE 入口做严格的 Intent 数据校验（scheme/host/path 白名单），避免直接信任外部传入参数。",
      evidence: relativePath,
    })
  }
  if (deeplinkNoAutoVerify.length > 0) {
    findings.push({
      severity: "low",
      code: "SOURCE_DEEPLINK_NO_AUTOVERIFY",
      title: "源码 Manifest 的 http/https 深链未启用 App Links 校验",
      detail:
        "以下 Activity 声明了 http/https scheme 的 intent-filter 却未设置 android:autoVerify=\"true\"，无法成为可信 App Links，其他应用可注册相同链接进行劫持：" +
        `${deeplinkNoAutoVerify.join("、")}。`,
      recommendation: "为对外深链设置 autoVerify=\"true\" 并部署 assetlinks.json（Digital Asset Links），使系统校验域名归属。",
      evidence: relativePath,
    })
  }
  if (customTaskAffinity.length > 0) {
    findings.push({
      severity: "medium",
      code: "SOURCE_CUSTOM_TASK_AFFINITY",
      title: "源码 Manifest 导出组件使用了自定义 taskAffinity",
      detail:
        "以下导出组件设置了非包名的 android:taskAffinity，可能被恶意应用利用进行任务栈劫持（StrandHogg 类攻击），伪装界面窃取输入：" +
        `${customTaskAffinity.join("、")}。`,
      recommendation: "除非有明确多任务需求，移除自定义 taskAffinity（留空以继承包名），或将相关 Activity 设为 exported=false。",
      evidence: relativePath,
    })
  }
  return findings
}

function parseSourceUsesPermissions(source: string): string[] {
  const permissions: string[] = []
  const re = /<uses-permission(?:-sdk-23)?\b[^>]*?android:name\s*=\s*["']([^"']+)["']/g
  let match: RegExpExecArray | null
  while ((match = re.exec(source)) !== null) permissions.push(match[1]!)
  return permissions
}

function parseSourceCustomPermissions(source: string): CustomPermission[] {
  const out: CustomPermission[] = []
  const re = /<permission\b([^>]*?)\/?>/g
  let match: RegExpExecArray | null
  while ((match = re.exec(source)) !== null) {
    const attrs = match[1] ?? ""
    const name = /android:name\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1]
    if (!name) continue
    const protectionLevel = /android:protectionLevel\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1] ?? ""
    out.push({ name, protectionLevel })
  }
  return out
}

function parseSourceMetaData(source: string): Array<{ name: string; value: string }> {
  const out: Array<{ name: string; value: string }> = []
  const re = /<meta-data\b([^>]*?)\/?>/g
  let match: RegExpExecArray | null
  while ((match = re.exec(source)) !== null) {
    const attrs = match[1] ?? ""
    const name = /android:name\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1] ?? ""
    const value = /android:value\s*=\s*["']([^"']+)["']/.exec(attrs)?.[1] ?? ""
    if (value.length > 0) out.push({ name, value })
  }
  return out
}

function resolveResXmlPath(moduleDir: string, reference: string): string | undefined {
  // Accept @xml/name or @<pkg>:xml/name; only local @xml/ references are resolvable.
  const name = /^@(?:[\w.]+:)?xml\/([\w.]+)$/.exec(reference)?.[1]
  if (!name) return undefined
  return path.join(moduleDir, "src", "main", "res", "xml", `${name}.xml`)
}

async function auditBackupRules(
  relativePath: string,
  source: string,
  moduleDir: string,
): Promise<Finding[]> {
  const findings: Finding[] = []
  const backupDisabled = /android:allowBackup\s*=\s*["']false["']/.test(source)
  if (backupDisabled) return findings

  const fullBackupRef = /android:fullBackupContent\s*=\s*["']([^"']+)["']/.exec(source)?.[1]
  const dataRulesRef = /android:dataExtractionRules\s*=\s*["']([^"']+)["']/.exec(source)?.[1]
  const refs = [fullBackupRef, dataRulesRef].filter((ref): ref is string => Boolean(ref))

  findings.push(...auditBackupPolicy({
    backupDisabled,
    hasFullBackupContent: fullBackupRef !== undefined,
    hasDataExtractionRules: dataRulesRef !== undefined,
    evidence: relativePath,
  }))
  if (refs.length === 0) return findings

  for (const ref of refs) {
    const filePath = resolveResXmlPath(moduleDir, ref)
    if (!filePath) continue
    const xml = await readFile(filePath, "utf8").catch(() => undefined)
    if (xml === undefined) continue
    findings.push(...auditBackupRulesXml(xml, ref))
  }
  return findings
}

async function auditManifest(
  relativePath: string,
  source: string,
  moduleDir: string,
): Promise<Finding[]> {
  const findings: Finding[] = []
  if (/android:debuggable\s*=\s*["']true["']/.test(source)) {
    findings.push({
      severity: "critical",
      code: "SOURCE_MANIFEST_DEBUGGABLE",
      title: "主 Manifest 允许调试",
      detail: "android:debuggable=true 可能进入最终发布 APK。",
      recommendation: "从主 Manifest 移除该属性，并在 release 合并清单中复核最终值。",
      evidence: relativePath,
    })
  }
  if (/android:usesCleartextTraffic\s*=\s*["']true["']/.test(source)) {
    findings.push({
      severity: "high",
      code: "SOURCE_MANIFEST_CLEARTEXT",
      title: "主 Manifest 允许明文网络流量",
      detail: "应用可能通过 HTTP 传输数据。",
      recommendation: "默认禁用明文流量，只对确有需要的域名设置最小例外。",
      evidence: relativePath,
    })
  }
  if (!/android:allowBackup\s*=\s*["']false["']/.test(source)) {
    findings.push({
      severity: "medium",
      code: "SOURCE_BACKUP_POLICY_UNCONFIRMED",
      title: "未确认敏感数据备份策略",
      detail: "主 Manifest 未明确 allowBackup=false；Android 12+ 还需结合 dataExtractionRules 评估。",
      recommendation: "根据数据分类配置备份与设备迁移排除规则。",
      evidence: relativePath,
    })
  }
  const nscRef = /android:networkSecurityConfig\s*=\s*["']([^"']+)["']/.exec(source)?.[1]
  if (!nscRef) {
    findings.push({
      severity: "info",
      code: "SOURCE_NETWORK_CONFIG_ABSENT",
      title: "未引用 Network Security Config",
      detail: "无法从主 Manifest 确认自定义网络信任策略。",
      recommendation: "若应用有复杂 TLS/调试 CA 策略，使用 Network Security Config 并保留轮换方案。",
      evidence: relativePath,
    })
  } else {
    const nscPath = resolveResXmlPath(moduleDir, nscRef)
    const nscXml = nscPath ? await readFile(nscPath, "utf8").catch(() => undefined) : undefined
    if (nscXml !== undefined) {
      const nscEvidence = nscPath ? path.relative(moduleDir, nscPath).replaceAll("\\", "/") : nscRef
      findings.push(...auditNetworkSecurityConfig(nscXml, nscEvidence))
    }
  }
  findings.push(...auditSourceExportedComponents(relativePath, source))
  findings.push(...buildPermissionFindings(
    parseSourceUsesPermissions(source),
    parseSourceCustomPermissions(source),
    "SOURCE",
  ))
  findings.push(...metaDataSecretFindings(parseSourceMetaData(source), "SOURCE"))
  findings.push(...(await auditBackupRules(relativePath, source, moduleDir)))

  const minSdk = /android:minSdkVersion\s*=\s*["'](\d+)["']/.exec(source)?.[1]
  if (minSdk !== undefined) {
    findings.push(...buildMinSdkFinding(Number.parseInt(minSdk, 10), "SOURCE"))
  }
  return findings
}

const MAX_SOURCE_FILES = 400
const MAX_SOURCE_CHARS = 8 * 1024 * 1024

// Scan app-module Java/Kotlin sources with the shared heuristic catalog. Each file is
// fed whole (as one blob) so evidence snippets can be taken around the match. Bounded
// by file count / total size so large projects don't blow memory or runtime.
async function scanAppSource(
  moduleDir: string,
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  onProgress?.("扫描源码（WebView/加密/组件/运行时自我保护等启发式）")
  const files = await findFiles(moduleDir, (relative) => /\.(?:kt|java)$/i.test(relative))
  const findings: Finding[] = []
  const blobs: string[] = []
  let totalChars = 0
  let scanned = 0
  let skipped = 0
  for (const filePath of files) {
    if (scanned >= MAX_SOURCE_FILES) {
      skipped += 1
      continue
    }
    const text = await readFile(filePath, "utf8").catch(() => undefined)
    if (text === undefined) continue
    if (totalChars + text.length > MAX_SOURCE_CHARS) {
      skipped += 1
      continue
    }
    blobs.push(text)
    totalChars += text.length
    scanned += 1
  }
  if (blobs.length === 0) return findings

  findings.push(...scanCodeStrings(blobs, "SOURCE"))
  findings.push(...pendingIntentImmutableFinding("SOURCE", blobs))

  const secretHits = scanStringsForSecrets(blobs.flatMap((blob) => blob.split(/\r?\n/)))
  if (secretHits.length > 0) {
    findings.push({
      severity: secretHits.some((hit) => hit.confidence === "confirmed" || hit.confidence === "high") ? "high" : "medium",
      confidence: strongestSecretConfidence(secretHits),
      code: "SOURCE_HARDCODED_SECRET",
      title: "源码中疑似硬编码密钥/凭据",
      detail:
        "为什么：源码中发现通过格式、长度、值域与熵阈值校验的密钥/令牌候选；示例值、占位符和低熵通用赋值已过滤。请先按脱敏证据定位，确认是真实凭据后立即轮换：" +
        secretHits.map((hit) => `${hit.label}(${hit.preview})`).join("、") + "。",
      recommendation: "将密钥移出源码，改由服务端保管或使用短期令牌；已泄露的凭据立即轮换。",
      evidence: secretHits.map((hit) => `${hit.code}:${hit.preview}`).join(", ").slice(0, 300),
    })
  }
  if (skipped > 0) {
    findings.push({
      severity: "info",
      code: "SOURCE_SCAN_TRUNCATED",
      title: "源码扫描未完整覆盖",
      detail: `为控制耗时与内存，源码启发式扫描在达到文件数/字符上限后跳过了约 ${skipped} 个文件；结果为部分覆盖。`,
      recommendation: "如担心遗漏，可缩小审计目录或分模块审计；核心敏感逻辑通常已被覆盖。",
    })
  }
  return findings
}

async function scanAppWebViewDebugging(
  moduleDir: string,
  projectPath: string,
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  onProgress?.("精审 WebView 调试的 release 显式关闭状态")
  const sourcePaths = (await findFiles(
    moduleDir,
    (relative) => /(^|\/)src\/(?:main|release|debug)\/.*\.(?:kt|java)$/i.test(relative),
  )).sort()
  const inputs: WebViewDebugSourceFile[] = []
  let totalChars = 0
  let skipped = Math.max(0, sourcePaths.length - MAX_SOURCE_FILES)
  for (const filePath of sourcePaths.slice(0, MAX_SOURCE_FILES)) {
    const content = await readFile(filePath, "utf8").catch(() => undefined)
    if (content === undefined || totalChars + content.length > MAX_SOURCE_CHARS) {
      skipped += 1
      continue
    }
    inputs.push({
      relativePath: path.relative(projectPath, filePath).replaceAll("\\", "/"),
      content,
    })
    totalChars += content.length
  }
  const modulePath = path.relative(projectPath, moduleDir).replaceAll("\\", "/") || "."
  const analysis = analyzeWebViewDebugging(inputs, modulePath)
  if (skipped === 0) return analysis.findings

  const incomplete: Finding = {
    severity: "info",
    confidence: "low",
    code: "SOURCE_WEBVIEW_DEBUGGING_AUDIT_INCOMPLETE",
    title: "WebView 调试源码审计未完整覆盖",
    detail: `模块 ${modulePath} 达到源码文件数或字符上限，约 ${skipped} 个文件未参与 WebView 调试四态判定。为避免误报，除已直接观察到的 release true 外，不输出“已关闭”或“仅 DEBUG 开启”结论。`,
    recommendation: "缩小项目范围或按模块审计，并人工核对未扫描的自定义 source set；最终使用 release APK 验证 Chrome DevTools 不可发现 WebView。",
    evidence: `scanned=${inputs.length}, skipped=${skipped}`,
  }
  return analysis.state === "release-enabled"
    ? [...analysis.findings, incomplete]
    : [incomplete]
}

async function scanAppSignatureSelfChecks(
  moduleDir: string,
  projectPath: string,
  onProgress?: (message: string) => void,
): Promise<ReturnType<typeof analyzeSignatureSelfChecks>> {
  onProgress?.("精审 App 自签名校验的配置、API、启动调用与处置")
  const sourcePaths = (await findFiles(
    moduleDir,
    (relative) => /(^|\/)src\/(?:main|release)\/.*\.(?:kt|java)$/i.test(relative),
  )).sort()
  const inputs: SignatureSourceFile[] = []
  let totalChars = 0
  for (const filePath of sourcePaths.slice(0, MAX_SOURCE_FILES)) {
    const content = await readFile(filePath, "utf8").catch(() => undefined)
    if (content === undefined || totalChars + content.length > MAX_SOURCE_CHARS) continue
    inputs.push({
      relativePath: path.relative(projectPath, filePath).replaceAll("\\", "/"),
      content,
    })
    totalChars += content.length
  }
  return analyzeSignatureSelfChecks(
    inputs,
    path.relative(projectPath, moduleDir).replaceAll("\\", "/") || ".",
  )
}

export async function auditProject(
  projectPath: string,
  onProgress?: (message: string) => void,
): Promise<SecurityAudit> {
  onProgress?.("查找 Android 模块与主 Manifest")
  const files = await findFiles(
    projectPath,
    (relative) =>
      /(^|\/)build\.gradle(?:\.kts)?$/.test(relative) ||
      /(^|\/)src\/main\/AndroidManifest\.xml$/.test(relative) ||
      /(^|\/)libs\.versions\.toml$/.test(relative) ||
      relative === "gradle.properties",
  )
  const findings: Finding[] = []
  let androidGradleFileCount = 0
  let appManifestCount = 0

  // Pre-scan: cache sources and record which module directories are app modules
  // (com.android.application). App-level manifest policies must only be checked on
  // app-module manifests — library/empty manifests legitimately omit them.
  const sources = new Map<string, string>()
  const appModuleDirs = new Set<string>()
  const appModules = new Map<string, R8AppModule>()
  for (const filePath of files) {
    const source = await readFile(filePath, "utf8")
    sources.set(filePath, source)
    const relative = path.relative(projectPath, filePath).replaceAll("\\", "/")
    if (/build\.gradle(?:\.kts)?$/.test(relative) && /com\.android\.application/.test(source)) {
      const moduleDirectory = path.resolve(path.dirname(filePath))
      appModuleDirs.add(moduleDirectory)
      appModules.set(moduleDirectory, {
        moduleDirectory,
        buildScriptRelativePath: relative,
        releaseConfiguration: extractReleaseBlocks(source),
      })
    }
  }

  for (const filePath of files) {
    const relative = path.relative(projectPath, filePath).replaceAll("\\", "/")
    const source = sources.get(filePath) ?? ""
    if (/build\.gradle(?:\.kts)?$/.test(relative) && /com\.android\.application|com\.android\.library/.test(source)) {
      androidGradleFileCount += 1
      findings.push(...auditGradle(relative, source))
    }
    if (/src\/main\/AndroidManifest\.xml$/.test(relative)) {
      // manifest path is <moduleDir>/src/main/AndroidManifest.xml
      const moduleDir = path.resolve(path.dirname(path.dirname(path.dirname(filePath))))
      if (appModuleDirs.has(moduleDir)) {
        appManifestCount += 1
        findings.push(...(await auditManifest(relative, source, moduleDir)))
      }
    }
    if (relative === "gradle.properties" && /android\.enableR8\.fullMode\s*=\s*false/.test(source)) {
      findings.push({
        severity: "medium",
        code: "R8_FULL_MODE_DISABLED",
        title: "R8 Full Mode 被关闭",
        detail: "gradle.properties 包含 android.enableR8.fullMode=false。",
        recommendation: "评估并移除旧兼容开关，然后完整回归 release 构建。",
        evidence: relative,
      })
    }
  }

  findings.push(...(await auditR8Rules(projectPath, [...appModules.values()])))
  findings.push(...(await auditSigningMaterials(projectPath, onProgress)))

  if (androidGradleFileCount === 0) {
    findings.push({
      severity: "high",
      code: "ANDROID_MODULE_NOT_FOUND",
      title: "未发现 Android Gradle 模块",
      detail: "没有找到应用/库插件声明，输入目录可能不是项目根目录。",
      recommendation: "选择包含 settings.gradle(.kts) 和 gradlew 的 Android 项目根目录。",
    })
  }

  const signatureSelfChecks: SignatureSelfCheckEvidence[] = []
  for (const dir of appModuleDirs) {
    findings.push(...(await scanAppSource(dir, onProgress)))
    findings.push(...(await scanAppWebViewDebugging(dir, projectPath, onProgress)))
    const signatureAnalysis = await scanAppSignatureSelfChecks(dir, projectPath, onProgress)
    findings.push(...signatureAnalysis.findings)
    if (signatureAnalysis.evidence) signatureSelfChecks.push(signatureAnalysis.evidence)
  }

  const softwareComponents = collectGradleSoftwareComponents(
    [...sources.entries()].map(([filePath, source]) => ({
      relativePath: path.relative(projectPath, filePath).replaceAll("\\", "/"),
      source,
    })),
  )
  const dependencies = softwareComponents.filter((component) => component.kind === "maven")
  const dependencyLabels = dependencies.map((component) =>
    `${component.namespace}:${component.name}${component.version ? `:${component.version}` : ":<unresolved>"}`,
  )
  if (dependencies.length > 0) {
    findings.push({
      severity: "info",
      code: "SUPPLYCHAIN_SDK_INVENTORY",
      title: "第三方依赖清单（Gradle）",
      detail:
        `从构建脚本/版本目录识别到 ${dependencies.length} 个依赖坐标（不做漏洞比对）：${dependencyLabels.slice(0, 40).join("、")}${dependencies.length > 40 ? " 等" : ""}。用于供应链梳理。`,
      recommendation: "维护依赖清单，定期用 gradle 依赖锁定与漏洞扫描（如 OWASP dependency-check）核对已知 CVE 并升级。",
      evidence: dependencyLabels.slice(0, 40).join(", "),
    })
  }
  if (appManifestCount === 0) {
    findings.push({
      severity: "high",
      code: "SOURCE_MANIFEST_NOT_FOUND",
      title: "未发现 app 模块的 src/main/AndroidManifest.xml",
      detail: "在应用模块(com.android.application)下没有找到主 Manifest，无法执行源码侧 Manifest 安全审计。",
      recommendation: "确认项目模块布局，或改为输入已构建 APK。",
    })
  }

  // Hybrid app (Capacitor/Cordova) detection: front-end www/JS assets are shipped in
  // cleartext inside the APK and are NOT covered by R8 (which only touches Java/Kotlin DEX).
  const hybridProbes: string[] = [path.join(projectPath, "capacitor-cordova-android-plugins")]
  for (const dir of appModuleDirs) {
    hybridProbes.push(
      path.join(dir, "capacitor.build.gradle"),
      path.join(dir, "src", "main", "assets", "public"),
      path.join(dir, "src", "main", "assets", "www"),
    )
  }
  let hybridDetected = false
  for (const probe of hybridProbes) {
    if (await stat(probe).then(() => true, () => false)) {
      hybridDetected = true
      break
    }
  }
  if (hybridDetected) {
    findings.push({
      severity: "info",
      code: "HYBRID_FRONTEND_CLEARTEXT",
      title: "混合应用：前端 www/JS 在 APK 内明文可见",
      detail:
        "检测到 Capacitor/Cordova 混合应用。业务逻辑主要在 WebView 的 www/assets（如 assets/public）里，这些 HTML/JS/CSS 天然以明文打进 APK，解压即可阅读；R8/ProGuard 只混淆 Java/Kotlin 编译出的 DEX，不覆盖这部分前端资源。",
      recommendation:
        "优先在 Web 源工程构建期完成压缩和兼容性测试；也可在 DroidSeal 向导中显式开启“Web JS 发布处理”，对 assets/public 与 assets/www 下的脚本做保守 Terser 压缩/混淆并移除 source map。该处理只提高阅读门槛，不提供保密：密钥与敏感业务逻辑必须移到服务端，并结合服务端完整性策略；DEX 加密/VMP/运行时外壳仍应在源码构建链接入已授权方案后由 DroidSeal 复核。",
    })
  }

  // Source-side WebView asset checks (CSP + sensitive plugins). Deduplicated across app modules.
  let cspChecked = false
  let clipboardReported = false
  for (const dir of appModuleDirs) {
    const assetsDir = path.join(dir, "src", "main", "assets")
    if (!cspChecked) {
      const indexHtml =
        (await readFile(path.join(assetsDir, "public", "index.html"), "utf8").catch(() => undefined)) ??
        (await readFile(path.join(assetsDir, "www", "index.html"), "utf8").catch(() => undefined))
      if (indexHtml !== undefined) {
        findings.push(...cspFindings(classifyCsp(indexHtml), "SOURCE_WEBVIEW"))
        cspChecked = true
      }
    }
    if (!clipboardReported) {
      const pluginsJson = await readFile(path.join(assetsDir, "capacitor.plugins.json"), "utf8").catch(() => undefined)
      if (pluginsJson !== undefined && detectClipboardPlugin(pluginsJson)) {
        findings.push(clipboardFinding("SOURCE_SENSITIVE_PLUGIN_CLIPBOARD"))
        clipboardReported = true
      }
    }
  }

  return { findings, softwareComponents, signatureSelfChecks }
}

// Inspect the Android application module(s) and report whether the release build type
// already enables R8/minification. Returns:
//   true      -> at least one app module has release minify enabled
//   false     -> an app module was found but none enable release minify
//   undefined -> no com.android.application module was found (can't tell)
export async function detectReleaseMinifyEnabled(projectPath: string): Promise<boolean | undefined> {
  const files = await findFiles(projectPath, (relative) =>
    /(^|\/)build\.gradle(?:\.kts)?$/.test(relative),
  )
  let appModuleFound = false
  for (const filePath of files) {
    const source = await readFile(filePath, "utf8").catch(() => "")
    if (!/com\.android\.application/.test(source)) continue
    appModuleFound = true
    const release = extractReleaseBlocks(source)
    if (release && releaseBlockHasMinify(release)) return true
  }
  return appModuleFound ? false : undefined
}
