import path from "node:path"
import { DroidSealError } from "./errors.ts"
import { extractApkEntryBytes } from "./apk-strip.ts"
import {
  auditApkNetworkSecurityConfig,
  parseAxmlElements,
  reconstructXml,
  xmlResourceEntryName,
  type AxmlAttribute,
  type AxmlElement,
} from "./axml-nsc.ts"
import { auditBackupPolicy, auditBackupRulesXml } from "./backup-rules-audit.ts"
import { resolveArscFilePath } from "./arsc-model.ts"
import { runProcess } from "./process.ts"
import { buildPermissionFindings, type CustomPermission } from "./permissions-catalog.ts"
import { scanStringsForSecrets, strongestSecretConfidence, containsPrivateKey } from "./secret-scan.ts"
import { extractDexStrings, scanDex, detectSdkPackages } from "./dex-scan.ts"
import { analyzeElf, buildSoFindings } from "./elf-scan.ts"
import type {
  ApkEntrySummary,
  ApkMetadata,
  Finding,
  SecurityAudit,
  SoftwareComponent,
  Toolchain,
} from "./types.ts"

interface ZipEntry {
  name: string
  compressedSize: number
  uncompressedSize: number
  method: number
  encrypted: boolean
}

const EOCD_SIGNATURE = 0x06054b50
const CENTRAL_SIGNATURE = 0x02014b50
const MAX_EOCD_SEARCH = 65_557
const MAX_CENTRAL_DIRECTORY = 128 * 1024 * 1024

function decoderFor(flags: number): TextDecoder {
  if ((flags & 0x0800) !== 0) return new TextDecoder("utf-8", { fatal: false })
  return new TextDecoder("utf-8", { fatal: false })
}

async function readSlice(file: Bun.BunFile, start: number, end: number): Promise<Uint8Array> {
  return new Uint8Array(await file.slice(start, end).arrayBuffer())
}

export async function parseZipEntries(apkPath: string): Promise<ZipEntry[]> {
  const file = Bun.file(apkPath)
  const size = file.size
  if (size < 22) {
    throw new DroidSealError({
      code: "APK_TOO_SMALL",
      message: "文件太小，不可能是有效 APK",
      explanation: "ZIP 结束记录至少需要 22 字节，输入文件可能为空、下载未完成或不是 APK。",
      suggestions: ["确认选择的是 .apk 文件", "重新复制或下载输入文件"],
      stepId: "apk-audit",
    })
  }

  const tailStart = Math.max(0, size - MAX_EOCD_SEARCH)
  const tail = await readSlice(file, tailStart, size)
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength)
  let eocdOffset = -1
  for (let offset = tail.length - 22; offset >= 0; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) {
      eocdOffset = offset
      break
    }
  }
  if (eocdOffset < 0) {
    throw new DroidSealError({
      code: "ZIP_EOCD_MISSING",
      message: "APK 缺少 ZIP 中央目录结束记录",
      explanation: "文件可能已损坏、被截断，或只是把其他格式改成了 .apk 扩展名。",
      suggestions: ["重新获取完整 APK", "核对来源提供的 SHA-256"],
      stepId: "apk-audit",
    })
  }

  const entryCount = view.getUint16(eocdOffset + 10, true)
  const centralSize = view.getUint32(eocdOffset + 12, true)
  const centralOffset = view.getUint32(eocdOffset + 16, true)
  if (entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) {
    throw new DroidSealError({
      code: "ZIP64_UNSUPPORTED",
      message: "暂不支持 ZIP64 格式的 APK",
      explanation: "常规 APK 不应需要 ZIP64；该文件可能异常巨大或由非标准工具生成。",
      suggestions: ["用 Android 官方构建工具重新生成 APK", "确认没有把超大 ZIP 文件误传为 APK"],
      stepId: "apk-audit",
    })
  }
  if (centralSize > MAX_CENTRAL_DIRECTORY || centralOffset + centralSize > size) {
    throw new DroidSealError({
      code: "ZIP_CENTRAL_DIRECTORY_INVALID",
      message: "APK 中央目录范围无效",
      explanation: "中央目录指向文件边界之外，说明容器损坏或被恶意构造。",
      suggestions: ["不要继续分发该 APK", "从可信构建产物重新开始"],
      stepId: "apk-audit",
    })
  }

  const central = await readSlice(file, centralOffset, centralOffset + centralSize)
  const centralView = new DataView(central.buffer, central.byteOffset, central.byteLength)
  const entries: ZipEntry[] = []
  let cursor = 0

  while (cursor < central.length && entries.length < entryCount) {
    if (cursor + 46 > central.length || centralView.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      throw new DroidSealError({
        code: "ZIP_ENTRY_INVALID",
        message: `APK 中央目录第 ${entries.length + 1} 项无效`,
        explanation: "ZIP 条目结构不完整或签名不匹配，文件可能损坏。",
        suggestions: ["使用 zipalign -c 验证 APK", "从构建系统重新导出 APK"],
        stepId: "apk-audit",
      })
    }
    const flags = centralView.getUint16(cursor + 8, true)
    const method = centralView.getUint16(cursor + 10, true)
    const compressedSize = centralView.getUint32(cursor + 20, true)
    const uncompressedSize = centralView.getUint32(cursor + 24, true)
    const nameLength = centralView.getUint16(cursor + 28, true)
    const extraLength = centralView.getUint16(cursor + 30, true)
    const commentLength = centralView.getUint16(cursor + 32, true)
    const nameStart = cursor + 46
    const next = nameStart + nameLength + extraLength + commentLength
    if (next > central.length) {
      throw new DroidSealError({
        code: "ZIP_ENTRY_TRUNCATED",
        message: "APK 中央目录条目被截断",
        explanation: "文件名、扩展字段或注释长度超出了中央目录边界。",
        suggestions: ["重新生成 APK", "检查文件传输过程是否完整"],
        stepId: "apk-audit",
      })
    }
    const name = decoderFor(flags).decode(central.subarray(nameStart, nameStart + nameLength))
    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      method,
      encrypted: (flags & 0x0001) !== 0,
    })
    cursor = next
  }

  if (entries.length !== entryCount) {
    throw new DroidSealError({
      code: "ZIP_ENTRY_COUNT_MISMATCH",
      message: "APK 条目数量与中央目录声明不一致",
      explanation: `中央目录声明 ${entryCount} 项，但只解析到 ${entries.length} 项。`,
      suggestions: ["使用 Android 官方构建工具重新生成 APK"],
      stepId: "apk-audit",
    })
  }
  return entries
}

function summarizeEntries(entries: ZipEntry[]): { summary: ApkEntrySummary; findings: Finding[] } {
  const findings: Finding[] = []
  const names = new Set<string>()
  const duplicates = new Set<string>()
  const unsafeNames: string[] = []
  const bombs: string[] = []
  const encrypted: string[] = []

  for (const entry of entries) {
    const normalizedSeparators = entry.name.replaceAll("\\", "/")
    const segments = normalizedSeparators.split("/")
    if (
      normalizedSeparators.startsWith("/") ||
      /^[a-zA-Z]:\//.test(normalizedSeparators) ||
      segments.some((segment) => segment === ".." || segment.includes("\0"))
    ) {
      unsafeNames.push(entry.name)
    }
    if (names.has(entry.name)) duplicates.add(entry.name)
    names.add(entry.name)
    if (
      entry.uncompressedSize > 10 * 1024 * 1024 &&
      entry.compressedSize > 0 &&
      entry.uncompressedSize / entry.compressedSize > 1_000
    ) {
      bombs.push(entry.name)
    }
    if (entry.encrypted) encrypted.push(entry.name)
  }

  if (unsafeNames.length > 0) {
    findings.push({
      severity: "critical",
      code: "APK_ZIP_PATH_TRAVERSAL",
      title: "APK 含不安全的 ZIP 路径",
      detail: `发现 ${unsafeNames.length} 个绝对路径、父目录跳转或空字节条目。`,
      recommendation: "不要安装或继续处理该 APK；从可信构建系统重新生成。",
      evidence: unsafeNames.slice(0, 5).join(", "),
    })
  }
  if (duplicates.size > 0) {
    findings.push({
      severity: "high",
      code: "APK_DUPLICATE_ENTRIES",
      title: "APK 含重复 ZIP 条目",
      detail: "不同解析器对重复条目可能采用不同内容，会造成验证与运行时解释不一致。",
      recommendation: "清理重复条目并重新构建、对齐和签名。",
      evidence: [...duplicates].slice(0, 5).join(", "),
    })
  }
  if (bombs.length > 0) {
    findings.push({
      severity: "high",
      code: "APK_EXTREME_COMPRESSION_RATIO",
      title: "APK 含异常压缩比条目",
      detail: "解压大小与压缩大小差距极端，可能造成资源耗尽。",
      recommendation: "检查对应资源是否由可信构建链生成。",
      evidence: bombs.slice(0, 5).join(", "),
    })
  }
  if (encrypted.length > 0) {
    findings.push({
      severity: "medium",
      code: "APK_ENCRYPTED_ZIP_ENTRIES",
      title: "APK 使用 ZIP 层加密条目",
      detail: "Android APK 的标准加载路径通常不使用 ZIP 通用加密标志，这可能导致兼容性问题。",
      recommendation: "确认保护方案与目标 Android 版本兼容，并进行真机回归测试。",
      evidence: encrypted.slice(0, 5).join(", "),
    })
  }

  if (names.has("DebugProbesKt.bin")) {
    findings.push({
      severity: "low",
      code: "APK_COROUTINES_DEBUG_PROBES",
      title: "APK 内含 kotlinx-coroutines 调试代理元数据",
      detail:
        "为什么：DebugProbesKt.bin 是 kotlinx-coroutines 调试代理（DebugProbes）的字节码探针元数据，仅供开发期协程调试用；随 release 打包属冗余，且会暴露少量协程内部结构信息。所以：正式产物不需要它。开发者需自行/或交给 DroidSeal：DroidSeal 会在 harden 阶段将其无损剔除（不改任何代码，仅从 ZIP 移除该条目并重新对齐、签名、验证）。",
      recommendation: "无需手动处理；DroidSeal 会在 harden 阶段安全剔除该文件。若要从根源避免，可在 release 依赖中排除 kotlinx-coroutines-debug。",
      evidence: "DebugProbesKt.bin",
    })
  }

  const dexFiles = entries.map((entry) => entry.name).filter((name) => /^classes(?:\d+)?\.dex$/.test(name))
  const nativeLibraries = entries.map((entry) => entry.name).filter((name) => /^lib\/[^/]+\/[^/]+\.so$/.test(name))
  const nativeArchitectures = [...new Set(nativeLibraries.map((name) => name.split("/")[1]).filter(Boolean) as string[])].sort()
  const legacySignatureFiles = entries
    .map((entry) => entry.name)
    .filter((name) => /^META-INF\/[^/]+\.(?:RSA|DSA|EC|SF)$/i.test(name))

  const hasManifest = names.has("AndroidManifest.xml")
  const hasResourcesTable = names.has("resources.arsc")
  if (!hasManifest) {
    findings.push({
      severity: "critical",
      code: "APK_MANIFEST_MISSING",
      title: "APK 缺少 AndroidManifest.xml",
      detail: "Android 无法把该容器识别为可安装应用。",
      recommendation: "检查输入类型并从 Android 构建系统重新导出 APK。",
    })
  }
  if (dexFiles.length === 0 && nativeLibraries.length === 0) {
    findings.push({
      severity: "high",
      code: "APK_EXECUTABLE_CODE_MISSING",
      title: "APK 未发现 DEX 或原生库",
      detail: "普通应用通常至少包含 classes.dex；纯资源 APK 需要确认是否属于预期分包。",
      recommendation: "确认输入是否为完整基础 APK，而不是拆分资源包。",
    })
  }

  return {
    summary: {
      totalEntries: entries.length,
      totalCompressedBytes: entries.reduce((sum, entry) => sum + entry.compressedSize, 0),
      totalUncompressedBytes: entries.reduce((sum, entry) => sum + entry.uncompressedSize, 0),
      dexFiles,
      nativeLibraries,
      nativeArchitectures,
      legacySignatureFiles,
      hasManifest,
      hasResourcesTable,
    },
    findings,
  }
}

function matchValue(output: string, expression: RegExp): string | undefined {
  return expression.exec(output)?.[1]
}

function parseBadging(output: string): ApkMetadata {
  const metadata: ApkMetadata = {}
  const values: Array<[keyof ApkMetadata, string | undefined]> = [
    ["packageName", matchValue(output, /^package: name='([^']+)'/m)],
    ["versionCode", matchValue(output, /^package:.*versionCode='([^']+)'/m)],
    ["versionName", matchValue(output, /^package:.*versionName='([^']+)'/m)],
    ["minSdk", matchValue(output, /^sdkVersion:'([^']+)'/m)],
    ["targetSdk", matchValue(output, /^targetSdkVersion:'([^']+)'/m)],
    ["applicationLabel", matchValue(output, /^application-label(?:-[^:]+)?:'([^']+)'/m)],
  ]
  for (const [key, value] of values) {
    if (value !== undefined) metadata[key] = value
  }
  return metadata
}

export function manifestFindings(xmlTree: string): Finding[] {
  const findings: Finding[] = []
  if (/android:debuggable\b[^\n]*0xffffffff/i.test(xmlTree)) {
    findings.push({
      severity: "critical",
      code: "MANIFEST_DEBUGGABLE",
      title: "发布 APK 允许调试",
      detail: "android:debuggable=true 会显著降低运行时保护强度。",
      recommendation: "在 release 构建中关闭 debuggable，并重新构建、签名。",
    })
  }
  if (/android:usesCleartextTraffic\b[^\n]*0xffffffff/i.test(xmlTree)) {
    findings.push({
      severity: "high",
      code: "MANIFEST_CLEARTEXT_TRAFFIC",
      title: "应用允许明文网络流量",
      detail: "Manifest 明确允许 cleartext traffic，敏感数据可能绕过 TLS。",
      recommendation: "设置 usesCleartextTraffic=false，并通过 Network Security Config 仅为必要域名配置例外。",
    })
  }
  if (/android:allowBackup\b[^\n]*0xffffffff/i.test(xmlTree)) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_BACKUP_ENABLED",
      title: "应用备份未关闭",
      detail: "应用数据可能进入系统备份或设备迁移流程；是否构成风险取决于数据分类和 Android 版本。",
      recommendation: "评估备份需求，并设置 allowBackup/dataExtractionRules 排除敏感数据。",
    })
  }
  if (/android:extractNativeLibs\b[^\n]*0xffffffff/i.test(xmlTree)) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_EXTRACT_NATIVE_LIBS",
      title: "应用显式允许提取 Native 库到可写目录",
      detail:
        "android:extractNativeLibs=\"true\" 会让系统把 .so 解压到应用可写目录；在旧 Android 上该目录可被应用自身改写，存在 .so 被替换/劫持的风险，并增大体积。",
      recommendation: "对 targetSdk ≥ 23 的应用移除该属性（默认即为 false），让系统直接从 APK 加载 .so；确需提取时仅针对必要库并做完整性校验。",
    })
  }
  if (!/android:networkSecurityConfig\b/i.test(xmlTree)) {
    findings.push({
      severity: "info",
      code: "NETWORK_SECURITY_CONFIG_NOT_DECLARED",
      title: "未声明 Network Security Config",
      detail: "这不一定是漏洞，但无法在 Manifest 层确认自定义信任锚、明文策略或调试覆盖。",
      recommendation: "如有精细网络安全策略，在源码中配置 networkSecurityConfig 并做证书轮换预案。",
    })
  }
  return findings
}

function axmlAttribute(element: AxmlElement | undefined, name: string): AxmlAttribute | undefined {
  if (!element) return undefined
  return element.attributes.find((attribute) =>
    attribute.name === name || attribute.name === `android:${name}`)
}

function findAxmlElement(elements: AxmlElement[], tag: string): AxmlElement | undefined {
  for (const element of elements) {
    if (element.tag === tag) return element
    const child = findAxmlElement(element.children, tag)
    if (child) return child
  }
  return undefined
}

function renderAxmlAsAaptTree(elements: AxmlElement[]): string {
  const lines: string[] = []
  const emit = (nodes: AxmlElement[], depth: number): void => {
    for (const node of nodes) {
      lines.push(`${"  ".repeat(depth)}E: ${node.tag}`)
      for (const attribute of node.attributes) {
        const indent = "  ".repeat(depth + 1)
        if (attribute.dataType === 0x03) {
          lines.push(`${indent}A: ${attribute.name}="${attribute.value.replaceAll('"', '\\"')}"`)
        } else {
          lines.push(
            `${indent}A: ${attribute.name}=(type 0x${attribute.dataType.toString(16)})0x${attribute.data.toString(16)}`,
          )
        }
      }
      emit(node.children, depth + 1)
    }
  }
  emit(elements, 0)
  return lines.join("\n")
}

export interface AxmlManifestAudit {
  findings: Finding[]
  metadata: ApkMetadata
  tree: AxmlElement[]
  xmlTree: string
}

// Parse AndroidManifest.xml directly from compiled AXML. The normalized dump
// matches the subset consumed by the existing manifest auditors, so aapt and
// direct-AXML modes share component, permission, and meta-data rules.
export function auditManifestAxml(bytes: Uint8Array): AxmlManifestAudit {
  const tree = parseAxmlElements(bytes)
  const manifest = findAxmlElement(tree, "manifest")
  if (!manifest) throw new Error("AXML manifest root not found")
  const xmlTree = renderAxmlAsAaptTree(tree)
  const usesSdk = findAxmlElement(tree, "uses-sdk")
  const metadata: ApkMetadata = {}
  const metadataAttrs: Array<[keyof ApkMetadata, AxmlAttribute | undefined]> = [
    ["packageName", axmlAttribute(manifest, "package")],
    ["versionName", axmlAttribute(manifest, "versionName")],
    ["versionCode", axmlAttribute(manifest, "versionCode")],
    ["minSdk", axmlAttribute(usesSdk, "minSdkVersion")],
    ["targetSdk", axmlAttribute(usesSdk, "targetSdkVersion")],
  ]
  for (const [key, attribute] of metadataAttrs) {
    if (attribute && attribute.value.length > 0) metadata[key] = attribute.value
  }

  const findings = manifestFindings(xmlTree)
  findings.push(...parseExportedComponents(xmlTree, metadata.packageName))
  findings.push(...buildPermissionFindings(
    parseUsesPermissions(xmlTree),
    parseCustomPermissions(xmlTree),
    "MANIFEST",
  ))
  findings.push(...metaDataSecretFindings(parseMetaDataValues(xmlTree), "MANIFEST"))
  return { findings, metadata, tree, xmlTree }
}

// Google Play policy baseline for the minimum targetSdk. Bump annually as policy advances.
export const POLICY_TARGET_SDK_BASELINE = 34

// Baseline for a meaningful security posture on modern devices. Below 23 the app
// installs with ALL permissions granted (no runtime permission model). Below 21 it
// runs on Android versions that no longer receive security patches.
export const POLICY_MIN_SDK_BASELINE = 23

interface XmlElement {
  tag: string
  attrs: Map<string, string>
}

// Parse an aapt `dump xmltree` text dump into a flat list of elements, each with its
// attributes. String attribute values are captured verbatim; typed (hex) values are
// captured as their raw hex token (e.g. "0x2") so callers can map them to enums.
export function parseXmlTreeElements(xmlTree: string): XmlElement[] {
  const stack: Array<{ indent: number; element: XmlElement }> = []
  const elements: XmlElement[] = []
  for (const rawLine of xmlTree.split(/\r?\n/)) {
    const trimmed = rawLine.trim()
    if (!trimmed) continue
    const indent = rawLine.length - rawLine.trimStart().length
    if (trimmed.startsWith("E:")) {
      while (stack.length > 0 && stack[stack.length - 1]!.indent >= indent) stack.pop()
      const tag = /^E:\s*([\w.-]+)/.exec(trimmed)?.[1] ?? ""
      const element: XmlElement = { tag, attrs: new Map() }
      elements.push(element)
      stack.push({ indent, element })
      continue
    }
    if (!trimmed.startsWith("A:")) continue
    while (stack.length > 0 && stack[stack.length - 1]!.indent >= indent) stack.pop()
    const owner = stack[stack.length - 1]
    if (!owner) continue
    const attrName = /^A:\s*([A-Za-z0-9_:.-]+)/.exec(trimmed)?.[1] ?? ""
    const stringValue = /="([^"]*)"/.exec(trimmed)?.[1]
    const typedHex = /=\(type 0x[0-9a-f]+\)(0x[0-9a-f]+)/i.exec(trimmed)?.[1]
    const value = stringValue ?? typedHex
    if (attrName && value !== undefined) owner.element.attrs.set(attrName, value)
  }
  return elements
}

export function parseUsesPermissions(xmlTree: string): string[] {
  return parseXmlTreeElements(xmlTree)
    .filter((element) => element.tag === "uses-permission" || element.tag === "uses-permission-sdk-23")
    .map((element) => element.attrs.get("android:name"))
    .filter((name): name is string => typeof name === "string" && name.length > 0)
}

const PROTECTION_LEVEL_BY_HEX: Record<string, string> = {
  "0x0": "normal",
  "0x1": "dangerous",
  "0x2": "signature",
  "0x3": "signatureOrSystem",
  "0x12": "signature|privileged",
}

export function parseCustomPermissions(xmlTree: string): CustomPermission[] {
  return parseXmlTreeElements(xmlTree)
    .filter((element) => element.tag === "permission")
    .map((element) => {
      const name = element.attrs.get("android:name") ?? ""
      const raw = (element.attrs.get("android:protectionLevel") ?? "").toLowerCase()
      const protectionLevel = PROTECTION_LEVEL_BY_HEX[raw] ?? raw
      return { name, protectionLevel }
    })
    .filter((entry) => entry.name.length > 0)
}

export function parseMetaDataValues(xmlTree: string): Array<{ name: string; value: string }> {
  return parseXmlTreeElements(xmlTree)
    .filter((element) => element.tag === "meta-data")
    .map((element) => ({
      name: element.attrs.get("android:name") ?? "",
      value: element.attrs.get("android:value") ?? "",
    }))
    .filter((entry) => entry.value.length > 0)
}

// Scan <meta-data android:value> entries for hardcoded secrets (API keys, tokens).
export function metaDataSecretFindings(
  entries: Array<{ name: string; value: string }>,
  codePrefix: "MANIFEST" | "SOURCE",
): Finding[] {
  const hits = scanStringsForSecrets(entries.map((entry) => `${entry.name}=${entry.value}`))
  if (hits.length === 0) return []
  return [{
    severity: hits.some((hit) => hit.confidence === "confirmed" || hit.confidence === "high") ? "high" : "medium",
    confidence: strongestSecretConfidence(hits),
    code: `${codePrefix}_METADATA_HARDCODED_SECRET`,
    title: "Manifest meta-data 中疑似硬编码密钥",
    detail: `在 <meta-data> 值中匹配到通过格式与熵阈值校验的凭据候选：${hits.map((hit) => `${hit.label}(${hit.preview})`).join("、")}。通用赋值按中等置信度报告，请先核验再轮换。`,
    recommendation: "不要把 API Key/Token 明文写进 Manifest；改用服务端下发、加密存储或受限的构建期注入，并轮换已泄露的凭据。",
    evidence: hits.map((hit) => hit.preview).join(", ").slice(0, 300),
  }]
}

// Compliance findings derived from already-parsed metadata + entry summary. Pure.
export function complianceFindings(
  metadata: ApkMetadata,
  summary: ApkEntrySummary,
  aaptAvailable: boolean,
): Finding[] {
  const findings: Finding[] = []
  const targetSdk = metadata.targetSdk ? Number.parseInt(metadata.targetSdk, 10) : undefined
  if (targetSdk !== undefined && !Number.isNaN(targetSdk) && targetSdk < POLICY_TARGET_SDK_BASELINE) {
    findings.push({
      severity: "medium",
      code: "COMPLIANCE_TARGET_SDK_OUTDATED",
      title: `targetSdkVersion 低于政策基线（${targetSdk} < ${POLICY_TARGET_SDK_BASELINE}）`,
      detail: `targetSdk=${targetSdk} 低于当前 Google Play 上架基线 ${POLICY_TARGET_SDK_BASELINE}，会失去新版系统的默认安全加固（分区存储、权限收敛、隐式 PendingIntent 限制等），且可能无法上架/更新。`,
      recommendation: `将 targetSdkVersion 提升至 ${POLICY_TARGET_SDK_BASELINE} 及以上并做兼容性回归测试。`,
      evidence: `targetSdkVersion=${targetSdk}`,
    })
  } else if (!aaptAvailable) {
    findings.push({
      severity: "low",
      code: "COMPLIANCE_MISSING_MANIFEST_SDK",
      title: "无法判定 targetSdk 合规性（aapt 缺失）",
      detail: "未读取到 Manifest 的 targetSdkVersion，无法评估上架政策与系统加固基线。",
      recommendation: "安装 Android SDK Build Tools 后重试，或用 APK Analyzer 确认 targetSdkVersion。",
    })
  }

  const archs = summary.nativeArchitectures
  if (archs.includes("armeabi-v7a") && !archs.includes("arm64-v8a")) {
    findings.push({
      severity: "high",
      code: "COMPLIANCE_MISSING_ARM64",
      title: "含 32 位原生库但缺少 arm64-v8a",
      detail: `发现 32 位原生库（${archs.join(", ")}）却没有 arm64-v8a。Google Play 要求 64 位支持，纯 32 位应用无法在仅 64 位设备运行且无法上架。`,
      recommendation: "为所有原生库补齐 arm64-v8a ABI 后重新构建。",
      evidence: archs.join(", "),
    })
  }

  const minSdk = metadata.minSdk ? Number.parseInt(metadata.minSdk, 10) : undefined
  if (minSdk !== undefined && !Number.isNaN(minSdk)) {
    findings.push(...buildMinSdkFinding(minSdk, "COMPLIANCE"))
  }
  return findings
}

// Shared minSdk baseline check used by both the APK (complianceFindings) and the
// source manifest audit (auditManifest). `codePrefix` keeps APK vs SOURCE codes distinct.
export function buildMinSdkFinding(minSdk: number, codePrefix: string): Finding[] {
  if (minSdk < 21) {
    return [{
      severity: "medium",
      code: `${codePrefix}_MIN_SDK_OUTDATED`,
      title: `minSdkVersion 过低（${minSdk} < 21）`,
      detail: `minSdk=${minSdk} 低于 21，会运行在极旧、不再接收安全补丁的 Android 上，缺失运行时权限模型、明文流量默认限制等多层防护。`,
      recommendation: "尽量提升 minSdkVersion 至 21 及以上，并对旧机型制定降级/退出策略。",
      evidence: `minSdkVersion=${minSdk}`,
    }]
  }
  if (minSdk < POLICY_MIN_SDK_BASELINE) {
    return [{
      severity: "low",
      code: `${codePrefix}_MIN_SDK_OUTDATED`,
      title: `minSdkVersion 未启用运行时权限模型（${minSdk} < ${POLICY_MIN_SDK_BASELINE}）`,
      detail: `minSdk=${minSdk} 低于 ${POLICY_MIN_SDK_BASELINE}，应用安装即授予全部权限，没有 Android 6.0 的运行时权限弹窗与按需授权，隐私暴露面更大。`,
      recommendation: `将 minSdkVersion 提升至 ${POLICY_MIN_SDK_BASELINE} 以启用运行时权限模型，并适配权限申请的运行时流程。`,
      evidence: `minSdkVersion=${minSdk}`,
    }]
  }
  return []
}

const COMPONENT_TAGS = new Set(["activity", "activity-alias", "service", "receiver", "provider"])
// Signature/privileged platform permissions: only the OS or apps signed with the platform key
// can hold them, so an exported component guarded by one is effectively unreachable by 3rd parties.
const KNOWN_PRIVILEGED_PERMISSIONS = new Set([
  "android.permission.DUMP",
  "android.permission.BIND_JOB_SERVICE",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
  "android.permission.BIND_DEVICE_ADMIN",
  "android.permission.BIND_VPN_SERVICE",
])

interface ParsedComponent {
  tag: string
  indent: number
  name: string | undefined
  exported: boolean | undefined
  permission: string | undefined
  hasMain: boolean
  hasLauncher: boolean
  hasBrowsable: boolean
  hasHttpScheme: boolean
  autoVerify: boolean
  taskAffinity: string | undefined
  grantUriPermissions: boolean
}

// Enumerate exported components from an aapt xmltree dump and classify their exposure. The tree
// is indentation-structured: `E: <tag>` open elements, `A: android:<attr>...` attributes owned by
// the nearest enclosing element. Length/format tolerant line parser.
// `packageName` (when known) lets us flag custom (non-package) taskAffinity values.
export function parseExportedComponents(xmlTree: string, packageName?: string): Finding[] {
  const stack: Array<{ tag: string; indent: number; component: ParsedComponent | undefined }> = []
  const components: ParsedComponent[] = []

  const nearestComponent = (): ParsedComponent | undefined => {
    for (let i = stack.length - 1; i >= 0; i -= 1) {
      if (stack[i]!.component) return stack[i]!.component
    }
    return undefined
  }

  for (const rawLine of xmlTree.split(/\r?\n/)) {
    const trimmed = rawLine.trim()
    if (!trimmed) continue
    const indent = rawLine.length - rawLine.trimStart().length

    if (trimmed.startsWith("E:")) {
      while (stack.length > 0 && stack[stack.length - 1]!.indent >= indent) stack.pop()
      const tag = /^E:\s*([\w.-]+)/.exec(trimmed)?.[1] ?? ""
      let component: ParsedComponent | undefined
      if (COMPONENT_TAGS.has(tag)) {
        component = {
          tag,
          indent,
          name: undefined,
          exported: undefined,
          permission: undefined,
          hasMain: false,
          hasLauncher: false,
          hasBrowsable: false,
          hasHttpScheme: false,
          autoVerify: false,
          taskAffinity: undefined,
          grantUriPermissions: false,
        }
        components.push(component)
      }
      stack.push({ tag, indent, component })
      continue
    }
    if (!trimmed.startsWith("A:")) continue

    while (stack.length > 0 && stack[stack.length - 1]!.indent >= indent) stack.pop()
    const owner = stack[stack.length - 1]
    if (!owner) continue
    const attrName = /^A:\s*([A-Za-z0-9_:.-]+)/.exec(trimmed)?.[1] ?? ""
    const stringValue = /="([^"]*)"/.exec(trimmed)?.[1]
    const typedHex = /=\(type 0x[0-9a-f]+\)(0x[0-9a-f]+)/i.exec(trimmed)?.[1]

    if (attrName === "android:name") {
      if (owner.tag === "action" && stringValue === "android.intent.action.MAIN") {
        const target = nearestComponent()
        if (target) target.hasMain = true
      } else if (owner.tag === "category" && stringValue === "android.intent.category.LAUNCHER") {
        const target = nearestComponent()
        if (target) target.hasLauncher = true
      } else if (owner.tag === "category" && stringValue === "android.intent.category.BROWSABLE") {
        const target = nearestComponent()
        if (target) target.hasBrowsable = true
      } else if (owner.component && stringValue !== undefined) {
        owner.component.name = stringValue
      }
    } else if (attrName === "android:exported" && owner.component && typedHex !== undefined) {
      owner.component.exported = /^0x0*f+$/i.test(typedHex)
    } else if (attrName === "android:permission" && owner.component && stringValue !== undefined) {
      owner.component.permission = stringValue
    } else if (attrName === "android:taskAffinity" && owner.component && stringValue !== undefined) {
      owner.component.taskAffinity = stringValue
    } else if (attrName === "android:grantUriPermissions" && owner.component && typedHex !== undefined) {
      owner.component.grantUriPermissions = /^0x0*f+$/i.test(typedHex)
    } else if (attrName === "android:autoVerify" && owner.tag === "intent-filter" && typedHex !== undefined) {
      const target = nearestComponent()
      if (target && /^0x0*f+$/i.test(typedHex)) target.autoVerify = true
    } else if (attrName === "android:scheme" && owner.tag === "data" && stringValue !== undefined) {
      if (stringValue === "http" || stringValue === "https") {
        const target = nearestComponent()
        if (target) target.hasHttpScheme = true
      }
    }
  }

  const findings: Finding[] = []
  const exported = components.filter((component) => component.exported === true)
  if (exported.length === 0) return findings

  const label = (component: ParsedComponent): string => component.name ?? `<${component.tag}>`
  const launchers: string[] = []
  const protectedComponents: ParsedComponent[] = []
  const unprotected: ParsedComponent[] = []
  for (const component of exported) {
    const isLauncher =
      (component.tag === "activity" || component.tag === "activity-alias") && component.hasMain && component.hasLauncher
    if (isLauncher) launchers.push(label(component))
    else if (component.permission) protectedComponents.push(component)
    else unprotected.push(component)
  }

  if (protectedComponents.length > 0) {
    findings.push({
      severity: "info",
      code: "MANIFEST_EXPORTED_COMPONENT_PROTECTED",
      title: "存在受权限保护的导出组件（属预期，非风险）",
      detail:
        "为什么标为信息而非风险：这些组件虽 exported=true，但都声明了 android:permission，调用方必须先持有对应权限才能触达。" +
        `其中受签名/特权级权限（如 android.permission.DUMP）保护的组件普通第三方应用无法触发，属良性。典型如 androidx.profileinstaller.ProfileInstallReceiver 由 AndroidX Baseline Profile 库自动合入、以 DUMP 权限保护，是框架预期行为。受保护导出组件：${protectedComponents
          .map((component) => `${label(component)}${component.permission && KNOWN_PRIVILEGED_PERMISSIONS.has(component.permission) ? "(特权权限)" : `(${component.permission})`}`)
          .join("、")}。`,
      recommendation: "无需处理；如需进一步收敛，可确认每个权限的 protectionLevel 是否满足最小暴露面需求。",
      evidence: protectedComponents.map(label).join(", ").slice(0, 300),
    })
  }
  if (unprotected.length > 0) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_EXPORTED_COMPONENT_UNPROTECTED",
      title: "存在无权限保护的导出组件",
      detail:
        "为什么：这些组件 exported=true 且未声明 android:permission，也不是 launcher 入口，任意第三方应用/ADB 都可向其发送 Intent。所以：可能造成越权调用、组件劫持或数据泄露。开发者需自行：确认它们确实需要对外暴露；若否则设为 exported=false，或用自定义 signature 级权限保护。" +
        `无保护导出组件：${unprotected.map(label).join("、")}。`,
      recommendation: "对不需要跨应用调用的组件设置 android:exported=\"false\"；确需导出的加 signature 级 android:permission 或做调用方校验。",
      evidence: unprotected.map(label).join(", ").slice(0, 300),
    })
  }
  findings.push({
    severity: "info",
    code: "MANIFEST_EXPORTED_SURFACE_OVERVIEW",
    title: "导出组件暴露面概览",
    detail:
      `共发现 ${exported.length} 个导出组件：launcher 入口 ${launchers.length} 个（${launchers.join("、") || "无"}）、受权限保护 ${protectedComponents.length} 个、无保护 ${unprotected.length} 个。` +
      (unprotected.length === 0
        ? "结论：除 launcher 入口外，其余导出组件均受权限约束，暴露面收敛良好。"
        : "结论：存在无保护导出组件，建议按上条收敛。"),
    recommendation: "保持仅 launcher 与必要组件导出，其余 exported=false。",
  })

  // Deep-link & task-hijack surface (Tier1-D).
  const deeplinkNoAutoVerify = exported.filter(
    (component) => component.hasHttpScheme && !component.autoVerify,
  )
  if (deeplinkNoAutoVerify.length > 0) {
    findings.push({
      severity: "low",
      code: "MANIFEST_DEEPLINK_NO_AUTOVERIFY",
      title: "http/https 深链未启用 App Links 校验",
      detail:
        "以下 Activity 声明了 http/https scheme 的 intent-filter 却未设置 android:autoVerify=\"true\"，无法成为可信 App Links，" +
        `其他应用可注册相同链接进行劫持：${deeplinkNoAutoVerify.map(label).join("、")}。`,
      recommendation: "为对外深链设置 autoVerify=\"true\" 并部署 assetlinks.json（Digital Asset Links），使系统校验域名归属。",
      evidence: deeplinkNoAutoVerify.map(label).join(", ").slice(0, 300),
    })
  }
  const browsableUnprotected = exported.filter(
    (component) =>
      component.hasBrowsable &&
      !component.permission &&
      (component.tag === "activity" || component.tag === "activity-alias"),
  )
  if (browsableUnprotected.length > 0) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_BROWSABLE_EXPORTED_ACTIVITY",
      title: "存在可被浏览器唤起且无权限保护的导出 Activity",
      detail:
        "以下 Activity 带 BROWSABLE 分类且 exported=true、无 android:permission，网页/其他应用可直接构造链接唤起并传入参数，" +
        `是深链参数注入与未授权跳转的常见入口：${browsableUnprotected.map(label).join("、")}。`,
      recommendation: "对 BROWSABLE 入口做严格的 Intent 数据校验（scheme/host/path 白名单），避免直接信任外部传入参数。",
      evidence: browsableUnprotected.map(label).join(", ").slice(0, 300),
    })
  }
  const customTaskAffinity = exported.filter(
    (component) =>
      component.taskAffinity !== undefined &&
      component.taskAffinity.length > 0 &&
      component.taskAffinity !== packageName,
  )
  if (customTaskAffinity.length > 0) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_CUSTOM_TASK_AFFINITY",
      title: "导出组件使用了自定义 taskAffinity",
      detail:
        "以下导出组件设置了非包名的 android:taskAffinity，可能被恶意应用利用进行任务栈劫持（StrandHogg 类攻击），伪装界面窃取输入：" +
        `${customTaskAffinity.map((component) => `${label(component)}(${component.taskAffinity})`).join("、")}。`,
      recommendation: "除非有明确多任务需求，移除自定义 taskAffinity（留空以继承包名），或将相关 Activity 设为 exported=false。",
      evidence: customTaskAffinity.map(label).join(", ").slice(0, 300),
    })
  }
  const grantUriProviders = exported.filter(
    (component) => component.tag === "provider" && component.grantUriPermissions && !component.permission,
  )
  if (grantUriProviders.length > 0) {
    findings.push({
      severity: "medium",
      code: "MANIFEST_PROVIDER_GRANT_URI",
      title: "导出 ContentProvider 开启了 grantUriPermissions",
      detail:
        "以下 exported 的 ContentProvider 开启了 android:grantUriPermissions 且无 android:permission，调用方可通过临时 URI 授权访问本不应暴露的数据：" +
        `${grantUriProviders.map(label).join("、")}。`,
      recommendation: "为 provider 设置 exported=false 或加读写权限；确需共享时用 <grant-uri-permission> 精确限定 path，并校验调用来源。",
      evidence: grantUriProviders.map(label).join(", ").slice(0, 300),
    })
  }
  return findings
}

// Classify the Content-Security-Policy of a WebView index.html:
//   "unsafe" -> CSP present but allows 'unsafe-inline' / 'unsafe-eval'
//   "absent" -> no CSP <meta> at all
//   "safe"   -> CSP present without unsafe directives
export function classifyCsp(html: string): "unsafe" | "absent" | "safe" {
  const metaTag = /<meta[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/i.exec(html)?.[0]
  if (!metaTag) return "absent"
  const content =
    /content\s*=\s*"([^"]*)"/i.exec(metaTag)?.[1] ??
    /content\s*=\s*'([^']*)'/i.exec(metaTag)?.[1] ??
    ""
  return /'unsafe-inline'|'unsafe-eval'/i.test(content) ? "unsafe" : "safe"
}

// True when capacitor.plugins.json registers @capacitor/clipboard.
export function detectClipboardPlugin(pluginsJson: string): boolean {
  try {
    const parsed = JSON.parse(pluginsJson)
    if (Array.isArray(parsed)) {
      return parsed.some((entry) => typeof entry?.pkg === "string" && entry.pkg === "@capacitor/clipboard")
    }
  } catch {
    // fall through to substring match
  }
  return /@capacitor\/clipboard/.test(pluginsJson)
}

export function cspFindings(csp: "unsafe" | "absent" | "safe", codePrefix: "WEBVIEW" | "SOURCE_WEBVIEW"): Finding[] {
  if (csp === "unsafe") {
    return [{
      severity: "low",
      code: `${codePrefix}_CSP_UNSAFE_INLINE`,
      title: "WebView 内容安全策略允许 unsafe-inline/unsafe-eval",
      detail:
        "为什么：index.html 的 Content-Security-Policy 含 'unsafe-inline' 或 'unsafe-eval'，会放行内联脚本/样式与动态求值，显著削弱对 XSS 的防护——一旦有注入点，攻击脚本可直接执行。所以：混合应用的 WebView 若加载任何外部/用户可控内容，风险被放大。开发者需自行（DroidSeal 不改前端资源）：用 nonce 或 hash 白名单替代 unsafe-inline，将内联脚本/样式拆到独立文件，移除 eval。",
      recommendation: "在 web 构建期改用基于 nonce/hash 的 CSP，去除 'unsafe-inline'/'unsafe-eval'；DroidSeal 的 APK 后处理不会修改前端资源。",
      evidence: "assets/public/index.html",
    }]
  }
  if (csp === "absent") {
    return [{
      severity: "info",
      code: `${codePrefix}_CSP_ABSENT`,
      title: "WebView 未声明 Content-Security-Policy",
      detail:
        "为什么：index.html 未发现 CSP <meta>，WebView 默认不限制脚本来源与内联执行。所以：无法在前端层缓解 XSS/注入。开发者需自行：为 WebView 内容配置最小可用的 CSP（基于 nonce/hash 的 script-src），仅放行必要来源。",
      recommendation: "为前端添加基于 nonce/hash 的 CSP meta 或响应头；DroidSeal 不会修改前端资源。",
      evidence: "assets/public/index.html",
    }]
  }
  return []
}

export function clipboardFinding(code: "HYBRID_SENSITIVE_PLUGIN_CLIPBOARD" | "SOURCE_SENSITIVE_PLUGIN_CLIPBOARD"): Finding {
  return {
    severity: "info",
    code,
    title: "启用了剪贴板插件（@capacitor/clipboard）",
    detail:
      "为什么：capacitor.plugins.json 注册了 @capacitor/clipboard，WebView 前端因此获得读写系统剪贴板的能力。所以：若前端存在注入点或加载不可信内容，剪贴板中的敏感数据（如复制的口令、验证码）可能被读取，构成暴露面。开发者需自行：确认业务确实需要剪贴板；若非必需则移除该插件以减小攻击面，必要时只保留写入、避免读取。",
    recommendation: "评估剪贴板读写是否必需；非必需则从 Capacitor 依赖与 capacitor.plugins.json 移除该插件。",
    evidence: "capacitor.plugins.json",
  }
}

export async function sha256File(filePath: string): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256")
  for await (const chunk of Bun.file(filePath).stream()) {
    hasher.update(chunk)
  }
  return hasher.digest("hex")
}

// Per-file byte cap so a single crafted entry cannot exhaust memory during scanning.
const MAX_SCAN_ENTRY_BYTES = 64 * 1024 * 1024
const MAX_NATIVE_LIBS_SCANNED = 24
const MAX_ASSET_ENTRIES_SCANNED = 400
const MAX_ASSET_ENTRY_BYTES = 4 * 1024 * 1024
const SCANNABLE_ASSET_RE = /^(?:assets|res\/raw)\/.*\.(?:json|xml|txt|properties|js|ts|env|cfg|conf|ini|yaml|yml|pem|key|p12|keystore|jks|html|htm|md)$/i

// F: parse each classes*.dex string pool and run the heuristic DEX scan on the
// combined, de-duplicated set of strings. Parse failures degrade to an info note.
async function scanDexFiles(
  apkPath: string,
  dexFiles: string[],
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  if (dexFiles.length === 0) return []
  onProgress?.("扫描 DEX 字符串池（密钥、弱加密、动态加载等启发式）")
  const combined = new Set<string>()
  let truncated = false
  let failed = 0
  for (const name of dexFiles) {
    const bytes = await extractApkEntryBytes(apkPath, name).catch(() => undefined)
    if (!bytes || bytes.length > MAX_SCAN_ENTRY_BYTES) {
      if (bytes && bytes.length > MAX_SCAN_ENTRY_BYTES) truncated = true
      else failed += 1
      continue
    }
    try {
      const result = extractDexStrings(bytes)
      if (result.truncated) truncated = true
      for (const value of result.strings) combined.add(value)
    } catch {
      failed += 1
    }
  }
  const findings = scanDex([...combined])
  const sdks = detectSdkPackages(combined)
  if (sdks.length > 0) {
    findings.push({
      severity: "info",
      code: "SUPPLYCHAIN_SDK_INVENTORY",
      title: "识别到的第三方 SDK（DEX 清单）",
      detail:
        `从 DEX 类型描述符识别到以下第三方 SDK（启发式，不做漏洞比对）：${sdks.join("、")}。用于供应链梳理，请自行核对版本与隐私合规。`,
      recommendation: "维护第三方 SDK 清单，关注其权限/数据采集行为与已知漏洞公告，及时升级。",
      evidence: sdks.join(", "),
    })
  }
  if (truncated || failed > 0) {
    findings.push({
      severity: "info",
      code: "DEX_SCAN_INCOMPLETE",
      title: "DEX 扫描未完整覆盖",
      detail:
        `部分 DEX 未能完整解析（超大或格式异常，失败 ${failed} 个${truncated ? "，另有字符串数量达到上限被截断" : ""}）。可能是加壳、DEX 加密或多 DEX 超限，结果为部分覆盖。`,
      recommendation: "如为主动加壳属预期；否则用 Android Studio APK Analyzer 复核 DEX。",
    })
  }
  return findings
}

// G: parse a representative subset of native libraries and report ELF hardening gaps.
async function scanNativeLibraries(
  apkPath: string,
  nativeLibraries: string[],
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  if (nativeLibraries.length === 0) return []
  onProgress?.("扫描 Native 库（ELF 加固：NX/RELRO/Canary + 明文密钥）")
  // De-duplicate by library base name so multi-arch copies are scanned once.
  const byBaseName = new Map<string, string>()
  for (const name of nativeLibraries) {
    const base = name.split("/").pop() ?? name
    if (!byBaseName.has(base)) byBaseName.set(base, name)
  }
  const findings: Finding[] = []
  let failed = 0
  let scanned = 0
  for (const entryName of byBaseName.values()) {
    if (scanned >= MAX_NATIVE_LIBS_SCANNED) break
    const bytes = await extractApkEntryBytes(apkPath, entryName).catch(() => undefined)
    if (!bytes || bytes.length > MAX_SCAN_ENTRY_BYTES) {
      failed += 1
      continue
    }
    try {
      const hardening = analyzeElf(bytes)
      const base = entryName.split("/").pop() ?? entryName
      findings.push(...buildSoFindings(base, hardening))
      const secretHits = scanStringsForSecrets(extractAsciiStrings(bytes))
      if (secretHits.length > 0) {
        findings.push({
          severity: secretHits.some((hit) => hit.confidence === "confirmed" || hit.confidence === "high") ? "high" : "medium",
          confidence: strongestSecretConfidence(secretHits),
          code: "SO_HARDCODED_SECRET",
          title: "Native 库中疑似硬编码密钥/凭据",
          detail:
            `在 ${base} 的可打印字符串中发现通过格式与熵阈值校验的密钥候选：` +
            secretHits.map((hit) => `${hit.label}(${hit.preview})`).join("、") + "。放在 .so 内的密钥同样可被静态提取。",
          recommendation: "将密钥移出客户端；确需本地存储时使用 Android Keystore 并做完整性校验。",
          evidence: `${base}: ${secretHits.map((hit) => hit.code).join(", ")}`,
        })
      }
      scanned += 1
    } catch {
      failed += 1
    }
  }
  if (failed > 0) {
    findings.push({
      severity: "info",
      code: "SO_SCAN_INCOMPLETE",
      title: "Native 库扫描未完整覆盖",
      detail: `有 ${failed} 个原生库不是可解析的 ELF 或超出大小限制，已跳过。`,
      recommendation: "如为加壳/加密的 .so 属预期；否则确认库文件完整。",
    })
  }
  return findings
}

// F2: scan plaintext asset / res/raw entries for hardcoded secrets and private keys.
async function scanEmbeddedAssets(
  apkPath: string,
  entries: ZipEntry[],
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  const candidates = entries
    .map((entry) => entry.name)
    .filter((name) => SCANNABLE_ASSET_RE.test(name))
    .slice(0, MAX_ASSET_ENTRIES_SCANNED)
  if (candidates.length === 0) return []
  onProgress?.("扫描 assets/res-raw 文本资源（硬编码密钥、私钥）")
  const decoder = new TextDecoder("utf-8", { fatal: false })
  const findings: Finding[] = []
  const secretEvidence: string[] = []
  const secretHits: ReturnType<typeof scanStringsForSecrets> = []
  const privateKeyFiles: string[] = []
  const seen = new Set<string>()
  for (const name of candidates) {
    const bytes = await extractApkEntryBytes(apkPath, name).catch(() => undefined)
    if (!bytes || bytes.length > MAX_ASSET_ENTRY_BYTES) continue
    const text = decoder.decode(bytes)
    if (containsPrivateKey(text)) privateKeyFiles.push(name)
    for (const hit of scanStringsForSecrets(text.split(/\r?\n/))) {
      if (hit.code === "PRIVATE_KEY_PEM") continue // reported once, below, with file-level confirmed evidence
      const key = `${hit.code}:${hit.preview}`
      if (seen.has(key)) continue
      seen.add(key)
      secretEvidence.push(`${name} → ${hit.label}(${hit.preview})`)
      secretHits.push(hit)
    }
  }
  if (privateKeyFiles.length > 0) {
    findings.push({
      severity: "critical",
      code: "ASSET_EMBEDDED_PRIVATE_KEY",
      title: "APK 资源内嵌入私钥",
      detail:
        `以下打包资源包含 PEM 私钥块：${privateKeyFiles.slice(0, 5).join("、")}。私钥随 APK 分发即视为完全泄露。`,
      recommendation: "立即从产物移除私钥并轮换对应密钥；客户端不应保存任何私钥。",
      evidence: privateKeyFiles.slice(0, 5).join(", "),
    })
  }
  if (secretEvidence.length > 0) {
    findings.push({
      severity: secretHits.some((hit) => hit.confidence === "confirmed" || hit.confidence === "high") ? "high" : "medium",
      confidence: strongestSecretConfidence(secretHits),
      code: "ASSET_HARDCODED_SECRET",
      title: "APK 资源内疑似硬编码密钥/凭据",
      detail:
        "在 assets/res-raw 文本资源中发现通过格式与熵阈值校验的密钥候选：" +
        secretEvidence.slice(0, 8).join("；") + "。",
      recommendation: "将密钥移出客户端资源，改由服务端保管或使用短期令牌；已泄露的立即轮换。",
      evidence: secretEvidence.slice(0, 8).join("; "),
    })
  }
  return findings
}

// Extract runs of printable ASCII (>=6 chars) from a binary buffer for secret scanning.
function extractAsciiStrings(bytes: Uint8Array, minLength = 6): string[] {
  const strings: string[] = []
  let current: number[] = []
  for (const byte of bytes) {
    if (byte >= 0x20 && byte < 0x7f) {
      current.push(byte)
    } else {
      if (current.length >= minLength) strings.push(String.fromCharCode(...current))
      current = []
    }
  }
  if (current.length >= minLength) strings.push(String.fromCharCode(...current))
  return strings
}

interface XmlResourceReference {
  value: string
  resourceId?: number
}

function configuredXmlReference(application: AxmlElement | undefined, name: string): XmlResourceReference | undefined {
  const attribute = axmlAttribute(application, name)
  if (!attribute) return undefined
  return {
    value: attribute.value,
    ...(attribute.dataType === 0x01 && attribute.data !== 0 ? { resourceId: attribute.data } : {}),
  }
}

async function auditApkConfiguredXmlResources(
  apkPath: string,
  entryNames: Set<string>,
  manifestTree: AxmlElement[],
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  const findings: Finding[] = []
  const application = findAxmlElement(manifestTree, "application")
  if (!application) return findings

  const nscRef = configuredXmlReference(application, "networkSecurityConfig")
  const fullBackupRef = configuredXmlReference(application, "fullBackupContent")
  const dataRulesRef = configuredXmlReference(application, "dataExtractionRules")
  const backupDisabled = axmlAttribute(application, "allowBackup")?.value === "false"
  findings.push(...auditBackupPolicy({
    backupDisabled,
    hasFullBackupContent: fullBackupRef !== undefined,
    hasDataExtractionRules: dataRulesRef !== undefined,
    evidence: "AndroidManifest.xml",
  }))

  if (!nscRef && backupDisabled) return findings
  const arscBytes = await extractApkEntryBytes(apkPath, "resources.arsc").catch(() => undefined)
  const xmlEntries = [...entryNames]
    .filter((name) => name !== "AndroidManifest.xml" && /\.xml$/i.test(name))
    .slice(0, 512)
  const bytesCache = new Map<string, Uint8Array | undefined>()
  const treeCache = new Map<string, AxmlElement[] | undefined>()

  const loadBytes = async (entryName: string): Promise<Uint8Array | undefined> => {
    if (!bytesCache.has(entryName)) {
      bytesCache.set(entryName, await extractApkEntryBytes(apkPath, entryName).catch(() => undefined))
    }
    return bytesCache.get(entryName)
  }
  const loadTree = async (entryName: string): Promise<AxmlElement[] | undefined> => {
    if (!treeCache.has(entryName)) {
      const bytes = await loadBytes(entryName)
      if (!bytes) treeCache.set(entryName, undefined)
      else {
        try {
          treeCache.set(entryName, parseAxmlElements(bytes))
        } catch {
          treeCache.set(entryName, undefined)
        }
      }
    }
    return treeCache.get(entryName)
  }
  const resolveEntries = async (reference: XmlResourceReference, expectedRoot: string): Promise<string[]> => {
    const direct = xmlResourceEntryName(reference.value)
    if (direct && entryNames.has(direct)) return [direct]
    if (reference.resourceId !== undefined && arscBytes) {
      const resolved = resolveArscFilePath(arscBytes, reference.resourceId)?.replaceAll("\\", "/")
      if (resolved && entryNames.has(resolved)) return [resolved]
    }

    const discovered: string[] = []
    for (const entryName of xmlEntries) {
      const tree = await loadTree(entryName)
      if (tree?.some((root) => root.tag === expectedRoot)) discovered.push(entryName)
    }
    return discovered
  }
  const unresolvedFinding = (reference: XmlResourceReference, kind: string): Finding => ({
    severity: "info",
    code: "APK_XML_RESOURCE_UNRESOLVED",
    title: `无法定位 APK 内的${kind}资源`,
    detail: `Manifest 引用了 ${reference.value}，但无法通过资源表或 XML 根节点定位对应文件；该项内容审计已安全降级。`,
    recommendation: "用 Android Studio APK Analyzer 复核该资源，或提供未做非标准资源加密的 APK。",
    evidence: reference.value,
  })

  if (nscRef) {
    onProgress?.("解析 APK 内 Network Security Config (AXML)")
    const entries = await resolveEntries(nscRef, "network-security-config")
    if (entries.length === 0) findings.push(unresolvedFinding(nscRef, "网络安全配置"))
    for (const entryName of entries) {
      const bytes = await loadBytes(entryName)
      if (bytes) findings.push(...auditApkNetworkSecurityConfig(bytes, entryName))
    }
  }

  if (!backupDisabled) {
    const refs: Array<[XmlResourceReference | undefined, string, string]> = [
      [fullBackupRef, "full-backup-content", "完整备份规则"],
      [dataRulesRef, "data-extraction-rules", "数据提取规则"],
    ]
    const auditedEntries = new Set<string>()
    for (const [reference, expectedRoot, label] of refs) {
      if (!reference) continue
      onProgress?.(`解析 APK 内${label} (AXML)`)
      const entries = await resolveEntries(reference, expectedRoot)
      if (entries.length === 0) findings.push(unresolvedFinding(reference, label))
      for (const entryName of entries) {
        if (auditedEntries.has(entryName)) continue
        auditedEntries.add(entryName)
        const tree = await loadTree(entryName)
        if (tree) findings.push(...auditBackupRulesXml(reconstructXml(tree), entryName))
      }
    }
  }
  return findings
}

export function apkSoftwareComponents(
  findings: readonly Finding[],
  nativeLibraries: readonly string[],
): SoftwareComponent[] {
  const components: SoftwareComponent[] = []
  const sdkNames = new Set<string>()
  for (const finding of findings) {
    if (finding.code !== "SUPPLYCHAIN_SDK_INVENTORY" || !finding.evidence) continue
    for (const name of finding.evidence.split(",").map((value) => value.trim()).filter(Boolean)) {
      sdkNames.add(name)
    }
  }
  for (const name of [...sdkNames].sort()) {
    components.push({
      kind: "sdk-family",
      name,
      resolution: "observed",
      scope: "runtime",
      evidence: [`DEX package family: ${name}`],
    })
  }

  const native = new Map<string, { paths: Set<string>; architectures: Set<string> }>()
  for (const entryPath of nativeLibraries) {
    const match = /^lib\/([^/]+)\/([^/]+\.so)$/i.exec(entryPath)
    if (!match) continue
    const architecture = match[1]!
    const name = match[2]!
    const current = native.get(name) ?? { paths: new Set<string>(), architectures: new Set<string>() }
    current.paths.add(entryPath)
    current.architectures.add(architecture)
    native.set(name, current)
  }
  for (const [name, observed] of [...native.entries()].sort(([left], [right]) => left.localeCompare(right))) {
    components.push({
      kind: "native-library",
      name,
      resolution: "observed",
      scope: "runtime",
      evidence: [...observed.paths].sort(),
      architectures: [...observed.architectures].sort(),
    })
  }
  return components
}

export async function auditApk(
  apkPath: string,
  toolchain: Toolchain,
  onProgress?: (message: string) => void,
): Promise<SecurityAudit> {
  onProgress?.("读取 APK ZIP 中央目录")
  const entries = await parseZipEntries(apkPath)
  const { summary, findings } = summarizeEntries(entries)
  const metadata: ApkMetadata = { sha256: await sha256File(apkPath) }
  const rawOutputs: string[] = []

  const entryNames = new Set(entries.map((entry) => entry.name))
  let directManifest: AxmlManifestAudit | undefined
  const manifestBytes = await extractApkEntryBytes(apkPath, "AndroidManifest.xml").catch(() => undefined)
  if (manifestBytes) {
    try {
      onProgress?.("直接解析 APK 二进制 Manifest (AXML)")
      directManifest = auditManifestAxml(manifestBytes)
      Object.assign(metadata, directManifest.metadata)
      findings.push(...directManifest.findings)
      findings.push(...(await auditApkConfiguredXmlResources(
        apkPath,
        entryNames,
        directManifest.tree,
        onProgress,
      )))
      rawOutputs.push(`[direct AXML]\n${directManifest.xmlTree}`)
    } catch {
      directManifest = undefined
    }
  }

  if (toolchain.aapt.path) {
    onProgress?.("使用 aapt 读取包名、版本与二进制 Manifest")
    const badging = await runProcess({
      command: toolchain.aapt.path,
      args: ["dump", "badging", apkPath],
      cwd: path.dirname(apkPath),
      timeoutMs: 60_000,
    })
    if (badging.exitCode === 0) {
      Object.assign(metadata, parseBadging(badging.stdout))
      rawOutputs.push(badging.stdout)
    } else {
      findings.push({
        severity: "medium",
        code: "AAPT_BADGING_FAILED",
        title: "aapt 无法读取 APK 元数据",
        detail: badging.stderr.trim() || `aapt 退出码 ${badging.exitCode}`,
        recommendation: "确认 APK 未损坏，并尝试与目标 compileSdk 匹配的新版 Build Tools。",
      })
    }

    const xmlTree = await runProcess({
      command: toolchain.aapt.path,
      args: ["dump", "xmltree", apkPath, "AndroidManifest.xml"],
      cwd: path.dirname(apkPath),
      timeoutMs: 60_000,
    })
    if (xmlTree.exitCode === 0) {
      if (!directManifest) {
        findings.push(...manifestFindings(xmlTree.stdout))
        findings.push(...parseExportedComponents(xmlTree.stdout, metadata.packageName))
        findings.push(...buildPermissionFindings(
          parseUsesPermissions(xmlTree.stdout),
          parseCustomPermissions(xmlTree.stdout),
          "MANIFEST",
        ))
        findings.push(...metaDataSecretFindings(parseMetaDataValues(xmlTree.stdout), "MANIFEST"))
      }
      rawOutputs.push(xmlTree.stdout)
    } else if (!directManifest) {
      findings.push({
        severity: "medium",
        code: "AAPT_MANIFEST_FAILED",
        title: "aapt 无法解析二进制 Manifest",
        detail: xmlTree.stderr.trim() || `aapt 退出码 ${xmlTree.exitCode}`,
        recommendation: "用 Android Studio APK Analyzer 复核 Manifest。",
      })
    }
  } else if (!directManifest) {
    findings.push({
      severity: "low",
      code: "AAPT_NOT_AVAILABLE",
      title: "未找到 aapt，Manifest 深度审计已降级",
      detail: "ZIP 结构审计已完成，但无法读取二进制 Manifest 中的安全属性。",
      recommendation: "安装 Android SDK Build Tools 或设置 ANDROID_SDK_ROOT 后重试。",
    })
  }

  findings.push(...complianceFindings(metadata, summary, Boolean(toolchain.aapt.path || directManifest)))

  // Hybrid (Capacitor/Cordova) WebView asset checks. Absent entries => not a hybrid app => skipped.
  onProgress?.("检查混合应用 WebView 资源（CSP、剪贴板插件）")
  const decoder = new TextDecoder("utf-8", { fatal: false })
  const indexHtmlBytes =
    (await extractApkEntryBytes(apkPath, "assets/public/index.html").catch(() => undefined)) ??
    (await extractApkEntryBytes(apkPath, "assets/www/index.html").catch(() => undefined))
  if (indexHtmlBytes) {
    findings.push(...cspFindings(classifyCsp(decoder.decode(indexHtmlBytes)), "WEBVIEW"))
  }
  const pluginsBytes = await extractApkEntryBytes(apkPath, "assets/capacitor.plugins.json").catch(() => undefined)
  if (pluginsBytes && detectClipboardPlugin(decoder.decode(pluginsBytes))) {
    findings.push(clipboardFinding("HYBRID_SENSITIVE_PLUGIN_CLIPBOARD"))
  }

  findings.push(...(await scanDexFiles(apkPath, summary.dexFiles, onProgress)))
  findings.push(...(await scanNativeLibraries(apkPath, summary.nativeLibraries, onProgress)))
  findings.push(...(await scanEmbeddedAssets(apkPath, entries, onProgress)))

  return {
    findings,
    softwareComponents: apkSoftwareComponents(findings, summary.nativeLibraries),
    apkEntries: summary,
    apkMetadata: metadata,
    rawToolOutput: rawOutputs.join("\n\n").slice(0, 100_000),
  }
}
