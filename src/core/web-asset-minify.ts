import { access, mkdir, rename, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { deflateRawSync } from "node:zlib"
import { minify } from "terser"
import { DroidSealError } from "./errors.ts"
import {
  buildZip,
  crc32Of,
  inflateEntry,
  parseRawZip,
  type OutEntry,
  type RawZipEntry,
} from "./harden-manifest.ts"
import type { Finding } from "./types.ts"

const WEB_ROOTS = ["assets/public/", "assets/www/"] as const
const MAX_SCRIPT_BYTES = 4 * 1024 * 1024
const MAX_TOTAL_SCRIPT_BYTES = 32 * 1024 * 1024
const MAX_INDEX_BYTES = 2 * 1024 * 1024
const MAX_SCRIPT_FILES = 2_048

export interface HybridWebAssetInspection {
  scriptNames: string[]
  mapNames: string[]
  roots: string[]
}

export interface WebAssetMinifyResult {
  changed: boolean
  filesProcessed: number
  moduleFiles: number
  mapsRemoved: number
  beforeBytes: number
  afterBytes: number
  roots: string[]
  findings: Finding[]
}

function webRoot(name: string): string | undefined {
  if (name.includes("\\") || name.includes("\0")) return undefined
  for (const root of WEB_ROOTS) {
    if (!name.startsWith(root)) continue
    const relative = name.slice(root.length)
    const segments = relative.split("/")
    if (!relative || relative.endsWith("/") || segments.some((segment) => !segment || segment === "." || segment === "..")) {
      return undefined
    }
    return root
  }
  return undefined
}

function inspectEntries(entries: RawZipEntry[]): HybridWebAssetInspection {
  const scripts: string[] = []
  const maps: string[] = []
  const roots = new Set<string>()
  const seenTargets = new Set<string>()

  for (const entry of entries) {
    const root = webRoot(entry.name)
    if (!root) continue
    const isScript = entry.name.endsWith(".js")
    const isMap = entry.name.endsWith(".map")
    if (!isScript && !isMap) continue
    if (seenTargets.has(entry.name)) {
      throw webAssetError(
        "WEB_ASSET_DUPLICATE_ENTRY",
        "混合应用 Web 资产存在重复 ZIP 条目",
        `发现重复目标条目 ${entry.name}；无法确定 WebView 实际读取哪一份内容。`,
      )
    }
    seenTargets.add(entry.name)
    roots.add(root)
    if (isScript) scripts.push(entry.name)
    else maps.push(entry.name)
  }

  scripts.sort()
  maps.sort()
  return { scriptNames: scripts, mapNames: maps, roots: [...roots].sort() }
}

function webAssetError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: [
      "在原 Web 工程中修复脚本或生成配置后重新构建 APK",
      "关闭 Web JS 发布处理以保留原始 APK，并人工复核兼容性",
    ],
    stepId: "web-assets",
  })
}

async function readApk(apkPath: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(apkPath).arrayBuffer())
}

export async function inspectHybridWebAssetsInApk(apkPath: string): Promise<HybridWebAssetInspection> {
  return inspectEntries(parseRawZip(await readApk(apkPath)))
}

function attribute(tag: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const match = new RegExp(`\\b${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>]+))`, "i").exec(tag)
  return match?.[1] ?? match?.[2] ?? match?.[3]
}

function resolveScriptName(root: string, source: string): string | undefined {
  const clean = source.trim().split(/[?#]/, 1)[0]?.replaceAll("\\", "/") ?? ""
  if (!clean || clean.startsWith("//") || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(clean)) return undefined
  const relative = path.posix.normalize(clean.startsWith("/") ? clean.slice(1) : clean)
  if (!relative || relative === "." || relative.startsWith("../") || path.posix.isAbsolute(relative)) return undefined
  const resolved = `${root}${relative}`
  return webRoot(resolved) ? resolved : undefined
}

function moduleScriptsFromHtml(root: string, html: string): Set<string> {
  const modules = new Set<string>()
  for (const match of html.matchAll(/<script\b[^>]*>/gi)) {
    const tag = match[0]
    if ((attribute(tag, "type") ?? "").trim().toLowerCase() !== "module") continue
    const source = attribute(tag, "src")
    if (!source) continue
    const resolved = resolveScriptName(root, source)
    if (resolved?.endsWith(".js")) modules.add(resolved)
  }
  return modules
}

function decodeUtf8(bytes: Uint8Array, entryName: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes)
  } catch {
    throw webAssetError(
      "WEB_ASSET_INVALID_UTF8",
      "Web JavaScript 不是有效的 UTF-8 文本",
      `${entryName} 无法按 UTF-8 严格解码，已停止且不会写出修改后的 APK。`,
    )
  }
}

function outputEntry(entry: RawZipEntry, bytes: Uint8Array): OutEntry {
  const method = entry.method === 0 ? 0 : 8
  const data = method === 0 ? bytes : new Uint8Array(deflateRawSync(bytes, { level: 9 }))
  return {
    name: entry.name,
    method,
    crc32: crc32Of(bytes),
    compressedSize: data.byteLength,
    uncompressedSize: bytes.byteLength,
    flags: entry.flags & ~0x08,
    data,
  }
}

function copiedEntry(entry: RawZipEntry): OutEntry {
  return {
    name: entry.name,
    method: entry.method,
    crc32: entry.crc32,
    compressedSize: entry.compressedSize,
    uncompressedSize: entry.uncompressedSize,
    flags: entry.flags,
    data: entry.data,
  }
}

function enforceLimits(entries: RawZipEntry[], inspection: HybridWebAssetInspection): void {
  if (inspection.scriptNames.length > MAX_SCRIPT_FILES) {
    throw webAssetError(
      "WEB_ASSET_LIMIT_EXCEEDED",
      "Web JavaScript 文件数量超过安全上限",
      `检测到 ${inspection.scriptNames.length} 个脚本，上限为 ${MAX_SCRIPT_FILES}；为避免 ZIP 资源耗尽已停止。`,
    )
  }
  const targets = new Set(inspection.scriptNames)
  let total = 0
  for (const entry of entries) {
    if (!targets.has(entry.name)) continue
    if (entry.uncompressedSize > MAX_SCRIPT_BYTES) {
      throw webAssetError(
        "WEB_ASSET_LIMIT_EXCEEDED",
        "单个 Web JavaScript 超过安全上限",
        `${entry.name} 声明解压后 ${entry.uncompressedSize} 字节，上限为 ${MAX_SCRIPT_BYTES}。`,
      )
    }
    total += entry.uncompressedSize
    if (total > MAX_TOTAL_SCRIPT_BYTES) {
      throw webAssetError(
        "WEB_ASSET_LIMIT_EXCEEDED",
        "Web JavaScript 总量超过安全上限",
        `目标脚本声明解压后总量超过 ${MAX_TOTAL_SCRIPT_BYTES} 字节；为避免资源耗尽已停止。`,
      )
    }
  }
}

async function moduleScriptNames(entries: RawZipEntry[], roots: string[]): Promise<Set<string>> {
  const modules = new Set<string>()
  for (const root of roots) {
    const index = entries.find((entry) => entry.name === `${root}index.html`)
    if (!index) continue
    if (index.uncompressedSize > MAX_INDEX_BYTES) {
      throw webAssetError(
        "WEB_ASSET_LIMIT_EXCEEDED",
        "混合应用 index.html 超过安全上限",
        `${index.name} 声明解压后 ${index.uncompressedSize} 字节，上限为 ${MAX_INDEX_BYTES}。`,
      )
    }
    const bytes = inflateEntry(index)
    if (bytes.byteLength !== index.uncompressedSize) {
      throw webAssetError(
        "WEB_ASSET_SIZE_MISMATCH",
        "混合应用 index.html 的 ZIP 大小不一致",
        `${index.name} 声明 ${index.uncompressedSize} 字节，实际解压为 ${bytes.byteLength} 字节。`,
      )
    }
    for (const name of moduleScriptsFromHtml(root, decodeUtf8(bytes, index.name))) modules.add(name)
  }
  return modules
}

async function atomicWrite(outputApk: string, bytes: Uint8Array): Promise<void> {
  await mkdir(path.dirname(outputApk), { recursive: true })
  if (await access(outputApk).then(() => true, () => false)) {
    throw webAssetError("WEB_ASSET_OUTPUT_EXISTS", "Web 资产处理输出已存在", `${outputApk} 已存在；DroidSeal 不会覆盖未知产物。`)
  }
  const temporary = `${outputApk}.droidseal-${crypto.randomUUID()}.tmp`
  try {
    await writeFile(temporary, bytes, { flag: "wx" })
    await rename(temporary, outputApk)
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined)
  }
}

export async function minifyHybridWebAssetsInApk(
  inputApk: string,
  outputApk: string,
): Promise<WebAssetMinifyResult> {
  const apkBytes = await readApk(inputApk)
  const entries = parseRawZip(apkBytes)
  const inspection = inspectEntries(entries)
  if (inspection.scriptNames.length === 0) {
    return {
      changed: false,
      filesProcessed: 0,
      moduleFiles: 0,
      mapsRemoved: 0,
      beforeBytes: 0,
      afterBytes: 0,
      roots: [],
      findings: [],
    }
  }

  enforceLimits(entries, inspection)
  const modules = await moduleScriptNames(entries, inspection.roots)
  const scriptSet = new Set(inspection.scriptNames)
  const mapSet = new Set(inspection.mapNames)
  const transformed = new Map<string, Uint8Array>()
  let beforeBytes = 0
  let afterBytes = 0
  let moduleFiles = 0

  // Every target is parsed and transformed in memory before any output file is created.
  for (const entry of entries) {
    if (!scriptSet.has(entry.name)) continue
    const sourceBytes = inflateEntry(entry)
    if (sourceBytes.byteLength !== entry.uncompressedSize) {
      throw webAssetError(
        "WEB_ASSET_SIZE_MISMATCH",
        "Web JavaScript 的 ZIP 大小不一致",
        `${entry.name} 声明 ${entry.uncompressedSize} 字节，实际解压为 ${sourceBytes.byteLength} 字节。`,
      )
    }
    const isModule = modules.has(entry.name)
    const source = decodeUtf8(sourceBytes, entry.name)
    if (source.trim().length === 0) {
      // 空白脚本:无需压缩,原样保留,避免 Terser 对空输入返回空输出被误判为失败
      transformed.set(entry.name, sourceBytes)
      continue
    }
    let code: string | undefined
    try {
      code = (await minify(source, {
        ecma: 2020,
        module: isModule,
        compress: { passes: 2, unsafe: false },
        mangle: isModule ? { toplevel: true } : true,
        format: { comments: /@license|@preserve|^!/i },
        sourceMap: false,
      })).code
    } catch (error) {
      const reason = error instanceof Error ? error.message.split(/\r?\n/, 1)[0] : "未知语法错误"
      throw webAssetError(
        "WEB_ASSET_MINIFY_FAILED",
        "Web JavaScript 压缩失败",
        `${entry.name} 无法由 Terser 解析：${reason}。全部修改已回退，未写出 APK。`,
      )
    }
    if (code === undefined) {
      throw webAssetError("WEB_ASSET_MINIFY_FAILED", "Web JavaScript 压缩失败", `${entry.name} 的 Terser 没有返回输出，未写出 APK。`)
    }
    if (/\/\/[#@]\s*sourceMappingURL\s*=/.test(code)) {
      throw webAssetError("WEB_ASSET_SOURCE_MAP_RETAINED", "Web JavaScript 仍引用 source map", `${entry.name} 的处理结果仍包含 sourceMappingURL，已停止。`)
    }
    const output = new TextEncoder().encode(`${code}\n`)
    transformed.set(entry.name, output)
    beforeBytes += sourceBytes.byteLength
    afterBytes += output.byteLength
    if (isModule) moduleFiles += 1
  }

  const outEntries: OutEntry[] = []
  for (const entry of entries) {
    if (mapSet.has(entry.name)) continue
    const replacement = transformed.get(entry.name)
    outEntries.push(replacement ? outputEntry(entry, replacement) : copiedEntry(entry))
  }
  const rebuilt = buildZip(outEntries)

  // Re-parse before touching the destination. This catches malformed ZIP output and
  // confirms every transformed script and source-map removal exactly.
  let verified: RawZipEntry[]
  try {
    verified = parseRawZip(rebuilt)
  } catch (error) {
    throw webAssetError(
      "WEB_ASSET_ZIP_VALIDATION_FAILED",
      "Web 资产处理后的 APK 未通过 ZIP 复核",
      error instanceof Error ? error.message : "重建 ZIP 无法重新解析。",
    )
  }
  const verifiedByName = new Map(verified.map((entry) => [entry.name, entry]))
  const manifestWasPresent = entries.some((entry) => entry.name === "AndroidManifest.xml")
  const valid =
    verified.length === entries.length - mapSet.size &&
    (!manifestWasPresent || verifiedByName.has("AndroidManifest.xml")) &&
    inspection.mapNames.every((name) => !verifiedByName.has(name)) &&
    [...transformed].every(([name, expected]) => {
      const entry = verifiedByName.get(name)
      if (!entry) return false
      const actual = inflateEntry(entry)
      return actual.byteLength === expected.byteLength && actual.every((value, index) => value === expected[index])
    })
  if (!valid) {
    throw webAssetError(
      "WEB_ASSET_ZIP_VALIDATION_FAILED",
      "Web 资产处理后的 APK 内容复核失败",
      "条目数量、Manifest、脚本内容或 source map 移除结果与预期不一致，未写出 APK。",
    )
  }

  await atomicWrite(outputApk, rebuilt)
  const finding: Finding = {
    severity: "info",
    confidence: "confirmed",
    code: "HYBRID_WEB_ASSETS_MINIFIED",
    title: "已压缩混淆混合应用 Web JavaScript",
    detail: `Terser 处理 ${inspection.scriptNames.length} 个脚本（其中 ${moduleFiles} 个 ES module），明文字节从 ${beforeBytes} 降至 ${afterBytes}，移除 ${inspection.mapNames.length} 个 source map。`,
    recommendation: "仍需真机回归启动、路由、懒加载、插件桥接和离线资源；客户端压缩混淆不等于源码保密，秘密与高价值规则应移到服务端。",
    evidence: `${inspection.roots.join(", ")} | js=${inspection.scriptNames.length}, modules=${moduleFiles}, maps=${inspection.mapNames.length}`,
  }
  return {
    changed: true,
    filesProcessed: inspection.scriptNames.length,
    moduleFiles,
    mapsRemoved: inspection.mapNames.length,
    beforeBytes,
    afterBytes,
    roots: inspection.roots,
    findings: [finding],
  }
}
