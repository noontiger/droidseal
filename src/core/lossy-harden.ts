import { parseArsc, serializeArsc } from "./arsc-model.ts"
import {
  analyzeResourceReflection,
  flattenFilePaths,
  shortenKeyNames,
  type FlattenPathsOptions,
} from "./arsc-obfuscate.ts"
import { extractDexStrings } from "./dex-scan.ts"
import { buildZip, crc32Of, inflateEntry, parseRawZip, type OutEntry } from "./harden-manifest.ts"
import type { Finding } from "./types.ts"

const ARSC_ENTRY = "resources.arsc"
const DEX_NAME_RE = /^classes(?:\d+)?\.dex$/

async function readWholeFile(apkPath: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(apkPath).arrayBuffer())
}

// Best-effort DEX string harvest for reflection safety. Malformed DEX entries are
// skipped so a single bad entry never aborts the whole obfuscation.
function collectDexStrings(entries: ReturnType<typeof parseRawZip>): string[] {
  const strings: string[] = []
  for (const entry of entries) {
    if (!DEX_NAME_RE.test(entry.name)) continue
    try {
      const { strings: pool } = extractDexStrings(inflateEntry(entry))
      strings.push(...pool)
    } catch {
      // skip: not a parseable DEX
    }
  }
  return strings
}

export interface ArscObfuscateOptions {
  // Mode A: shorten resource entry (key) names. Default true.
  shortenKeys?: boolean
  // Mode B: flatten resource file paths + rename matching ZIP entries. Default true.
  flattenPaths?: boolean
  // Extra names/paths the caller wants preserved beyond reflection detection.
  keepKeys?: ReadonlySet<string>
  keepPaths?: ReadonlySet<string>
  // Destination directory prefix for flattened paths (default "r/").
  pathPrefix?: string
}

export interface ArscObfuscateResult {
  changed: boolean
  keysRenamed: number
  pathsRenamed: number
  entriesRenamed: number
  usesGetIdentifier: boolean
  findings: Finding[]
}

// End-to-end opt-in lossy ARSC obfuscation over a whole APK. Extracts resources.arsc,
// applies AndResGuard-style mode A/B with fail-safe reflection/path preservation, then
// rebuilds the ZIP: resources.arsc is replaced STORED and any flattened file entries
// are renamed to stay in sync with the rewritten string pool. Resources are looked up
// by integer ID at runtime, so DEX/XML never need touching. Writes `outputApk` only
// when something actually changed; callers must re-align and re-sign afterwards.
export async function obfuscateArscInApk(
  inputApk: string,
  outputApk: string,
  options: ArscObfuscateOptions = {},
): Promise<ArscObfuscateResult> {
  const shortenKeys = options.shortenKeys ?? true
  const flattenPaths = options.flattenPaths ?? true

  const bytes = await readWholeFile(inputApk)
  const entries = parseRawZip(bytes)
  const arscEntry = entries.find((entry) => entry.name === ARSC_ENTRY)
  if (!arscEntry) {
    return { changed: false, keysRenamed: 0, pathsRenamed: 0, entriesRenamed: 0, usesGetIdentifier: false, findings: [] }
  }

  const table = parseArsc(inflateEntry(arscEntry))

  // Reflection/path safety: dynamic getIdentifier keeps every key; literal ZIP
  // resource paths referenced from DEX are never flattened.
  const dexStrings = collectDexStrings(entries)
  const resourceNames = new Set<string>()
  for (const pkg of table.packages) {
    for (const name of pkg.keyStrings.strings) resourceNames.add(name)
  }
  const reflection = analyzeResourceReflection(resourceNames, dexStrings)

  const findings: Finding[] = []
  if (reflection.finding) findings.push(reflection.finding)

  const keepKeys = new Set<string>(options.keepKeys ?? [])
  for (const name of reflection.keep) keepKeys.add(name)
  const keepPaths = new Set<string>(options.keepPaths ?? [])
  const dexSet = new Set(dexStrings)
  for (const resourcePath of table.globalStrings.strings) {
    if (resourcePath.startsWith("res/") && dexSet.has(resourcePath)) keepPaths.add(resourcePath)
  }
  if (keepPaths.size > (options.keepPaths?.size ?? 0)) {
    findings.push({
      severity: "info",
      confidence: "high",
      code: "ARSC_LITERAL_PATHS_PRESERVED",
      title: "已保留 DEX 明文引用的资源路径",
      detail: `安全预检发现并保留了 ${keepPaths.size - (options.keepPaths?.size ?? 0)} 个 DEX 字符串直接引用的 res/ 路径，避免扁平化后字符串加载失败。`,
      recommendation: "无需处理；这是资源混淆的兼容性保护记录。",
    })
  }

  let keysRenamed = 0
  let pathsRenamed = 0
  let pathMapping = new Map<string, string>()
  if (shortenKeys) {
    keysRenamed = shortenKeyNames(table, { keep: keepKeys }).renamed
  }
  if (flattenPaths) {
    const opts: FlattenPathsOptions = { keep: keepPaths }
    if (options.pathPrefix !== undefined) opts.prefix = options.pathPrefix
    const result = flattenFilePaths(table, opts)
    pathsRenamed = result.renamed
    pathMapping = result.mapping
  }

  if (keysRenamed === 0 && pathsRenamed === 0) {
    return {
      changed: false,
      keysRenamed: 0,
      pathsRenamed: 0,
      entriesRenamed: 0,
      usesGetIdentifier: reflection.usesGetIdentifier,
      findings,
    }
  }

  const newArsc = serializeArsc(table)

  const outEntries: OutEntry[] = []
  let entriesRenamed = 0
  for (const entry of entries) {
    if (entry.name === ARSC_ENTRY) {
      outEntries.push({
        name: ARSC_ENTRY,
        method: 0,
        crc32: crc32Of(newArsc),
        compressedSize: newArsc.byteLength,
        uncompressedSize: newArsc.byteLength,
        flags: 0,
        data: newArsc,
      })
      continue
    }
    const renamed = pathMapping.get(entry.name)
    outEntries.push({
      name: renamed ?? entry.name,
      method: entry.method,
      crc32: entry.crc32,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      flags: entry.flags,
      data: entry.data,
    })
    if (renamed) entriesRenamed += 1
  }

  await Bun.write(outputApk, buildZip(outEntries))

  findings.push({
    severity: "info",
    code: "LOSSY_ARSC_OBFUSCATED",
    title: "已执行 ARSC 资源名混淆（有损、可选）",
    detail:
      `DroidSeal 重命名了 ${keysRenamed} 个资源条目名` +
      (pathsRenamed > 0 ? `，并扁平化了 ${pathsRenamed} 个资源文件路径（同步重命名 ${entriesRenamed} 个 ZIP 条目）` : "") +
      "。资源在运行时通常按整数 ID 查找；检测到 getIdentifier 时会保留全部条目名，DEX 直接引用的 res/ 路径也不会被扁平化。此为有损操作，已在对齐前生成新包，随后会重新对齐与签名。",
    recommendation: "仍需在真机回归启动、主题切换、动态皮肤和 WebView 本地资源路径；发现异常时关闭本步骤。",
  })

  return {
    changed: true,
    keysRenamed,
    pathsRenamed,
    entriesRenamed,
    usesGetIdentifier: reflection.usesGetIdentifier,
    findings,
  }
}
