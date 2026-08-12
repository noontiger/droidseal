import { type ArscTable, markPoolDirty } from "./arsc-model.ts"
import type { Finding } from "./types.ts"

// Deterministic short-name generator: a, b, ..., z, aa, ab, ... (base-26).
export function shortName(index: number): string {
  let n = index
  let out = ""
  do {
    out = String.fromCharCode(97 + (n % 26)) + out
    n = Math.floor(n / 26) - 1
  } while (n >= 0)
  return out
}

export interface KeyRenameOptions {
  // Entry names that must NOT be renamed (e.g. looked up via getIdentifier).
  keep?: ReadonlySet<string>
}

export interface KeyRenameResult {
  renamed: number
  // Original entry name -> new short name (only for names actually changed).
  mapping: Map<string, string>
}

// Mode A: shorten resource entry (key) names in place. Runtime lookups use the
// integer resource ID, not the name, so key indices stay 1:1 and DEX/XML are
// untouched. Names in `keep` are preserved verbatim.
export function shortenKeyNames(table: ArscTable, options: KeyRenameOptions = {}): KeyRenameResult {
  const keep = options.keep ?? new Set<string>()
  const mapping = new Map<string, string>()
  const used = new Set<string>()
  let counter = 0

  const nextName = (): string => {
    let candidate: string
    do {
      candidate = shortName(counter)
      counter += 1
    } while (used.has(candidate) || keep.has(candidate))
    used.add(candidate)
    return candidate
  }

  let renamed = 0
  for (const pkg of table.packages) {
    const pool = pkg.keyStrings
    let changed = false
    for (let i = 0; i < pool.strings.length; i += 1) {
      const original = pool.strings[i]!
      if (keep.has(original)) {
        used.add(original)
        continue
      }
      const existing = mapping.get(original)
      const replacement = existing ?? nextName()
      if (!existing) mapping.set(original, replacement)
      if (replacement !== original) {
        pool.strings[i] = replacement
        renamed += 1
        changed = true
      }
    }
    if (changed) markPoolDirty(pool)
  }

  return { renamed, mapping }
}

function splitExt(path: string): { ext: string } {
  const slash = path.lastIndexOf("/")
  const dot = path.lastIndexOf(".")
  if (dot > slash && dot !== -1) return { ext: path.slice(dot) }
  return { ext: "" }
}

export interface FlattenPathsOptions {
  // Resource file paths that must NOT be renamed.
  keep?: ReadonlySet<string>
  // Destination directory prefix for flattened paths (default "r/").
  prefix?: string
}

export interface FlattenResult {
  renamed: number
  // Original ZIP path -> new flattened path. The caller must rename the matching
  // ZIP entries so the on-disk file names stay in sync with the arsc references.
  mapping: Map<string, string>
}

// Mode B: flatten resource file paths (e.g. res/drawable-hdpi/ic.png -> r/a.png).
// File resources are referenced by a global-pool string index; rewriting the
// string in place keeps every Res_value reference valid. The returned mapping
// MUST be applied to the ZIP entry names by the caller.
export function flattenFilePaths(table: ArscTable, options: FlattenPathsOptions = {}): FlattenResult {
  const keep = options.keep ?? new Set<string>()
  const prefix = options.prefix ?? "r/"
  const mapping = new Map<string, string>()
  const usedPaths = new Set<string>()
  let counter = 0

  const pool = table.globalStrings
  let changed = false
  let renamed = 0
  for (let i = 0; i < pool.strings.length; i += 1) {
    const original = pool.strings[i]!
    if (!original.startsWith("res/") || keep.has(original)) continue
    const existing = mapping.get(original)
    let replacement = existing
    if (!replacement) {
      const { ext } = splitExt(original)
      do {
        replacement = `${prefix}${shortName(counter)}${ext}`
        counter += 1
      } while (usedPaths.has(replacement))
      usedPaths.add(replacement)
      mapping.set(original, replacement)
    }
    if (replacement !== original) {
      pool.strings[i] = replacement
      renamed += 1
      changed = true
    }
  }
  if (changed) markPoolDirty(pool)

  return { renamed, mapping }
}

export interface ReflectionAnalysis {
  // True when the DEX string pool references Resources.getIdentifier.
  usesGetIdentifier: boolean
  // Resource names that must be preserved (they appear verbatim as DEX string
  // literals and may be resolved by name at runtime). Empty when getIdentifier
  // is not used.
  keep: Set<string>
  finding?: Finding
}

// Detect name-based resource lookup (Resources.getIdentifier). The argument can
// be assembled dynamically, so preserving only names seen as DEX literals is not
// safe enough: strict mode preserves every key name when this API is present.
export function analyzeResourceReflection(
  resourceNames: Iterable<string>,
  dexStrings: Iterable<string>,
): ReflectionAnalysis {
  const dexSet = new Set(dexStrings)
  const usesGetIdentifier = dexSet.has("getIdentifier")
  const keep = new Set<string>()
  if (usesGetIdentifier) {
    for (const name of resourceNames) keep.add(name)
  }

  const result: ReflectionAnalysis = { usesGetIdentifier, keep }
  if (usesGetIdentifier) {
    const finding: Finding = {
      severity: "info",
      confidence: "medium",
      code: "ARSC_RESOURCE_NAME_REFLECTION",
      title: "检测到 getIdentifier；已保留全部资源条目名",
      detail:
        "DEX 字符串池中出现 Resources.getIdentifier 信号。调用参数可能由运行时动态拼接，无法仅凭字符串池精确枚举，因此安全预检已禁止重命名全部资源条目名；资源路径扁平化仍会单独执行其保留检查。",
      recommendation: "无需手工猜测白名单。若确认应用不按名称动态查找资源，可在源码移除 getIdentifier 后重新构建再执行混淆。",
    }
    if (keep.size > 0) {
      finding.evidence = [...keep].slice(0, 20).join(", ")
    }
    result.finding = finding
  }
  return result
}
