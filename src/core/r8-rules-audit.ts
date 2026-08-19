import path from "node:path"
import { readdir, readFile, stat } from "node:fs/promises"
import type { Finding } from "./types.ts"

export interface R8AppModule {
  moduleDirectory: string
  buildScriptRelativePath: string
  releaseConfiguration: string
}

interface RuleStatement {
  line: number
  text: string
}

interface RuleHit extends RuleStatement {
  relativePath: string
  effects?: string[]
}

interface MissingRuleReference {
  buildScriptRelativePath: string
  literal: string
}

const MAX_RULE_FILE_BYTES = 2 * 1024 * 1024
const MAX_KEEP_RULE_FILES = 200
const DEFAULT_ANDROID_RULE_FILES = new Set([
  "proguard-android.txt",
  "proguard-android-optimize.txt",
])

function isWithin(root: string, target: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(target))
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function relativeProjectPath(projectRoot: string, target: string): string {
  return path.relative(projectRoot, target).replaceAll("\\", "/") || "."
}

function pathKey(target: string): string {
  const resolved = path.resolve(target)
  return process.platform === "win32" ? resolved.toLowerCase() : resolved
}

async function existingFile(target: string): Promise<boolean> {
  return stat(target).then((value) => value.isFile(), () => false)
}

function looksLikeRulePath(literal: string): boolean {
  const normalized = literal.replaceAll("\\", "/")
  const lower = normalized.toLowerCase()
  const base = path.posix.basename(lower)
  if (DEFAULT_ANDROID_RULE_FILES.has(base)) return false
  if (/(?:^|\/)keeprules(?:\/|$)/i.test(normalized)) return true
  if (/\.(?:pro|rules|cfg|keep)$/i.test(base)) return true
  return /(?:proguard|r8|keep|rules)[^/]*\.txt$/i.test(base)
}

function referencedRuleLiterals(releaseConfiguration: string): string[] {
  const literals = new Set<string>()
  const quoted = /(["'])([^"'\r\n]+)\1/g
  let match: RegExpExecArray | null
  while ((match = quoted.exec(releaseConfiguration)) !== null) {
    const literal = match[2]!.trim()
    if (
      literal.length === 0 ||
      literal.includes("$") ||
      literal.includes("{") ||
      literal.includes("}") ||
      literal.includes("://") ||
      !looksLikeRulePath(literal)
    ) {
      continue
    }

    const prefix = releaseConfiguration.slice(Math.max(0, match.index - 180), match.index)
    if (!/(?:proguardFiles?|consumerProguardFiles?|configurationFiles|keepRules|\bfile)[\s\S]*$/i.test(prefix)) {
      continue
    }
    literals.add(literal)
  }
  return [...literals].sort()
}

function referenceCandidates(projectRoot: string, moduleDirectory: string, literal: string): string[] {
  const platformPath = literal.replaceAll("/", path.sep).replaceAll("\\", path.sep)
  const rawCandidates = path.isAbsolute(platformPath)
    ? [path.resolve(platformPath)]
    : [path.resolve(moduleDirectory, platformPath), path.resolve(projectRoot, platformPath)]
  const candidates: string[] = []
  const seen = new Set<string>()
  for (const candidate of rawCandidates) {
    const key = pathKey(candidate)
    if (!seen.has(key) && isWithin(projectRoot, candidate)) {
      seen.add(key)
      candidates.push(candidate)
    }
  }
  return candidates
}

async function collectKeepRuleFiles(directory: string): Promise<string[]> {
  const found: string[] = []
  const queue: Array<{ directory: string; depth: number }> = [{ directory, depth: 0 }]
  while (queue.length > 0 && found.length < MAX_KEEP_RULE_FILES) {
    const current = queue.shift()
    if (!current || current.depth > 8) continue
    const entries = await readdir(current.directory, { withFileTypes: true }).catch(() => [])
    entries.sort((left, right) => left.name.localeCompare(right.name))
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue
      const absolute = path.join(current.directory, entry.name)
      if (entry.isDirectory()) {
        queue.push({ directory: absolute, depth: current.depth + 1 })
      } else if (entry.isFile()) {
        found.push(absolute)
        if (found.length >= MAX_KEEP_RULE_FILES) break
      }
    }
  }
  return found
}

function braceDelta(text: string): number {
  let depth = 0
  for (const character of text) {
    if (character === "{") depth += 1
    else if (character === "}") depth -= 1
  }
  return depth
}

function parseRuleStatements(source: string): RuleStatement[] {
  const statements: RuleStatement[] = []
  let current: RuleStatement | undefined
  let depth = 0

  const finish = (): void => {
    if (!current) return
    statements.push({ line: current.line, text: current.text.replace(/\s+/g, " ").trim() })
    current = undefined
    depth = 0
  }

  const lines = source.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const text = (lines[index] ?? "").replace(/#.*$/, "").trim()
    if (text.length === 0) continue

    if (!current) {
      if (!text.startsWith("-")) continue
      current = { line: index + 1, text }
      depth = braceDelta(text)
    } else {
      current.text += ` ${text}`
      depth += braceDelta(text)
    }

    if (depth <= 0) finish()
  }
  finish()
  return statements
}

function keepRuleEffects(statement: string): { scope: "global" | "package"; selector: string; effects: string[] } | undefined {
  const directive = /^-(keepnames|keep)(?:,([a-z,]+))?\s+([\s\S]+)$/i.exec(statement)
  if (!directive) return undefined

  const kind = directive[1]!.toLowerCase()
  const options = new Set((directive[2] ?? "").toLowerCase().split(",").filter(Boolean))
  const rest = directive[3]!
  const classMatch = /\b(?:class|interface|enum)\s+([^\s{]+)/i.exec(rest)
  if (!classMatch) return undefined

  const beforeClass = rest.slice(0, classMatch.index)
  if (/@[\w.$*?\-]+/.test(beforeClass)) return undefined

  const selector = classMatch[1]!.replace(/,+$/, "")
  const tail = rest.slice(classMatch.index + classMatch[0].length).split("{", 1)[0] ?? ""
  if (/\b(?:extends|implements)\b/i.test(tail)) return undefined

  const scope =
    selector === "*" || selector === "**" || selector === "***"
      ? "global"
      : selector.endsWith(".**")
        ? "package"
        : undefined
  if (!scope) return undefined

  const effects: string[] = []
  if (kind === "keepnames") {
    if (!options.has("allowobfuscation")) effects.push("名称混淆")
  } else {
    if (!options.has("allowshrinking")) effects.push("代码裁剪")
    if (!options.has("allowoptimization")) effects.push("代码优化")
    if (!options.has("allowobfuscation")) effects.push("名称混淆")
  }
  if (effects.length === 0) return undefined
  return { scope, selector, effects }
}

function hitEvidence(hits: readonly RuleHit[]): string {
  return hits
    .slice(0, 20)
    .map((hit) => `${hit.relativePath}:${hit.line}`)
    .join(", ")
}

function hitDetails(hits: readonly RuleHit[]): string {
  return hits
    .slice(0, 8)
    .map((hit) => {
      const effects = hit.effects?.length ? `；限制：${hit.effects.join("、")}` : ""
      return `${hit.relativePath}:${hit.line} → ${hit.text.slice(0, 220)}${effects}`
    })
    .join("；")
}

function findingForHits(code: string, hits: readonly RuleHit[]): Finding {
  const definitions: Record<string, Omit<Finding, "code" | "detail" | "evidence">> = {
    R8_OBFUSCATION_DISABLED: {
      severity: "high",
      confidence: "confirmed",
      title: "R8 名称混淆被规则显式关闭",
      recommendation: "移除 -dontobfuscate；若仅有少量反射/JNI 入口需要稳定名称，请改成精确到类或成员的 keep 规则。",
    },
    R8_SHRINKING_DISABLED: {
      severity: "high",
      confidence: "confirmed",
      title: "R8 代码裁剪被规则显式关闭",
      recommendation: "移除 -dontshrink，并通过定向 keep 规则保护动态访问点；使用 usage.txt 验证裁剪结果。",
    },
    R8_OPTIMIZATION_DISABLED: {
      severity: "medium",
      confidence: "confirmed",
      title: "R8 代码优化被规则显式关闭",
      recommendation: "评估并移除 -dontoptimize；若确有工具链兼容问题，应记录具体版本、最小复现和局部替代规则。",
    },
    R8_GLOBAL_KEEP_RULE: {
      severity: "high",
      confidence: "confirmed",
      title: "R8 存在全局宽泛 keep 规则",
      recommendation: "把全局通配规则收窄到真实的反射、序列化、JNI、动态加载或 WebView JS 接口入口。",
    },
    R8_BROAD_PACKAGE_KEEP_RULE: {
      severity: "medium",
      confidence: "confirmed",
      title: "R8 存在整包宽泛 keep 规则",
      recommendation: "按注解、接口、具体类或必要成员收窄规则；保留 allowobfuscation/allowshrinking/allowoptimization 中可安全放开的能力。",
    },
  }
  const definition = definitions[code]
  if (!definition) throw new Error(`Unknown R8 finding code: ${code}`)
  return {
    ...definition,
    code,
    detail: `已从实际规则文件确认 ${hits.length} 处配置：${hitDetails(hits)}。`,
    evidence: hitEvidence(hits),
  }
}

export async function auditR8Rules(
  projectPath: string,
  modules: readonly R8AppModule[],
): Promise<Finding[]> {
  if (modules.length === 0) return []

  const projectRoot = path.resolve(projectPath)
  const files = new Map<string, string>()
  const missing: MissingRuleReference[] = []

  const addRuleFile = (absolute: string): void => {
    if (!isWithin(projectRoot, absolute)) return
    files.set(pathKey(absolute), path.resolve(absolute))
  }

  const orderedModules = [...modules].sort((left, right) =>
    left.buildScriptRelativePath.localeCompare(right.buildScriptRelativePath),
  )

  for (const module of orderedModules) {
    const moduleDirectory = path.resolve(module.moduleDirectory)
    if (!isWithin(projectRoot, moduleDirectory)) continue

    const conventional = path.join(moduleDirectory, "proguard-rules.pro")
    if (await existingFile(conventional)) addRuleFile(conventional)

    const keepRulesDirectory = path.join(moduleDirectory, "src", "main", "keepRules")
    for (const ruleFile of await collectKeepRuleFiles(keepRulesDirectory)) addRuleFile(ruleFile)

    for (const literal of referencedRuleLiterals(module.releaseConfiguration)) {
      let resolved: string | undefined
      for (const candidate of referenceCandidates(projectRoot, moduleDirectory, literal)) {
        if (await existingFile(candidate)) {
          resolved = candidate
          break
        }
      }
      if (resolved) addRuleFile(resolved)
      else missing.push({ buildScriptRelativePath: module.buildScriptRelativePath, literal })
    }
  }

  const orderedFiles = [...files.values()].sort((left, right) =>
    relativeProjectPath(projectRoot, left).localeCompare(relativeProjectPath(projectRoot, right)),
  )
  const hits = new Map<string, RuleHit[]>()
  const unreadable: string[] = []

  const record = (code: string, hit: RuleHit): void => {
    const current = hits.get(code) ?? []
    current.push(hit)
    hits.set(code, current)
  }

  for (const absolute of orderedFiles) {
    const relativePath = relativeProjectPath(projectRoot, absolute)
    try {
      const info = await stat(absolute)
      if (!info.isFile() || info.size > MAX_RULE_FILE_BYTES) {
        unreadable.push(relativePath)
        continue
      }
      const sourceText = await readFile(absolute, "utf8")
      for (const statement of parseRuleStatements(sourceText)) {
        const hit: RuleHit = { ...statement, relativePath }
        if (/^-dontobfuscate(?:\s|$)/i.test(statement.text)) {
          record("R8_OBFUSCATION_DISABLED", hit)
          continue
        }
        if (/^-dontshrink(?:\s|$)/i.test(statement.text)) {
          record("R8_SHRINKING_DISABLED", hit)
          continue
        }
        if (/^-dontoptimize(?:\s|$)/i.test(statement.text)) {
          record("R8_OPTIMIZATION_DISABLED", hit)
          continue
        }
        const keep = keepRuleEffects(statement.text)
        if (keep) {
          record(keep.scope === "global" ? "R8_GLOBAL_KEEP_RULE" : "R8_BROAD_PACKAGE_KEEP_RULE", {
            ...hit,
            effects: keep.effects,
          })
        }
      }
    } catch {
      unreadable.push(relativePath)
    }
  }

  const findings: Finding[] = []
  if (orderedFiles.length > 0) {
    const relativeFiles = orderedFiles.map((file) => relativeProjectPath(projectRoot, file))
    findings.push({
      severity: "info",
      confidence: "confirmed",
      code: "R8_RULE_FILES_AUDITED",
      title: "已审计 R8/ProGuard 规则文件",
      detail: `仅检查 app 模块 release 明确引用、模块 proguard-rules.pro 与 src/main/keepRules 下的规则，共 ${relativeFiles.length} 个：${relativeFiles.join("、")}。`,
      recommendation: "保留精确 keep 规则和本次报告；结合 mapping/configuration/seeds/usage 与真机回归持续收窄。",
      evidence: relativeFiles.join(", "),
    })
  }

  for (const code of [
    "R8_OBFUSCATION_DISABLED",
    "R8_SHRINKING_DISABLED",
    "R8_OPTIMIZATION_DISABLED",
    "R8_GLOBAL_KEEP_RULE",
    "R8_BROAD_PACKAGE_KEEP_RULE",
  ]) {
    const codeHits = hits.get(code)
    if (codeHits?.length) findings.push(findingForHits(code, codeHits))
  }

  if (missing.length > 0) {
    const evidence = missing
      .slice(0, 20)
      .map((item) => `${item.buildScriptRelativePath} → ${item.literal}`)
      .join(", ")
    findings.push({
      severity: "high",
      confidence: "confirmed",
      code: "R8_RULE_FILE_REFERENCE_MISSING",
      title: "release 引用的本地 R8 规则文件不存在",
      detail: `已确认 ${missing.length} 个静态本地规则引用无法在 app 模块或项目根目录解析：${evidence}。动态变量引用未参与本判定。`,
      recommendation: "修正规则文件路径或恢复缺失文件；确认 release 构建实际加载预期的反射、JNI、序列化和 WebView 规则。",
      evidence,
    })
  }

  if (unreadable.length > 0) {
    findings.push({
      severity: "medium",
      confidence: "confirmed",
      code: "R8_RULE_FILE_AUDIT_INCOMPLETE",
      title: "部分 R8 规则文件未完成审计",
      detail: `以下规则文件无法读取、不是普通文件或超过 ${MAX_RULE_FILE_BYTES} 字节安全上限：${unreadable.join("、")}。`,
      recommendation: "确认规则文件可读且体积合理，然后重新运行 DroidSeal；未审计文件不能视为安全。",
      evidence: unreadable.join(", "),
    })
  }

  return findings
}
