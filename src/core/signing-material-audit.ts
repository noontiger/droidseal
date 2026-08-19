import { readdir, readFile, stat } from "node:fs/promises"
import path from "node:path"
import { runProcess } from "./process.ts"
import type { Finding } from "./types.ts"

const SKIP_DIRECTORIES = new Set([
  ".git",
  ".gradle",
  ".idea",
  ".droidseal",
  "build",
  "dist",
  "node_modules",
  "dependencies",
  "out",
])
const KEYSTORE_EXTENSIONS = new Set([".jks", ".keystore", ".p12", ".pfx", ".bks"])
const SIGNING_PROPERTY_FILES = new Set([
  "keystore.properties",
  "key.properties",
  "signing.properties",
  "release-signing.properties",
])
const DOCUMENT_EXTENSIONS = new Set([".md", ".txt"])
const MAX_TEXT_BYTES = 2 * 1024 * 1024
const MAX_DEPTH = 8
const MAX_CANDIDATES = 128

export type GitExposure = "tracked" | "history" | "untracked" | "unknown"
export type SigningMaterialKind = "keystore" | "properties" | "documentation"

export interface SigningMaterialInput {
  relativePath: string
  kind: SigningMaterialKind
  gitExposure: GitExposure
  content?: string
}

interface PasswordHit {
  relativePath: string
  line: number
  field: "storePassword" | "keyPassword"
  kind: Exclude<SigningMaterialKind, "keystore">
  gitExposure: GitExposure
}

function normalizedValue(raw: string): string {
  return raw
    .trim()
    .replace(/^[`"']+|[`"',;。.，]+$/g, "")
    .trim()
}

function isReferenceOrPlaceholder(raw: string): boolean {
  const value = normalizedValue(raw)
  if (!value) return true
  if (
    /(?:System\.getenv|providers?\.environmentVariable|process\.env|findProperty|gradleProperty|localProperties|keystoreProps|getProperty|\$\{|\$[A-Za-z_]|<[^>]+>|\*{3,}|RELEASE_(?:STORE|KEY)_PASSWORD)/i.test(value)
  ) return true
  const normalized = value.toLowerCase().replace(/[^a-z0-9]/g, "")
  return /^(?:example|sample|dummy|test|testing|changeme|replaceme|yourpassword|password|secret|todo|undefined|null|x+|0+|1+)$/.test(normalized)
}

function passwordHits(input: SigningMaterialInput): PasswordHit[] {
  if (!input.content || input.kind === "keystore") return []
  const hits: PasswordHit[] = []
  const lines = input.content.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]!
    const pattern = /\b(storePassword|keyPassword|storepass|keypass)\b\s*(?:=|:)\s*([^\s`]+)/gi
    let match: RegExpExecArray | null
    while ((match = pattern.exec(line)) !== null) {
      const field = match[1] as PasswordHit["field"]
      if (isReferenceOrPlaceholder(match[2] ?? "")) continue
      hits.push({
        relativePath: input.relativePath,
        line: index + 1,
        field,
        kind: input.kind,
        gitExposure: input.gitExposure,
      })
    }
  }
  return hits
}

function gitLabel(exposure: GitExposure): string {
  if (exposure === "tracked") return "当前 Git tracked"
  if (exposure === "history") return "Git 历史出现"
  if (exposure === "untracked") return "当前未跟踪"
  return "Git 状态未知"
}

export function analyzeSigningMaterials(inputs: readonly SigningMaterialInput[]): Finding[] {
  const sorted = [...inputs].sort((a, b) => a.relativePath.localeCompare(b.relativePath))
  const properties: PasswordHit[] = []
  const documents: PasswordHit[] = []
  for (const input of sorted) {
    const hits = passwordHits(input)
    if (input.kind === "properties") properties.push(...hits)
    if (input.kind === "documentation") documents.push(...hits)
  }

  const findings: Finding[] = []
  const passwordFinding = (
    hits: PasswordHit[],
    code: string,
    title: string,
  ): Finding | undefined => {
    if (hits.length === 0) return undefined
    return {
      severity: "critical",
      confidence: "confirmed",
      code,
      title,
      detail:
        `检测到 ${hits.length} 处 storePassword/keyPassword 真实字面量。证据只保留相对路径、行号和字段名，密码值已丢弃；若文件曾提交，应按已泄露处理并轮换发布密钥。`,
      recommendation:
        "立即停止使用仓库内明文密码，改用 CI secret/环境变量或受控凭据服务；删除工作区副本并清理 Git 历史。若私钥与密码可能同时暴露，生成新发布密钥并按应用商店/渠道规则执行密钥轮换。",
      evidence: hits
        .slice(0, 24)
        .map((hit) => `${hit.relativePath}:${hit.line} ${hit.field}=<redacted>（${gitLabel(hit.gitExposure)}）`)
        .join("; "),
    }
  }
  const propertyFinding = passwordFinding(
    properties,
    "SIGNING_PASSWORD_LITERAL_IN_PROPERTIES",
    "签名属性文件包含明文密码",
  )
  if (propertyFinding) findings.push(propertyFinding)
  const documentationFinding = passwordFinding(
    documents,
    "SIGNING_PASSWORD_LITERAL_IN_DOCUMENTATION",
    "文档包含可用的签名密码",
  )
  if (documentationFinding) findings.push(documentationFinding)

  const keystores = sorted.filter((input) => input.kind === "keystore")
  const exposed = keystores.filter((input) => input.gitExposure === "tracked" || input.gitExposure === "history")
  const localOnly = keystores.filter((input) => input.gitExposure !== "tracked" && input.gitExposure !== "history")
  if (exposed.length > 0) {
    findings.push({
      severity: "critical",
      confidence: "confirmed",
      code: "SIGNING_KEYSTORE_GIT_EXPOSED",
      title: "发布密钥库已被 Git 跟踪或进入历史",
      detail:
        `检测到 ${exposed.length} 个 JKS/keystore/P12/PFX 当前被 Git 跟踪或曾出现在历史中。私钥文件一旦与密码同时泄露，攻击者可签发具有相同发布身份的更新包。`,
      recommendation:
        "立即限制仓库访问并启动事件响应；从当前树和 Git 历史移除密钥库，但不要误以为改写历史能撤销已经发生的泄露。按发布渠道规则轮换密钥，并核查所有已发布版本和 CI 凭据。",
      evidence: exposed.map((input) => `${input.relativePath}（${gitLabel(input.gitExposure)}）`).join("; "),
    })
  }
  if (localOnly.length > 0) {
    findings.push({
      severity: "high",
      confidence: "confirmed",
      code: "SIGNING_KEYSTORE_IN_PROJECT",
      title: "项目目录内存在发布密钥库",
      detail:
        `检测到 ${localOnly.length} 个签名密钥库位于项目目录。即使当前未被 Git 跟踪，也容易被目录打包、备份、聊天传输或错误提交带出安全边界。`,
      recommendation:
        "把发布密钥库移到仓库外的受控绝对路径或 CI 密钥服务；在 .gitignore 和发布检查中阻止 JKS/keystore/P12/PFX，并限制文件 ACL 与备份范围。",
      evidence: localOnly.map((input) => `${input.relativePath}（${gitLabel(input.gitExposure)}）`).join("; "),
    })
  }

  if ((keystores.length > 0 || properties.length > 0 || documents.length > 0) && sorted.every((input) => input.gitExposure === "unknown")) {
    findings.push({
      severity: "info",
      confidence: "confirmed",
      code: "SIGNING_MATERIAL_GIT_STATUS_UNAVAILABLE",
      title: "无法确认签名材料的 Git 暴露状态",
      detail: "已发现签名材料候选，但当前目录不是可读取的 Git 工作树或 Git 命令不可用；文件系统发现仍有效，Git tracked/历史判断已降级。",
      recommendation: "在项目仓库中运行 git ls-files 与 git log --all -- <path> 复核当前和历史暴露，再按最坏情况处理。",
      evidence: sorted.map((input) => input.relativePath).join(", "),
    })
  }

  return findings
}

async function collectCandidates(projectPath: string): Promise<Array<Omit<SigningMaterialInput, "gitExposure">>> {
  const candidates: Array<Omit<SigningMaterialInput, "gitExposure">> = []
  const queue: Array<{ directory: string; depth: number }> = [{ directory: projectPath, depth: 0 }]
  while (queue.length > 0 && candidates.length < MAX_CANDIDATES) {
    const current = queue.shift()
    if (!current || current.depth > MAX_DEPTH) continue
    const entries = await readdir(current.directory, { withFileTypes: true }).catch(() => [])
    entries.sort((a, b) => a.name.localeCompare(b.name))
    for (const entry of entries) {
      if (candidates.length >= MAX_CANDIDATES) break
      const absolute = path.join(current.directory, entry.name)
      const relativePath = path.relative(projectPath, absolute).replaceAll("\\", "/")
      if (entry.isDirectory()) {
        if (!SKIP_DIRECTORIES.has(entry.name)) queue.push({ directory: absolute, depth: current.depth + 1 })
        continue
      }
      if (!entry.isFile()) continue
      const extension = path.extname(entry.name).toLowerCase()
      const base = entry.name.toLowerCase()
      if (KEYSTORE_EXTENSIONS.has(extension)) {
        candidates.push({ relativePath, kind: "keystore" })
        continue
      }
      const kind: SigningMaterialKind | undefined = SIGNING_PROPERTY_FILES.has(base)
        ? "properties"
        : DOCUMENT_EXTENSIONS.has(extension)
          ? "documentation"
          : undefined
      if (!kind) continue
      const metadata = await stat(absolute).catch(() => undefined)
      if (!metadata?.isFile() || metadata.size > MAX_TEXT_BYTES) continue
      const content = await readFile(absolute, "utf8").catch(() => undefined)
      if (content === undefined) continue
      if (kind === "documentation" && !/\b(?:storePassword|keyPassword)\b/.test(content)) continue
      candidates.push({ relativePath, kind, content })
    }
  }
  return candidates
}

async function inspectGitExposure(
  projectPath: string,
  candidates: ReadonlyArray<Omit<SigningMaterialInput, "gitExposure">>,
): Promise<Map<string, GitExposure>> {
  const result = new Map(candidates.map((candidate) => [candidate.relativePath, "unknown" as GitExposure]))
  if (candidates.length === 0) return result
  try {
    const rootResult = await runProcess({
      command: "git",
      args: ["-C", projectPath, "rev-parse", "--show-toplevel"],
      cwd: projectPath,
      timeoutMs: 5000,
    })
    if (rootResult.exitCode !== 0) return result
    const gitRoot = rootResult.stdout.trim()
    if (!gitRoot) return result

    for (const candidate of candidates) {
      const absolute = path.resolve(projectPath, candidate.relativePath)
      const gitRelative = path.relative(gitRoot, absolute).replaceAll("\\", "/")
      if (gitRelative.startsWith("../") || path.isAbsolute(gitRelative)) continue
      const tracked = await runProcess({
        command: "git",
        args: ["-C", gitRoot, "ls-files", "--error-unmatch", "--", gitRelative],
        cwd: gitRoot,
        timeoutMs: 5000,
      })
      if (tracked.exitCode === 0) {
        result.set(candidate.relativePath, "tracked")
        continue
      }
      const history = await runProcess({
        command: "git",
        args: ["-C", gitRoot, "log", "--all", "-n", "1", "--format=%H", "--", gitRelative],
        cwd: gitRoot,
        timeoutMs: 5000,
      })
      result.set(candidate.relativePath, history.exitCode === 0 && Boolean(history.stdout.trim()) ? "history" : "untracked")
    }
  } catch {
    // Keep "unknown": filesystem findings remain valid when Git is unavailable.
  }
  return result
}

export async function auditSigningMaterials(
  projectPath: string,
  onProgress?: (message: string) => void,
): Promise<Finding[]> {
  onProgress?.("检查签名属性、密钥库、文档与 Git 暴露状态")
  const candidates = await collectCandidates(projectPath)
  const gitStates = await inspectGitExposure(projectPath, candidates)
  const inputs: SigningMaterialInput[] = candidates.map((candidate) => ({
    ...candidate,
    gitExposure: gitStates.get(candidate.relativePath) ?? "unknown",
  }))
  return analyzeSigningMaterials(inputs)
}
