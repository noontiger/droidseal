import type { Finding, SignatureExpectationStatus, SignatureSelfCheckEvidence } from "./types.ts"

export interface SignatureSourceFile {
  relativePath: string
  content: string
}

export interface SignatureSelfCheckAnalysis {
  evidence?: SignatureSelfCheckEvidence
  findings: Finding[]
}

interface MethodBlock {
  name: string
  body: string
  relativePath: string
  bodyOffset: number
  declarationOffset: number
}

interface ExpectationCandidate {
  name: string
  status: SignatureExpectationStatus
  fingerprint?: string
  location: string
}

const FINGERPRINT_LITERAL = /(["'])((?:[0-9A-Fa-f]{64})|(?:(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}))\1/g
const SIGNING_API = /\b(?:GET_SIGNING_CERTIFICATES|GET_SIGNATURES|SigningInfo|signingCertificateHistory|apkContentsSigners|getPackageInfo)\b/
const SHA256_API = /MessageDigest\s*\.\s*getInstance\s*\(\s*["']SHA-?256["']\s*\)|\b(?:sha256|sha_256|SHA256)\s*\(/i
const DISPOSITION = /\b(?:finishAffinity|finishAndRemoveTask|exitProcess|System\s*\.\s*exit|Process\s*\.\s*killProcess|throw\s+(?:new\s+)?SecurityException|Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exit)\b/
const CHECK_NAME = /(?:verify|check|validate|is)[A-Za-z0-9_$]*(?:signature|signing|certificate|cert)|(?:signature|signing|certificate|cert)[A-Za-z0-9_$]*(?:valid|match|trusted|expected)/i
const STARTUP_METHODS = new Set(["oncreate", "attachbasecontext"])

function lineNumber(source: string, offset: number): number {
  let line = 1
  for (let index = 0; index < offset; index += 1) if (source.charCodeAt(index) === 10) line += 1
  return line
}

function location(file: SignatureSourceFile, offset: number): string {
  return `${file.relativePath}:${lineNumber(file.content, Math.max(0, offset))}`
}

function endOfBlock(source: string, open: number): number | undefined {
  let depth = 0
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1
    else if (source[index] === "}") {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return undefined
}

function methodBlocks(file: SignatureSourceFile): MethodBlock[] {
  const declarations = [
    /\bfun\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)[^{=]*\{/g,
    /(?:^|\n)\s*(?:(?:public|private|protected|static|final|synchronized|override|open|internal)\s+)*(?:[\w$.<>\[\]?]+\s+)+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?\{/gm,
  ]
  const blocks: MethodBlock[] = []
  const seen = new Set<number>()
  for (const declaration of declarations) {
    for (const match of file.content.matchAll(declaration)) {
      const declarationOffset = match.index ?? 0
      const open = file.content.indexOf("{", declarationOffset)
      if (open < 0 || seen.has(open)) continue
      const close = endOfBlock(file.content, open)
      if (close === undefined) continue
      seen.add(open)
      blocks.push({
        name: match[1]!,
        body: file.content.slice(open + 1, close),
        relativePath: file.relativePath,
        bodyOffset: open + 1,
        declarationOffset,
      })
    }
  }
  return blocks.sort((a, b) => a.declarationOffset - b.declarationOffset)
}

function isExpectationName(name: string): boolean {
  return /(?:expected|trusted|allowed|release|valid)/i.test(name) &&
    /(?:signature|signing|cert|fingerprint|sha256|digest)/i.test(name)
}

function nearestExpectationName(prefix: string): string | undefined {
  const identifiers = [...prefix.matchAll(/\b[A-Za-z_$][\w$]*\b/g)]
  for (let index = identifiers.length - 1; index >= 0; index -= 1) {
    const match = identifiers[index]!
    const name = match[0]
    if (!isExpectationName(name)) continue
    const gap = prefix.slice((match.index ?? 0) + name.length)
    if (/=[\s\S]*$/.test(gap) && !/;[^=]*$/.test(gap)) return name
  }
  return undefined
}

function normalizedFingerprint(value: string): string {
  return value.replaceAll(":", "").toLowerCase()
}

function looksPlaceholderFingerprint(value: string): boolean {
  return new Set(value.toLowerCase()).size < 4
}

function expectationCandidates(file: SignatureSourceFile): ExpectationCandidate[] {
  const candidates: ExpectationCandidate[] = []
  for (const match of file.content.matchAll(FINGERPRINT_LITERAL)) {
    const offset = match.index ?? 0
    const prefix = file.content.slice(Math.max(0, offset - 1_200), offset)
    const name = nearestExpectationName(prefix)
    if (!name) continue
    const fingerprint = normalizedFingerprint(match[2]!)
    candidates.push({
      name,
      status: looksPlaceholderFingerprint(fingerprint) ? "placeholder" : "literal",
      ...(looksPlaceholderFingerprint(fingerprint) ? {} : { fingerprint }),
      location: location(file, offset),
    })
  }

  const assignment = /([^\r\n;]{1,200})=\s*([^\r\n;]+)/g
  for (const match of file.content.matchAll(assignment)) {
    const left = match[1]!
    const expectationNames = [...left.matchAll(/\b[A-Za-z_$][\w$]*\b/g)]
      .map((candidate) => candidate[0])
      .filter(isExpectationName)
    const name = expectationNames.at(-1)
    if (!name || left.trimEnd().endsWith("!")) continue
    const value = match[2]!.trim()
    const where = location(file, match.index ?? 0)
    if (/\b(?:BuildConfig\.[A-Za-z_$][\w$]*|System\s*\.\s*getenv\s*\(|System\s*\.\s*getProperty\s*\(|providers?\s*\.\s*gradleProperty\s*\(|project\s*\.\s*findProperty\s*\()/i.test(value)) {
      candidates.push({ name, status: "unresolved", location: where })
    } else if (/["'][^"']*(?:TODO|YOUR[_ -]?|REPLACE|CHANGE[_ -]?ME|EXPECTED[_ -]?SIGNATURE|<[^>]+>)[^"']*["']/i.test(value)) {
      candidates.push({ name, status: "placeholder", location: where })
    }
  }
  return candidates
}

function signalLocation(
  filesByPath: Map<string, SignatureSourceFile>,
  block: MethodBlock,
  expression: RegExp,
): string | undefined {
  const file = filesByPath.get(block.relativePath)
  const match = expression.exec(block.body)
  expression.lastIndex = 0
  if (!file || !match) return undefined
  return location(file, block.bodyOffset + (match.index ?? 0))
}

function unique(values: Array<string | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))].sort()
}

function evidenceLine(evidence: SignatureSelfCheckEvidence): string {
  const pieces = [
    ...evidence.locations.configuration.map((item) => `config=${item}`),
    ...evidence.locations.signingApi.map((item) => `api=${item}`),
    ...evidence.locations.digest.map((item) => `sha256=${item}`),
    ...evidence.locations.startup.map((item) => `startup=${item}`),
    ...evidence.locations.disposition.map((item) => `disposition=${item}`),
  ]
  return pieces.join(", ").slice(0, 800)
}

export function analyzeSignatureSelfChecks(
  files: readonly SignatureSourceFile[],
  modulePath: string,
): SignatureSelfCheckAnalysis {
  const filesByPath = new Map(files.map((file) => [file.relativePath, file]))
  const candidates = files.flatMap(expectationCandidates)
  const names = new Set(candidates.map((candidate) => candidate.name))
  const blocks = files.flatMap(methodBlocks)
  const verifierMethods = blocks.filter((block) => {
    if (!CHECK_NAME.test(block.name) || !SIGNING_API.test(block.body) || !SHA256_API.test(block.body)) return false
    SIGNING_API.lastIndex = 0
    SHA256_API.lastIndex = 0
    return [...names].some((name) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(block.body)) ||
      candidates.some((candidate) => candidate.fingerprint && block.body.toLowerCase().includes(candidate.fingerprint))
  })
  if (verifierMethods.length === 0) return { findings: [] }

  const verifierNames = new Set(verifierMethods.map((block) => block.name))
  const startupBlocks = blocks.filter((block) => {
    if (!STARTUP_METHODS.has(block.name.toLowerCase())) return false
    return [...verifierNames].some((name) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*\\(`).test(block.body))
  })
  const dispositionBlocks = [
    ...startupBlocks.filter((block) => DISPOSITION.test(block.body)),
    ...verifierMethods.filter((block) => DISPOSITION.test(block.body)),
  ]
  DISPOSITION.lastIndex = 0

  const literalFingerprints = unique(candidates.filter((candidate) => candidate.status === "literal").map((candidate) => candidate.fingerprint))
  const expectedStatus: SignatureExpectationStatus = literalFingerprints.length > 0
    ? "literal"
    : candidates.some((candidate) => candidate.status === "placeholder")
      ? "placeholder"
      : "unresolved"
  const evidence: SignatureSelfCheckEvidence = {
    modulePath,
    expectedStatus,
    expectedFingerprints: literalFingerprints,
    checkMethodNames: [...verifierNames].sort(),
    hasSigningApi: true,
    hasSha256Digest: true,
    startupInvoked: startupBlocks.length > 0,
    forcedDisposition: dispositionBlocks.length > 0,
    locations: {
      configuration: unique(candidates.map((candidate) => candidate.location)),
      signingApi: unique(verifierMethods.map((block) => signalLocation(filesByPath, block, SIGNING_API))),
      digest: unique(verifierMethods.map((block) => signalLocation(filesByPath, block, SHA256_API))),
      startup: unique(startupBlocks.map((block) => {
        const file = filesByPath.get(block.relativePath)
        return file ? location(file, block.declarationOffset) : undefined
      })),
      disposition: unique(dispositionBlocks.map((block) => signalLocation(filesByPath, block, DISPOSITION))),
    },
  }
  const findings: Finding[] = []

  if (expectedStatus === "placeholder") {
    findings.push({
      severity: "high",
      confidence: "confirmed",
      code: "SIGNATURE_SELF_CHECK_PLACEHOLDER",
      title: "App 自签名校验仍使用占位指纹",
      detail: "已交叉观察到 Android 签名 API、SHA-256 与语义明确的校验方法，但期望证书配置仍是占位值；未把占位文本或源码片段写入证据。",
      recommendation: "在受控 release 配置中填入真实发布证书 SHA-256，并保留轮换期允许列表；构建后由 DroidSeal 与最终证书交叉验证。",
      evidence: evidenceLine(evidence),
    })
  } else if (expectedStatus === "unresolved") {
    findings.push({
      severity: "low",
      confidence: "high",
      code: "SIGNATURE_SELF_CHECK_EXPECTED_UNRESOLVED",
      title: "App 自签名校验的期望指纹无法静态解析",
      detail: "校验方法引用 BuildConfig、环境变量或 Gradle 属性中的期望证书值；DroidSeal 不猜测构建时注入内容，因此无法与最终证书自动比较。",
      recommendation: "让 release 构建输出一份不含秘密的期望证书 SHA-256 清单供 CI/DroidSeal 核对，或使用可静态审计的 release 常量。",
      evidence: evidenceLine(evidence),
    })
  } else if (!evidence.startupInvoked) {
    findings.push({
      severity: "medium",
      confidence: "high",
      code: "SIGNATURE_SELF_CHECK_STARTUP_NOT_CONFIRMED",
      title: "未确认 App 自签名校验在启动生命周期执行",
      detail: "已定位期望指纹、Android 签名 API、SHA-256 和校验方法，但未在 onCreate/attachBaseContext 的方法体中观察到对该校验方法的直接调用。",
      recommendation: "在 Application 或首个可信 Activity 的启动路径调用校验，并对延迟初始化、异常路径和多进程入口做真机回归。",
      evidence: evidenceLine(evidence),
    })
  } else if (!evidence.forcedDisposition) {
    findings.push({
      severity: "high",
      confidence: "high",
      code: "SIGNATURE_SELF_CHECK_DISPOSITION_NOT_CONFIRMED",
      title: "App 自签名校验未确认具有强制处置",
      detail: "已确认启动路径调用签名校验，但在启动调用或校验方法中未观察到 finish/退出进程/抛出 SecurityException 等强制处置信号；仅记录日志不能阻止重签包继续运行。",
      recommendation: "让校验失败进入可测试的拒绝路径；客户端处置仍可被补丁绕过，应与服务端授权和完整性信号联合使用。",
      evidence: evidenceLine(evidence),
    })
  } else {
    findings.push({
      severity: "info",
      confidence: "confirmed",
      code: "SIGNATURE_SELF_CHECK_OBSERVED",
      title: "已观察到 App 启动期自签名校验闭环",
      detail: `交叉确认 ${literalFingerprints.length} 个有效 SHA-256 期望指纹、Android 签名 API、SHA-256 摘要、启动调用和强制处置。该静态证据只说明实现与配置存在，不代表无法被补丁或 Hook 绕过。`,
      recommendation: "继续在最终证书、轮换列表和服务端授权之间做 CI/运行时闭环，并通过重签包、旧证书与异常路径真机测试验证。",
      evidence: evidenceLine(evidence),
    })
  }
  return { evidence, findings }
}

function maskFingerprint(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-8)}`
}

export function compareSignatureSelfCheckFingerprints(
  checks: readonly SignatureSelfCheckEvidence[],
  actualFingerprints: readonly string[],
): Finding[] {
  const actual = unique(actualFingerprints.map(normalizedFingerprint).filter((value) => /^[0-9a-f]{64}$/.test(value)))
  if (actual.length === 0) return []
  const findings: Finding[] = []
  for (const check of checks) {
    if (
      check.expectedStatus !== "literal" ||
      !check.hasSigningApi ||
      !check.hasSha256Digest ||
      !check.startupInvoked ||
      !check.forcedDisposition
    ) continue
    const expected = unique(check.expectedFingerprints.map(normalizedFingerprint).filter((value) => /^[0-9a-f]{64}$/.test(value)))
    if (expected.length === 0) continue
    const matched = expected.filter((fingerprint) => actual.includes(fingerprint))
    if (matched.length === 0) {
      findings.push({
        severity: "critical",
        confidence: "confirmed",
        code: "SIGNATURE_SELF_CHECK_CERT_MISMATCH",
        title: "App 自签名校验期望值与最终发布证书不一致",
        detail: `模块 ${check.modulePath} 内置 ${expected.length} 个允许指纹，但没有一个匹配最终 APK 的 ${actual.length} 个签名证书指纹。按当前配置，合法发布包可能在启动时被拒绝，或校验代码使用了错误证书。`,
        recommendation: "停止发布；使用实际发布证书更新允许列表并保留受控轮换项，重新构建、签名后再次验证。不要为通过检查而关闭处置逻辑。",
        evidence: `module=${check.modulePath}, expected=${expected.map(maskFingerprint).join("|")}, actual=${actual.map(maskFingerprint).join("|")}`,
      })
    } else {
      findings.push({
        severity: "info",
        confidence: "confirmed",
        code: "SIGNATURE_SELF_CHECK_CERT_MATCH",
        title: "App 自签名校验允许列表与最终发布证书匹配",
        detail: `模块 ${check.modulePath} 的 ${expected.length} 个允许指纹中有 ${matched.length} 个匹配最终 APK 证书。该结果只证明本次构建配置一致，不证明客户端校验不可被补丁或 Hook 绕过。`,
        recommendation: "保留证书轮换和重签负向测试，并继续由服务端决定高价值授权。",
        evidence: `module=${check.modulePath}, matched=${matched.map(maskFingerprint).join("|")}, allowedCount=${expected.length}, actualCount=${actual.length}`,
      })
    }
  }
  return findings
}
