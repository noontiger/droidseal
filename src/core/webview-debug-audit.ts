import type { Finding } from "./types.ts"

export interface WebViewDebugSourceFile {
  relativePath: string
  content: string
}

export type WebViewDebuggingState =
  | "explicit-disabled"
  | "debug-only-enabled"
  | "release-enabled"
  | "not-explicitly-disabled"
  | "not-applicable"

export interface WebViewDebuggingAnalysis {
  modulePath: string
  state: WebViewDebuggingState
  findings: Finding[]
  locations: {
    explicitFalse: string[]
    debugOnlyTrue: string[]
    releaseTrue: string[]
    unresolved: string[]
    webViewUsage: string[]
  }
}

interface IfSpan {
  start: number
  end: number
  debugOnly: boolean
}

interface CallEvidence {
  kind: "false" | "debug-only-true" | "release-true" | "unresolved"
  location: string
}

const DEBUGGING_CALL = /\b(?:android\s*\.\s*webkit\s*\.\s*)?WebView\s*\.\s*setWebContentsDebuggingEnabled\s*\(\s*([^()\r\n]+?)\s*\)/g
const WEBVIEW_USAGE = /\bimport\s+android\.webkit\.WebView\b|\bandroid\.webkit\.WebView\b|\bWebView\s*[<(.:]|\.loadUrl\s*\(/g

function lineNumber(source: string, offset: number): number {
  let line = 1
  for (let index = 0; index < offset; index += 1) {
    if (source.charCodeAt(index) === 10) line += 1
  }
  return line
}

function location(file: WebViewDebugSourceFile, offset: number): string {
  return `${file.relativePath}:${lineNumber(file.content, Math.max(0, offset))}`
}

/**
 * Replace comments and string/character literal contents with spaces while
 * preserving offsets and newlines. This prevents examples in comments, log
 * text, and documentation strings from becoming security evidence.
 */
function codeOnly(source: string): string {
  const out = source.split("")
  let state: "code" | "line-comment" | "block-comment" | "string" | "char" | "triple" = "code"
  let escaped = false
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index]!
    const next = source[index + 1]
    const nextTwo = source.slice(index, index + 3)
    if (state === "code") {
      if (char === "/" && next === "/") {
        out[index] = out[index + 1] = " "
        index += 1
        state = "line-comment"
      } else if (char === "/" && next === "*") {
        out[index] = out[index + 1] = " "
        index += 1
        state = "block-comment"
      } else if (nextTwo === '\"\"\"') {
        out[index] = out[index + 1] = out[index + 2] = " "
        index += 2
        state = "triple"
      } else if (char === '\"') {
        out[index] = " "
        escaped = false
        state = "string"
      } else if (char === "'") {
        out[index] = " "
        escaped = false
        state = "char"
      }
      continue
    }
    if (char !== "\n" && char !== "\r") out[index] = " "
    if (state === "line-comment" && (char === "\n" || char === "\r")) {
      state = "code"
    } else if (state === "block-comment" && char === "*" && next === "/") {
      out[index + 1] = " "
      index += 1
      state = "code"
    } else if (state === "triple" && nextTwo === '\"\"\"') {
      out[index] = out[index + 1] = out[index + 2] = " "
      index += 2
      state = "code"
    } else if (state === "string" || state === "char") {
      if (escaped) {
        escaped = false
      } else if (char === "\\") {
        escaped = true
      } else if ((state === "string" && char === '\"') || (state === "char" && char === "'")) {
        state = "code"
      }
    }
  }
  return out.join("")
}

function matchingDelimiter(source: string, open: number, left: string, right: string): number | undefined {
  let depth = 0
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === left) depth += 1
    else if (source[index] === right) {
      depth -= 1
      if (depth === 0) return index
    }
  }
  return undefined
}

function conditionRequiresDebugBuild(condition: string): boolean {
  const compact = condition.replace(/\s+/g, "")
  const buildConfig = /(?:[A-Za-z_$][\w$]*\.)*BuildConfig\.DEBUG/
  if (compact.includes("||")) return false
  const match = buildConfig.exec(compact)
  if (match) {
    const before = compact.slice(0, match.index)
    const after = compact.slice(match.index + match[0].length)
    if (before.endsWith("!") || /^(?:==false|!=true)/i.test(after)) return false
    return true
  }
  return /FLAG_DEBUGGABLE/.test(compact) &&
    /(?:!=0|>0|0!=)/.test(compact) &&
    /(?:applicationInfo|getApplicationInfo\(\))/.test(compact)
}

function ifSpans(source: string): IfSpan[] {
  const spans: IfSpan[] = []
  for (const match of source.matchAll(/\bif\s*\(/g)) {
    const start = match.index ?? 0
    const open = source.indexOf("(", start)
    const close = matchingDelimiter(source, open, "(", ")")
    if (close === undefined) continue
    let bodyStart = close + 1
    while (/\s/.test(source[bodyStart] ?? "")) bodyStart += 1
    let end: number
    if (source[bodyStart] === "{") {
      end = matchingDelimiter(source, bodyStart, "{", "}") ?? source.length
    } else {
      const lineEnd = source.indexOf("\n", bodyStart)
      const semicolon = source.indexOf(";", bodyStart)
      const candidates = [lineEnd, semicolon].filter((value) => value >= 0)
      end = candidates.length > 0 ? Math.min(...candidates) : source.length
    }
    spans.push({
      start: bodyStart,
      end,
      debugOnly: conditionRequiresDebugBuild(source.slice(open + 1, close)),
    })
  }
  return spans
}

function normalizedArgument(value: string): string {
  let out = value.replace(/\s+/g, "")
  while (out.startsWith("(") && out.endsWith(")")) out = out.slice(1, -1)
  return out
}

function isDebugSource(relativePath: string): boolean {
  return /(^|\/)src\/debug\//i.test(relativePath.replaceAll("\\", "/"))
}

function buildConfigArgumentState(value: string): "debug-only" | "release-enabled" | undefined {
  const id = "(?:[A-Za-z_$][\\w$]*\\.)*BuildConfig\\.DEBUG"
  const debugOnly = new RegExp("^(?:" + id + "(?:==true|!=false)?|true==" + id + "|false!=" + id + ")$")
  if (debugOnly.test(value)) return "debug-only"
  const releaseEnabled = new RegExp("^(?:!" + id + "|" + id + "(?:==false|!=true)|false==" + id + "|true!=" + id + ")$")
  if (releaseEnabled.test(value)) return "release-enabled"
  return undefined
}

function analyzeCalls(file: WebViewDebugSourceFile, source: string): CallEvidence[] {
  const spans = ifSpans(source)
  const calls: CallEvidence[] = []
  for (const match of source.matchAll(DEBUGGING_CALL)) {
    const offset = match.index ?? 0
    const argument = normalizedArgument(match[1]!)
    const where = location(file, offset)
    if (/^(?:false|Boolean\.FALSE)$/.test(argument)) {
      calls.push({ kind: "false", location: where })
    } else if (/^(?:true|Boolean\.TRUE)$/.test(argument)) {
      const debugGuarded = isDebugSource(file.relativePath) ||
        spans.some((span) => span.debugOnly && offset >= span.start && offset <= span.end)
      calls.push({ kind: debugGuarded ? "debug-only-true" : "release-true", location: where })
    } else if (buildConfigArgumentState(argument) === "debug-only") {
      calls.push({ kind: "debug-only-true", location: where })
    } else if (buildConfigArgumentState(argument) === "release-enabled") {
      calls.push({ kind: "release-true", location: where })
    } else {
      calls.push({ kind: "unresolved", location: where })
    }
  }
  return calls
}

function unique(values: string[]): string[] {
  return [...new Set(values)].sort()
}

function evidence(values: string[]): string {
  return values.join(", ").slice(0, 800)
}

export function analyzeWebViewDebugging(
  files: readonly WebViewDebugSourceFile[],
  modulePath: string,
): WebViewDebuggingAnalysis {
  const locations = {
    explicitFalse: [] as string[],
    debugOnlyTrue: [] as string[],
    releaseTrue: [] as string[],
    unresolved: [] as string[],
    webViewUsage: [] as string[],
  }
  for (const file of files) {
    const source = codeOnly(file.content)
    const usage = WEBVIEW_USAGE.exec(source)
    WEBVIEW_USAGE.lastIndex = 0
    if (usage) locations.webViewUsage.push(location(file, usage.index ?? 0))
    for (const call of analyzeCalls(file, source)) {
      if (call.kind === "false") locations.explicitFalse.push(call.location)
      else if (call.kind === "debug-only-true") locations.debugOnlyTrue.push(call.location)
      else if (call.kind === "release-true") locations.releaseTrue.push(call.location)
      else locations.unresolved.push(call.location)
    }
  }
  for (const values of Object.values(locations)) values.splice(0, values.length, ...unique(values))

  if (locations.webViewUsage.length === 0) {
    return { modulePath, state: "not-applicable", findings: [], locations }
  }
  if (locations.releaseTrue.length > 0) {
    return {
      modulePath,
      state: "release-enabled",
      locations,
      findings: [{
        severity: "high",
        confidence: "confirmed",
        code: "SOURCE_WEBVIEW_DEBUGGING_ENABLED_IN_RELEASE",
        title: "WebView 调试在 release 可达路径中被显式开启",
        detail: `模块 ${modulePath} 的 main/release 源码存在未受可确认 DEBUG 条件保护的 setWebContentsDebuggingEnabled(true)。发布包可通过 Chrome DevTools 检查 WebView、执行脚本或读取页面状态。注释和字符串中的示例已排除。`,
        recommendation: "在 Application.onCreate 且创建任何 WebView 之前显式调用 WebView.setWebContentsDebuggingEnabled(false)；如开发确需调试，只允许在 BuildConfig.DEBUG 条件或 src/debug 中开启，并回归 release 产物。",
        evidence: evidence(locations.releaseTrue),
      }],
    }
  }
  if (locations.unresolved.length === 0 && locations.explicitFalse.length > 0) {
    return {
      modulePath,
      state: "explicit-disabled",
      locations,
      findings: [{
        severity: "info",
        confidence: "confirmed",
        code: "SOURCE_WEBVIEW_DEBUGGING_EXPLICITLY_DISABLED",
        title: "WebView 调试已显式关闭",
        detail: `模块 ${modulePath} 明确调用 setWebContentsDebuggingEnabled(false)，且未观察到 release 可达的 true 或无法解析的动态参数；DEBUG 条件内的 true 不改变该结论。`,
        recommendation: "保持关闭调用早于首个 WebView 创建，并在 release 真机/自动化测试中确认 Chrome DevTools 无法发现该 WebView。",
        evidence: evidence([...locations.explicitFalse, ...locations.debugOnlyTrue]),
      }],
    }
  }
  if (locations.unresolved.length === 0 && locations.debugOnlyTrue.length > 0) {
    return {
      modulePath,
      state: "debug-only-enabled",
      locations,
      findings: [{
        severity: "info",
        confidence: "confirmed",
        code: "SOURCE_WEBVIEW_DEBUGGING_DEBUG_ONLY",
        title: "WebView 调试仅在可确认的 DEBUG 路径开启",
        detail: `模块 ${modulePath} 仅在 src/debug、BuildConfig.DEBUG 参数或可确认 DEBUG 条件内开启 WebView 调试；未观察到 release 可达的 true。`,
        recommendation: "继续让 release Manifest 保持 debuggable=false，并对最终发布 APK 做真机 DevTools 不可发现回归；自定义 flavor 条件仍需人工核对。",
        evidence: evidence(locations.debugOnlyTrue),
      }],
    }
  }
  return {
    modulePath,
    state: "not-explicitly-disabled",
    locations,
    findings: [{
      severity: "info",
      confidence: "low",
      code: "SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED",
      title: "未观察到 WebView 调试的明确 release 关闭证据",
      detail: locations.unresolved.length > 0
        ? `模块 ${modulePath} 使用 WebView，但 setWebContentsDebuggingEnabled 的参数无法静态解析；DroidSeal 不猜测运行时值，也不把平台默认关闭当成源码闭环。`
        : `模块 ${modulePath} 使用 WebView，但在 main/release/debug 源码中未观察到 setWebContentsDebuggingEnabled(false) 或仅限 DEBUG 的显式配置。Android 当前默认关闭不等同于可复核的 release 配置。`,
      recommendation: "在 Application.onCreate 且创建任何 WebView 之前显式关闭调试；若 debug 构建需要开启，使用 BuildConfig.DEBUG 或 src/debug，并用 release APK 做 DevTools 不可发现验证。",
      evidence: evidence([...locations.unresolved, ...locations.webViewUsage]),
    }],
  }
}
