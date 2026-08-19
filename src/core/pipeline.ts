import path from "node:path"
import { copyFile, mkdir, readdir, rm, stat } from "node:fs/promises"
import { auditApk, parseZipEntries, sha256File } from "./apk-audit.ts"
import { DroidSealError, explainCommandFailure, normalizeError } from "./errors.ts"
import { flipDebuggableFalse, manifestBytesAreDebuggable, readManifestXmlBytes } from "./harden-manifest.ts"
import { stripApkEntries } from "./apk-strip.ts"
import { obfuscateArscInApk } from "./lossy-harden.ts"
import { inspectHybridWebAssetsInApk, minifyHybridWebAssetsInApk } from "./web-asset-minify.ts"
import {
  detectCapacitorProject,
  detectNodeTools,
  parseJavaMajor,
  patchCapacitorJavaVersion,
} from "./capacitor-build.ts"
import { gradleJvmArgsString, runProcess } from "./process.ts"
import { auditProject, detectReleaseMinifyEnabled } from "./project-audit.ts"
import { analyzeApksignerVerbose, analyzeCertPrint, buildSigningFindings } from "./signing-audit.ts"
import { compareSignatureSelfCheckFingerprints } from "./signature-self-check.ts"
import { writeReports } from "./report.ts"
import { selectedMissingTools } from "./tool-installer.ts"
import { discoverToolchain } from "./toolchain.ts"
import type {
  CommandResult,
  Finding,
  PipelineConfig,
  PipelineEvent,
  RunContext,
  SkipKind,
  StepId,
  StepResult,
  StepState,
  StepStatus,
  ToolLocation,
} from "./types.ts"

interface OperationResult {
  status?: "success" | "skipped"
  skipKind?: SkipKind
  summary: string
  detail?: string[]
  artifactAfter?: string
  command?: CommandResult
  findings?: Finding[]
}

interface StepDefinition {
  id: StepId
  title: string
  description: string
  skippable: boolean
}

export const STEP_DEFINITIONS: readonly StepDefinition[] = [
  { id: "doctor", title: "环境诊断", description: "检查本次流程需要的 JDK、Android Build Tools 与 Gradle Wrapper", skippable: true },
  { id: "prepare", title: "准备工作区", description: "检查输入并创建工作副本，原文件保持不变", skippable: false },
  { id: "keystore", title: "签名库", description: "签名前先验证现有 JKS/PKCS12 或创建新签名库，尽早发现密码/别名问题", skippable: true },
  { id: "source-audit", title: "源码安全审计", description: "检查 release、R8、Manifest 与明文签名密码", skippable: true },
  { id: "build", title: "构建 Release APK", description: "使用项目自己的 Gradle Wrapper 生成 APK", skippable: false },
  { id: "apk-audit", title: "APK 安全审计", description: "检查 ZIP 结构、Manifest、DEX、SO 与元数据", skippable: true },
  { id: "protect", title: "本地安全防护", description: "核验 R8、DEX、反调试与完整性证据，确定商业加固前可安全执行的边界", skippable: true },
  { id: "harden", title: "Release 归一化", description: "强制 debuggable=false，保证最终产物为安全 Release 状态", skippable: true },
  { id: "web-assets", title: "Web JS 发布处理", description: "可选：压缩混淆混合应用 JavaScript 并移除 source map，签名前生成新包", skippable: true },
  { id: "arsc-obfuscate", title: "资源名混淆", description: "可选有损：重命名 resources.arsc 资源名并扁平化资源路径，签名前生成新包", skippable: true },
  { id: "align", title: "ZIP 对齐", description: "签名前用 zipalign 生成独立的对齐 APK", skippable: true },
  { id: "sign", title: "APK 签名", description: "使用 apksigner 和内存中的密码生成已签名 APK", skippable: true },
  { id: "verify", title: "最终验证", description: "验证 zipalign、签名方案、证书并计算 SHA-256", skippable: true },
  { id: "report", title: "生成报告", description: "保存最终 APK，并生成 JSON/Markdown、发布证据、SBOM 与修复资料", skippable: true },
] as const

export function stepGuidance(stepId: StepId, config: PipelineConfig): string[] {
  const common: Record<StepId, string> = {
    doctor: "只检查工具位置和版本，不修改 APK 或系统 PATH。",
    prepare: "APK 输入会先复制到本次运行目录；后续步骤不会覆盖原文件。",
    "source-audit": "读取 Gradle 与 Manifest 配置（含权限模型、导出/深链组件、meta-data 密钥、网络安全配置与备份规则），不自动修改源码。",
    build: `执行 ${config.gradleTask}，再把生成的 APK 复制到工作区。`,
    "apk-audit": "读取 APK 的 ZIP、Manifest（权限、导出/深链组件、合规、meta-data 密钥）、DEX 字符串与 SO 加固信息，不修改 APK。",
    protect: "执行本地安全档：结合源码/APK 证据核验保护覆盖；R8、Release 归一化、可选资源混淆、对齐、签名和验证由对应步骤落实。证据不足只作低置信度提示，不对未知 APK 注入启动代码。",
    harden: config.signing.mode === "skip"
      ? "在对齐前，把二进制 Manifest 的 android:debuggable 强制改为 false；最终验证会再次确认。当前不重新签名，因此检测到有效现有签名时不会剔除残留条目，避免产出无法安装的 APK。"
      : "在对齐和签名前，把二进制 Manifest 的 android:debuggable 强制改为 false；最终验证会再次确认。",
    "web-assets": config.enableWebAssetMinification
      ? "显式可选步骤：仅处理 assets/public 与 assets/www 下的 JavaScript；ES module 才启用顶层 mangle，普通脚本保留可能被 HTML/其他脚本调用的全局名。全部脚本成功后才原子写出，并移除 source map。压缩混淆只提高阅读门槛，不等于保密。"
      : "当前未开启 Web JavaScript 发布处理；本步骤按配置跳过，不改写 APK 内前端资产。",
    "arsc-obfuscate": config.enableArscObfuscation
      ? "有损可选步骤：解析 resources.arsc 并做严格兼容性预检；出现 getIdentifier 时保留全部条目名，DEX 直接引用的资源路径也保留，其余项才重命名。生成新包后仍会重新对齐与签名。"
      : "当前未开启资源名混淆，本步骤会按配置跳过，不改写任何资源。",
    align: "zipalign 必须在签名前执行；未重签时会优先保护已有 v2/v3 签名。",
    keystore: config.signing.mode === "skip"
      ? "当前选择“不重新签名”，因此无需读取签名库。"
      : "只验证签名库、密码和 PrivateKeyEntry 别名，不修改签名库。",
    sign: config.signing.mode === "skip"
      ? "当前选择“不重新签名”；下一步仍会验证 APK 的现有签名。"
      : "apksigner 会生成新的已签名副本，不覆盖输入 APK。",
    verify: "独立验证 zipalign、APK 签名方案与证书（含签名方案覆盖、证书有效期、调试证书与弱密钥检测），并计算 SHA-256。",
    report: "保存最终 APK、JSON/Markdown、发布证据、CycloneDX SBOM、许可证待核验清单及置信度感知发布门禁；外部控制不会被静态信号误标为已完成，密码与 keystore 不会进入制品。",
  }
  const applicability =
    stepId === "source-audit" && config.inputKind === "apk"
      ? "输入是 APK，本步骤会标记为“跳过·不适用”；后续 APK 安全审计仍会执行。"
      : stepId === "build" && config.inputKind === "apk"
        ? "输入已经是 APK，本步骤会标记为“跳过·不适用”，不会重复构建。"
        : undefined
  return applicability ? [common[stepId], applicability] : [common[stepId]]
}

function runId(): string {
  const timestamp = new Date().toISOString().replace(/[-:TZ.]/g, "").slice(0, 14)
  const random = crypto.getRandomValues(new Uint8Array(3)).toHex()
  return `${timestamp}-${random}`
}

function emptyContext(config: PipelineConfig): RunContext {
  const id = runId()
  const runDirectory = path.join(path.resolve(config.outputDirectory), ".droidseal", "runs", id)
  return {
    runId: id,
    runDirectory,
    artifactDirectory: path.join(runDirectory, "artifacts"),
    reportDirectory: path.join(runDirectory, "reports"),
    currentArtifact: undefined,
    originalArtifact: undefined,
    finalArtifact: undefined,
    toolchain: undefined,
    audit: { findings: [] },
    stepResults: [],
  }
}

function resultWithOptional(
  base: Omit<StepResult, "skipKind" | "artifactBefore" | "artifactAfter" | "rollbackMessage" | "command" | "findings">,
  optional: {
    skipKind?: SkipKind | undefined
    artifactBefore?: string | undefined
    artifactAfter?: string | undefined
    rollbackMessage?: string | undefined
    command?: CommandResult | undefined
    findings?: Finding[] | undefined
  },
): StepResult {
  const result: StepResult = { ...base }
  if (optional.skipKind !== undefined) result.skipKind = optional.skipKind
  if (optional.artifactBefore !== undefined) result.artifactBefore = optional.artifactBefore
  if (optional.artifactAfter !== undefined) result.artifactAfter = optional.artifactAfter
  if (optional.rollbackMessage !== undefined) result.rollbackMessage = optional.rollbackMessage
  if (optional.command !== undefined) result.command = optional.command
  if (optional.findings !== undefined) result.findings = optional.findings
  return result
}

async function newestApk(
  root: string,
  matches: (name: string) => boolean = (name) => name.toLowerCase().endsWith(".apk"),
): Promise<string | undefined> {
  const candidates: Array<{ file: string; modified: number }> = []
  const queue = [root]
  while (queue.length > 0) {
    const directory = queue.shift()
    if (!directory) continue
    let entries
    try {
      entries = await readdir(directory, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) {
        queue.push(absolute)
      } else if (matches(entry.name)) {
        const info = await stat(absolute)
        candidates.push({ file: absolute, modified: info.mtimeMs })
      }
    }
  }
  candidates.sort((a, b) => b.modified - a.modified)
  return candidates[0]?.file
}

function requiredTool(tool: ToolLocation, stepId: StepId): string {
  if (tool.path) return tool.path
  throw new DroidSealError({
    code: "REQUIRED_TOOL_MISSING",
    message: `未找到 ${tool.name}`,
    explanation: `${tool.name} 是“${STEP_DEFINITIONS.find((step) => step.id === stepId)?.title ?? stepId}”步骤的必需工具。`,
    suggestions: [
      "安装 Android SDK Build Tools/JDK",
      "设置 ANDROID_SDK_ROOT、ANDROID_HOME 或 JAVA_HOME",
      "重新执行环境诊断",
    ],
    stepId,
  })
}

function distinguishName(config: Extract<PipelineConfig["signing"], { mode: "create" }>): string {
  const fields: Array<[string, string]> = [
    ["CN", config.distinguishedName.commonName],
    ["OU", config.distinguishedName.organizationalUnit],
    ["O", config.distinguishedName.organization],
    ["L", config.distinguishedName.locality],
    ["ST", config.distinguishedName.state],
    ["C", config.distinguishedName.country.toUpperCase()],
  ]
  return fields
    .filter(([, value]) => value.trim())
    .map(([key, value]) => `${key}=${value.replaceAll("\\", "\\\\").replaceAll(",", "\\,")}`)
    .join(", ")
}

function artifactName(inputPath: string, suffix: string): string {
  const base = path.basename(inputPath, path.extname(inputPath)).replace(/[^\p{L}\p{N}._-]+/gu, "-")
  return `${base || "application"}-${suffix}.apk`
}

function findingLine(finding: Finding): string {
  const confidence = finding.confidence
    ? ` · 证据${{ confirmed: "已确认", high: "高", medium: "中", low: "低" }[finding.confidence]}`
    : ""
  return `[${finding.severity}${confidence}] ${finding.title}`
}

// "unknown" means apksigner was unavailable, so the signature can neither be confirmed nor
// ruled out. Callers must treat it as conservatively as "valid".
type SignatureState = "valid" | "invalid" | "unknown"

// Gradle init script (build-time overlay) that force-enables R8 for the release build type
// WITHOUT modifying the developer's tracked source files. Applied only to this DroidSeal build.
const FORCE_R8_INIT_SCRIPT = `// Generated by DroidSeal — forces R8/minify for release without editing project sources.
gradle.beforeProject { project ->
    project.plugins.withId('com.android.application') {
        def android = project.extensions.findByName('android')
        if (android != null) {
            android.buildTypes.named('release').configure { bt ->
                bt.minifyEnabled = true
                bt.shrinkResources = true
                bt.proguardFiles android.getDefaultProguardFile('proguard-android-optimize.txt')
                def rules = project.file('proguard-rules.pro')
                if (rules.exists()) {
                    bt.proguardFiles rules
                }
            }
        }
    }
}
`

export class Pipeline {
  readonly config: PipelineConfig
  readonly context: RunContext
  private readonly listeners = new Set<(event: PipelineEvent) => void>()
  private readonly states = new Map<StepId, StepState>()

  constructor(config: PipelineConfig) {
    this.config = config
    this.context = emptyContext(config)
    for (const definition of STEP_DEFINITIONS) {
      this.states.set(definition.id, { ...definition, status: "pending" })
    }
  }

  onEvent(listener: (event: PipelineEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  getSteps(): StepState[] {
    return STEP_DEFINITIONS.map((definition) => this.states.get(definition.id)!)
  }

  getStep(stepId: StepId): StepState {
    return this.states.get(stepId)!
  }

  async retryStep(stepId: StepId): Promise<StepResult> {
    const state = this.getStep(stepId)
    if (state.status === "processing") {
      throw new Error(`Step ${stepId} is still processing`)
    }
    if (state.result) {
      this.context.stepResults = this.context.stepResults.filter((result) => result !== state.result)
      delete state.result
    }
    state.status = "pending"
    return await this.runStep(stepId)
  }

  private emit(event: PipelineEvent): void {
    for (const listener of this.listeners) listener(event)
  }

  private progress(stepId: StepId, message: string): void {
    this.emit({ type: "step-progress", stepId, message })
  }

  async skipStep(stepId: StepId, reason = "用户选择跳过"): Promise<StepResult> {
    const state = this.getStep(stepId)
    if (!state.skippable) {
      throw new DroidSealError({
        code: "MANDATORY_STEP",
        message: `“${state.title}”不能手动跳过`,
        explanation: "该步骤负责建立后续步骤所需的有效输入或工作区。",
        stepId,
      })
    }
    const startedAt = new Date().toISOString()
    const result = resultWithOptional(
      {
        id: stepId,
        status: "skipped",
        title: state.title,
        summary: reason,
        detail: [
          "跳过类型：用户选择。这不是执行失败。",
          "影响：本步骤没有运行，当前有效 APK 未发生变化；报告会保留这项选择。",
        ],
        startedAt,
        finishedAt: new Date().toISOString(),
        durationMs: 0,
      },
      {
        skipKind: "user-choice",
        artifactBefore: this.context.currentArtifact,
        artifactAfter: this.context.currentArtifact,
        rollbackMessage: "当前有效 APK 已保留，流程可以继续。",
      },
    )
    state.status = "skipped"
    state.result = result
    this.context.stepResults.push(result)
    this.emit({ type: "step-finished", step: state, result })
    return result
  }

  async runStep(stepId: StepId): Promise<StepResult> {
    const state = this.getStep(stepId)
    if (state.status !== "pending") {
      if (state.result) return state.result
      throw new Error(`Step ${stepId} is already ${state.status}`)
    }

    const artifactBefore = this.context.currentArtifact
    const started = performance.now()
    const startedAt = new Date().toISOString()
    state.status = "processing"
    this.emit({ type: "step-started", step: state })

    try {
      const operation = await this.execute(stepId)
      if (operation.artifactAfter) this.context.currentArtifact = operation.artifactAfter
      const result = resultWithOptional(
        {
          id: stepId,
          status: operation.status ?? "success",
          title: state.title,
          summary: operation.summary,
          detail: operation.detail ?? [],
          startedAt,
          finishedAt: new Date().toISOString(),
          durationMs: Math.round(performance.now() - started),
        },
        {
          skipKind: operation.skipKind,
          artifactBefore,
          artifactAfter: this.context.currentArtifact,
          command: operation.command,
          findings: operation.findings,
        },
      )
      state.status = result.status
      state.result = result
      this.context.stepResults.push(result)
      this.emit({ type: "step-finished", step: state, result })
      if (stepId === "report") await writeReports(this.config, this.context)
      return result
    } catch (caught) {
      this.context.currentArtifact = artifactBefore
      const error = normalizeError(caught, stepId)
      const detail = [`原因：${error.explanation}`, ...error.suggestions.map((suggestion) => `处理建议：${suggestion}`)]
      if (error.causeResult?.stderr.trim()) detail.push(`工具输出（已脱敏）：${error.causeResult.stderr.trim().slice(0, 6_000)}`)
      const result = resultWithOptional(
        {
          id: stepId,
          status: "failed",
          title: state.title,
          summary: `${error.message} [${error.code}]`,
          detail,
          startedAt,
          finishedAt: new Date().toISOString(),
          durationMs: Math.round(performance.now() - started),
        },
        {
          artifactBefore,
          artifactAfter: artifactBefore,
          rollbackMessage: artifactBefore
            ? `回退完成：失败输出未采用，继续使用步骤开始前的 APK：${artifactBefore}`
            : "回退完成：本步骤没有留下输出；当前还没有可供后续步骤使用的 APK。",
          command: error.causeResult,
        },
      )
      state.status = "failed"
      state.result = result
      this.context.stepResults.push(result)
      this.emit({ type: "step-finished", step: state, result })
      return result
    }
  }

  private async execute(stepId: StepId): Promise<OperationResult> {
    switch (stepId) {
      case "doctor":
        return await this.doctor()
      case "prepare":
        return await this.prepare()
      case "source-audit":
        return await this.sourceAudit()
      case "build":
        return await this.build()
      case "apk-audit":
        return await this.apkAudit()
      case "protect":
        return await this.protect()
      case "harden":
        return await this.harden()
      case "web-assets":
        return await this.webAssets()
      case "arsc-obfuscate":
        return await this.arscObfuscate()
      case "align":
        return await this.align()
      case "keystore":
        return await this.keystore()
      case "sign":
        return await this.sign()
      case "verify":
        return await this.verify()
      case "report":
        return await this.report()
    }
  }

  private async doctor(): Promise<OperationResult> {
    this.context.audit.findings = this.context.audit.findings.filter(
      (finding) => !finding.code.startsWith("TOOL_"),
    )
    this.progress("doctor", "搜索 PATH、JAVA_HOME 与 Android SDK")
    const toolchain = await discoverToolchain(this.config)
    this.context.toolchain = toolchain

    const missing = selectedMissingTools(this.config, toolchain)
    const findings = missing.map<Finding>((tool) => ({
      severity: "high",
      code: `TOOL_${tool.name.toUpperCase().replaceAll(/\W+/g, "_")}_MISSING`,
      title: `缺少 ${tool.name}`,
      detail: `${tool.detail}不可用；对应步骤会解释错误并回退。`,
      recommendation: "安装所需 JDK/Android SDK Build Tools，并重新运行环境诊断。",
    }))
    this.context.audit.findings.push(...findings)

    if (missing.length > 0) {
      throw new DroidSealError({
        code: "TOOLCHAIN_INCOMPLETE",
        message: `所选流程缺少 ${missing.map((tool) => tool.name).join("、")}`,
        explanation: "DroidSeal 已暂停流水线，未启动后续构建、签名或修改操作。",
        suggestions: [
          "在界面中选择“下载并继续”，安装完成后会重新诊断并自动续跑",
          "也可以查看安装说明，手动安装后点击“已安装，重新检测”",
        ],
        stepId: "doctor",
      })
    }

    const tools = [
      toolchain.java,
      toolchain.keytool,
      toolchain.aapt,
      toolchain.zipalign,
      toolchain.apksigner,
      toolchain.gradleWrapper,
    ]
    return {
      summary: missing.length === 0 ? "所选流程的必需工具均可用" : `发现 ${missing.length} 个必需工具缺失`,
      detail: tools.map((tool) => `${tool.path ? "✓" : "○"} ${tool.name}: ${tool.path ?? "未找到"} (${tool.source})`),
      findings,
    }
  }

  private async prepare(): Promise<OperationResult> {
    const input = path.resolve(this.config.inputPath)
    const info = await stat(input).catch(() => undefined)
    if (!info) {
      throw new DroidSealError({
        code: "INPUT_NOT_FOUND",
        message: "输入路径不存在",
        explanation: `没有找到 ${input}。路径可能拼写错误、网络盘未连接或文件已被移动。`,
        suggestions: ["输入绝对路径", "确认当前用户有读取权限"],
        stepId: "prepare",
      })
    }
    if (this.config.inputKind === "apk" && !info.isFile()) {
      throw new DroidSealError({
        code: "INPUT_NOT_APK_FILE",
        message: "APK 输入必须是文件",
        explanation: "当前路径是目录；请选择具体的 .apk 文件。",
        stepId: "prepare",
      })
    }
    if (this.config.inputKind === "project" && !info.isDirectory()) {
      throw new DroidSealError({
        code: "INPUT_NOT_PROJECT_DIRECTORY",
        message: "项目输入必须是目录",
        explanation: "请选择包含 gradlew/gradlew.bat 的 Android 项目根目录。",
        stepId: "prepare",
      })
    }

    await Promise.all([
      mkdir(this.context.artifactDirectory, { recursive: true }),
      mkdir(this.context.reportDirectory, { recursive: true }),
      mkdir(path.resolve(this.config.outputDirectory), { recursive: true }),
    ])

    if (this.config.inputKind === "project") {
      return {
        summary: "项目路径与事务工作区已准备",
        detail: [`项目：${input}`, `运行目录：${this.context.runDirectory}`, "后续构建产物会复制后再处理。"],
      }
    }

    const prepared = path.join(this.context.artifactDirectory, "01-input.apk")
    this.progress("prepare", "复制输入 APK，原文件保持只读")
    await copyFile(input, prepared)
    this.context.originalArtifact = input
    return {
      summary: "输入 APK 已复制到隔离工作区",
      detail: [`原文件：${input}`, `工作副本：${prepared}`, "所有后续步骤只产生新文件，不原地覆盖。"],
      artifactAfter: prepared,
    }
  }

  private async sourceAudit(): Promise<OperationResult> {
    if (this.config.inputKind !== "project") {
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "输入为 APK，源码安全审计不适用",
        detail: ["这是正常跳过，不是失败。后续仍会执行 APK 结构、Manifest、DEX 和 SO 审计。"],
      }
    }
    const audit = await auditProject(this.config.inputPath, (message) => this.progress("source-audit", message))
    this.context.audit.findings.push(...audit.findings)
    if (audit.softwareComponents?.length) {
      this.context.audit.softwareComponents = [
        ...(this.context.audit.softwareComponents ?? []),
        ...audit.softwareComponents,
      ]
    }
    if (audit.signatureSelfChecks) {
      this.context.audit.signatureSelfChecks = audit.signatureSelfChecks
    }
    return {
      summary: `源码审计完成：${audit.findings.length} 项发现`,
      detail: audit.findings.map(findingLine),
      findings: audit.findings,
    }
  }

  private async build(): Promise<OperationResult> {
    if (this.config.inputKind !== "project") {
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "输入已经是 APK，无需执行 Gradle 构建",
        detail: ["这是正常跳过，不是失败。流程会继续处理准备步骤创建的 APK 副本。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    const wrapper = requiredTool(toolchain.gradleWrapper, "build")
    const project = path.resolve(this.config.inputPath)
    const capacitor = await detectCapacitorProject(project)
    const gradleCwd = capacitor.isCapacitor ? capacitor.androidDir : project
    // Size the Gradle/worker JVM so AGP's lint/compile/D8 stages don't hit a
    // Metaspace OOM. Passed via -Dorg.gradle.jvmargs so the setting reaches
    // forked worker processes (JAVA_TOOL_OPTIONS is not reliably inherited by
    // Gradle workers). Empty on non-Windows (no commit-limit issue there).
    const gradleJvmArg = gradleJvmArgsString()
    const gradleJvmArgs = gradleJvmArg ? ["-Dorg.gradle.jvmargs=" + gradleJvmArg] : []
    const capacitorFindings: Finding[] = []

    if (capacitor.isCapacitor) {
      const buildMode = this.config.buildMode ?? "full"
      this.progress("build", `检测到 Capacitor 项目：执行 Web 层（${buildMode === "full" ? "完整构建" : "快速重建"}）`)
      const detectedFinding: Finding = {
        severity: "info",
        code: "CAPACITOR_PROJECT_DETECTED",
        title: "检测到 Capacitor 项目",
        detail: `根目录含 Capacitor 配置，原生工程位于 ${capacitor.androidDir}。将先执行 Web 层（${buildMode === "full" ? "npm install + cap sync + clean" : "cap sync"}）再构建原生 APK。`,
        evidence: capacitor.configFile ?? "capacitor.config.*",
        recommendation: "无需操作，DroidSeal 已自动处理 Capacitor Web 层同步。",
      }
      this.context.audit.findings.push(detectedFinding)
      capacitorFindings.push(detectedFinding)

      const nodeTools = detectNodeTools()
      if (!nodeTools.npx || (buildMode === "full" && !nodeTools.npm)) {
        throw new DroidSealError({
          code: "NODE_TOOLCHAIN_MISSING",
          message: "未找到 Node.js 工具链（npm/npx）",
          explanation: "Capacitor 项目需要 Node.js 安装依赖并把 Web 资源同步到原生工程。",
          suggestions: [
            "安装 Node.js LTS（自带 npm/npx）",
            "确认 node、npm、npx 已在 PATH 中",
            "安装后重新运行环境诊断",
          ],
          stepId: "build",
        })
      }

      if (buildMode === "full") {
        this.progress("build", "npm install：安装 Web 依赖")
        const install = await runProcess({
          command: nodeTools.npm!,
          args: ["install"],
          cwd: project,
          timeoutMs: 30 * 60_000,
          onLine: (line) => this.progress("build", line.slice(0, 180)),
        })
        if (install.exitCode !== 0) {
          throw new DroidSealError({
            code: "NPM_INSTALL_FAILED",
            message: "npm install 失败",
            explanation: "Web 依赖安装失败，无法继续同步与构建。原生工程未被改动。",
            suggestions: ["检查网络与 npm 源", "排查 package.json 依赖冲突", "手动运行 npm install 复现根因"],
            stepId: "build",
            causeResult: install,
          })
        }
      }

      this.progress("build", "npx cap sync android：同步 Web 资源与插件")
      const sync = await runProcess({
        command: nodeTools.npx!,
        args: ["cap", "sync", "android"],
        cwd: project,
        timeoutMs: 30 * 60_000,
        onLine: (line) => this.progress("build", line.slice(0, 180)),
      })
      if (sync.exitCode !== 0) {
        throw new DroidSealError({
          code: "CAPACITOR_SYNC_FAILED",
          message: "npx cap sync android 失败",
          explanation: "Capacitor 未能把 Web 资源与插件同步到原生工程，后续 Gradle 构建会缺少最新 www 内容。",
          suggestions: [
            "确认已安装 @capacitor/cli 与 @capacitor/android",
            "检查 capacitor.config 的 webDir 是否存在",
            "手动运行 npx cap sync android 复现根因",
          ],
          stepId: "build",
          causeResult: sync,
        })
      }

      const javaTool = requiredTool(toolchain.java, "build")
      const javaVersion = await runProcess({ command: javaTool, args: ["-version"], cwd: project })
      const major = parseJavaMajor(`${javaVersion.stderr}\n${javaVersion.stdout}`)
      if (major !== undefined) {
        const patch = await patchCapacitorJavaVersion(capacitor.androidDir, major)
        if (patch?.changed) {
          const patchFinding: Finding = {
            severity: "low",
            code: "CAPACITOR_JAVA_VERSION_PATCHED",
            title: "已对齐 capacitor.build.gradle 的 JavaVersion 到本机 JDK",
            detail: `JavaVersion.VERSION_${patch.from} → VERSION_${patch.to}（本机 JDK 主版本 ${major}）。该文件由 cap sync 生成，可安全改写；原文件已备份至 ${patch.backupPath ?? "（无）"}。`,
            evidence: patch.filePath,
            recommendation: "如需长期生效，可在 capacitor.config.ts 中固定 Java 版本要求，或统一团队 JDK 版本。",
          }
          this.context.audit.findings.push(patchFinding)
          capacitorFindings.push(patchFinding)
          this.progress("build", `已对齐 JavaVersion → VERSION_${patch.to}（已备份原文件）`)
        }
      }

      if (buildMode === "full") {
        this.progress("build", "gradlew clean：清理旧产物")
        const clean = await runProcess({
          command: wrapper,
          args: [...gradleJvmArgs, "clean", "--console=plain", "--no-daemon"],
          cwd: gradleCwd,
          timeoutMs: 30 * 60_000,
          gradle: true,
          onLine: (line) => this.progress("build", line.slice(0, 180)),
        })
        if (clean.exitCode !== 0) throw explainCommandFailure("build", clean)
      }
    }

    this.progress("build", "检查 release 是否已启用 R8")
    const minifyState = await detectReleaseMinifyEnabled(gradleCwd)
    const extraArgs: string[] = []
    let r8Finding: Finding | undefined
    let forcedR8 = false
    if (minifyState === false) {
      const initScript = path.join(this.context.artifactDirectory, "droidseal-force-r8.init.gradle")
      await Bun.write(initScript, FORCE_R8_INIT_SCRIPT)
      extraArgs.push("--init-script", initScript)
      forcedR8 = true
      r8Finding = {
        severity: "info",
        confidence: "confirmed",
        code: "R8_FORCED_BY_DROIDSEAL",
        title: "release 未开 R8，DroidSeal 已在本次构建强制启用",
        detail:
          "检测到项目 release 块未启用 minifyEnabled。为了不污染你的仓库、保证可复现与可回滚，DroidSeal 没有直接改写 build.gradle，而是用构建期 Gradle init-script 覆盖，仅对本次构建强制开启 R8 代码混淆、资源压缩，并挂载优化版默认 ProGuard 规则（proguard-android-optimize.txt，若存在 proguard-rules.pro 一并加载）。此开启不会写回源码，下次不经 DroidSeal 的普通构建仍是原状态。",
        recommendation:
          "开发者需自行负责：1) 补充 -keep 规则覆盖反射、Gson/Moshi 等序列化、JNI、动态类加载与 WebView JS 接口，否则 R8 可能在运行时崩溃；2) 在真机矩阵回归启动与关键业务路径；3) 若要长期生效，请在源码 release 块写入 minifyEnabled true / shrinkResources true 并提交。",
        evidence: "build.gradle(release)",
      }
      this.progress("build", "release 未开 R8：已用 init-script 覆盖强制启用（不改源码）")
    }

    const gradleJvmFinding: Finding = {
      severity: "info",
      code: "GRADLE_DAEMON_JVM_SIZED",
      title: "已为 Gradle 守护进程配置合适的 JVM 内存",
      detail:
        "DroidSeal 为 Gradle 守护进程单独设置了 -XX:MaxMetaspaceSize=512m（轻量 JVM 工具默认仅 128m），以避免 lint/编译阶段 Metaspace 溢出导致构建崩溃。",
      recommendation: "一般无需改动；仅当超大型多模块项目仍报 Metaspace OOM 时，提高 DROIDSEAL_GRADLE_JVM_OPTIONS。",
    }
    this.context.audit.findings.push(gradleJvmFinding)

    this.progress("build", `运行 ${this.config.gradleTask}`)
    const command = await runProcess({
      command: wrapper,
      args: [...gradleJvmArgs, ...extraArgs, this.config.gradleTask, "--console=plain", "--no-daemon"],
      cwd: gradleCwd,
      timeoutMs: 30 * 60_000,
      gradle: true,
      onLine: (line) => this.progress("build", line.slice(0, 180)),
    })
    if (command.exitCode !== 0) {
      const metaspaceOom =
        /OutOfMemoryError:\s*Metaspace|daemon has disappeared|BUILD FAILED.*Metaspace|java\.lang\.OutOfMemoryError/i.test(
          command.stderr,
        )
      if (forcedR8) {
        throw new DroidSealError({
          code: "BUILD_FAILED_AFTER_FORCED_R8",
          message: "强制启用 R8 后 Gradle 构建失败",
          explanation:
            "DroidSeal 为本次构建强制开启了 R8/资源压缩（未改源码）。构建失败很可能是缺少 -keep 规则或与资源压缩冲突。原始源码未被修改。",
          suggestions: [
            "查看错误输出中 R8/Shrinker 的第一处根因",
            "在 proguard-rules.pro 补充反射、序列化、JNI、动态资源引用的 keep 规则",
            "如需先出包，可在项目 release 块自行决定是否启用 R8 后重跑",
          ],
          stepId: "build",
          causeResult: command,
        })
      }
      if (metaspaceOom) {
        throw new DroidSealError({
          code: "GRADLE_DAEMON_METASPACE_OOM",
          message: "Gradle 守护进程因 Metaspace 不足崩溃",
          explanation:
            "Gradle 守护进程在分析/编译阶段耗尽了元空间（Metaspace）。DroidSeal 已为 Gradle 守护进程设置 -XX:MaxMetaspaceSize=512m（轻量工具默认仅 128m），但超大型/多模块项目仍可能不足。",
          suggestions: [
            "提高上限：设置环境变量 DROIDSEAL_GRADLE_JVM_OPTIONS=\"-Xmx2048m -XX:MaxMetaspaceSize=768m\" 后重试",
            "确保机器有足够提交内存（RAM + 页面文件）",
            "关闭其他占用内存较多的进程后重试",
          ],
          stepId: "build",
          causeResult: command,
        })
      }
      throw explainCommandFailure("build", command)
    }

    const explicit = this.config.explicitBuiltApkPath
      ? path.resolve(project, this.config.explicitBuiltApkPath)
      : undefined
    const source =
      explicit ??
      (await newestApk(
        gradleCwd,
        capacitor.isCapacitor
          ? (name) => {
              const lower = name.toLowerCase()
              return lower.endsWith(".apk") && !lower.endsWith("-debug.apk")
            }
          : undefined,
      ))
    if (!source || !(await stat(source).catch(() => undefined))?.isFile()) {
      throw new DroidSealError({
        code: "BUILD_APK_NOT_FOUND",
        message: "Gradle 成功结束，但未找到生成的 APK",
        explanation: "任务可能生成了 AAB、使用了自定义输出路径，或处理的是库模块。",
        suggestions: ["填写明确的 APK 输出路径", "选择 assemble...Release 任务", "确认目标模块应用了 com.android.application"],
        stepId: "build",
        causeResult: command,
      })
    }
    const built = path.join(this.context.artifactDirectory, "02-built.apk")
    await copyFile(source, built)
    this.context.originalArtifact = source
    if (r8Finding) {
      const unresolved = this.context.audit.findings.filter((finding) =>
        finding.code !== "R8_MINIFICATION_NOT_CONFIRMED" &&
        finding.code !== "RESOURCE_SHRINKING_NOT_CONFIRMED",
      )
      this.context.audit.findings.splice(0, this.context.audit.findings.length, ...unresolved, r8Finding)
    }
    const detail = [`Gradle 产物：${source}`, `工作副本：${built}`]
    if (forcedR8) {
      detail.push(
        "本次构建由 DroidSeal 用 init-script 强制启用了 R8/资源压缩（未改源码）。",
        "提醒：R8 缺 keep 规则可能导致运行时崩溃，请补 keep 规则并真机回归；如需长期生效请在源码 release 块自行开启。",
      )
    }

    if (capacitor.isCapacitor) {
      this.progress("build", "运行 assembleDebug：生成调试包（旁路产物，不参与签名/加固）")
      const debugBuild = await runProcess({
        command: wrapper,
        args: [...gradleJvmArgs, "assembleDebug", "--console=plain", "--no-daemon"],
        cwd: gradleCwd,
        timeoutMs: 30 * 60_000,
        gradle: true,
        onLine: (line) => this.progress("build", line.slice(0, 180)),
      })
      if (debugBuild.exitCode !== 0) throw explainCommandFailure("build", debugBuild)
      const debugSource = await newestApk(gradleCwd, (name) => name.toLowerCase().endsWith("-debug.apk"))
      if (debugSource) {
        await mkdir(this.config.outputDirectory, { recursive: true })
        const debugOut = path.join(this.config.outputDirectory, path.basename(debugSource))
        await copyFile(debugSource, debugOut)
        detail.push(`调试包（旁路产物，未签名/加固）：${debugOut}`)
        const debugFinding: Finding = {
          severity: "info",
          code: "CAPACITOR_DEBUG_ARTIFACT",
          title: "已生成 Capacitor 调试包（旁路产物）",
          detail: `assembleDebug 产物已复制到输出目录：${debugOut}。该调试包不参与 DroidSeal 的签名与加固流程，仅供本地联调。`,
          evidence: debugSource,
          recommendation: "调试包可直接安装到设备用于开发联调，无需签名或加固。",
        }
        this.context.audit.findings.push(debugFinding)
        capacitorFindings.push(debugFinding)
      }
    }

    const findings = [...capacitorFindings, ...(r8Finding ? [r8Finding] : [])]
    return {
      summary: forcedR8 ? "Release APK 构建完成（DroidSeal 已强制启用 R8）" : "Release APK 构建完成并复制到隔离工作区",
      detail,
      artifactAfter: built,
      command,
      ...(findings.length ? { findings } : {}),
    }
  }

  private async apkAudit(): Promise<OperationResult> {
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行 APK 安全审计",
        detail: ["前面的准备或构建步骤没有产生 APK；请先修复对应失败，再重新运行。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    const audit = await auditApk(artifact, toolchain, (message) => this.progress("apk-audit", message))
    this.context.audit.findings.push(...audit.findings)
    if (audit.softwareComponents?.length) {
      this.context.audit.softwareComponents = [
        ...(this.context.audit.softwareComponents ?? []),
        ...audit.softwareComponents,
      ]
    }
    if (audit.apkEntries !== undefined) this.context.audit.apkEntries = audit.apkEntries
    if (audit.apkMetadata !== undefined) this.context.audit.apkMetadata = audit.apkMetadata
    if (audit.rawToolOutput !== undefined) this.context.audit.rawToolOutput = audit.rawToolOutput
    return {
      summary: `APK 审计完成：${audit.findings.length} 项发现`,
      detail: [
        `ZIP 条目：${audit.apkEntries?.totalEntries ?? 0}`,
        `DEX：${audit.apkEntries?.dexFiles.join(", ") || "未发现"}`,
        `原生架构：${audit.apkEntries?.nativeArchitectures.join(", ") || "无"}`,
        ...audit.findings.map(findingLine),
      ],
      findings: audit.findings,
    }
  }

  private async protect(): Promise<OperationResult> {
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行应用保护",
        detail: ["前面的准备或构建步骤没有产生 APK；本步骤没有修改任何文件。"],
      }
    }
    const evidenceCodes = new Set(this.context.audit.findings.map((finding) => finding.code))
    const hasRuntimeDebugSignal = [...evidenceCodes].some((code) => code.endsWith("_RUNTIME_DEBUGGER_DETECTION"))
    const hasIntegritySignal = [...evidenceCodes].some((code) =>
      code.endsWith("_RUNTIME_INTEGRITY_ATTESTATION") ||
      code === "SIGNATURE_SELF_CHECK_OBSERVED",
    )
    const findings: Finding[] = []

    if ((this.context.audit.apkEntries?.dexFiles.length ?? 0) > 0) {
      findings.push({
        severity: "low",
        confidence: "confirmed",
        code: "DEX_STANDARD_FORMAT_PRESENT",
        title: "标准 DEX 仍可被静态读取（商业加壳边界）",
        detail:
          "已直接确认 APK 中存在标准 classes*.dex。R8 能缩短名称、优化和裁剪代码，但不会把 DEX 变成不可读格式；这是能力边界，不等同于构建失败或已发现漏洞。",
        recommendation: "高价值业务继续移到服务端；如确需 DEX 抽取/VMP，使用有授权且经过设备矩阵验证的商业方案，再把产物交回 DroidSeal 做审计、对齐、签名与验证。",
        evidence: this.context.audit.apkEntries!.dexFiles.join(", "),
      })
    }

    if (!hasRuntimeDebugSignal) {
      findings.push({
        severity: "info",
        confidence: "low",
        code: "ANTI_DEBUG_NOT_OBSERVED",
        title: "未观察到运行时调试器检测证据",
        detail:
          "源码/DEX 的严格证据扫描未观察到 isDebuggerConnected 等运行时检测信号；由于混淆、Native 实现或动态调用可能不可见，这只是低置信度覆盖缺口，不再断言应用一定没有反调试。DroidSeal 仍会在后续步骤强制 debuggable=false。",
        recommendation: "需要更深防护时，优先在源码构建期集成可测试的反调试/反 Hook 逻辑；不要对未知 APK 事后注入启动代码。",
      })
    }

    if (!hasIntegritySignal) {
      findings.push({
        severity: "info",
        confidence: "low",
        code: "RUNTIME_INTEGRITY_NOT_OBSERVED",
        title: "未观察到运行时完整性校验证据",
        detail:
          "严格静态扫描未观察到 Play Integrity、签名自检或明确的运行时完整性信号。缺少字符串证据不能证明功能不存在，因此仅报告为低置信度覆盖缺口。",
        recommendation: "在源码侧加入服务端校验的 Play Integrity/设备完整性策略，并对发布证书与关键业务状态做服务端约束；客户端自检只作为纵深防御。",
      })
    }

    this.context.audit.findings.push(...findings)
    const observed: string[] = []
    if (hasRuntimeDebugSignal) observed.push("已观察到反调试信号")
    if (hasIntegritySignal) observed.push("已观察到完整性/attestation 信号")
    return {
      summary: `本地安全防护边界核验完成：${findings.length} 项残留能力提示`,
      detail: [
        "本地安全档已启用：源码项目强制 release R8/资源裁剪，成品继续执行 debuggable=false、调试残留清理、可选资源混淆、对齐、签名与最终验证。",
        observed.length > 0 ? observed.join("；") : "未把“未观察到”当成已确认漏洞，相关能力只按低置信度提示。",
        "为优先保证可安装与启动稳定性，不默认执行 DEX 业务字节码重写、Application 劫持式注入或进程自毁逻辑。",
        "商业加固边界保留为 DEX 抽取/加密、VMP 与成熟运行时壳；其产物仍可回到 DroidSeal 完成后续发布校验。",
        ...findings.map(findingLine),
      ],
      findings,
    }
  }

  /**
   * Checks whether an artifact currently carries a signature that apksigner accepts, so a
   * lossless rewrite can decide if it would destroy something the pipeline cannot rebuild.
   */
  private async existingSignatureState(artifact: string): Promise<SignatureState> {
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    if (!toolchain.apksigner.path) return "unknown"
    const verified = await runProcess({
      command: toolchain.apksigner.path,
      args: ["verify", artifact],
      cwd: path.dirname(artifact),
      timeoutMs: 2 * 60_000,
    })
    return verified.exitCode === 0 ? "valid" : "invalid"
  }

  private async harden(): Promise<OperationResult> {
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行 Release 归一化",
        detail: ["前面的准备或构建步骤没有产生 APK；本步骤没有生成输出。"],
      }
    }

    // Entries that are confirmed lossless to remove from a release APK. Kept intentionally strict.
    const STRIP_ALLOWLIST = ["DebugProbesKt.bin"] as const

    this.progress("harden", "检查 debuggable 与可无损剔除的残留条目")
    const debuggable = manifestBytesAreDebuggable(await readManifestXmlBytes(artifact))
    const beforeEntries = await parseZipEntries(artifact)
    const beforeNames = new Set(beforeEntries.map((entry) => entry.name))
    const residuals = STRIP_ALLOWLIST.filter((name) => beforeNames.has(name))

    if (!debuggable && residuals.length === 0) {
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "APK 已是安全 Release 状态，无需归一化",
        detail: [`输入：${artifact}`, "二进制 Manifest 未声明 debuggable 或已为 false，且无可剔除的残留条目。最终验证仍会再次确认。"],
      }
    }

    // Any rewrite below (debuggable flip or residual strip) rebuilds the ZIP and therefore
    // invalidates an existing APK signature. When the user opted out of re-signing, nothing
    // downstream can restore it, so the two changes are weighted differently: forcing
    // debuggable=false is a real security fix and still wins, but stripping residual entries
    // is hygiene and must never turn a signed, installable APK into an unsigned one.
    let signatureState: SignatureState = "invalid"
    if (this.config.signing.mode === "skip") {
      this.progress("harden", "检查现有签名，避免归一化破坏无法重建的签名")
      signatureState = await this.existingSignatureState(artifact)
    }

    if (signatureState !== "invalid" && !debuggable) {
      const preserved: Finding = {
        severity: "info",
        code: "HARDEN_SKIPPED_TO_PRESERVE_SIGNATURE",
        title: "为保护现有签名，未剔除残留条目",
        detail:
          signatureState === "valid"
            ? `APK 的现有签名可通过验证，且本次未配置重新签名。剔除 ${residuals.join("、")} 会重建 ZIP 并使签名失效，产物将无法安装，因此 DroidSeal 保留原包。`
            : `未找到 apksigner，无法确认 APK 的签名状态，且本次未配置重新签名。剔除 ${residuals.join("、")} 可能使现有签名失效，因此 DroidSeal 保守保留原包。`,
        recommendation: "如需一并剔除残留条目，请配置签名库，让流水线在改写后重新签名。",
        evidence: residuals.join(", "),
      }
      this.context.audit.findings.push(preserved)
      return {
        status: "skipped",
        skipKind: "safety",
        summary: "检测到需保护的现有签名，已跳过残留条目剔除",
        detail: [
          `输入：${artifact}`,
          "这是安全保护，不是失败。APK 未声明 debuggable，只存在可选的残留条目。",
          `保留的残留条目：${residuals.join("、")}`,
          "配置签名库后重跑，即可在剔除残留条目后重新签名。",
        ],
        findings: [preserved],
      }
    }

    const findings: Finding[] = []
    const detail: string[] = [`输入：${artifact}`]
    let workingInput = artifact

    if (debuggable) {
      this.progress("harden", "强制 android:debuggable=false")
      const flipped = path.join(this.context.artifactDirectory, "03b-hardened.apk")
      const { changed } = await flipDebuggableFalse(workingInput, flipped)
      if (changed) {
        workingInput = flipped
        const finding: Finding = {
          severity: "info",
          code: "HARDEN_DEBUGGABLE_FORCED",
          title: "已强制 debuggable=false",
          detail: "DroidSeal 在对齐和签名前把二进制 Manifest 的 android:debuggable 从 true 改为 false。",
          recommendation: "从根本上应在源码 release 构建中关闭 debuggable，避免依赖后处理归一化。",
        }
        findings.push(finding)
        detail.push("已强制 debuggable=false")
        if (signatureState !== "invalid") {
          const invalidated: Finding = {
            severity: "medium",
            code: "HARDEN_SIGNATURE_INVALIDATED",
            title: "归一化 debuggable 已使现有签名失效",
            detail:
              "APK 声明了 debuggable=true，这是必须修复的发布风险，因此 DroidSeal 重写了二进制 Manifest。重写会重建 ZIP 并使原有签名失效，而本次未配置重新签名，最终产物将是未签名 APK，无法直接安装。",
            recommendation:
              "配置签名库后重跑，让流水线在归一化后重新签名；或在源码 release 构建中关闭 debuggable。",
          }
          findings.push(invalidated)
          detail.push("注意：原有签名已因归一化失效，最终产物未签名")
        }
      }
    }

    if (residuals.length > 0) {
      this.progress("harden", `尝试无损剔除残留条目：${residuals.join("、")}`)
      const stripped = path.join(this.context.artifactDirectory, "03c-stripped.apk")
      const inputEntryCount = (await parseZipEntries(workingInput)).length
      const { removed } = await stripApkEntries(workingInput, stripped, residuals)
      if (removed.length > 0) {
        // Safety net: re-parse the stripped APK and confirm it is still structurally sound
        // (expected entry count, manifest present, DEX preserved). Abort on any mismatch.
        const after = await parseZipEntries(stripped).catch(() => undefined)
        const afterNames = after ? new Set(after.map((entry) => entry.name)) : undefined
        const originalHadDex = beforeEntries.some((entry) => /^classes(?:\d+)?\.dex$/.test(entry.name))
        const dexOk = !originalHadDex || (afterNames ? [...afterNames].some((name) => /^classes(?:\d+)?\.dex$/.test(name)) : false)
        const safe =
          after !== undefined &&
          afterNames !== undefined &&
          after.length === inputEntryCount - removed.length &&
          afterNames.has("AndroidManifest.xml") &&
          dexOk
        if (safe) {
          workingInput = stripped
          const finding: Finding = {
            severity: "info",
            code: "APK_RESIDUAL_STRIPPED",
            title: "已无损剔除冗余残留条目",
            detail: `DroidSeal 从 APK 中原样移除了以下无损残留条目并保持其余字节不变：${removed.join("、")}。移除后已通过结构复核（Manifest 与 DEX 完整、条目数符合预期），随后会重新对齐、签名与验证。`,
            recommendation: "无需额外处理；若要从根源避免，可在 release 依赖中排除产生该文件的调试库。",
            evidence: removed.join(", "),
          }
          findings.push(finding)
          detail.push(`已无损剔除残留条目：${removed.join("、")}`)
        } else {
          await this.safeRemove(stripped)
          const finding: Finding = {
            severity: "info",
            code: "APK_RESIDUAL_STRIP_SKIPPED",
            title: "残留条目剔除未通过安全复核，已保留原包",
            detail: `尝试剔除 ${removed.join("、")} 后，结构复核未通过（条目数、Manifest 或 DEX 校验不满足），出于安全 DroidSeal 放弃了本次剔除，保留改写前的 APK。`,
            recommendation: "可用 Android Studio APK Analyzer 复核该 APK 结构；确认无误后再重试。",
            evidence: residuals.join(", "),
          }
          findings.push(finding)
          detail.push(`残留剔除已放弃（安全复核未通过），保留原包：${residuals.join("、")}`)
        }
      }
    }

    this.context.audit.findings.push(...findings)

    if (workingInput === artifact) {
      // Nothing was actually rewritten (e.g. strip aborted by the safety net, no flip needed).
      return {
        status: "skipped",
        skipKind: "safety",
        summary: "未改写 APK：无需归一化或剔除被安全放弃",
        detail,
        findings,
      }
    }

    detail.push(`输出：${workingInput}`, "对齐和签名将基于归一化后的 APK 执行。")
    return {
      summary: "Release 归一化完成",
      detail,
      artifactAfter: workingInput,
      findings,
    }
  }


  private async webAssets(): Promise<OperationResult> {
    if (!this.config.enableWebAssetMinification) {
      return {
        status: "skipped",
        skipKind: "configuration",
        summary: "按配置跳过 Web JavaScript 发布处理",
        detail: ["用户未开启该可选步骤；assets/public 与 assets/www 中的脚本和 source map 均保持不变。"],
      }
    }
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行 Web JavaScript 发布处理",
        detail: ["前面的准备或构建步骤没有产生 APK；本步骤没有生成输出。"],
      }
    }

    this.progress("web-assets", "识别 assets/public 与 assets/www 中的 JavaScript")
    const inspection = await inspectHybridWebAssetsInApk(artifact)
    if (inspection.scriptNames.length === 0) {
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "未发现可处理的混合应用 Web JavaScript",
        detail: [
          `输入：${artifact}`,
          "严格路径白名单内没有 .js 文件；非混合 APK 或其他资产目录不会被猜测和改写。",
        ],
      }
    }

    if (this.config.signing.mode === "skip") {
      this.progress("web-assets", "检查现有签名，避免 Web 资产改写破坏无法重建的签名")
      const signatureState = await this.existingSignatureState(artifact)
      if (signatureState !== "invalid") {
        const finding: Finding = {
          severity: "info",
          confidence: signatureState === "valid" ? "confirmed" : "low",
          code: "WEB_ASSET_MINIFY_SKIPPED_TO_PRESERVE_SIGNATURE",
          title: "为保护现有 APK 签名，已跳过 Web JavaScript 发布处理",
          detail:
            signatureState === "valid"
              ? `检测到有效现有签名，且本次未配置重新签名。改写 ${inspection.scriptNames.length} 个 JavaScript 会使 v2/v3 签名失效，因此保留原包。`
              : "未找到可用 apksigner，无法确认当前 APK 的签名状态，且本次未配置重新签名；出于安全边界保守保留原包。",
          recommendation: "如需处理这些 Web 资产，请配置可用的发布签名库，使流水线在改写后重新对齐、签名并验证。",
          evidence: `${inspection.roots.join(", ")} | js=${inspection.scriptNames.length}`,
        }
        this.context.audit.findings.push(finding)
        return {
          status: "skipped",
          skipKind: "safety",
          summary: "检测到需要保护或无法确认的现有签名，已保守跳过 Web JavaScript 发布处理",
          detail: [
            `输入：${artifact}`,
            `目标脚本：${inspection.scriptNames.length} 个；source map：${inspection.mapNames.length} 个`,
            "这是签名完整性保护，不是处理失败；配置重新签名后可安全执行。",
          ],
          findings: [finding],
        }
      }
    }

    this.progress("web-assets", `用 Terser 处理 ${inspection.scriptNames.length} 个脚本并在内存中复核 ZIP`)
    const output = path.join(this.context.artifactDirectory, "03d-web-assets.apk")
    const result = await minifyHybridWebAssetsInApk(artifact, output)
    if (!result.changed) {
      await this.safeRemove(output)
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "未发现可处理的混合应用 Web JavaScript",
        detail: [`输入：${artifact}`, "APK 未被改写。"],
      }
    }

    this.context.audit.findings.push(...result.findings)
    return {
      summary: `Web JavaScript 发布处理完成：${result.filesProcessed} 个脚本，移除 ${result.mapsRemoved} 个 source map`,
      detail: [
        `输入：${artifact}`,
        `输出：${output}`,
        `严格处理目录：${result.roots.join("、")}`,
        `脚本：${result.filesProcessed} 个（ES module ${result.moduleFiles} 个）`,
        `明文字节：${result.beforeBytes} → ${result.afterBytes}`,
        `移除 source map：${result.mapsRemoved} 个`,
        "普通脚本保留顶层全局名，ES module 才执行顶层 mangle；所有脚本转换和 ZIP 复核成功后才原子写出。",
        "该处理只提高直接阅读和复制门槛，不提供源码保密；随后仍需重新对齐、签名并做真机 WebView 回归。",
      ],
      artifactAfter: output,
      findings: result.findings,
    }
  }

  private async arscObfuscate(): Promise<OperationResult> {
    if (!this.config.enableArscObfuscation) {
      return {
        status: "skipped",
        skipKind: "configuration",
        summary: "按配置跳过资源名混淆",
        detail: ["用户未开启有损资源名混淆；resources.arsc 未被改写，后续照常对齐与签名。"],
      }
    }
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行资源名混淆",
        detail: ["前面的准备或构建步骤没有产生 APK；本步骤没有生成输出。"],
      }
    }

    this.progress("arsc-obfuscate", "解析 resources.arsc 并检测 getIdentifier 反射")
    const output = path.join(this.context.artifactDirectory, "03e-arsc-obfuscated.apk")
    const result = await obfuscateArscInApk(artifact, output, {})
    this.context.audit.findings.push(...result.findings)

    if (!result.changed) {
      await this.safeRemove(output)
      return {
        status: "skipped",
        skipKind: "not-applicable",
        summary: "resources.arsc 缺失或无可混淆的资源名，已保留原包",
        detail: [`输入：${artifact}`, "未找到可安全重命名的资源条目名或资源文件路径；当前 APK 未改写。"],
        findings: result.findings,
      }
    }

    return {
      summary: `资源名混淆完成：重命名 ${result.keysRenamed} 个条目名、扁平化 ${result.pathsRenamed} 个资源路径`,
      detail: [
        `输入：${artifact}`,
        `输出：${output}`,
        `重命名资源条目名：${result.keysRenamed}`,
        `扁平化资源文件路径：${result.pathsRenamed}（同步重命名 ${result.entriesRenamed} 个 ZIP 条目）`,
        result.usesGetIdentifier
          ? "检测到 getIdentifier 反射：安全预检已保留全部资源条目名，避免动态拼接名称导致漏保。"
          : "未检测到 getIdentifier 反射按名查找。",
        "这是有损操作；对齐与签名将基于混淆后的 APK 执行。",
      ],
      artifactAfter: output,
      findings: result.findings,
    }
  }

  private async align(): Promise<OperationResult> {
    if (!this.config.enableAlignment) {
      return {
        status: "skipped",
        skipKind: "configuration",
        summary: "按配置跳过 zipalign",
        detail: ["用户在向导中关闭了 APK 对齐。最终验证仍会检查当前 APK 是否已经正确对齐。"],
      }
    }
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行 zipalign",
        detail: ["前面的准备或构建步骤没有产生 APK；本步骤没有生成输出。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain

    if (this.config.signing.mode === "skip") {
      if (!toolchain.apksigner.path) {
        return {
          status: "skipped",
          summary: "未配置重签名且无法检测现有签名，已保守跳过对齐",
          skipKind: "safety",
          detail: [
            "zipalign 必须在签名之前执行；对已签名 APK 再对齐可能破坏 v2/v3 签名。",
            "安装 Android Build Tools 后可自动识别；或配置签名库，在对齐后重新签名。",
          ],
        }
      }
      this.progress("align", "检查现有签名，避免对齐破坏 v2/v3 签名")
      const signature = await runProcess({
        command: toolchain.apksigner.path,
        args: ["verify", "--verbose", artifact],
        cwd: path.dirname(artifact),
        timeoutMs: 2 * 60_000,
      })
      if (signature.exitCode === 0) {
        this.context.signatureVerified = true
        return {
          status: "skipped",
          summary: "检测到有效现有签名，已跳过对齐以保护签名",
          skipKind: "safety",
          detail: ["这是安全保护，不是失败。对已签名 APK 再执行 zipalign 可能破坏 v2/v3 签名。", "最终验证步骤会再次输出签名方案和证书摘要。"],
          command: signature,
        }
      }
      this.context.signatureVerified = false
    }

    const zipalign = requiredTool(toolchain.zipalign, "align")
    const output = path.join(this.context.artifactDirectory, "04-aligned.apk")
    this.progress("align", "按 4 字节边界对齐 APK，并对未压缩 SO 做页对齐")
    const command = await runProcess({
      command: zipalign,
      args: ["-p", "-f", "4", artifact, output],
      cwd: path.dirname(artifact),
      timeoutMs: 5 * 60_000,
    })
    if (command.exitCode !== 0) {
      await this.safeRemove(output)
      throw explainCommandFailure("align", command)
    }
    return {
      summary: "APK 对齐完成",
      detail: [`输入：${artifact}`, `输出：${output}`, "签名将在对齐之后执行。"],
      artifactAfter: output,
      command,
    }
  }

  private async keystore(): Promise<OperationResult> {
    if (this.config.signing.mode === "skip") {
      return {
        status: "skipped",
        skipKind: "configuration",
        summary: "用户选择不重新签名，无需签名库",
        detail: ["后续对齐步骤会检测并保护输入 APK 的现有签名，最终验证会再次核对签名方案与证书。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    const keytool = requiredTool(toolchain.keytool, "keystore")
    const signing = this.config.signing
    const keystorePath = path.resolve(signing.keystorePath)

    if (signing.mode === "existing") {
      if (!(await stat(keystorePath).catch(() => undefined))?.isFile()) {
        throw new DroidSealError({
          code: "KEYSTORE_NOT_FOUND",
          message: "签名库文件不存在",
          explanation: `没有找到 ${keystorePath}。`,
          suggestions: ["重新选择签名库", "如果要创建新签名库，请在向导中选择“新建”"],
          stepId: "keystore",
        })
      }
      this.progress("keystore", "验证签名库密码与别名")
      const command = await runProcess({
        command: keytool,
        args: [
          "-J-Duser.language=en",
          "-J-Duser.country=US",
          "-J-Dfile.encoding=UTF-8",
          "-list",
          "-keystore",
          keystorePath,
          "-alias",
          signing.keyAlias,
          "-storepass:env",
          "DROIDSEAL_STORE_PASSWORD",
        ],
        cwd: path.dirname(keystorePath),
        env: { DROIDSEAL_STORE_PASSWORD: signing.storePassword },
        redact: [signing.storePassword, signing.keyPassword],
        timeoutMs: 60_000,
      })
      if (command.exitCode !== 0) throw explainCommandFailure("keystore", command)
      return {
        summary: "签名库与别名验证通过",
        detail: [`签名库：${keystorePath}`, `别名：${signing.keyAlias}`, "密码未写入命令参数或报告。"],
        command,
      }
    }

    if ((await stat(keystorePath).catch(() => undefined))?.isFile()) {
      if (signing.overwrite) {
        await rm(keystorePath, { force: true })
        this.progress("keystore", "已删除同名旧签名库以生成替换密钥（换新）")
      } else {
        throw new DroidSealError({
          code: "KEYSTORE_ALREADY_EXISTS",
          message: "目标签名库已经存在",
          explanation: "为避免覆盖不可恢复的发布密钥，DroidSeal 默认不会替换现有签名库。",
          suggestions: ["选择另一个新路径", "改为“使用现有签名库”", "若确要换新密钥，请在向导中选择“覆盖生成”"],
          stepId: "keystore",
        })
      }
    }
    if (!signing.distinguishedName.commonName.trim()) {
      throw new DroidSealError({
        code: "SIGNER_COMMON_NAME_REQUIRED",
        message: "签名证书 CN 不能为空",
        explanation: "新建自签名证书至少需要一个可识别的 Common Name。",
        stepId: "keystore",
      })
    }
    if (
      signing.distinguishedName.country &&
      !/^[A-Za-z]{2}$/.test(signing.distinguishedName.country)
    ) {
      throw new DroidSealError({
        code: "SIGNER_COUNTRY_INVALID",
        message: "国家代码必须是两个字母",
        explanation: "X.500 DN 的 C 字段应使用 ISO 3166-1 两字母代码，例如 CN、US。",
        stepId: "keystore",
      })
    }
    const storeType = path.extname(keystorePath).toLowerCase() === ".jks" ? "JKS" : "PKCS12"
    if (storeType === "PKCS12" && signing.keyPassword !== signing.storePassword) {
      throw new DroidSealError({
        code: "PKCS12_PASSWORD_MISMATCH",
        message: "新建 PKCS12 时密钥密码必须与签名库密码一致",
        explanation: "多数 JDK 的 PKCS12 实现不支持同一条目使用不同的 key password。",
        suggestions: ["把密钥密码留空/设为签名库密码", "如确需不同密码，使用 .jks 扩展名创建 JKS"],
        stepId: "keystore",
      })
    }

    await mkdir(path.dirname(keystorePath), { recursive: true })
    const algorithmArgs =
      signing.keyAlgorithm === "RSA"
        ? ["-keyalg", "RSA", "-keysize", String(signing.keySize), "-sigalg", "SHA256withRSA"]
        : ["-keyalg", "EC", "-groupname", "secp256r1", "-sigalg", "SHA256withECDSA"]
    this.progress("keystore", `创建 ${signing.keyAlgorithm} 发布签名库`)
    const command = await runProcess({
      command: keytool,
      args: [
        "-J-Duser.language=en",
        "-J-Duser.country=US",
        "-J-Dfile.encoding=UTF-8",
        "-genkeypair",
        "-keystore",
        keystorePath,
        "-storetype",
        storeType,
        "-alias",
        signing.keyAlias,
        ...algorithmArgs,
        "-validity",
        String(signing.validityDays),
        "-dname",
        distinguishName(signing),
        "-storepass:env",
        "DROIDSEAL_STORE_PASSWORD",
        "-keypass:env",
        "DROIDSEAL_KEY_PASSWORD",
        "-noprompt",
      ],
      cwd: path.dirname(keystorePath),
      env: {
        DROIDSEAL_STORE_PASSWORD: signing.storePassword,
        DROIDSEAL_KEY_PASSWORD: signing.keyPassword,
      },
      redact: [signing.storePassword, signing.keyPassword],
      timeoutMs: 2 * 60_000,
    })
    if (command.exitCode !== 0) {
      await rm(keystorePath, { force: true }).catch(() => undefined)
      throw explainCommandFailure("keystore", command)
    }
    return {
      summary: "新发布签名库已创建",
      detail: [
        `路径：${keystorePath}`,
        `类型：${storeType}`,
        `别名：${signing.keyAlias}`,
        "请立即离线备份；丢失发布密钥可能导致无法更新既有应用。",
      ],
      command,
    }
  }

  private async sign(): Promise<OperationResult> {
    if (this.config.signing.mode === "skip") {
      return {
        status: "skipped",
        skipKind: "configuration",
        summary: this.context.signatureVerified
          ? "已保留现有有效签名，未重新签名"
          : "用户选择不重新签名；最终验证将检查现有签名",
      }
    }
    // The keystore step already proved the store/alias/password combination is unusable.
    // Re-running apksigner here cannot succeed and would only report a second, vaguer error
    // (apksigner cannot distinguish a missing alias from a wrong password), masking the real one.
    const keystoreStep = this.getStep("keystore")
    if (keystoreStep.status === "failed") {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "签名库校验未通过，已跳过签名",
        detail: [
          `签名库步骤失败：${keystoreStep.result?.summary ?? "原因见上一步"}`,
          "请先按签名库步骤给出的原因修复密码、别名或路径，再重新执行。",
          "当前有效 APK 未被改写；最终产物将是未签名 APK。",
        ],
      }
    }
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行 apksigner",
        detail: ["前面的准备、构建或保护步骤没有产生 APK；本步骤没有生成签名文件。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    const apksigner = requiredTool(toolchain.apksigner, "sign")
    const signing = this.config.signing
    const output = path.join(this.context.artifactDirectory, "05-signed.apk")
    this.progress("sign", "使用 apksigner 生成独立签名 APK")
    const command = await runProcess({
      command: apksigner,
      args: [
        "sign",
        "--ks",
        path.resolve(signing.keystorePath),
        "--ks-key-alias",
        signing.keyAlias,
        "--ks-pass",
        "env:DROIDSEAL_STORE_PASSWORD",
        "--key-pass",
        "env:DROIDSEAL_KEY_PASSWORD",
        "--out",
        output,
        artifact,
      ],
      cwd: path.dirname(artifact),
      env: {
        DROIDSEAL_STORE_PASSWORD: signing.storePassword,
        DROIDSEAL_KEY_PASSWORD: signing.keyPassword || signing.storePassword,
      },
      redact: [signing.storePassword, signing.keyPassword],
      timeoutMs: 5 * 60_000,
    })
    if (command.exitCode !== 0) {
      await this.safeRemove(output)
      throw explainCommandFailure("sign", command)
    }
    return {
      summary: "APK 签名完成",
      detail: [`输出：${output}`, `签名别名：${signing.keyAlias}`, "签名密码未持久化。"],
      artifactAfter: output,
      command,
    }
  }

  private async verify(): Promise<OperationResult> {
    const artifact = this.context.currentArtifact
    if (!artifact) {
      return {
        status: "skipped",
        skipKind: "missing-input",
        summary: "没有有效 APK，无法执行最终验证",
        detail: ["前面的步骤没有产生可验证的 APK。报告步骤仍会记录失败原因。"],
      }
    }
    const toolchain = this.context.toolchain ?? (await discoverToolchain(this.config))
    this.context.toolchain = toolchain
    const detail: string[] = []
    let lastCommand: CommandResult | undefined

    if (toolchain.zipalign.path) {
      this.progress("verify", "验证 ZIP 对齐")
      const alignment = await runProcess({
        command: toolchain.zipalign.path,
        args: ["-c", "-v", "4", artifact],
        cwd: path.dirname(artifact),
        timeoutMs: 2 * 60_000,
      })
      lastCommand = alignment
      if (alignment.exitCode !== 0 && this.getStep("align").status === "success") {
        throw explainCommandFailure("verify", alignment)
      }
      detail.push(alignment.exitCode === 0 ? "✓ zipalign 验证通过" : "○ 当前 APK 未通过 zipalign（本次未执行对齐）")
    } else {
      detail.push("○ 未找到 zipalign，无法验证对齐")
    }

    let signatureVerified = false
    if (toolchain.apksigner.path) {
      const apksigner = toolchain.apksigner.path
      this.progress("verify", "验证 APK 签名方案与证书")
      const signature = await runProcess({
        command: apksigner,
        args: ["verify", "--verbose", "--print-certs", artifact],
        cwd: path.dirname(artifact),
        timeoutMs: 2 * 60_000,
      })
      lastCommand = signature
      signatureVerified = signature.exitCode === 0
      this.context.signatureVerified = signatureVerified
      if (!signatureVerified && this.config.signing.mode !== "skip") {
        // If signing never produced an artifact, the raw apksigner output ("DOES NOT VERIFY")
        // is a symptom, not the cause. Point at the step that actually failed instead.
        if (this.getStep("sign").status !== "success") {
          throw new DroidSealError({
            code: "SIGNATURE_MISSING_AFTER_FAILED_SIGNING",
            message: "最终 APK 未签名：签名步骤未成功完成",
            explanation:
              "本次配置要求重新签名，但签名步骤没有成功产出已签名 APK，因此最终验证只能看到一个未签名的产物。根因在签名库或签名步骤，请优先查看那一步的错误。",
            suggestions: [
              "查看“签名库”与“APK 签名”步骤的错误说明并修复",
              "用 keytool -list -v 单独确认签名库密码与别名",
              "确认无误后重新执行流程",
            ],
            stepId: "verify",
            causeResult: signature,
          })
        }
        throw explainCommandFailure("verify", signature)
      }
      if (signatureVerified) {
        detail.push(
          this.config.signing.mode === "skip"
            ? "✓ 现有 APK 签名验证通过（未重新签名）"
            : "✓ apksigner 验证通过",
        )
        for (const line of signature.stdout.split(/\r?\n/)) {
          if (/Verified using|certificate (DN|SHA-256 digest)/i.test(line)) detail.push(line.trim())
        }
      } else {
        detail.push("○ 当前 APK 未签名或签名无效；用户选择不重新签名")
      }

      // Signing-depth audit (Tier1-C): scheme coverage, cert validity, debug cert, weak key.
      if (signatureVerified) {
        const { schemes, certs: apksignerCerts } = analyzeApksignerVerbose(signature.stdout)
        let certs = apksignerCerts
        if (toolchain.keytool.path) {
          const certPrint = await runProcess({
            command: toolchain.keytool.path,
            args: ["-printcert", "-jarfile", artifact],
            cwd: path.dirname(artifact),
            timeoutMs: 2 * 60_000,
          })
          if (certPrint.exitCode === 0) {
            const parsed = analyzeCertPrint(certPrint.stdout)
            if (parsed.length > 0) certs = parsed
          }
        }
        const minSdkRaw = this.context.audit.apkMetadata?.minSdk
        const minSdk = minSdkRaw ? Number.parseInt(minSdkRaw, 10) : undefined
        const signingFindings = buildSigningFindings({
          schemes,
          certs,
          minSdk: minSdk !== undefined && !Number.isNaN(minSdk) ? minSdk : undefined,
          now: new Date(),
        })
        this.context.audit.findings.push(...signingFindings)
        if (signingFindings.length > 0) {
          detail.push(`签名深度审计新增 ${signingFindings.length} 条发现（见报告）`)
        }

        // Cross-check source-side expected certificate allowlists only after apksigner
        // has verified the final artifact and returned concrete signer fingerprints.
        this.context.audit.findings = this.context.audit.findings.filter(
          (finding) =>
            !finding.code.startsWith("SIGNATURE_SELF_CHECK_CERT_") &&
            finding.code !== "SIGNATURE_SELF_CHECK_MODULE_UNRESOLVED",
        )
        const sourceChecks = this.context.audit.signatureSelfChecks ?? []
        let comparableChecks = sourceChecks
        if (sourceChecks.length > 0 && this.config.inputKind === "project") {
          const sourceArtifact = this.context.originalArtifact
          const relativeArtifact = sourceArtifact
            ? path.relative(path.resolve(this.config.inputPath), sourceArtifact).replaceAll("\\", "/")
            : ""
          const matchedModules = sourceChecks.filter((check) =>
            check.modulePath === "."
              ? relativeArtifact.startsWith("build/")
              : relativeArtifact.startsWith(`${check.modulePath}/build/`),
          )
          comparableChecks = matchedModules
          if (matchedModules.length === 0) {
            const unresolved: Finding = {
              severity: "info",
              confidence: "low",
              code: "SIGNATURE_SELF_CHECK_MODULE_UNRESOLVED",
              title: "无法把最终 APK 精确关联到源码签名自检模块",
              detail: "本次 Gradle APK 路径无法精确关联到含签名自检证据的 Android application 模块；为避免把其他模块的允许列表用于当前产物，DroidSeal 未猜测期望证书并跳过交叉比较。",
              recommendation: "使用模块明确的 Gradle 任务和标准 build/outputs 路径，或只审计本次实际发布模块。",
              evidence: `modules=${sourceChecks.map((check) => check.modulePath).sort().join("|")}`,
            }
            this.context.audit.findings.push(unresolved)
            detail.push("○ 源码签名自检无法与本次 APK 精确关联，已保守跳过证书比较")
          }
        }
        const actualFingerprints = [...new Set(
          [...apksignerCerts, ...certs]
            .map((cert) => cert.sha256?.replaceAll(":", "").toLowerCase())
            .filter((value): value is string => Boolean(value && /^[0-9a-f]{64}$/.test(value))),
        )]
        const crossFindings = compareSignatureSelfCheckFingerprints(comparableChecks, actualFingerprints)
        this.context.audit.findings.push(...crossFindings)
        if (crossFindings.length > 0) {
          const mismatch = crossFindings.some((finding) => finding.code === "SIGNATURE_SELF_CHECK_CERT_MISMATCH")
          detail.push(
            mismatch
              ? "✗ App 自签名校验允许列表与最终发布证书不一致（confirmed critical，见报告）"
              : "✓ App 自签名校验允许列表与最终发布证书匹配（仅证明配置一致）",
          )
        }

      }
    } else {
      delete this.context.signatureVerified
      detail.push("○ 未找到 apksigner，无法确认当前 APK 的签名状态")
    }

    this.progress("verify", "计算 SHA-256")
    const sha256 = await sha256File(artifact)
    this.context.audit.apkMetadata = { ...(this.context.audit.apkMetadata ?? {}), sha256 }
    detail.push(`SHA-256: ${sha256}`)

    this.progress("verify", "确认最终 APK 的 debuggable 状态")
    let debuggable = false
    if (toolchain.aapt.path) {
      const xmltree = await runProcess({
        command: toolchain.aapt.path,
        args: ["dump", "xmltree", artifact, "AndroidManifest.xml"],
        cwd: path.dirname(artifact),
        timeoutMs: 2 * 60_000,
      })
      if (xmltree.exitCode === 0) {
        debuggable = /android:debuggable\b[^\n]*0xffffffff/i.test(xmltree.stdout)
      } else {
        debuggable = manifestBytesAreDebuggable(await readManifestXmlBytes(artifact))
      }
    } else {
      debuggable = manifestBytesAreDebuggable(await readManifestXmlBytes(artifact))
    }
    if (debuggable) {
      throw new DroidSealError({
        code: "VERIFY_DEBUGGABLE_STILL_TRUE",
        message: "最终 APK 仍为 debuggable=true",
        explanation:
          "Release 归一化本应把 android:debuggable 改为 false，但最终产物仍可调试。可能是归一化步骤被跳过，或后续步骤重新引入了可调试标记。",
        suggestions: ["确认 harden（Release 归一化）步骤未被跳过", "在源码 release 构建中关闭 debuggable 后重新执行"],
        stepId: "verify",
      })
    }
    detail.push("✓ 最终 APK debuggable=false")

    const operation: OperationResult = {
      summary: this.config.signing.mode !== "skip"
        ? "对齐、签名与哈希验证完成"
        : signatureVerified
          ? "现有签名、结构与哈希验证完成"
          : "结构与哈希验证完成（APK 未签名或签名无效）",
      detail,
    }
    if (lastCommand) operation.command = lastCommand
    return operation
  }

  private async report(): Promise<OperationResult> {
    const artifact = this.context.currentArtifact
    if (artifact) {
      await mkdir(path.resolve(this.config.outputDirectory), { recursive: true })
      // The suffix is a claim about the artifact, so it must follow what verification actually
      // observed — not what the run was configured to do. A failed signing step previously still
      // produced a file named "sealed-signed", which misrepresents an uninstallable APK.
      const suffix = !this.context.signatureVerified
        ? "sealed-unsigned"
        : this.config.signing.mode !== "skip"
          ? "sealed-signed"
          : "sealed-signed-preserved"
      const finalPath = path.join(
        path.resolve(this.config.outputDirectory),
        artifactName(this.config.inputPath, suffix),
      )
      await copyFile(artifact, finalPath)
      this.context.finalArtifact = finalPath
      this.context.audit.apkMetadata = {
        ...(this.context.audit.apkMetadata ?? {}),
        sha256: await sha256File(finalPath),
      }
    }
    const reports = await writeReports(this.config, this.context)
    const result: OperationResult = {
      summary: artifact ? "最终 APK 与审计报告已生成" : "未生成 APK；已输出失败诊断报告",
      detail: [
        `JSON 报告：${reports.json}`,
        `Markdown 报告：${reports.markdown}`,
        `发布门禁：${{ pass: "通过", review: "需人工复核", block: "阻断发布" }[reports.releaseDecisionStatus]} (${reports.releaseDecisionStatus})`,
        `发布证据：${reports.releaseEvidenceManifest}`,
        `CycloneDX SBOM：${reports.sbom}`,
        `许可证待核验清单：${reports.licenseReview}`,
        ...(reports.remediationDirectory ? [`修复模板与计划：${reports.remediationDirectory}`] : []),
        this.context.finalArtifact ? `最终 APK：${this.context.finalArtifact}` : "最终 APK：无",
      ],
    }
    if (artifact !== undefined) result.artifactAfter = artifact
    return result
  }

  private async safeRemove(filePath: string): Promise<void> {
    const root = path.resolve(this.context.artifactDirectory)
    const target = path.resolve(filePath)
    const relative = path.relative(root, target)
    if (relative.startsWith("..") || path.isAbsolute(relative)) return
    await rm(target, { force: true, recursive: true }).catch(() => undefined)
  }
}

export function statusGlyph(status: StepStatus): string {
  const glyphs: Record<StepStatus, string> = {
    pending: "○",
    processing: "◐",
    success: "●",
    failed: "×",
    skipped: "−",
  }
  return glyphs[status]
}
