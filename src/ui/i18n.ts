// TUI 全量中英文文案(默认英文;右上角切换按钮在 en/zh 之间切换)
import { createSignal } from "solid-js"

export const [language, setLanguage] = createSignal<"en" | "zh">("en")

const en = {
  // 头部
  headerTitle: "Android release pipeline",
  headerLocalOnly: "local only",
  headerReady: "ready",
  headerProcessing: "processing",

  // 侧栏
  sidebarSuccess: "Success",
  sidebarSkipped: "Skipped",
  sidebarFailed: "Failed",
  sidebarCurrentArtifact: "Current artifact",
  sidebarLegend: "● success   − skipped (see reason)   × failed",
  sidebarSkipNote: "Skipped is not failure; it counts as processed.",
  sidebarNotGenerated: "Not generated yet",
  sidebarOpenFolder: "▸ Open containing folder",
  sidebarNoOverwrite: "Failure never overwrites · local only",

  // 输入区
  composerPlaceholder: "Type a message or /help · or drag a file here",
  secretPlaceholder: "Type and confirm",
  inputTitleNeed: "Need input",
  inputTitleSecret: "Need secure input",
  inputTitleComposer: "Type a command · chat with DroidSeal",
  inputTitlePassive: "No input needed · use the actions above",

  // 底部栏
  bottomBar: "Interaction zoom {zoom}% · Ctrl± · secrets redacted",

  // 欢迎页
  welcomeTitle: "Welcome to DroidSeal",
  welcomeDesc1:
    "DroidSeal runs the Release build, R8/Manifest/APK audit, security baseline, zipalign, apksigner signing and verification entirely on this machine.",
  welcomeDesc2:
    "Not familiar with the flow? Choose “Guided”; every step explains its purpose and keeps jargon in the original form.",
  welcomeDesc3:
    "“Skipped” marks not-applicable, user choice, per-config, safety protection, or a missing prerequisite APK; skipping is not failure.",
  welcomeDesc4: "All processing uses an isolated copy; failures roll back to the last valid APK.",

  // 输入提示(被动提示行)
  passiveRecovery: "No input needed · click a recovery action above, or press D / H / R",
  passiveChoice: "No input needed · click an option above, or press the matching number key",
  passiveReady: "Configuration ready · click “Start”, or press Enter",
  passiveBusy: "Processing · no input needed right now",
  passiveDone: "Pipeline finished · use the buttons above to start a new task or exit",
  passiveFailureAdvance: "No input needed · click the rollback button, or press Enter to continue",
  passiveGuided: "No input needed · click “Execute”/“Skip”, or press Enter / S",
  passiveOneClick: "Running continuously · no input needed",

  // 按钮
  btnStart: "Start",
  btnStartDetail: "Create the pipeline from the summary above",
  btnRefill: "Refill",
  btnRefillDetail: "Clear this in-memory configuration",
  btnNewTask: "New task",
  btnExit: "Exit",
  btnRollbackAdvance: "Skip and roll back, continue",
  btnRollbackAdvanceDetail: "The APK is restored to the state before the step",
  btnExecute: "Execute step",
  btnSkip: "Skip",
  btnSkipDetail: "Mark as user choice · keep the current valid APK",
  btnHome: "Back to home",
  btnHomeDetail: "Clear progress and return to the home screen",
  btnConfirmInput: "Confirm input",
  btnUseDefault: "Use default",
  btnContinueEmpty: "Leave empty and continue",
  btnPleaseInput: "Please input first",
  btnFillAndContinue: "Fill the current item and continue",
  reuseStorePassword: "Reuse the keystore password",

  // 跳过原因
  skipNotApplicable: "Not applicable",
  skipUserChoice: "User choice",
  skipConfiguration: "Per config",
  skipSafety: "Safety protection",
  skipMissingInput: "Missing prerequisite APK",
  skipReasonExplained: "Reason explained",

  // 步骤标题
  stepDoctor: "Environment check",
  stepPrepare: "Prepare workspace",
  stepKeystore: "Keystore",
  stepSourceAudit: "Source security audit",
  stepBuild: "Build Release APK",
  stepApkAudit: "APK security audit",
  stepProtect: "Local security baseline",
  stepHarden: "Release normalization",
  stepWebAssets: "Web JS release processing",
  stepArscObfuscate: "Resource-name obfuscation",
  stepAlign: "ZIP alignment",
  stepSign: "APK signing",
  stepVerify: "Final verification",
  stepReport: "Generate report",

  // 步骤描述
  stepDescDoctor: "Checks the JDK, Android Build Tools and Gradle Wrapper required by this flow",
  stepDescPrepare: "Validates the input and creates a working copy; the original files stay untouched",
  stepDescKeystore: "Verifies an existing JKS/PKCS12 or creates a new keystore before signing, catching password/alias problems early",
  stepDescSourceAudit: "Checks release, R8, Manifest and plaintext signing passwords",
  stepDescBuild: "Builds the APK with the project's own Gradle Wrapper",
  stepDescApkAudit: "Checks ZIP structure, Manifest, DEX, SO and metadata",
  stepDescProtect: "Verifies R8, DEX, anti-debug and integrity evidence to determine what is safe before commercial hardening",
  stepDescHarden: "Forces debuggable=false so the final artifact is a secure Release state",
  stepDescWebAssets: "Optional: minifies hybrid-app JavaScript and removes source maps, rebuilding before signing",
  stepDescArscObfuscate: "Optional lossy: renames resources.arsc resource names and flattens paths, rebuilding before signing",
  stepDescAlign: "Produces a separate zipalign-aligned APK before signing",
  stepDescSign: "Signs the APK with apksigner using in-memory passwords",
  stepDescVerify: "Verifies zipalign, signing scheme, certificate and computes SHA-256",
  stepDescReport: "Saves the final APK and generates JSON/Markdown, release evidence, SBOM and remediation material",

  // 流水线消息
  msgStepN: "Step {current}/{total}",
  msgSkipped: "Skipped · {kind}：{summary}",
  msgPipelineCreated: "Pipeline created",
  msgRunId: "Run ID: {id}",
  msgRecognizedApk: "I recognized an APK path",
  msgRecognizedApkBody: "Choose “Existing APK” first, then paste this path.",
  msgWelcomeStart: "I can start from here",
  msgWelcomeStartBody: "Type “One-click”, “Guided” or “Doctor”, or click a button below.",

  // 工具恢复
  btnDownloadContinue: "Download & continue",
  btnInstallInstructions: "Install instructions",
  btnRecheckContinue: "Recheck & continue",
  recoveryDownloadHint:
    "You can click “Download & continue”; clicking means you accept the corresponding official component license. DroidSeal downloads, verifies, installs and resumes automatically.",
  recoveryManualHint: "Missing items must be fixed manually following the install instructions.",
  recoveryRecheckHint: "You can also install manually, then click “Recheck & continue”; the signing config and step progress are kept.",
  recoveryAuto: "Click “Download & continue” to accept the corresponding official component license; or view the instructions and install manually.",
  recoveryManual: "View the install instructions and fix manually.",
  msgToolSafety:
    "All tools are launched as argument arrays, never through a shell; signing passwords pass via the child process environment and are redacted in output.",
  msgToolsNeeded: "The selected flow needs missing tools",
  msgMissingTools: "Missing: {names}",
  msgCannotSkipStep: "Cannot skip this step",
  msgSearchTools: "Searching JDK and Android SDK",
  msgDoctorToolsFound: "Doctor found tools that can be installed",

  // 帮助
  helpTitle: "Help & security boundaries",
  helpBody1: "/guided guided · /oneclick one-click · /doctor doctor · /restart home · /quit exit",
  helpBody2: "Bottom-left interaction: Ctrl+Plus zoom in, Ctrl+Minus zoom out, Ctrl+0 reset.",
  helpBody3: "When required tools are missing, the flow pauses; you can download and continue, or install manually and recheck.",
  helpBody4: "Chat parsing runs entirely locally; no model service is contacted and no paths, APKs or signing info are uploaded.",
  helpBody5:
    "Built-in capabilities target legitimate app protection: strict evidence-based audit, R8, Release normalization, alignment, signing and verification run by default; resource-name obfuscation is a lossy optional gated by a compatibility precheck.",
  helpBody6:
    "For active hardening (DEX packing/VMP/anti-debug), integrate an authorized solution at the source level; DroidSeal also ships a self-developed, opt-in build-time anti-debug stub for source integration.",
  helpBody7: "Unpacking, certificate-bypass, detection-evasion, memory tampering or unauthorized reverse-engineering automation are not provided.",

  // 输入提示细节
  inputPrefillNote: "A default is prefilled; confirm or edit",
  inputEmptyOk: "This item may be left empty; continue",
}

const zh: Record<keyof typeof en, string> = {
  headerTitle: "Android 发布流水线",
  headerLocalOnly: "仅本机",
  headerReady: "就绪",
  headerProcessing: "处理中",

  sidebarSuccess: "成功",
  sidebarSkipped: "跳过",
  sidebarFailed: "失败",
  sidebarCurrentArtifact: "当前有效产物",
  sidebarLegend: "● 成功  − 跳过（见原因）  × 失败",
  sidebarSkipNote: "跳过不一定是失败；已计入“已处理”。",
  sidebarNotGenerated: "尚未生成",
  sidebarOpenFolder: "▸ 打开所在目录",
  sidebarNoOverwrite: "失败不覆盖 · 本地处理",

  composerPlaceholder: "输入消息或 /help · 或拖动文件到此处",
  secretPlaceholder: "请输入后确认",
  inputTitleNeed: "需要输入",
  inputTitleSecret: "需要安全输入",
  inputTitleComposer: "可输入指令 · 和 DroidSeal 对话",
  inputTitlePassive: "无需输入 · 使用上方操作",

  bottomBar: "交互区 {zoom}% · Ctrl± · secrets redacted",

  welcomeTitle: "欢迎使用 DroidSeal",
  welcomeDesc1: "DroidSeal 在本机完成 Release 构建、R8/Manifest/APK 审计、安全审计基线、zipalign、apksigner 签名与验证。",
  welcomeDesc2: "不熟悉流程可选择“分步处理”；每一步都会说明用途，专业术语保持原名。",
  welcomeDesc3: "“跳过”会标明是不适用、用户选择、按配置、安全保护或缺少前置 APK；跳过不一定是失败。",
  welcomeDesc4: "所有处理使用独立副本，失败时回退到上一个有效 APK。",

  passiveRecovery: "无需输入文字 · 请点击上方恢复方式，或按 D / H / R",
  passiveChoice: "无需输入文字 · 请点击上方选项，或直接按对应数字键",
  passiveReady: "配置已就绪 · 点击“开始处理”，或按 Enter",
  passiveBusy: "正在处理 · 当前不需要输入",
  passiveDone: "流程已结束 · 请使用上方按钮开始新任务或退出",
  passiveFailureAdvance: "无需输入文字 · 点击回退按钮，或按 Enter 进入下一步",
  passiveGuided: "无需输入文字 · 点击“执行此步”/“跳过”，或按 Enter / S",
  passiveOneClick: "正在连续处理 · 当前不需要输入",

  btnStart: "开始处理",
  btnStartDetail: "按上方摘要创建流水线",
  btnRefill: "重新填写",
  btnRefillDetail: "清空本次内存配置",
  btnNewTask: "开始新任务",
  btnExit: "退出",
  btnRollbackAdvance: "跳过并回退，进入下一步",
  btnRollbackAdvanceDetail: "当前 APK 已恢复为步骤开始前版本",
  btnExecute: "执行此步",
  btnSkip: "跳过",
  btnSkipDetail: "标记为用户选择 · 保留当前有效 APK",
  btnHome: "回到首页",
  btnHomeDetail: "清空当前进度，返回首页",
  btnConfirmInput: "确认输入",
  btnUseDefault: "使用默认值",
  btnContinueEmpty: "留空并继续",
  btnPleaseInput: "请先输入",
  btnFillAndContinue: "填写当前项后继续",
  reuseStorePassword: "沿用签名库密码",

  skipNotApplicable: "不适用",
  skipUserChoice: "用户选择",
  skipConfiguration: "按配置",
  skipSafety: "安全保护",
  skipMissingInput: "缺少前置 APK",
  skipReasonExplained: "已说明原因",

  stepDoctor: "环境诊断",
  stepPrepare: "准备工作区",
  stepKeystore: "签名库",
  stepSourceAudit: "源码安全审计",
  stepBuild: "构建 Release APK",
  stepApkAudit: "APK 安全审计",
  stepProtect: "本地安全防护",
  stepHarden: "Release 归一化",
  stepWebAssets: "Web JS 发布处理",
  stepArscObfuscate: "资源名混淆",
  stepAlign: "ZIP 对齐",
  stepSign: "APK 签名",
  stepVerify: "最终验证",
  stepReport: "生成报告",

  stepDescDoctor: "检查本次流程需要的 JDK、Android Build Tools 与 Gradle Wrapper",
  stepDescPrepare: "检查输入并创建工作副本，原文件保持不变",
  stepDescKeystore: "签名前先验证现有 JKS/PKCS12 或创建新签名库，尽早发现密码/别名问题",
  stepDescSourceAudit: "检查 release、R8、Manifest 与明文签名密码",
  stepDescBuild: "使用项目自己的 Gradle Wrapper 生成 APK",
  stepDescApkAudit: "检查 ZIP 结构、Manifest、DEX、SO 与元数据",
  stepDescProtect: "核验 R8、DEX、反调试与完整性证据，确定商业加固前可安全执行的边界",
  stepDescHarden: "强制 debuggable=false，保证最终产物为安全 Release 状态",
  stepDescWebAssets: "可选：压缩混淆混合应用 JavaScript 并移除 source map，签名前生成新包",
  stepDescArscObfuscate: "可选有损：重命名 resources.arsc 资源名并扁平化资源路径，签名前生成新包",
  stepDescAlign: "签名前用 zipalign 生成独立的对齐 APK",
  stepDescSign: "使用 apksigner 和内存中的密码生成已签名 APK",
  stepDescVerify: "验证 zipalign、签名方案、证书并计算 SHA-256",
  stepDescReport: "保存最终 APK，并生成 JSON/Markdown、发布证据、SBOM 与修复资料",

  msgStepN: "第 {current}/{total} 步",
  msgSkipped: "已跳过 · {kind}：{summary}",
  msgPipelineCreated: "流水线已创建",
  msgRunId: "运行编号：{id}",
  msgRecognizedApk: "已识别到 APK 路径",
  msgRecognizedApkBody: "请先选择“已有 APK”，然后粘贴这一路径。",
  msgWelcomeStart: "我可以从这里开始",
  msgWelcomeStartBody: "输入“一键处理”“分步处理”或“环境诊断”，也可以点击下方按钮。",

  btnDownloadContinue: "下载并继续",
  btnInstallInstructions: "安装说明",
  btnRecheckContinue: "已安装，重新检测",
  recoveryDownloadHint:
    "可以点击“下载并继续”；点击表示同意对应官方组件许可，DroidSeal 会下载、校验、安装并自动续跑。",
  recoveryManualHint: "当前缺失项需要按安装说明手动修复。",
  recoveryRecheckHint: "也可以手动安装后点击“已安装，重新检测”，当前签名配置和步骤进度会保留。",
  recoveryAuto: "点击“下载并继续”表示同意对应官方组件许可；也可以查看说明后手动安装。",
  recoveryManual: "请查看安装说明并手动修复。",
  msgToolSafety:
    "所有工具都以参数数组直接启动，不经过 shell；签名密码通过子进程环境传递并在输出中脱敏。",
  msgToolsNeeded: "所选流程需要补齐工具",
  msgMissingTools: "缺少：{names}",
  msgCannotSkipStep: "无法跳过该步骤",
  msgSearchTools: "搜索 JDK 与 Android SDK",
  msgDoctorToolsFound: "环境诊断发现可补齐的工具",

  helpTitle: "帮助与安全边界",
  helpBody1: "/guided 分步处理 · /oneclick 一键处理 · /doctor 环境诊断 · /restart 返回首页 · /quit 退出",
  helpBody2: "左下交互区：Ctrl+加号放大、Ctrl+减号缩小、Ctrl+0 复位。",
  helpBody3: "所选流程缺少必需工具时会暂停，可下载并继续，或手动安装后重新检测。",
  helpBody4: "聊天解析完全在本机执行，不连接模型服务，也不会上传路径、APK 或签名信息。",
  helpBody5: "内置能力面向合法应用防护：严格证据审计、R8、Release 归一化、对齐、签名与验证默认执行；资源名混淆是经兼容性预检的有损可选项。",
  helpBody6: "如需主动加固（DEX 加壳/VMP/反调试），请在源码接入有授权的方案；DroidSeal 另提供自研、opt-in 的构建期反调试 stub 供源码集成。",
  helpBody7: "不提供脱壳、绕过证书校验、规避检测、内存篡改或未授权逆向自动化。",

  inputPrefillNote: "已预填默认值，可直接确认或修改",
  inputEmptyOk: "此项允许留空，可直接继续",
}

export type I18nKey = keyof typeof en

const dict = { en, zh } as const

export function t(key: I18nKey): string {
  return dict[language()][key]
}

// 步骤标题按 id 查翻译(侧栏/消息使用)
const stepTitleKeys: Record<string, I18nKey> = {
  doctor: "stepDoctor",
  prepare: "stepPrepare",
  keystore: "stepKeystore",
  "source-audit": "stepSourceAudit",
  build: "stepBuild",
  "apk-audit": "stepApkAudit",
  protect: "stepProtect",
  harden: "stepHarden",
  "web-assets": "stepWebAssets",
  "arsc-obfuscate": "stepArscObfuscate",
  align: "stepAlign",
  sign: "stepSign",
  verify: "stepVerify",
  report: "stepReport",
}

export function tStep(stepId: string): string {
  const key = stepTitleKeys[stepId]
  return key ? t(key) : stepId
}

// 步骤描述按 id 查翻译
const stepDescKeys: Record<string, I18nKey> = {
  doctor: "stepDescDoctor",
  prepare: "stepDescPrepare",
  keystore: "stepDescKeystore",
  "source-audit": "stepDescSourceAudit",
  build: "stepDescBuild",
  "apk-audit": "stepDescApkAudit",
  protect: "stepDescProtect",
  harden: "stepDescHarden",
  "web-assets": "stepDescWebAssets",
  "arsc-obfuscate": "stepDescArscObfuscate",
  align: "stepDescAlign",
  sign: "stepDescSign",
  verify: "stepDescVerify",
  report: "stepDescReport",
}

export function tStepDesc(stepId: string): string {
  const key = stepDescKeys[stepId]
  return key ? t(key) : stepId
}
