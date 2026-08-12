import type { CommandResult, StepId } from "./types.ts"

export class DroidSealError extends Error {
  readonly code: string
  readonly explanation: string
  readonly suggestions: string[]
  readonly stepId: StepId | undefined
  readonly causeResult: CommandResult | undefined

  constructor(input: {
    code: string
    message: string
    explanation: string
    suggestions?: string[]
    stepId?: StepId | undefined
    cause?: unknown
    causeResult?: CommandResult | undefined
  }) {
    super(input.message, { cause: input.cause })
    this.name = "DroidSealError"
    this.code = input.code
    this.explanation = input.explanation
    this.suggestions = input.suggestions ?? []
    this.stepId = input.stepId
    this.causeResult = input.causeResult
  }
}

export function explainCommandFailure(stepId: StepId, result: CommandResult): DroidSealError {
  const combined = `${result.stderr}\n${result.stdout}`.toLowerCase()

  if (result.timedOut) {
    return new DroidSealError({
      code: "PROCESS_TIMEOUT",
      message: `命令在限定时间内没有完成：${result.command}`,
      explanation:
        "外部工具可能卡在交互式提示、Gradle 依赖下载或文件锁等待。DroidSeal 已终止本步骤，并保留步骤开始前的有效产物。",
      suggestions: ["检查是否有被隐藏的密码/确认提示", "确认网络与 Gradle 仓库可用", "关闭占用 APK 或输出目录的程序"],
      stepId,
      causeResult: result,
    })
  }

  if (
    combined.includes("keystore was tampered") ||
    combined.includes("password was incorrect") ||
    combined.includes("failed to load signer")
  ) {
    return new DroidSealError({
      code: "KEYSTORE_PASSWORD_INVALID",
      message: "无法打开签名库",
      explanation:
        "签名库密码不正确、签名库格式不受当前 JDK 支持，或文件已损坏。密码只保存在本次进程内存中，未写入报告。",
      suggestions: ["重新输入签名库密码", "用 keytool -list 单独验证签名库", "确认 JKS/PKCS12 文件没有被截断"],
      stepId,
      causeResult: result,
    })
  }

  if (
    combined.includes("does not contain key") ||
    combined.includes("no key found") ||
    combined.includes("alias") && combined.includes("not exist")
  ) {
    return new DroidSealError({
      code: "KEY_ALIAS_NOT_FOUND",
      message: "签名别名不存在或不是私钥条目",
      explanation: "apksigner 只能使用含私钥和证书链的别名；仅证书条目不能用于签名。",
      suggestions: ["用 keytool -list -v -keystore <文件> 查看可用别名", "检查别名大小写和前后空格"],
      stepId,
      causeResult: result,
    })
  }

  if (combined.includes("sdk location not found") || combined.includes("android_home")) {
    return new DroidSealError({
      code: "ANDROID_SDK_NOT_FOUND",
      message: "Gradle 找不到 Android SDK",
      explanation: "项目构建需要有效的 Android SDK 路径，但 ANDROID_HOME、ANDROID_SDK_ROOT 或 local.properties 未正确配置。",
      suggestions: ["在项目 local.properties 中设置 sdk.dir", "设置 ANDROID_HOME 或 ANDROID_SDK_ROOT", "从 Android Studio 安装对应 SDK"],
      stepId,
      causeResult: result,
    })
  }

  if (combined.includes("task") && combined.includes("not found")) {
    return new DroidSealError({
      code: "GRADLE_TASK_NOT_FOUND",
      message: "指定的 Gradle 任务不存在",
      explanation: "当前项目没有该构建变体或任务名拼写不正确。",
      suggestions: ["运行 gradlew tasks 查看任务", "常见任务为 assembleRelease 或 assemble<Flavor>Release"],
      stepId,
      causeResult: result,
    })
  }

  if (combined.includes("already signed") || combined.includes("signature")) {
    return new DroidSealError({
      code: "SIGNATURE_OPERATION_FAILED",
      message: "APK 签名操作失败",
      explanation:
        "APK 结构、现有签名块、签名算法兼容性或签名库配置导致 apksigner 拒绝处理。DroidSeal 使用独立输出文件，因此原始 APK 未被改写。",
      suggestions: ["先执行 apksigner verify --verbose 查看现有签名", "确认 zipalign 在签名前执行", "检查 minSdk 与签名算法是否兼容"],
      stepId,
      causeResult: result,
    })
  }

  if (combined.includes("not a valid zip") || combined.includes("zip archive") || combined.includes("central directory")) {
    return new DroidSealError({
      code: "INVALID_APK_ARCHIVE",
      message: "输入文件不是有效的 APK/ZIP",
      explanation: "APK 本质上是 ZIP 容器；中央目录缺失、文件被截断或扩展名伪装都会导致该错误。",
      suggestions: ["重新获取完整 APK", "核对文件大小与 SHA-256", "不要把 AAB 文件当作 APK 传入"],
      stepId,
      causeResult: result,
    })
  }

  return new DroidSealError({
    code: "EXTERNAL_TOOL_FAILED",
    message: `${result.command} 执行失败（退出码 ${result.exitCode}）`,
    explanation:
      "外部工具返回了非零退出码。详细输出已经过密码脱敏并保留在本步骤结果中；DroidSeal 已回退到步骤前的有效产物。",
    suggestions: ["查看错误输出中的第一处根因", "运行环境诊断确认工具版本", "检查输入、输出路径和文件权限"],
    stepId,
    causeResult: result,
  })
}

export function normalizeError(error: unknown, stepId?: StepId): DroidSealError {
  if (error instanceof DroidSealError) return error
  if (error instanceof Error) {
    return new DroidSealError({
      code: "UNEXPECTED_ERROR",
      message: error.message,
      explanation: "DroidSeal 遇到了未分类的异常。当前步骤不会覆盖上一份有效 APK。",
      suggestions: ["查看报告中的异常类型", "使用 --debug 复现并提交问题"],
      stepId,
      cause: error,
    })
  }
  return new DroidSealError({
    code: "UNKNOWN_ERROR",
    message: String(error),
    explanation: "捕获到非标准错误值。当前步骤已经停止并回退。",
    stepId,
    cause: error,
  })
}
