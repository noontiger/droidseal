import path from "node:path"
import type {
  BuildMode,
  CreateSigningConfig,
  InputKind,
  PipelineConfig,
  RunMode,
  SigningMode,
} from "../core/types.ts"

export type QuestionKind = "text" | "secret" | "choice"

export interface QuestionChoice {
  value: string
  label: string
  detail: string
  shortcut: string
}

export interface WizardQuestion {
  id: string
  kind: QuestionKind
  title: string
  prompt: string
  detail: string
  defaultValue?: string
  placeholder?: string
  choices?: QuestionChoice[]
}

export interface WizardDraft {
  runMode: RunMode
  inputKind?: InputKind
  inputPath: string
  gradleTask: string
  buildMode?: BuildMode
  explicitBuiltApkPath: string
  outputDirectory: string
  enableAlignment?: boolean
  enableWebAssetMinification?: boolean
  enableArscObfuscation?: boolean
  signingMode?: SigningMode
  // Only meaningful when signingMode === "existing": when true, the user wants
  // to generate a fresh replacement keystore (换新密钥) instead of reusing the
  // existing one. buildPipelineConfig then emits a CreateSigningConfig.
  renewKey?: boolean
  keystorePath: string
  keyAlias: string
  storePassword: string
  keyPassword: string
  commonName: string
  organizationalUnit: string
  organization: string
  locality: string
  state: string
  country: string
  validityDays: number
  keyAlgorithm: "RSA" | "EC"
}

export function createDraft(runMode: RunMode): WizardDraft {
  return {
    runMode,
    inputPath: "",
    gradleTask: "assembleRelease",
    buildMode: "full",
    explicitBuiltApkPath: "",
    outputDirectory: "",
    keystorePath: "",
    keyAlias: "",
    storePassword: "",
    keyPassword: "",
    commonName: "",
    organizationalUnit: "",
    organization: "",
    locality: "",
    state: "",
    country: "CN",
    validityDays: 9_125,
    keyAlgorithm: "RSA",
  }
}

function withoutOuterQuotes(value: string): string {
  const trimmed = value.trim()
  if (
    trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

function outputDefault(draft: WizardDraft): string {
  if (!draft.inputPath) return path.resolve("droidseal-output")
  const input = path.resolve(draft.inputPath)
  return draft.inputKind === "apk"
    ? path.join(path.dirname(input), "droidseal-output")
    : path.join(input, "droidseal-output")
}

// 最终 APK 文件名以输入项目/APK 名称为基础（与 pipeline 的 artifactName 一致），
// 默认带 -guarded-signed 后缀；签名未通过验证时为 -guarded-unsigned。
function outputFileBase(draft: WizardDraft): string {
  if (!draft.inputPath) return "application"
  return (
    path.basename(draft.inputPath, path.extname(draft.inputPath)).replace(/[^\p{L}\p{N}._-]+/gu, "-") || "application"
  )
}

function keystoreDefault(draft: WizardDraft): string {
  return path.join(draft.outputDirectory || outputDefault(draft), "release-key.p12")
}

export function questionsFor(draft: WizardDraft): WizardQuestion[] {
  const questions: WizardQuestion[] = [
    {
      id: "inputKind",
      kind: "choice",
      title: "选择输入类型",
      prompt: "这次从哪里开始？",
      detail: "选择 APK 时，“源码安全审计”和“Gradle 构建”会因不适用而正常跳过；选择项目时会执行源码审计和构建。",
      choices: [
        { value: "apk", label: "已有 APK", detail: "从现成 .apk 开始，不重复构建", shortcut: "1" },
        { value: "project", label: "Android 项目", detail: "先审计源码，再用 Gradle Wrapper 构建", shortcut: "2" },
      ],
    },
    {
      id: "inputPath",
      kind: "text",
      title: draft.inputKind === "project" ? "Android 项目路径" : "APK 文件路径",
      prompt:
        draft.inputKind === "project"
          ? "请输入包含 gradlew/gradlew.bat 的项目根目录"
          : "请输入需要处理的 .apk 文件",
      detail: "支持绝对路径；从文件管理器复制的带引号路径也可以直接粘贴。",
      placeholder: draft.inputKind === "project" ? "C:\\work\\my-android-app" : "C:\\work\\app-release.apk",
    },
  ]

  if (draft.inputKind === "project") {
    questions.push(
      {
        id: "gradleTask",
        kind: "text",
        title: "Gradle 构建任务",
        prompt: "输入要执行的 release 构建任务（通常直接回车）",
        detail: "默认 assembleRelease；多渠道项目可填写 assembleDemoRelease 等实际任务名。这里不是项目名、APK 名或输出目录。",
        defaultValue: "assembleRelease",
      },
      {
        id: "buildMode",
        kind: "choice",
        title: "构建模式",
        prompt: "这次是完整构建还是快速重建？",
        detail:
          "完整构建适合首次或依赖有变：先 npm install 装依赖、再 gradlew clean 清理后出包。快速重建只改了代码/资源时用：跳过 npm install 与 clean，更快。仅对 Capacitor 项目生效（会自动 cap sync 同步 www 并按本机 JDK 适配 capacitor.build.gradle）；纯 Gradle 项目此项不影响。",
        choices: [
          { value: "full", label: "完整构建", detail: "npm install + cap sync + clean + 出包（首次或依赖有变）", shortcut: "1" },
          { value: "quick", label: "快速重建", detail: "cap sync + 出包，跳过 npm install 与 clean（更快）", shortcut: "2" },
        ],
      },
      {
        id: "explicitBuiltApkPath",
        kind: "text",
        title: "APK 输出路径（可留空）",
        prompt: "若项目使用自定义输出路径，请填写构建后的 APK；否则直接回车",
        detail: "必须是具体的 .apk 文件，不能填写或拖入项目目录。留空时会自动查找最新生成的 APK；相对路径以项目根目录为基准。",
        defaultValue: "",
        placeholder: "app/build/outputs/apk/release/app-release.apk",
      },
    )
  }

  questions.push(
    {
      id: "outputDirectory",
      kind: "text",
      title: "输出目录（已提供默认地址）",
      prompt: "最终 APK 和本次报告保存到哪个目录？",
      detail: `默认地址会显示并预填在输入框中，可直接确认或修改。最终 APK 将保存为该目录下的 ${outputFileBase(draft)}-guarded-signed.apk（若最终签名未通过验证则为 ${outputFileBase(draft)}-guarded-unsigned.apk），并生成隐藏的 .droidseal/runs 运行记录；原始 APK 不会被覆盖。`,
      defaultValue: outputDefault(draft),
    },
  )

  questions.push(
    {
      id: "enableAlignment",
      kind: "choice",
      title: "APK 对齐",
      prompt: "签名前是否执行 zipalign？",
      detail: "推荐执行。若不重新签名，DroidSeal 会优先保护 APK 的现有 v2/v3 签名，必要时安全跳过 zipalign。",
      choices: [
        { value: "yes", label: "执行 zipalign", detail: "推荐：签名前对齐，最终再验证", shortcut: "1" },
        { value: "no", label: "不执行 zipalign", detail: "最终验证仍会检查当前 APK 的对齐状态", shortcut: "2" },
      ],
    },
    {
      id: "enableWebAssetMinification",
      kind: "choice",
      title: "混合应用 Web JavaScript 处理（可选）",
      prompt: "签名前是否用 Terser 压缩混淆 assets/public 与 assets/www 中的 JavaScript？",
      detail: "推荐用于 Capacitor/Cordova 发布包。仅处理严格白名单目录并移除 source map；ES module 才混淆顶层名，普通脚本保留可能跨文件或被 HTML 调用的全局名。全部脚本成功并复核 ZIP 后才写出；若不重新签名则保护已有签名并跳过。只能提高阅读门槛，不等于源码保密，仍需真机回归。",
      choices: [
        { value: "yes", label: "处理 Web JavaScript", detail: "推荐：Terser 保守压缩/混淆并移除 source map", shortcut: "1" },
        { value: "no", label: "保持 Web 资产不变", detail: "不改写 assets/public 与 assets/www", shortcut: "2" },
      ],
    },
    {
      id: "enableArscObfuscation",
      kind: "choice",
      title: "资源名混淆（有损·可选）",
      prompt: "签名前是否重命名 resources.arsc 资源名并扁平化资源路径？",
      detail: "默认不执行。开启后先做兼容性预检：检测到 getIdentifier 时保留全部条目名，DEX 明文引用的 res/ 路径也会保留；其余资源才重命名并在之后重新对齐、签名。仍建议真机回归动态皮肤和 WebView 本地资源。",
      choices: [
        { value: "no", label: "不混淆资源名", detail: "默认：保持 resources.arsc 不变", shortcut: "1" },
        { value: "yes", label: "混淆资源名", detail: "有损：重命名资源条目名并扁平化资源路径", shortcut: "2" },
      ],
    },
    {
      id: "signingMode",
      kind: "choice",
      title: "签名方式",
      prompt: "选择发布签名方式",
      detail: "签名密码只保存在本次进程内存，不写入配置、命令行参数或报告。无密钥可选“生成新密钥”；已有发布密钥可选“使用现有密钥”（或在该选项下换新密钥）；无需改动签名可“不签名”。",
      choices: [
        { value: "existing", label: "使用现有密钥（已有发布密钥）", detail: "复用已有 JKS/PKCS12 重新签名；更新已上架应用必须用原发布密钥。", shortcut: "1" },
        { value: "existing-renew", label: "使用现有密钥并换新密钥", detail: "在所选路径上生成全新密钥库并覆盖原文件；新密钥与旧密钥不同，用它签名的 APK 无法覆盖更新用旧密钥签名的应用安装，仅在确需更换发布主体或旧密钥泄露时使用。", shortcut: "2" },
        { value: "create", label: "生成新密钥（尚无发布密钥）", detail: "为尚未发布的新应用创建签名库：填写证书信息后由 DroidSeal 调用 keytool 生成。生成后务必立即备份——密钥一旦丢失将无法再为同一应用发布更新。", shortcut: "3" },
        { value: "skip", label: "不签名", detail: "保留并验证 APK 现有签名；若 APK 没有有效签名则无法正式发布。", shortcut: "4" },
      ],
    },
  )

  const isRenew = draft.signingMode === "existing" && draft.renewKey === true

  if (draft.signingMode && draft.signingMode !== "skip") {
    questions.push(
      {
        id: "keystorePath",
        kind: "text",
        title:
          isRenew
            ? "新密钥库路径（覆盖原文件）"
            : draft.signingMode === "create"
              ? "新签名库路径（可自定）"
              : "现有签名库路径",
        prompt:
          isRenew
            ? "输入要生成的新密钥库路径；同名原文件将被覆盖"
            : draft.signingMode === "create"
              ? "输入新签名库保存路径（可自由选择位置，请妥善备份）"
              : "输入现有 JKS/PKCS12 文件路径",
        detail:
          isRenew
            ? "将在此路径生成全新密钥库并覆盖同名原文件。⚠ 新密钥与旧密钥不同，用它签名的 APK 无法覆盖更新用旧密钥签名的应用安装。建议先备份原密钥库再继续。"
            : draft.signingMode === "create"
              ? "DroidSeal 绝不覆盖现有密钥文件；新密钥库请保存在可靠且已备份的位置。.p12 使用 PKCS12，.jks 使用 JKS。可在此自由选择文件保存位置。"
              : "请使用正式发布密钥；调试密钥（debug.keystore）不适合分发。",
        ...((draft.signingMode === "create" || isRenew)
          ? { defaultValue: draft.keystorePath || keystoreDefault(draft) }
          : { placeholder: "C:\\keys\\release.jks" }),
      },
      {
        id: "keyAlias",
        kind: "text",
        title: isRenew ? "新密钥别名" : "密钥别名",
        prompt: isRenew
          ? "输入新密钥库中的密钥别名"
          : "输入 JKS/PKCS12 中用于签名的 alias",
        detail: isRenew
          ? "新密钥库的密钥别名（将覆盖原文件中的密钥条目）。"
          : draft.signingMode === "existing"
            ? "别名必须指向 PrivateKeyEntry，而不仅是证书条目。请仔细核对填写的密钥别名——用错别名会导致签名校验失败并回到本步骤重新填写。"
            : "别名必须指向 PrivateKeyEntry，而不仅是证书条目。",
      },
      {
        id: "storePassword",
        kind: "secret",
        title: isRenew ? "新签名库密码" : "签名库密码",
        prompt: "输入签名库密码",
        detail: isRenew
          ? "新建密钥库密码，通常要求至少 6 个字符；本次生成的密钥库请务必立即备份。"
          : draft.signingMode === "create"
            ? "新建密钥通常要求至少 6 个字符。"
            : "输入不会回显。请仔细核对填写的签名库密码——密码错误会导致签名校验失败并回到本步骤重新填写。",
        placeholder: "••••••••",
      },
      {
        id: "keyPassword",
        kind: "secret",
        title: isRenew ? "新私钥密码" : "私钥密码",
        prompt: "输入私钥密码；直接回车表示与签名库密码相同",
        detail: isRenew
          ? "新建 PKCS12 必须与签名库密码一致；JKS 可使用独立密码。生成的新密钥库请务必备份。"
          : "新建 PKCS12 时必须与签名库密码一致；JKS 可使用独立密码。",
        defaultValue: "",
        placeholder: "••••••••（回车沿用上一项）",
      },
    )
  }

  if (draft.signingMode === "create" || isRenew) {
    questions.push(
      {
        id: "commonName",
        kind: "text",
        title: "证书名称（CN）",
        prompt: "输入证书持有者或产品名称",
        detail: "CN 是证书主题中的 Common Name。建议填写公司法定名称或稳定的发布主体。",
        placeholder: "Example Technology Co., Ltd.",
      },
      {
        id: "organizationalUnit",
        kind: "text",
        title: "组织部门（OU，可留空）",
        prompt: "输入组织部门，或直接回车",
        detail: "例如 Mobile Engineering。",
        defaultValue: "",
      },
      {
        id: "organization",
        kind: "text",
        title: "组织（O，可留空）",
        prompt: "输入组织名称，或直接回车",
        detail: "建议与发布主体一致。",
        defaultValue: "",
      },
      {
        id: "locality",
        kind: "text",
        title: "城市（L，可留空）",
        prompt: "输入城市，或直接回车",
        detail: "X.500 Distinguished Name 字段。",
        defaultValue: "",
      },
      {
        id: "state",
        kind: "text",
        title: "省/州（ST，可留空）",
        prompt: "输入省或州，或直接回车",
        detail: "X.500 Distinguished Name 字段。",
        defaultValue: "",
      },
      {
        id: "country",
        kind: "text",
        title: "国家代码（C）",
        prompt: "输入两个字母的国家/地区代码",
        detail: "例如 CN、US；也可以留空。",
        defaultValue: "CN",
      },
      {
        id: "validityDays",
        kind: "text",
        title: "证书有效期",
        prompt: "输入有效天数",
        detail: "发布证书应覆盖应用预期维护周期；默认约 25 年。",
        defaultValue: "9125",
      },
      {
        id: "keyAlgorithm",
        kind: "choice",
        title: "密钥算法",
        prompt: "选择新签名密钥算法",
        detail: "RSA 兼容范围广；EC 密钥更短，但需确认目标设备与分发链兼容。",
        choices: [
          { value: "RSA", label: "RSA 4096", detail: "推荐兼容选项", shortcut: "1" },
          { value: "EC", label: "EC P-256", detail: "更短密钥与签名", shortcut: "2" },
        ],
      },
    )
  }
  return questions
}

export function nextQuestion(draft: WizardDraft, answered: ReadonlySet<string>): WizardQuestion | undefined {
  return questionsFor(draft).find((question) => !answered.has(question.id))
}

export function applyAnswer(
  draft: WizardDraft,
  question: WizardQuestion,
  rawValue: string,
): { draft: WizardDraft; displayValue: string } {
  const next = { ...draft }
  const defaulted = rawValue.trim() === "" && question.defaultValue !== undefined
    ? question.defaultValue
    : rawValue
  const value = question.kind === "secret" ? defaulted : withoutOuterQuotes(defaulted)

  switch (question.id) {
    case "inputKind":
      if (value !== "apk" && value !== "project") throw new Error("请选择“已有 APK”或“Android 项目”")
      next.inputKind = value
      break
    case "inputPath":
      if (!value) throw new Error("输入路径不能为空")
      next.inputPath = value
      break
    case "gradleTask":
      if (!/^[A-Za-z0-9_:.-]+$/.test(value)) throw new Error("Gradle 任务名只能包含字母、数字、_、:、. 和 -")
      if (
        draft.inputPath &&
        value.toLowerCase() === `${path.basename(path.resolve(draft.inputPath)).toLowerCase()}-release`
      ) {
        throw new Error(`“${value}”看起来是 APK/项目名称，不是 Gradle 任务；这里通常直接回车使用 assembleRelease`)
      }
      next.gradleTask = value
      break
    case "buildMode":
      if (value !== "full" && value !== "quick") throw new Error("请选择“完整构建”或“快速重建”")
      next.buildMode = value
      break
    case "explicitBuiltApkPath":
      if (value && path.extname(value).toLowerCase() !== ".apk") {
        throw new Error("APK 输出路径必须指向具体的 .apk 文件；若拖入的是整个项目目录，请在这里直接回车留空")
      }
      next.explicitBuiltApkPath = value
      break
    case "outputDirectory":
      if (!value) throw new Error("输出目录不能为空")
      next.outputDirectory = value
      break
    case "enableAlignment":
      if (value !== "yes" && value !== "no") throw new Error("请选择是否执行对齐")
      next.enableAlignment = value === "yes"
      break
    case "enableWebAssetMinification":
      if (value !== "yes" && value !== "no") throw new Error("请选择是否处理 Web JavaScript")
      next.enableWebAssetMinification = value === "yes"
      break
    case "enableArscObfuscation":
      if (value !== "yes" && value !== "no") throw new Error("请选择是否混淆资源名")
      next.enableArscObfuscation = value === "yes"
      break
    case "signingMode":
      if (value !== "existing" && value !== "existing-renew" && value !== "create" && value !== "skip") {
        throw new Error("请选择有效的签名方式")
      }
      // “换新密钥”作为“使用现有密钥”选项下的子选项：existing-renew 同时设置 renewKey。
      next.signingMode = value === "existing-renew" ? "existing" : value
      next.renewKey = value === "existing-renew"
      break
    case "keystorePath":
      if (!value) throw new Error("签名库路径不能为空")
      next.keystorePath = value
      break
    case "keyAlias":
      if (!value) throw new Error("密钥别名不能为空")
      next.keyAlias = value
      break
    case "storePassword":
      if (!value) throw new Error("签名库密码不能为空")
      if (draft.signingMode === "create" && value.length < 6) throw new Error("新签名库密码至少需要 6 个字符")
      next.storePassword = value
      break
    case "keyPassword":
      next.keyPassword = value || draft.storePassword
      if (draft.signingMode === "create" && next.keyPassword.length < 6) {
        throw new Error("新私钥密码至少需要 6 个字符")
      }
      break
    case "commonName":
      if (!value) throw new Error("证书 CN 不能为空")
      next.commonName = value
      break
    case "organizationalUnit":
      next.organizationalUnit = value
      break
    case "organization":
      next.organization = value
      break
    case "locality":
      next.locality = value
      break
    case "state":
      next.state = value
      break
    case "country":
      if (value && !/^[A-Za-z]{2}$/.test(value)) throw new Error("国家代码必须为空或恰好两个字母")
      next.country = value.toUpperCase()
      break
    case "validityDays": {
      const days = Number(value)
      if (!Number.isInteger(days) || days < 365 || days > 36_500) {
        throw new Error("有效期必须是 365 到 36500 之间的整数天")
      }
      next.validityDays = days
      break
    }
    case "keyAlgorithm":
      if (value !== "RSA" && value !== "EC") throw new Error("请选择 RSA 或 EC")
      next.keyAlgorithm = value
      break
    default:
      throw new Error(`未知向导字段：${question.id}`)
  }
  return {
    draft: next,
    displayValue: question.kind === "secret" ? "••••••（已安全接收）" : value || "（留空）",
  }
}

export function buildPipelineConfig(draft: WizardDraft): PipelineConfig {
  if (!draft.inputKind || draft.enableAlignment === undefined || draft.enableWebAssetMinification === undefined || draft.enableArscObfuscation === undefined || !draft.signingMode) {
    throw new Error("向导尚未完成")
  }
  const protection: PipelineConfig["protection"] = { mode: "local-safe" }

  let signing: PipelineConfig["signing"]

  const createSigning = (overwrite: boolean): CreateSigningConfig => ({
    mode: "create",
    keystorePath: draft.keystorePath,
    keyAlias: draft.keyAlias,
    storePassword: draft.storePassword,
    keyPassword: draft.keyPassword || draft.storePassword,
    validityDays: draft.validityDays,
    keyAlgorithm: draft.keyAlgorithm,
    keySize: draft.keyAlgorithm === "RSA" ? 4_096 : 256,
    distinguishedName: {
      commonName: draft.commonName,
      organizationalUnit: draft.organizationalUnit,
      organization: draft.organization,
      locality: draft.locality,
      state: draft.state,
      country: draft.country,
    },
    overwrite,
  })

  const renewing = draft.signingMode === "existing" && draft.renewKey === true
  if (draft.signingMode === "skip") {
    signing = { mode: "skip" }
  } else if (draft.signingMode === "existing" && !renewing) {
    signing = {
      mode: "existing",
      keystorePath: draft.keystorePath,
      keyAlias: draft.keyAlias,
      storePassword: draft.storePassword,
      keyPassword: draft.keyPassword || draft.storePassword,
    }
  } else {
    // 生成新密钥，或在“使用现有密钥”下选择“换新密钥”（覆盖原文件）。
    signing = createSigning(renewing)
  }

  const config: PipelineConfig = {
    runMode: draft.runMode,
    inputKind: draft.inputKind,
    inputPath: path.resolve(draft.inputPath),
    outputDirectory: path.resolve(draft.outputDirectory),
    gradleTask: draft.gradleTask,
    buildMode: draft.buildMode ?? "full",
    enableAlignment: draft.enableAlignment,
    enableWebAssetMinification: draft.enableWebAssetMinification,
    enableArscObfuscation: draft.enableArscObfuscation,
    signing,
    protection,
  }
  if (draft.explicitBuiltApkPath) config.explicitBuiltApkPath = draft.explicitBuiltApkPath
  return config
}

export function summaryLines(draft: WizardDraft): string[] {
  const signingSummary =
    draft.signingMode === "skip"
      ? "不重新签名；最终验证现有签名"
      : draft.signingMode === "existing" && draft.renewKey
        ? "换新密钥：覆盖生成全新密钥库并签名（新密钥无法更新旧安装）"
        : draft.signingMode === "existing"
          ? "使用现有签名库重新签名"
          : "新建签名库并签名"
  return [
    `模式：${draft.runMode === "one-click" ? "一键处理" : "分步确认"}`,
    `输入：${draft.inputKind === "project" ? "Android 项目" : "APK"} · ${draft.inputPath}`,
    ...(draft.inputKind === "project"
      ? [`构建：${draft.gradleTask} · ${draft.buildMode === "quick" ? "快速重建" : "完整构建"}`]
      : []),
    `输出：${draft.outputDirectory}`,
    "保护：本地安全档（严格证据审计 + R8 + Release 归一化；不对未知 APK 注入启动代码）",
    `zipalign：${draft.enableAlignment ? "执行" : "按配置不执行；最终仍验证"}`,
    `Web JavaScript：${draft.enableWebAssetMinification ? "Terser 处理并移除 source map（签名前）" : "不处理"}`,
    `资源名混淆：${draft.enableArscObfuscation ? "执行（有损，签名前生成新包）" : "不执行"}`,
    `签名：${signingSummary}`,
    ...(draft.signingMode && draft.signingMode !== "skip"
      ? [
          `签名库：${draft.keystorePath}${draft.signingMode === "existing" && draft.renewKey ? "（将覆盖原文件）" : ""}`,
          `别名：${draft.keyAlias}`,
          "密码：••••••（仅内存）",
        ]
      : []),
  ]
}
