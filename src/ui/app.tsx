import path from "node:path"
import { stat } from "node:fs/promises"
import {
  For,
  Show,
  createEffect,
  createMemo,
  createSignal,
  onCleanup,
  onMount,
} from "solid-js"
import type { MouseEvent, ScrollBoxRenderable } from "@opentui/core"
import { useKeyboard, usePaste, useRenderer, useTerminalDimensions } from "@opentui/solid"
import { DROIDSEAL_LOGO, DROIDSEAL_LOGO_HEIGHT, DROIDSEAL_LOGO_WIDTH, VERSION } from "../brand.ts"
import { Pipeline, STEP_DEFINITIONS, statusGlyph } from "../core/pipeline.ts"
import { sha256File } from "../core/apk-audit.ts"
import { language, setLanguage, t, tGuidance, translateDetail, translateProgress, translateSummary, tStep, tStepDesc } from "./i18n.ts"
import {
  createToolRecoveryPlan,
  installMissingTools,
  type ToolRecoveryPlan,
} from "../core/tool-installer.ts"
import { discoverToolchain } from "../core/toolchain.ts"
import type {
  PipelineConfig,
  RunMode,
  SkipKind,
  StepResult,
  StepState,
  Toolchain,
} from "../core/types.ts"
import { Button } from "./button.tsx"
import { stepColor, theme } from "./theme.ts"
import { changeInteractionZoom, interactionZoomMetrics, zoomDirectionFromKey, type InteractionZoom } from "./zoom.ts"
import {
  applyAnswer,
  buildPipelineConfig,
  createDraft,
  nextQuestion,
  questionsFor,
  summaryLines,
  type WizardDraft,
  type WizardQuestion,
} from "./wizard.ts"

type Screen = "welcome" | "wizard" | "pipeline"

interface ActiveButton {
  label: string
  detail?: string
  shortcut?: string
  tone?: "accent" | "neutral" | "danger" | "input"
  disabled?: boolean
  centered?: boolean
  onPress: () => void
}
type MessageRole = "assistant" | "user" | "success" | "error" | "system" | "warning"

interface ChatMessage {
  id: number
  role: MessageRole
  title: string
  body: string[]
}

interface ToolRecoveryState {
  config: PipelineConfig | undefined
  toolchain: Toolchain
  plan: ToolRecoveryPlan
  resume: "standalone" | "guided" | "one-click"
  stepIndex: number
}

const SPINNER = ["✦", "✧", "·", "✧"] as const

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

// 读取系统剪贴板文本(右键粘贴用);失败时返回空字符串
function readClipboard(): string {
  try {
    if (process.platform === "win32") {
      const result = Bun.spawnSync(["powershell", "-NoProfile", "-Command", "Get-Clipboard"], { stdout: "pipe" })
      return result.stdout?.toString().trim() ?? ""
    }
    for (const command of [["xclip", "-o", "-selection", "clipboard"], ["wl-paste"]]) {
      const result = Bun.spawnSync(command, { stdout: "pipe" })
      if (result.exitCode === 0) return result.stdout?.toString().trim() ?? ""
    }
  } catch {
    // 剪贴板不可用时静默返回空
  }
  return ""
}

// 复制文本到系统剪贴板(Ctrl+C 用);失败时静默返回
function copyToClipboard(text: string): void {
  if (!text) return
  try {
    if (process.platform === "win32") {
      const safe = text.replace(/'/g, "''")
      Bun.spawnSync(["powershell", "-NoProfile", "-Command", `Set-Clipboard -Value '${safe}'`])
    } else {
      for (const command of [["xclip", "-selection", "clipboard"], ["wl-copy"]]) {
        const proc = Bun.spawn(command, { stdin: "pipe" })
        proc.stdin?.write(text)
        proc.stdin?.end()
        return
      }
    }
  } catch {
    // 剪贴板不可用时静默返回
  }
}

function roleColor(role: MessageRole): string {
  const colors: Record<MessageRole, string> = {
    assistant: theme.accent,
    user: theme.purple,
    success: theme.success,
    error: theme.error,
    system: theme.textMuted,
    warning: theme.warning,
  }
  return colors[role]
}

function resultRole(result: StepResult): MessageRole {
  if (result.status === "success") return "success"
  if (result.status === "failed") return "error"
  return "system"
}

export function skipKindLabel(kind: SkipKind | undefined): string {
  const labels: Record<SkipKind, string> = {
    "not-applicable": t("skipNotApplicable"),
    "user-choice": t("skipUserChoice"),
    configuration: t("skipConfiguration"),
    safety: t("skipSafety"),
    "missing-input": t("skipMissingInput"),
  }
  return kind ? labels[kind] : t("skipReasonExplained")
}

function choiceFromText(question: WizardQuestion, raw: string): string {
  const normalized = raw.trim().toLowerCase()
  const match = question.choices?.find(
    (choice) =>
      normalized === choice.value.toLowerCase() ||
      normalized === choice.label.toLowerCase() ||
      normalized === choice.shortcut.toLowerCase() ||
      choice.label.toLowerCase().includes(normalized),
  )
  if (match) return match.value

  if (question.id === "enableAlignment") {
    if (["是", "执行", "对齐", "yes", "y"].includes(normalized)) return "yes"
    if (["否", "不", "跳过", "no", "n"].includes(normalized)) return "no"
  }
  if (question.id === "enableWebAssetMinification") {
    if (["是", "执行", "处理", "压缩", "混淆", "yes", "y"].includes(normalized)) return "yes"
    if (["否", "不", "跳过", "no", "n"].includes(normalized)) return "no"
  }
  if (question.id === "enableArscObfuscation") {
    if (["是", "执行", "混淆", "yes", "y"].includes(normalized)) return "yes"
    if (["否", "不", "跳过", "no", "n"].includes(normalized)) return "no"
  }
  if (question.id === "inputKind") {
    if (normalized.includes("apk")) return "apk"
    if (normalized.includes("项目") || normalized.includes("project")) return "project"
  }
  if (question.id === "signingMode") {
    if (normalized.includes("现有")) return "existing"
    if (normalized.includes("新建") || normalized.includes("创建")) return "create"
    if (normalized.includes("跳过") || normalized.includes("不签")) return "skip"
  }
  return raw
}

export function App() {
  const renderer = useRenderer()
  const dimensions = useTerminalDimensions()
  const [screen, setScreen] = createSignal<Screen>("welcome")
  const [messages, setMessages] = createSignal<ChatMessage[]>([
    {
      id: 1,
      role: "assistant",
      title: t("welcomeTitle"),
      body: [t("welcomeDesc1"), t("welcomeDesc2"), t("welcomeDesc3"), t("welcomeDesc4")],
    },
  ])
  // 欢迎消息随语言切换更新(id=1 是欢迎消息)
  createEffect(() => {
    language()
    setMessages((current) =>
      current.map((message) =>
        message.id === 1
          ? { ...message, title: t("welcomeTitle"), body: [t("welcomeDesc1"), t("welcomeDesc2"), t("welcomeDesc3"), t("welcomeDesc4")] }
          : message,
      ),
    )
  })
  const [messageId, setMessageId] = createSignal(2)
  const [composer, setComposer] = createSignal("")
  const [secretBuffer, setSecretBuffer] = createSignal("")
  const [draft, setDraft] = createSignal<WizardDraft>(createDraft("guided"))
  const [answered, setAnswered] = createSignal<Set<string>>(new Set())
  const [pipeline, setPipeline] = createSignal<Pipeline>()
  const [steps, setSteps] = createSignal<StepState[]>(
    STEP_DEFINITIONS.map((definition) => ({ ...definition, status: "pending" })),
  )
  const [currentStepIndex, setCurrentStepIndex] = createSignal(0)
  const [busy, setBusy] = createSignal(false)
  const [thinking, setThinking] = createSignal("")
  const [needsFailureAdvance, setNeedsFailureAdvance] = createSignal(false)
  const [pipelineDone, setPipelineDone] = createSignal(false)
  const [spinnerIndex, setSpinnerIndex] = createSignal(0)
  const [toolRecovery, setToolRecovery] = createSignal<ToolRecoveryState>()
  const [interactionZoom, setInteractionZoom] = createSignal<InteractionZoom>(100)

  const currentQuestion = createMemo(() =>
    screen() === "wizard" ? nextQuestion(draft(), answered()) : undefined,
  )
  const isSecretQuestion = createMemo(() => currentQuestion()?.kind === "secret")
  const isTextQuestion = createMemo(() => currentQuestion()?.kind === "text")
  const needsWizardInput = createMemo(() => isTextQuestion() || isSecretQuestion())
  const showSidebar = createMemo(() => dimensions().width >= 104)
  const currentStep = createMemo(() => steps()[currentStepIndex()])
  const completedCount = createMemo(
    () => steps().filter((step) => ["success", "failed", "skipped"].includes(step.status)).length,
  )
  const zoomMetrics = createMemo(() => interactionZoomMetrics(interactionZoom()))
  const successCount = createMemo(() => steps().filter((step) => step.status === "success").length)
  const skippedCount = createMemo(() => steps().filter((step) => step.status === "skipped").length)
  const failedCount = createMemo(() => steps().filter((step) => step.status === "failed").length)

  const inputValue = createMemo(() => isSecretQuestion() ? secretBuffer() : composer())
  const canSubmitInput = createMemo(() =>
    needsWizardInput() && (
      inputValue().trim().length > 0 || currentQuestion()?.defaultValue !== undefined
    ),
  )
  const inputActionLabel = createMemo(() => {
    const question = currentQuestion()
    if (question?.defaultValue !== undefined && inputValue() === question.defaultValue) {
      if (question.id === "keyPassword") return t("reuseStorePassword")
      return question.defaultValue ? t("btnUseDefault") : t("btnContinueEmpty")
    }
    if (inputValue().trim()) return t("btnConfirmInput")
    if (currentQuestion()?.defaultValue !== undefined) return t("btnUseDefault")
    return t("btnPleaseInput")
  })
  const inputActionDetail = createMemo(() => {
    const defaultValue = currentQuestion()?.defaultValue
    if (defaultValue === undefined) return t("btnFillAndContinue")
    return defaultValue ? t("inputPrefillNote") : t("inputEmptyOk")
  })
  const passiveInteractionText = createMemo(() => {
    if (toolRecovery()) return t("passiveRecovery")
    if (screen() === "wizard") {
      return currentQuestion()?.kind === "choice"
        ? t("passiveChoice")
        : t("passiveReady")
    }
    if (screen() === "pipeline") {
      if (busy()) return t("passiveBusy")
      if (pipelineDone()) return t("passiveDone")
      if (needsFailureAdvance()) return t("passiveFailureAdvance")
      if (pipeline()?.config.runMode === "guided") return t("passiveGuided")
      return t("passiveOneClick")
    }
    return ""
  })
  const showComposer = createMemo(() => screen() === "welcome" && !toolRecovery())

  // 对话框上方操作行的按钮:方向键左右循环切换焦点,Enter 激活聚焦按钮。
  const [focusedButtonIndex, setFocusedButtonIndex] = createSignal(0)
  // 当前有效产物名(反应式):由流水线事件驱动更新,避免直接读 context 可变属性不触发渲染
  const [currentArtifactName, setCurrentArtifactName] = createSignal<string | undefined>()
  // 当前产物完整路径与信息(大小/SHA-256/所在目录)
  const [artifactPath, setArtifactPath] = createSignal<string>()
  const [artifactInfo, setArtifactInfo] = createSignal<{ size: number; sha256: string; dir: string }>()
  createEffect(() => {
    const artifact = artifactPath()
    if (!artifact) {
      setArtifactInfo(undefined)
      return
    }
    void (async () => {
      const info = await stat(artifact).catch(() => undefined)
      const sha256 = await sha256File(artifact).catch(() => "")
      setArtifactInfo({ size: info?.size ?? 0, sha256, dir: path.dirname(artifact) })
    })()
  })
  const openArtifactFolder = () => {
    const artifact = artifactPath()
    if (!artifact) return
    if (process.platform === "win32") {
      void Bun.spawn(["explorer", `/select,${artifact}`])
    } else {
      void Bun.spawn(["xdg-open", path.dirname(artifact)])
    }
  }
  const activeButtons = createMemo<ActiveButton[]>(() => {
    if (screen() === "wizard") {
      const question = currentQuestion()
      if (question?.kind === "choice") {
        return (
          question.choices?.map((choice) => ({
            label: choice.label,
            detail: choice.detail,
            shortcut: choice.shortcut,
            tone: choice.shortcut === "1" ? ("accent" as const) : ("neutral" as const),
            onPress: () => submitWizardAnswer(choice.value, choice.label),
          })) ?? []
        )
      }
      if (!question) {
        return [
          { label: t("btnStart"), shortcut: "Enter", tone: "accent" as const, detail: t("btnStartDetail"), onPress: startConfiguredPipeline },
          { label: t("btnRefill"), detail: t("btnRefillDetail"), onPress: () => startWizard(draft().runMode) },
        ]
      }
      return []
    }
    if (screen() === "pipeline") {
      if (pipelineDone()) {
        return [
          { label: t("btnNewTask"), detail: t("btnNewTaskDetail"), tone: "accent" as const, centered: true, onPress: resetHome },
          { label: t("btnExit"), detail: t("btnExitDetail"), centered: true, onPress: () => renderer.destroy() },
        ]
      }
      if (!busy() && pipeline()?.config.runMode === "guided" && !toolRecovery()) {
        if (needsFailureAdvance()) {
          return [
            {
              label: t("btnRollbackAdvance"),
              shortcut: "Enter",
              tone: "danger" as const,
              detail: t("btnRollbackAdvanceDetail"),
              onPress: () => {
                setNeedsFailureAdvance(false)
                advanceGuided()
              },
            },
          ]
        }
        const buttons: ActiveButton[] = [
          { label: t("btnExecute"), shortcut: "Enter", tone: "accent" as const, detail: currentStep()?.title ?? "", disabled: busy(), onPress: () => void executeGuidedStep() },
        ]
        if (currentStep()?.skippable) {
          buttons.push({ label: t("btnSkip"), shortcut: "S", detail: t("btnSkipDetail"), disabled: busy(), onPress: () => void skipGuidedStep() })
        }
        return buttons
      }
      return []
    }
    return []
  })
  // 场景切换后焦点索引自动收敛到有效范围
  createEffect(() => {
    const count = activeButtons().length
    if (count > 0 && focusedButtonIndex() >= count) setFocusedButtonIndex(0)
  })

  // Ctrl+C 复制:优先复制当前鼠标选中内容(OpenTUI 拖选),无选中时复制当前输入
  const copyForClipboard = () => {
    const selection = renderer.getSelection()
    const selected = selection?.isActive ? selection.getSelectedText() : ""
    copyToClipboard(selected || (isSecretQuestion() ? secretBuffer() : composer()))
  }

  onMount(() => {
    renderer.setTerminalTitle("DroidSeal · Android release security pipeline")
    const timer = setInterval(() => setSpinnerIndex((value) => (value + 1) % SPINNER.length), 120)
    onCleanup(() => clearInterval(timer))
    // Ctrl+C 永不退出:拦截 SIGINT 并复制(终端 ISIG 未清除时 Ctrl+C 会先发信号)
    const interruptHandler = () => {
      copyForClipboard()
    }
    process.on("SIGINT", interruptHandler)
    onCleanup(() => process.off("SIGINT", interruptHandler))
  })

  // 处理中强制消息区贴底:新步骤消息出现时保持在底部可见,避免停留在旧位置
  createEffect(() => {
    const current = steps()
    const active = thinking()
    const box = messageScrollBox
    if (!box) return
    if (active || current.some((step) => step.status === "processing")) {
      box.scrollTop = 1_000_000
    }
  })

  // 侧栏自动滚动:处理中的步骤显示在列表可见区中间(成功/跳过/失败 与底部产物区之间),
  // 与主界面进度保持关联;不再贴底
  createEffect(() => {
    const current = steps()
    const processingIndex = current.findIndex((step) => step.status === "processing")
    const box = progressScrollBox
    if (processingIndex < 0 || !box) return
    let offset = 0
    for (let i = 0; i < processingIndex; i += 1) {
      const step = current[i]!
      const resultLines = step.result ? Math.max(1, Math.ceil((step.result.summary ?? "").length / 36)) : 0
      offset += 1 + resultLines + 1 // 标题行 + 结果行 + paddingBottom
    }
    // 视口高度估算:窗口高 - 头部/底栏/计数行/底部产物区等固定开销
    const viewportEstimate = Math.max(4, dimensions().height - 21)
    box.scrollTop = Math.max(0, offset - Math.floor(viewportEstimate / 2))
  })

  // Show generated paths and other defaults as editable values before they are
  // accepted, rather than applying an invisible default after an empty Enter.
  createEffect(() => {
    const question = currentQuestion()
    if (screen() === "wizard" && question?.kind === "text") {
      setComposer(question.defaultValue ?? "")
    } else if (screen() !== "welcome") {
      setComposer("")
    }
  })

  const addMessage = (role: MessageRole, title: string, body: string[] = []) => {
    const id = messageId()
    setMessageId(id + 1)
    setMessages((current) => [...current, { id, role, title, body }])
  }

  const adjustInteractionZoom = (direction: "in" | "out" | "reset") => {
    setInteractionZoom((current) => changeInteractionZoom(current, direction))
  }

  let messageScrollBox: ScrollBoxRenderable | undefined
  let progressScrollBox: ScrollBoxRenderable | undefined
  const WHEEL_LINES = 3

  const isWithin = (node: unknown, ancestor: unknown): boolean => {
    let current = node as { parent?: unknown } | undefined
    while (current) {
      if (current === ancestor) return true
      current = current.parent as { parent?: unknown } | undefined
    }
    return false
  }

  // Wheel over a scrollbox's own content scrolls natively via OpenTUI's event
  // bubbling; this forwards wheel that lands on surrounding chrome (padding,
  // button row, sidebar frame) to the scrollbox instead of doing nothing. The
  // subtree guard prevents doubling the native scroll distance.
  const forwardWheel = (box: ScrollBoxRenderable | undefined, event: MouseEvent): boolean => {
    if (!box || !event.scroll) return false
    const direction = event.scroll.direction
    if (direction !== "up" && direction !== "down") return false
    if (isWithin(event.target, box)) return false
    box.scrollTop += direction === "down" ? WHEEL_LINES : -WHEEL_LINES
    return true
  }

  const handleInteractionMouseScroll = (event: MouseEvent) => {
    if (!event.scroll) return
    if (forwardWheel(messageScrollBox, event)) {
      event.preventDefault()
      event.stopPropagation()
    }
  }

  const handleProgressMouseScroll = (event: MouseEvent) => {
    if (!event.scroll || event.modifiers.ctrl) return
    if (forwardWheel(progressScrollBox, event)) {
      event.preventDefault()
      event.stopPropagation()
    }
  }

  const presentQuestion = (question: WizardQuestion | undefined, answerDraft = draft()) => {
    if (!question) {
      addMessage("assistant", "配置已填写完成", [
        ...summaryLines(answerDraft),
        "请检查摘要。签名密码不会显示，也不会写入报告。",
      ])
      return
    }
    addMessage("assistant", question.title, [
      question.prompt,
      question.detail,
      ...(question.defaultValue !== undefined
        ? ["默认值：" + (question.defaultValue || "留空") + "（可直接按 Enter）"]
        : []),
      question.kind === "choice"
        ? "此处无需输入文字，请点击选项或按对应数字键。"
        : "此处需要确认输入，填写后按 Enter 或点击“确认输入”。",
    ])
  }

  const startWizard = (mode: RunMode) => {
    const nextDraft = createDraft(mode)
    setDraft(nextDraft)
    setAnswered(new Set<string>())
    setSecretBuffer("")
    setScreen("wizard")
    setPipeline(undefined)
    setPipelineDone(false)
    setToolRecovery(undefined)
    setSteps(STEP_DEFINITIONS.map((definition) => ({ ...definition, status: "pending" })))
    addMessage(
      "assistant",
      mode === "one-click" ? t("msgOneClickSelected") : t("msgGuidedSelected"),
      [
        mode === "one-click"
          ? "填写必要信息后，所有步骤将连续执行；失败步骤自动回退并继续。"
          : "填写必要信息后，每个步骤执行前都会再次询问，可以点击“跳过”。",
      ],
    )
    presentQuestion(questionsFor(nextDraft)[0], nextDraft)
  }

  const submitWizardAnswer = (raw: string, displayOverride?: string) => {
    const question = currentQuestion()
    if (!question) return
    const normalized = question.kind === "choice" ? choiceFromText(question, raw) : raw
    try {
      const applied = applyAnswer(draft(), question, normalized)
      const nextAnswered = new Set(answered())
      nextAnswered.add(question.id)
      setDraft(applied.draft)
      setAnswered(nextAnswered)
      setSecretBuffer("")
      addMessage("user", displayOverride ?? applied.displayValue)
      presentQuestion(nextQuestion(applied.draft, nextAnswered), applied.draft)
    } catch (error) {
      addMessage("error", "这项信息还不能使用", [
        error instanceof Error ? error.message : String(error),
        "请修改后重新输入；当前问题不会被跳过。",
      ])
    }
  }

  // 签名相关的所有向导问题：校验失败时清空这些问题的已答状态，让用户重新填写。
  const SIGNING_QUESTION_IDS = [
    "signingMode", "renewKey", "keystorePath", "keyAlias", "storePassword", "keyPassword",
    "commonName", "organizationalUnit", "organization", "locality", "state", "country",
    "validityDays", "keyAlgorithm",
  ] as const

  // 签名库步骤（密码/别名/路径）或签名步骤失败时，回到签名方式问题重新填写；
  // 重新确认后流水线会从头开始执行。
  const resumeSigningAfterFailure = (failedStepId: string) => {
    const nextAnswered = new Set(answered())
    for (const id of SIGNING_QUESTION_IDS) nextAnswered.delete(id)
    setAnswered(nextAnswered)
    setSecretBuffer("")
    setBusy(false)
    setScreen("wizard")
    addMessage("error", "签名信息未通过校验", [
      failedStepId === "keystore"
        ? "签名库路径、密钥别名或密码可能不正确。请重新填写签名信息；确认后流水线将从头开始执行。"
        : "apksigner 签名失败，可能由密钥别名或密码错误导致。请重新填写签名信息；确认后流水线将从头开始执行。",
      "如果确认信息无误，请检查是否使用了正式发布密钥（调试密钥不适合分发）。",
    ])
    presentQuestion(nextQuestion(draft(), nextAnswered), draft())
  }

  const announceGuidedStep = (index: number) => {
    const state = pipeline()?.getSteps()[index]
    if (!state) {
      finishPipeline()
      return
    }
    setCurrentStepIndex(index)
    setNeedsFailureAdvance(false)
    addMessage("assistant", `${t("msgStepN").replace("{current}", String(index + 1)).replace("{total}", String(STEP_DEFINITIONS.length))}：${tStep(state.id)}`, [
      tStepDesc(state.id),
      ...tGuidance(state.id, pipeline()!.config),
      state.skippable ? t("guidStepSkippable") : t("guidStepRequired"),
    ])
  }

  const finishPipeline = () => {
    const active = pipeline()
    if (!active || pipelineDone()) return
    setPipelineDone(true)
    setBusy(false)
    setThinking("")
    const failed = active.getSteps().filter((step) => step.status === "failed")
    const skipped = active.getSteps().filter((step) => step.status === "skipped")
    const finalArtifact = active.context.finalArtifact
    addMessage(failed.length === 0 ? "success" : "warning", "全部步骤已处理", [
      `已处理：${active.getSteps().length}/${active.getSteps().length}；其中成功：${successCount()}；跳过：${skipped.length}；失败并回退：${failed.length}。请以“已处理”判断流程是否走完。`,
      ...(skipped.length > 0
        ? [`跳过原因：${skipped.map((step) => `${step.title}（${skipKindLabel(step.result?.skipKind)}）`).join("、")}。跳过不等于失败。`]
        : []),
      finalArtifact ? `最终 APK：${finalArtifact}` : "没有生成最终 APK，请根据失败步骤解释修复后重试。",
      active.context.signatureVerified === true ? "签名状态：apksigner 验证通过。" : active.context.signatureVerified === false ? "签名状态：未签名或签名无效。" : "签名状态：未验证。",
      `运行记录：${active.context.runDirectory}`,
    ])
  }

  const pauseForToolRecovery = async (
    active: Pipeline,
    resume: "guided" | "one-click",
    stepIndex: number,
  ): Promise<boolean> => {
    const tools = active.context.toolchain ?? await discoverToolchain(active.config)
    const plan = createToolRecoveryPlan(active.config, tools)
    if (plan.missing.length === 0) return false
    setToolRecovery({
      config: active.config,
      toolchain: tools,
      plan,
      resume,
      stepIndex,
    })
    setBusy(false)
    setThinking("")
    addMessage("warning", t("msgToolsNeeded"), [
      t("msgMissingTools").replace("{names}", plan.missing.map((tool) => tool.name).join("、")),
      plan.canAutoInstall
        ? t("recoveryDownloadHint")
        : t("recoveryManualHint"),
      t("recoveryRecheckHint"),
    ])
    return true
  }

  const runAll = async (active: Pipeline, startIndex = 0) => {
    setBusy(true)
    for (let index = startIndex; index < STEP_DEFINITIONS.length; index += 1) {
      setCurrentStepIndex(index)
      const definition = STEP_DEFINITIONS[index]!
      const result = await active.runStep(definition.id)
      if (definition.id === "doctor" && result.status === "failed") {
        if (await pauseForToolRecovery(active, "one-click", index)) return
      }
      if ((definition.id === "keystore" || definition.id === "sign") && result.status === "failed") {
        await resumeSigningAfterFailure(definition.id)
        return
      }
    }
    finishPipeline()
  }

  const startConfiguredPipeline = () => {
    let config: PipelineConfig
    try {
      config = buildPipelineConfig(draft())
    } catch (error) {
      addMessage("error", "无法开始", [error instanceof Error ? error.message : String(error)])
      return
    }
    const active = new Pipeline(config)
    active.onEvent((event) => {
      // 生成新的 step 对象引用,确保 Solid <For> 在每次事件时重渲染侧栏(原地修改同一对象不触发)
      setSteps(active.getSteps().map((step) => ({ ...step })))
      if (event.type === "step-started") {
        setThinking(`${t("headerProcessing")} ${event.step.title}`)
        if (config.runMode === "one-click") {
          const index = STEP_DEFINITIONS.findIndex((step) => step.id === event.step.id)
          addMessage("assistant", `${t("msgStepN").replace("{current}", String(index + 1)).replace("{total}", String(STEP_DEFINITIONS.length))}：${tStep(event.step.id)}`, [
            tStepDesc(event.step.id),
            ...tGuidance(event.step.id, config),
          ])
        }
      } else if (event.type === "step-progress") {
        setThinking(`${t("headerProcessing")} ${translateProgress(event.message)}`)
      } else {
        setCurrentArtifactName(active.context.currentArtifact ? path.basename(active.context.currentArtifact) : undefined)
        setArtifactPath(active.context.currentArtifact ?? undefined)
        setThinking("")
        const detail = [...event.result.detail].map((line) => translateDetail(line))
        if (event.result.rollbackMessage) detail.push(translateDetail(event.result.rollbackMessage))
        const title = event.result.status === "skipped"
          ? t("msgSkipped").replace("{kind}", skipKindLabel(event.result.skipKind)).replace("{summary}", translateSummary(event.result.summary))
          : translateSummary(event.result.summary)
        addMessage(resultRole(event.result), title, detail)
      }
    })
    setPipeline(active)
    setScreen("pipeline")
    setCurrentStepIndex(0)
    setPipelineDone(false)
    setCurrentArtifactName(undefined)
    setArtifactPath(undefined)
    addMessage("system", t("msgPipelineCreated"), [
      t("msgRunId").replace("{id}", active.context.runId),
      t("msgToolSafety"),
    ])
    if (config.runMode === "one-click") void runAll(active)
    else announceGuidedStep(0)
  }

  const advanceGuided = () => {
    const next = currentStepIndex() + 1
    if (next >= STEP_DEFINITIONS.length) finishPipeline()
    else announceGuidedStep(next)
  }

  const executeGuidedStep = async () => {
    const active = pipeline()
    const state = currentStep()
    if (!active || !state || busy() || pipelineDone()) return
    setBusy(true)
    const result = await active.runStep(state.id)
    setBusy(false)
    if (result.status === "failed") {
      if (state.id === "doctor" && await pauseForToolRecovery(active, "guided", currentStepIndex())) {
        return
      }
      if (state.id === "keystore" || state.id === "sign") {
        await resumeSigningAfterFailure(state.id)
        return
      }
      setNeedsFailureAdvance(true)
      addMessage("assistant", "本步已经安全回退", [
        "点击“跳过并回退，进入下一步”继续；后续依赖缺失产物的步骤会自动说明并跳过。",
      ])
    } else {
      advanceGuided()
    }
  }

  const skipGuidedStep = async () => {
    const active = pipeline()
    const state = currentStep()
    if (!active || !state || busy() || !state.skippable) return
    setBusy(true)
    try {
      await active.skipStep(state.id, "用户选择跳过")
      setBusy(false)
      advanceGuided()
    } catch (error) {
      setBusy(false)
      addMessage("error", t("msgCannotSkipStep"), [error instanceof Error ? error.message : String(error)])
    }
  }

  const showHelp = () => {
    addMessage("assistant", t("helpTitle"), [
      t("helpBody1"),
      t("helpBody2"),
      t("helpBody3"),
      t("helpBody4"),
      t("helpBody5"),
      t("helpBody6"),
      t("helpBody7"),
    ])
  }

  const runDoctor = async () => {
    if (busy()) return
    setBusy(true)
    setThinking(`${t("headerProcessing")} ${t("msgSearchTools")}`)
    try {
      const tools = await discoverToolchain()
      const plan = createToolRecoveryPlan(undefined, tools)
      const detail = [
        `Java：${tools.java.path ?? "未找到"}`,
        `keytool：${tools.keytool.path ?? "未找到"}`,
        `aapt：${tools.aapt.path ?? "未找到"}`,
        `zipalign：${tools.zipalign.path ?? "未找到"}`,
        `apksigner：${tools.apksigner.path ?? "未找到"}`,
        `Android SDK：${tools.androidSdkRoot ?? "未找到"}${tools.buildToolsVersion ? ` · Build Tools ${tools.buildToolsVersion}` : ""}`,
        "Gradle Wrapper 会在选择 Android 项目后，从项目根目录单独检查。",
      ]
      if (plan.missing.length === 0) {
        setToolRecovery(undefined)
        addMessage("success", t("msgDoctorDone"), detail)
      } else {
        setToolRecovery({
          config: undefined,
          toolchain: tools,
          plan,
          resume: "standalone",
          stepIndex: 0,
        })
        addMessage("warning", t("msgDoctorToolsFound"), [
          ...detail,
          t("msgMissingTools").replace("{names}", plan.missing.map((tool) => tool.name).join("、")),
          plan.canAutoInstall
            ? t("recoveryAuto")
            : t("recoveryManual"),
        ])
      }
    } catch (error) {
      addMessage("error", t("msgDoctorFailed"), [error instanceof Error ? error.message : String(error)])
    } finally {
      setBusy(false)
      setThinking("")
    }
  }

  const showToolInstallInstructions = () => {
    const recovery = toolRecovery()
    if (!recovery) return
    addMessage("assistant", "工具安装与重新运行说明", [
      ...recovery.plan.manualInstructions,
      "下载或安装失败不会修改当前 APK；修复完成前流水线保持暂停。",
    ])
  }

  const resumeRecoveredFlow = async (recovery: ToolRecoveryState, tools: Toolchain) => {
    const remaining = createToolRecoveryPlan(recovery.config, tools)
    if (remaining.missing.length > 0) {
      setToolRecovery({ ...recovery, toolchain: tools, plan: remaining })
      setBusy(false)
      setThinking("")
      addMessage("warning", "仍有工具不可用", [
        `缺少：${remaining.missing.map((tool) => tool.name).join("、")}`,
        ...remaining.manualInstructions,
      ])
      return
    }

    setToolRecovery(undefined)
    if (recovery.resume === "standalone") {
      setBusy(false)
      setThinking("")
      await runDoctor()
      return
    }

    const active = pipeline()
    if (!active) {
      setBusy(false)
      setThinking("")
      addMessage("error", "无法恢复流水线", ["流水线上下文已经不存在，请从首页重新开始。"])
      return
    }

    setThinking(`${t("headerProcessing")} ${t("msgRecheckDoctor")}`)
    const result = await active.retryStep("doctor")
    if (result.status === "failed") {
      await pauseForToolRecovery(active, recovery.resume, recovery.stepIndex)
      return
    }

    addMessage("success", t("msgToolsReady"), [t("msgToolsReadyBody")])
    if (recovery.resume === "one-click") {
      await runAll(active, recovery.stepIndex + 1)
    } else {
      setBusy(false)
      setThinking("")
      advanceGuided()
    }
  }

  const installToolsAndContinue = async () => {
    const recovery = toolRecovery()
    if (!recovery || busy() || !recovery.plan.canAutoInstall) return
    setBusy(true)
    setThinking("processing · 准备下载官方工具")
    addMessage("system", "开始补齐工具", [
      "下载来源仅限 Android 官方仓库与 Eclipse Adoptium 官方 API。",
      "归档会先校验发布方提供的 SHA-256，再解压到用户目录 .droidseal/tools。",
      "继续即确认接受对应官方组件许可；DroidSeal 不会静默修改系统 PATH。",
    ])
    try {
      const outcome = await installMissingTools(recovery.config, recovery.toolchain, {
        onProgress: (message) => setThinking(`processing · ${message}`),
      })
      if (outcome.installed.length > 0) {
        addMessage("success", "工具安装步骤完成", outcome.installed)
      }
      await resumeRecoveredFlow(recovery, outcome.toolchain)
    } catch (error) {
      setBusy(false)
      setThinking("")
      addMessage("error", "工具下载或安装失败", [
        error instanceof Error ? error.message : String(error),
        "当前 APK 和流水线进度没有改变。可以重试，或查看安装说明后手动安装。",
      ])
    }
  }

  const recheckToolsAndContinue = async () => {
    const recovery = toolRecovery()
    if (!recovery || busy()) return
    setBusy(true)
    setThinking("processing · 重新检测工具")
    try {
      const tools = await discoverToolchain(recovery.config)
      await resumeRecoveredFlow(recovery, tools)
    } catch (error) {
      setBusy(false)
      setThinking("")
      addMessage("error", "重新检测失败", [error instanceof Error ? error.message : String(error)])
    }
  }

  const resetHome = () => {
    setScreen("welcome")
    setPipeline(undefined)
    setPipelineDone(false)
    setBusy(false)
    setThinking("")
    setAnswered(new Set<string>())
    setToolRecovery(undefined)
    setSecretBuffer("")
    setSteps(STEP_DEFINITIONS.map((definition) => ({ ...definition, status: "pending" })))
    addMessage("system", t("msgBackHome"), [t("msgBackHomeBody")])
  }

  const handleCommand = (raw: string): boolean => {
    const command = raw.trim().toLowerCase()
    if (command === "/guided") {
      startWizard("guided")
      return true
    }
    if (command === "/oneclick") {
      startWizard("one-click")
      return true
    }
    if (command === "/doctor") {
      void runDoctor()
      return true
    }
    if (command === "/help" || command === "/") {
      showHelp()
      return true
    }
    if (command === "/restart") {
      resetHome()
      return true
    }
    if (command === "/quit" || command === "/exit") {
      renderer.destroy()
      return true
    }
    return false
  }

  const handleSubmit = (rawInput?: string) => {
    const raw = (rawInput ?? composer()).trim()
    setComposer("")
    if (!raw && !isSecretQuestion()) {
      if (screen() === "wizard" && currentQuestion()?.defaultValue !== undefined) {
        submitWizardAnswer("")
      }
      return
    }
    if (raw.startsWith("/") && handleCommand(raw)) return

    if (toolRecovery()) {
      addMessage("user", raw)
      const recoveryCommand = raw.toLowerCase()
      if (recoveryCommand.includes("下载") || recoveryCommand === "d") {
        void installToolsAndContinue()
      } else if (recoveryCommand.includes("说明") || recoveryCommand.includes("帮助") || recoveryCommand === "h") {
        showToolInstallInstructions()
      } else if (recoveryCommand.includes("检测") || recoveryCommand.includes("已安装") || recoveryCommand === "r") {
        void recheckToolsAndContinue()
      } else {
        addMessage("assistant", "工具恢复流程已暂停等待", ["请输入“下载”“安装说明”或“重新检测”，也可以点击对应按钮。"])
      }
      return
    }

    if (screen() === "wizard") {
      if (currentQuestion()) submitWizardAnswer(raw)
      else if (["开始", "执行", "确认", "start", "run"].includes(raw.toLowerCase())) startConfiguredPipeline()
      else addMessage("warning", "配置已完成", ["点击“开始处理”，或输入“开始”。"])
      return
    }

    if (screen() === "pipeline") {
      if (pipelineDone()) {
        addMessage("user", raw)
        addMessage("assistant", "本次流程已经结束", ["输入 /restart 开始新任务，或 /quit 退出。"])
        return
      }
      if (pipeline()?.config.runMode === "guided" && !busy()) {
        const normalized = raw.toLowerCase()
        addMessage("user", raw)
        if (needsFailureAdvance()) {
          if (["继续", "下一步", "跳过", "enter"].includes(normalized)) {
            setNeedsFailureAdvance(false)
            advanceGuided()
          } else {
            addMessage("assistant", "等待进入下一步", ["请输入“下一步”或点击回退按钮。"])
          }
        } else if (["执行", "开始", "yes", "y", "1"].includes(normalized)) {
          void executeGuidedStep()
        } else if (["跳过", "skip", "s", "2"].includes(normalized)) {
          void skipGuidedStep()
        } else {
          addMessage("assistant", "请选择本步操作", ["输入“执行”或“跳过”。"])
        }
        return
      }
      addMessage("warning", "流水线正在执行", ["当前输入未打断外部工具；完成后可使用 /restart 开始新任务。"])
      return
    }

    addMessage("user", raw)
    const normalized = raw.toLowerCase()
    if (normalized.includes("一键") || normalized.includes("one")) startWizard("one-click")
    else if (normalized.includes("分步") || normalized.includes("向导") || normalized.includes("guided")) startWizard("guided")
    else if (normalized.includes("诊断") || normalized.includes("doctor")) void runDoctor()
    else if (/\.apk["']?$/.test(raw)) {
      startWizard("guided")
      addMessage("assistant", t("msgRecognizedApk"), [t("msgRecognizedApkBody")])
    } else {
      addMessage("assistant", t("msgWelcomeStart"), [
        t("msgWelcomeStartBody"),
      ])
    }
  }

  useKeyboard((event) => {
    if (event.ctrl) {
      const ctrlKey = (event.sequence || event.name).toLowerCase()
      // Ctrl+C 复制当前选中内容(含鼠标拖选)、Ctrl+V 粘贴剪贴板;不再触发退出(含原始字节 \x03 / \x16)
      if (ctrlKey === "c" || ctrlKey === "\u0003") {
        event.preventDefault()
        event.stopPropagation()
        copyForClipboard()
        return
      }
      if (ctrlKey === "v" || ctrlKey === "\u0016") {
        event.preventDefault()
        event.stopPropagation()
        const pasted = readClipboard()
        if (!pasted) return
        if (isSecretQuestion()) setSecretBuffer((value) => value + pasted)
        else setComposer((value) => (value ? `${value}${pasted}` : pasted))
        return
      }
      const direction = zoomDirectionFromKey(event.name, event.sequence)
      if (direction) {
        event.preventDefault()
        event.stopPropagation()
        adjustInteractionZoom(direction)
        return
      }
    }

    if (busy()) return
    const key = (event.sequence || event.name).toLowerCase()
    const isEnter = event.name === "return" || event.name === "enter"
    const consume = () => {
      event.preventDefault()
      event.stopPropagation()
    }

    if (toolRecovery()) {
      if (key === "d") {
        consume()
        void installToolsAndContinue()
      } else if (key === "h") {
        consume()
        showToolInstallInstructions()
      } else if (key === "r") {
        consume()
        void recheckToolsAndContinue()
      }
      return
    }

    // 方向键在操作行按钮间循环切换焦点;Enter 激活聚焦按钮。
    // 文本输入场景(activeButtons 为空)不拦截,方向键留给输入框移动光标。
    if (key === "arrowleft" || key === "arrowright") {
      const buttons = activeButtons()
      if (buttons.length > 1) {
        consume()
        const delta = key === "arrowright" ? 1 : -1
        setFocusedButtonIndex((index) => (index + delta + buttons.length) % buttons.length)
        return
      }
    }
    if (isEnter && activeButtons().length > 0) {
      const focused = activeButtons()[focusedButtonIndex()]
      if (focused && !focused.disabled) {
        consume()
        focused.onPress()
        return
      }
    }

    if (screen() === "wizard") {
      const question = currentQuestion()
      if (question?.kind === "choice") {
        const choice = question.choices?.find(
          (candidate) => candidate.shortcut.toLowerCase() === key,
        )
        if (choice) {
          consume()
          submitWizardAnswer(choice.value, choice.label)
        }
        return
      }
      if (!question) {
        if (isEnter) {
          consume()
          startConfiguredPipeline()
        }
        return
      }
    }

    if (
      screen() === "pipeline" &&
      pipeline()?.config.runMode === "guided" &&
      !pipelineDone()
    ) {
      if (isEnter) {
        consume()
        if (needsFailureAdvance()) {
          setNeedsFailureAdvance(false)
          advanceGuided()
        } else {
          void executeGuidedStep()
        }
      } else if (key === "s" && currentStep()?.skippable && !needsFailureAdvance()) {
        consume()
        void skipGuidedStep()
      }
      return
    }

    if (!isSecretQuestion() || screen() !== "wizard") return
    if (event.ctrl && event.name === "c") return
    consume()
    if (isEnter) {
      submitWizardAnswer(secretBuffer())
      return
    }
    if (event.name === "backspace") {
      setSecretBuffer((value) => [...value].slice(0, -1).join(""))
      return
    }
    if (event.ctrl || event.meta || event.sequence.startsWith("\x1b")) return
    if (event.sequence && event.sequence >= " ") {
      setSecretBuffer((value) => value + event.sequence)
    }
  })

  usePaste((event) => {
    if (!isSecretQuestion() || screen() !== "wizard") return
    event.preventDefault()
    event.stopPropagation()
    setSecretBuffer((value) => value + new TextDecoder().decode(event.bytes).replaceAll(/\r?\n/g, ""))
  })

  return (
    <box width="100%" height="100%" flexDirection="column" backgroundColor={theme.background}>
      <box
        flexShrink={0}
        flexDirection="row"
        alignItems="flex-start"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={0}
        border={["bottom"]}
        borderColor={theme.border}
      >
        <box
          flexDirection="column"
          width={DROIDSEAL_LOGO_WIDTH}
          height={DROIDSEAL_LOGO_HEIGHT}
          flexShrink={0}
        >
          <For each={DROIDSEAL_LOGO}>
            {(line) => (
              <text width={DROIDSEAL_LOGO_WIDTH} height={1} wrapMode="none" fg={theme.accentStrong} selectable={false}>
                {line}
              </text>
            )}
          </For>
        </box>
        <Show when={dimensions().width >= DROIDSEAL_LOGO_WIDTH + 32}>
          <box flexDirection="column" alignItems="flex-end" flexGrow={1} flexShrink={1}>
            <text fg={theme.text}>
              <b>{t("headerTitle")}</b>
            </text>
            <text fg={theme.textMuted}>{t("headerLocalOnly")} · v{VERSION}</text>
            <text fg={busy() ? theme.ice : theme.success}>
              {busy()
                ? `${SPINNER[spinnerIndex()]} ${t("headerProcessing")}`
                : `● ${t("headerReady")}`}
            </text>
            <box
              border
              borderColor={theme.borderActive}
              paddingLeft={1}
              paddingRight={1}
              marginTop={0}
              onMouseUp={() => setLanguage((current) => (current === "en" ? "zh" : "en"))}
            >
              <text fg={theme.accentStrong} selectable={false}>
                {language() === "en" ? "中文" : "English"}
              </text>
            </box>
          </box>
        </Show>
      </box>

      <box flexDirection="row" flexGrow={1} minHeight={0}>
        <box
          flexDirection="column"
          flexGrow={1}
          minWidth={0}
          paddingLeft={zoomMetrics().panePadding}
          paddingRight={zoomMetrics().panePadding}
          onMouseScroll={handleInteractionMouseScroll}
        >
          <scrollbox
            ref={(el: ScrollBoxRenderable) => {
              messageScrollBox = el
            }}
            flexGrow={1}
            minHeight={0}
            stickyScroll
            stickyStart="bottom"
            paddingTop={zoomMetrics().messageGap}
            paddingRight={1}
            verticalScrollbarOptions={{
              trackOptions: { backgroundColor: theme.background, foregroundColor: theme.borderActive },
            }}
          >
            <For each={messages()}>
              {(message) => (
                <box
                  flexDirection="column"
                  flexShrink={0}
                  border={["left"]}
                  borderColor={roleColor(message.role)}
                  paddingLeft={zoomMetrics().messageIndent}
                  paddingBottom={zoomMetrics().messageGap}
                  marginBottom={zoomMetrics().messageGap}
                >
                  <text fg={roleColor(message.role)} selectable={false}>
                    <b>
                      {message.role === "user" ? "›" : message.role === "success" ? "✓" : message.role === "error" ? "×" : "◆"}{" "}
                      {message.title}
                    </b>
                  </text>
                  <For each={message.body}>
                    {(line) => <text fg={theme.textMuted} wrapMode="word">{line}</text>}
                  </For>
                </box>
              )}
            </For>
            <Show when={thinking()}>
              <box flexShrink={0} paddingLeft={2} paddingBottom={1}>
                <text fg={theme.ice} wrapMode="word">
                  <span style={{ fg: theme.ice }}>{SPINNER[spinnerIndex()]}</span> {thinking()}
                </text>
              </box>
            </Show>
          </scrollbox>

          <box flexShrink={0} flexDirection="row" flexWrap="wrap" gap={zoomMetrics().actionGap} paddingTop={1} paddingBottom={1} alignItems="center">
            <Show when={toolRecovery()}>
              <Show when={toolRecovery()?.plan.canAutoInstall}>
                <Button
                  shortcut="D"
                  label={t("btnDownloadContinue")}
                  detail={t("btnDownloadContinueDetail")}
                  tone="accent"
                  disabled={busy()}
                  onPress={() => void installToolsAndContinue()}
                />
              </Show>
              <Button
                shortcut="H"
                label={t("btnInstallInstructions")}
                detail={t("btnInstallInstructionsDetail")}
                disabled={busy()}
                onPress={showToolInstallInstructions}
              />
              <Button
                shortcut="R"
                label={t("btnRecheckContinue")}
                detail={t("btnRecheckContinueDetail")}
                disabled={busy()}
                onPress={() => void recheckToolsAndContinue()}
              />
            </Show>

            <Show when={screen() === "welcome" && !toolRecovery()}>
              <Button shortcut="1" label="分步处理" detail="每一步执行前确认" tone="accent" onPress={() => startWizard("guided")} />
              <Button shortcut="2" label="一键处理" detail="失败自动回退并继续" onPress={() => startWizard("one-click")} />
              <Button shortcut="3" label="环境诊断" detail="检查 JDK 与 Android SDK" onPress={() => void runDoctor()} />
            </Show>

            <Show when={screen() === "wizard" && needsWizardInput()}>
              <Button
                shortcut="Enter"
                label={inputActionLabel()}
                detail={inputActionDetail()}
                tone="input"
                disabled={!canSubmitInput()}
                onPress={() => {
                  if (isSecretQuestion()) {
                    submitWizardAnswer(secretBuffer())
                  } else {
                    handleSubmit(composer())
                  }
                }}
              />
            </Show>

            <For each={activeButtons()}>
              {(button, index) => (
                <Button
                  label={button.label}
                  {...(button.detail !== undefined ? { detail: button.detail } : {})}
                  {...(button.shortcut !== undefined ? { shortcut: button.shortcut } : {})}
                  {...(button.tone !== undefined ? { tone: button.tone } : {})}
                  {...(button.disabled !== undefined ? { disabled: button.disabled } : {})}
                  {...(button.centered !== undefined ? { centered: button.centered } : {})}
                  focused={index() === focusedButtonIndex()}
                  onPress={button.onPress}
                />
              )}
            </For>

            <Show when={screen() !== "welcome"}>
              <Button label={t("btnHome")} detail={t("btnHomeDetail")} disabled={busy()} onPress={resetHome} />
            </Show>
          </box>

          <box
            flexShrink={0}
            flexDirection="column"
            border
            borderColor={
              needsWizardInput()
                ? isSecretQuestion() ? theme.purple : theme.input
                : showComposer() ? theme.borderActive : theme.border
            }
            backgroundColor={
              needsWizardInput()
                ? theme.panelInput
                : showComposer() ? theme.panel : theme.panelPassive
            }
            paddingLeft={1}
            paddingRight={1}
            marginBottom={1}
            onMouseUp={(event) => {
              // 右键不退出:在对话框内右键 = 粘贴剪贴板文本(或文件路径)
              if (event.button === 2) {
                event.preventDefault?.()
                event.stopPropagation?.()
                const text = readClipboard()
                if (text) setComposer((value) => (value ? `${value}${text}` : text))
              }
            }}
            title={
              needsWizardInput()
                ? `${isSecretQuestion() ? t("inputTitleSecret") : t("inputTitleNeed")} · ${currentQuestion()?.title ?? ""}`
                : showComposer() ? t("inputTitleComposer") : t("inputTitlePassive")
            }
            titleColor={
              needsWizardInput()
                ? isSecretQuestion() ? theme.purple : theme.input
                : showComposer() ? theme.accentStrong : theme.textMuted
            }
          >
            <Show
              when={needsWizardInput()}
              fallback={
                <Show
                  when={showComposer()}
                  fallback={
                    <text fg={theme.accentStrong} selectable={false}>
                      ◆ {passiveInteractionText()}
                    </text>
                  }
                >
                  <input
                    value={composer()}
                    focused
                    placeholder={t("composerPlaceholder")}
                    textColor={theme.text}
                    focusedTextColor={theme.text}
                    backgroundColor={theme.panel}
                    focusedBackgroundColor={theme.panel}
                    placeholderColor={theme.textMuted}
                    onInput={setComposer}
                    onSubmit={() => handleSubmit(composer())}
                  />
                </Show>
              }
            >
              <Show
                when={isSecretQuestion()}
                fallback={
                  <input
                    value={composer()}
                    focused
                    placeholder={currentQuestion()?.placeholder ?? t("secretPlaceholder")}
                    textColor={theme.text}
                    focusedTextColor={theme.text}
                    backgroundColor={theme.panelInput}
                    focusedBackgroundColor={theme.panelInput}
                    placeholderColor={theme.textMuted}
                    onInput={setComposer}
                    onSubmit={() => handleSubmit(composer())}
                  />
                }
              >
                <text fg={secretBuffer().length > 0 ? theme.text : theme.textMuted}>
                  {secretBuffer().length > 0 ? "•".repeat(Math.min(secretBuffer().length, 48)) : currentQuestion()?.placeholder ?? "输入密码"}
                </text>
              </Show>
            </Show>
          </box>
        </box>

        <Show when={showSidebar()}>
          <box
            width={42}
            height="100%"
            flexShrink={0}
            flexDirection="column"
            backgroundColor={theme.panel}
            border={["left"]}
            borderColor={theme.border}
            paddingLeft={2}
            paddingRight={2}
            paddingTop={1}
            paddingBottom={1}
            onMouseScroll={handleProgressMouseScroll}
          >
            <text fg={theme.textMuted}>
              {t("sidebarSuccess")} {successCount()} · {t("sidebarSkipped")} {skippedCount()} · {t("sidebarFailed")} {failedCount()}
            </text>
            <box height={1} />
            <scrollbox ref={(el: ScrollBoxRenderable) => { progressScrollBox = el }} flexGrow={1} minHeight={0}>
              <For each={steps()}>
                {(step, index) => (
                  <box flexDirection="column" flexShrink={0} paddingBottom={1}>
                    <text fg={stepColor(step.status)} selectable={false}>
                      {statusGlyph(step.status)} {String(index() + 1).padStart(2, "0")} · <b>{tStep(step.id)}</b>
                    </text>
                    <Show when={step.status === "processing"}>
                      <text fg={theme.ice}>
                        <span style={{ fg: theme.ice }}>{SPINNER[spinnerIndex()]}</span> processing…
                      </text>
                    </Show>
                    <Show when={step.result}>
                      {(result) => <text fg={theme.textMuted} wrapMode="word">  {translateSummary(result().summary)}</text>}
                    </Show>
                  </box>
                )}
              </For>
            </scrollbox>
            <box flexShrink={0} border={["top"]} borderColor={theme.border} paddingTop={1}>
              <text fg={theme.text}><b>{t("sidebarCurrentArtifact")}</b></text>
              <text fg={theme.textMuted}>{t("sidebarLegend")}</text>
              <text fg={theme.textMuted}>{t("sidebarSkipNote")}</text>
              <box height={1} />
              <text fg={theme.textMuted} wrapMode="word">
                {currentArtifactName() ?? t("sidebarNotGenerated")}
              </text>
              <Show when={artifactInfo()}>
                {(info) => (
                  <>
                    <text fg={theme.textMuted}>
                      {formatBytes(info().size)} · SHA-256 {info().sha256.slice(0, 12)}…
                    </text>
                    <text fg={theme.accentStrong} selectable={false} onMouseUp={() => openArtifactFolder()}>
                      {t("sidebarOpenFolder")}
                    </text>
                  </>
                )}
              </Show>
              <text fg={theme.textMuted}>{t("sidebarNoOverwrite")}</text>
            </box>
          </box>
        </Show>
      </box>

      <box
        flexShrink={0}
        flexDirection="row"
        paddingLeft={2}
        paddingRight={2}
        border={["top"]}
        borderColor={theme.border}
      >
        <text fg={theme.textMuted}>DroidSeal</text>
        <box flexGrow={1} />
        <text fg={theme.textMuted}>{t("bottomBar").replace("{zoom}", String(interactionZoom()))}</text>
      </box>
    </box>
  )
}
