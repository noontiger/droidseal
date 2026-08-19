import path from "node:path"
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
import { Pipeline, STEP_DEFINITIONS, statusGlyph, stepGuidance } from "../core/pipeline.ts"
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
    "not-applicable": "不适用",
    "user-choice": "用户选择",
    configuration: "按配置",
    safety: "安全保护",
    "missing-input": "缺少前置 APK",
  }
  return kind ? labels[kind] : "已说明原因"
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
      title: "欢迎使用 DroidSeal",
      body: [
        "DroidSeal 在本机完成 Release 构建、R8/Manifest/APK 审计、安全审计基线、zipalign、apksigner 签名与验证。",
        "不熟悉流程可选择“分步处理”；每一步都会说明用途，专业术语保持原名。",
        "“跳过”会标明是不适用、用户选择、按配置、安全保护或缺少前置 APK；跳过不一定是失败。",
        "所有处理使用独立副本，失败时回退到上一个有效 APK。",
      ],
    },
  ])
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
      if (question.id === "keyPassword") return "沿用签名库密码"
      return question.defaultValue ? "使用默认值" : "留空并继续"
    }
    if (inputValue().trim()) return "确认输入"
    if (currentQuestion()?.defaultValue !== undefined) return "使用默认值"
    return "请先输入"
  })
  const inputActionDetail = createMemo(() => {
    const defaultValue = currentQuestion()?.defaultValue
    if (defaultValue === undefined) return "填写当前项后继续"
    return defaultValue ? "已预填默认值，可直接确认或修改" : "此项允许留空，可直接继续"
  })
  const passiveInteractionText = createMemo(() => {
    if (toolRecovery()) return "无需输入文字 · 请点击上方恢复方式，或按 D / H / R"
    if (screen() === "wizard") {
      return currentQuestion()?.kind === "choice"
        ? "无需输入文字 · 请点击上方选项，或直接按对应数字键"
        : "配置已就绪 · 点击“开始处理”，或按 Enter"
    }
    if (screen() === "pipeline") {
      if (busy()) return "正在处理 · 当前不需要输入"
      if (pipelineDone()) return "流程已结束 · 请使用上方按钮开始新任务或退出"
      if (needsFailureAdvance()) return "无需输入文字 · 点击回退按钮，或按 Enter 进入下一步"
      if (pipeline()?.config.runMode === "guided") return "无需输入文字 · 点击“执行此步”/“跳过”，或按 Enter / S"
      return "正在连续处理 · 当前不需要输入"
    }
    return ""
  })
  const showComposer = createMemo(() => screen() === "welcome" && !toolRecovery())

  // 对话框上方操作行的按钮:方向键左右循环切换焦点,Enter 激活聚焦按钮。
  const [focusedButtonIndex, setFocusedButtonIndex] = createSignal(0)
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
          { label: "开始处理", shortcut: "Enter", tone: "accent" as const, detail: "按上方摘要创建流水线", onPress: startConfiguredPipeline },
          { label: "重新填写", detail: "清空本次内存配置", onPress: () => startWizard(draft().runMode) },
        ]
      }
      return []
    }
    if (screen() === "pipeline") {
      if (pipelineDone()) {
        return [
          { label: "开始新任务", tone: "accent" as const, onPress: resetHome },
          { label: "退出", onPress: () => renderer.destroy() },
        ]
      }
      if (!busy() && pipeline()?.config.runMode === "guided" && !toolRecovery()) {
        if (needsFailureAdvance()) {
          return [
            {
              label: "跳过并回退，进入下一步",
              shortcut: "Enter",
              tone: "danger" as const,
              detail: "当前 APK 已恢复为步骤开始前版本",
              onPress: () => {
                setNeedsFailureAdvance(false)
                advanceGuided()
              },
            },
          ]
        }
        const buttons: ActiveButton[] = [
          { label: "执行此步", shortcut: "Enter", tone: "accent" as const, detail: currentStep()?.title ?? "", disabled: busy(), onPress: () => void executeGuidedStep() },
        ]
        if (currentStep()?.skippable) {
          buttons.push({ label: "跳过", shortcut: "S", detail: "标记为用户选择 · 保留当前有效 APK", disabled: busy(), onPress: () => void skipGuidedStep() })
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

  onMount(() => {
    renderer.setTerminalTitle("DroidSeal · Android release security pipeline")
    const timer = setInterval(() => setSpinnerIndex((value) => (value + 1) % SPINNER.length), 120)
    onCleanup(() => clearInterval(timer))
  })

  // 侧栏进度填充条:14 格,颜色随进度变化(未完成=强调色,全部完成=完成色)
  const progressBarText = createMemo(() => {
    const total = steps().length
    const done = completedCount()
    if (total === 0) return "██████████████"
    const filledCells = Math.min(14, Math.round((done / total) * 14))
    return "█".repeat(filledCells) + "░".repeat(14 - filledCells)
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
      "system",
      mode === "one-click" ? "已选择一键处理" : "已选择分步处理",
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
    addMessage("assistant", `第 ${index + 1}/${STEP_DEFINITIONS.length} 步：${state.title}`, [
      state.description,
      ...stepGuidance(state.id, pipeline()!.config),
      state.skippable
        ? "可执行此步，也可手动跳过；手动跳过不会改动当前有效 APK，并会在报告中标记“用户选择”。"
        : "这是建立有效产物所需的基础步骤，不能手动跳过。",
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
    addMessage("warning", "所选流程需要补齐工具", [
      `缺少：${plan.missing.map((tool) => tool.name).join("、")}`,
      plan.canAutoInstall
        ? "可以点击“下载并继续”；点击表示同意对应官方组件许可，DroidSeal 会下载、校验、安装并自动续跑。"
        : "当前缺失项需要按安装说明手动修复。",
      "也可以手动安装后点击“已安装，重新检测”，当前签名配置和步骤进度会保留。",
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
      setSteps([...active.getSteps()])
      if (event.type === "step-started") {
        setThinking(`processing · ${event.step.title}`)
        if (config.runMode === "one-click") {
          const index = STEP_DEFINITIONS.findIndex((step) => step.id === event.step.id)
          addMessage("assistant", `第 ${index + 1}/${STEP_DEFINITIONS.length} 步：${event.step.title}`, [
            event.step.description,
            ...stepGuidance(event.step.id, config),
          ])
        }
      } else if (event.type === "step-progress") {
        setThinking(`processing · ${event.message}`)
      } else {
        setThinking("")
        const detail = [...event.result.detail]
        if (event.result.rollbackMessage) detail.push(event.result.rollbackMessage)
        const title = event.result.status === "skipped"
          ? `已跳过 · ${skipKindLabel(event.result.skipKind)}：${event.result.summary}`
          : event.result.summary
        addMessage(resultRole(event.result), title, detail)
      }
    })
    setPipeline(active)
    setScreen("pipeline")
    setCurrentStepIndex(0)
    setPipelineDone(false)
    addMessage("system", "流水线已创建", [
      `运行编号：${active.context.runId}`,
      "所有工具都以参数数组直接启动，不经过 shell；签名密码通过子进程环境传递并在输出中脱敏。",
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
      addMessage("error", "无法跳过该步骤", [error instanceof Error ? error.message : String(error)])
    }
  }

  const showHelp = () => {
    addMessage("assistant", "帮助与安全边界", [
      "/guided 分步处理 · /oneclick 一键处理 · /doctor 环境诊断 · /restart 返回首页 · /quit 退出",
      "左下交互区：Ctrl+加号放大、Ctrl+减号缩小、Ctrl+0 复位。",
      "所选流程缺少必需工具时会暂停，可下载并继续，或手动安装后重新检测。",
      "聊天解析完全在本机执行，不连接模型服务，也不会上传路径、APK 或签名信息。",
      "内置能力面向合法应用防护：严格证据审计、R8、Release 归一化、对齐、签名与验证默认执行；资源名混淆是经兼容性预检的有损可选项。",
      "如需主动加固（DEX 加壳/VMP/反调试），请在源码接入有授权的方案；DroidSeal 另提供自研、opt-in 的构建期反调试 stub 供源码集成。",
      "不提供脱壳、绕过证书校验、规避检测、内存篡改或未授权逆向自动化。",
    ])
  }

  const runDoctor = async () => {
    if (busy()) return
    setBusy(true)
    setThinking("processing · 搜索 JDK 与 Android SDK")
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
        addMessage("success", "环境诊断完成", detail)
      } else {
        setToolRecovery({
          config: undefined,
          toolchain: tools,
          plan,
          resume: "standalone",
          stepIndex: 0,
        })
        addMessage("warning", "环境诊断发现可补齐的工具", [
          ...detail,
          `缺少：${plan.missing.map((tool) => tool.name).join("、")}`,
          plan.canAutoInstall
            ? "点击“下载并继续”表示同意对应官方组件许可；也可以查看说明后手动安装。"
            : "请查看安装说明并手动修复。",
        ])
      }
    } catch (error) {
      addMessage("error", "环境诊断失败", [error instanceof Error ? error.message : String(error)])
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

    setThinking("processing · 重新执行环境诊断")
    const result = await active.retryStep("doctor")
    if (result.status === "failed") {
      await pauseForToolRecovery(active, recovery.resume, recovery.stepIndex)
      return
    }

    addMessage("success", "工具已就绪，自动继续", ["环境诊断已经重新通过，签名配置和已有进度均已保留。"])
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
    addMessage("system", "已返回首页", ["可以开始新的分步或一键处理。"])
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
      addMessage("assistant", "已识别到 APK 路径", ["请先选择“已有 APK”，然后粘贴这一路径。"])
    } else {
      addMessage("assistant", "我可以从这里开始", [
        "输入“一键处理”“分步处理”或“环境诊断”，也可以点击下方按钮。",
      ])
    }
  }

  useKeyboard((event) => {
    if (event.ctrl) {
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
        alignItems="center"
        paddingLeft={2}
        paddingRight={2}
        paddingTop={1}
        paddingBottom={1}
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
            <text fg={theme.text}><b>Android release pipeline</b></text>
            <text fg={theme.textMuted}>local only · v{VERSION}</text>
            <text fg={busy() ? theme.accent : theme.success}>
              {busy() ? `${SPINNER[spinnerIndex()]} processing` : "● ready"}
            </text>
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
                <text fg={theme.accent}>
                  <span style={{ fg: theme.purple }}>{SPINNER[spinnerIndex()]}</span> {thinking()}
                </text>
              </box>
            </Show>
          </scrollbox>

          <box flexShrink={0} flexDirection="row" flexWrap="wrap" gap={zoomMetrics().actionGap} paddingTop={1} paddingBottom={1}>
            <Show when={toolRecovery()}>
              <Show when={toolRecovery()?.plan.canAutoInstall}>
                <Button
                  shortcut="D"
                  label="下载并继续"
                  detail="同意官方许可 · SHA-256 校验 · 自动续跑"
                  tone="accent"
                  disabled={busy()}
                  onPress={() => void installToolsAndContinue()}
                />
              </Show>
              <Button
                shortcut="H"
                label="查看安装说明"
                detail="手动安装后无需重新填写配置"
                disabled={busy()}
                onPress={showToolInstallInstructions}
              />
              <Button
                shortcut="R"
                label="已安装，重新检测"
                detail="检测通过后从暂停位置继续"
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
                  focused={index() === focusedButtonIndex()}
                  onPress={button.onPress}
                />
              )}
            </For>

            <Show when={screen() !== "welcome"}>
              <Button label="回到首页" detail="清空当前进度，返回首页" onPress={resetHome} />
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
            title={
              needsWizardInput()
                ? (isSecretQuestion() ? "需要安全输入 · " : "需要输入 · ") + (currentQuestion()?.title ?? "")
                : showComposer() ? "可输入指令 · 和 DroidSeal 对话" : "无需输入 · 使用上方操作"
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
                    placeholder="输入消息或 /help"
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
                    placeholder={currentQuestion()?.placeholder ?? "请输入后确认"}
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
            <text fg={theme.text}><b>处理进度 · 已处理 {completedCount()}/{steps().length}</b></text>
            <text
              fg={steps().length > 0 && completedCount() >= steps().length ? theme.complete : theme.accent}
              selectable={false}
            >
              {progressBarText()}
            </text>
            <text fg={theme.textMuted}>
              成功 {successCount()} · 跳过 {skippedCount()} · 失败 {failedCount()}
            </text>
            <box height={1} />
            <scrollbox ref={(el: ScrollBoxRenderable) => { progressScrollBox = el }} flexGrow={1} minHeight={0} stickyScroll stickyStart="bottom">
              <For each={steps()}>
                {(step, index) => (
                  <box flexDirection="column" flexShrink={0} paddingBottom={1}>
                    <text fg={stepColor(step.status)} selectable={false}>
                      {statusGlyph(step.status)} {String(index() + 1).padStart(2, "0")} · <b>{step.title}</b>
                    </text>
                    <Show when={step.status === "processing"}>
                      <text fg={theme.accent}>
                        <span style={{ fg: theme.purple }}>{SPINNER[spinnerIndex()]}</span> processing…
                      </text>
                    </Show>
                    <Show when={step.result}>
                      {(result) => <text fg={theme.textMuted} wrapMode="word">  {result().summary}</text>}
                    </Show>
                  </box>
                )}
              </For>
            </scrollbox>
            <box flexShrink={0} border={["top"]} borderColor={theme.border} paddingTop={1}>
              <text fg={theme.text}><b>当前有效产物</b></text>
              <text fg={theme.textMuted}>● 成功  − 跳过（见原因）  × 失败</text>
              <text fg={theme.textMuted}>跳过不一定是失败；已计入“已处理”。</text>
              <box height={1} />
              <text fg={theme.textMuted} wrapMode="word">
                {pipeline()?.context.currentArtifact
                  ? path.basename(pipeline()!.context.currentArtifact!)
                  : "尚未生成"}
              </text>
              <text fg={theme.textMuted}>失败不覆盖 · 本地处理</text>
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
        <text fg={theme.textMuted}>交互区 {interactionZoom()}% · Ctrl± · secrets redacted</text>
      </box>
    </box>
  )
}
