#!/usr/bin/env bun
import { createCliRenderer } from "@opentui/core"
import { render } from "@opentui/solid"
import { VERSION } from "./brand.ts"
import { createToolRecoveryPlan } from "./core/tool-installer.ts"
import { discoverToolchain } from "./core/toolchain.ts"
import { theme } from "./ui/theme.ts"
import { App } from "./ui/app.tsx"

const args = process.argv.slice(2)

function usage(): string {
  return `droidseal ${VERSION}

用法:
  droidseal             打开交互式 TUI
  droidseal doctor      以 JSON 输出环境诊断
  droidseal --help      显示帮助
  droidseal --version   显示版本

TUI 命令:
  /guided    分步处理
  /oneclick  一键处理
  /doctor    环境诊断
  /restart   返回首页
  /quit      退出
`
}

if (args.includes("--help") || args.includes("-h")) {
  console.log(usage())
  process.exit(0)
}

if (args.includes("--version") || args.includes("-v")) {
  console.log(VERSION)
  process.exit(0)
}

if (args[0] === "doctor") {
  const result = await discoverToolchain()
  const recovery = createToolRecoveryPlan(undefined, result)
  console.log(JSON.stringify({
    ...result,
    recovery: {
      missing: recovery.missing.map((tool) => tool.name),
      canAutoInstallInTui: recovery.canAutoInstall,
      instructions: recovery.manualInstructions,
    },
  }, null, 2))
  process.exit(0)
}

if (!process.stdin.isTTY || !process.stdout.isTTY) {
  console.error("DroidSeal TUI 需要交互式终端。使用 `droidseal doctor` 可进行非交互环境诊断。")
  // 双击启动时控制台窗口会在进程退出瞬间关闭，导致上面的提示不可见。
  // 等待一次按键（或最多 5 秒）让用户看到原因；stdin 为 EOF（CI/管道）时立即返回，不会挂起。
  process.stdin.resume()
  await new Promise<void>((resolve) => {
    const done = () => resolve()
    process.stdin.once("data", done)
    process.stdin.once("end", done)
    setTimeout(done, 5_000)
  })
  process.exit(2)
}

const renderer = await createCliRenderer({
  exitOnCtrlC: true,
  useMouse: true,
  enableMouseMovement: true,
  targetFps: 60,
  maxFps: 60,
  gatherStats: false,
  autoFocus: false,
  screenMode: "alternate-screen",
  backgroundColor: theme.background,
  openConsoleOnError: false,
  useKittyKeyboard: {
    disambiguate: true,
    alternateKeys: true,
  },
})

await render(() => <App />, renderer)
