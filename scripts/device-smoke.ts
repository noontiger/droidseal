import path from "node:path"
import { access, readdir } from "node:fs/promises"
import { homedir } from "node:os"
import { runProcess } from "../src/core/process.ts"

// Stage-B acceptance harness. The DEX/AXML write engines (M0–M4) ship with
// automated Stage-A tests (byte round-trips, layout invariants, cipher
// round-trips). Stage-B — validating that a rewritten APK actually parses on
// the platform toolchain and installs/runs on a device — depends on external
// binaries (apksigner/dexdump/aapt/adb) and a connected device, neither of
// which can be assumed in CI or a fresh checkout. This script auto-detects what
// is present, runs the gates it can, and SKIPS the rest with actionable
// guidance. It exits 0 when a gate is skipped for a missing tool/device (a
// skip is not a failure); it exits 1 only when a gate that COULD run FAILED.

type GateOutcome = "pass" | "fail" | "skip"

interface GateResult {
  name: string
  outcome: GateOutcome
  detail: string
}

const isWindows = process.platform === "win32"
const results: GateResult[] = []

async function exists(target: string | undefined): Promise<boolean> {
  if (!target) return false
  try {
    await access(target)
    return true
  } catch {
    return false
  }
}

function fromPath(name: string): string | undefined {
  return Bun.which(name) ?? Bun.which(isWindows ? `${name}.exe` : name) ?? undefined
}

function versionParts(value: string): number[] {
  return value.split(/[^0-9]+/).filter(Boolean).map(Number)
}

function compareVersions(a: string, b: string): number {
  const left = versionParts(a)
  const right = versionParts(b)
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const delta = (left[index] ?? 0) - (right[index] ?? 0)
    if (delta !== 0) return delta
  }
  return 0
}

async function sdkRoots(): Promise<string[]> {
  const candidates = [
    process.env.ANDROID_SDK_ROOT,
    process.env.ANDROID_HOME,
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Android", "Sdk") : undefined,
    process.env.HOME ? path.join(process.env.HOME, "Library", "Android", "sdk") : undefined,
    process.env.HOME ? path.join(process.env.HOME, "Android", "Sdk") : undefined,
    path.join(homedir(), ".droidseal", "tools", "android-sdk"),
  ].filter((value): value is string => Boolean(value))
  const unique = [...new Set(candidates.map((candidate) => path.resolve(candidate)))]
  const valid: string[] = []
  for (const candidate of unique) {
    if (await exists(candidate)) valid.push(candidate)
  }
  return valid
}

async function newestBuildTools(): Promise<string | undefined> {
  for (const root of await sdkRoots()) {
    const buildTools = path.join(root, "build-tools")
    if (!(await exists(buildTools))) continue
    const entries = await readdir(buildTools, { withFileTypes: true })
    const versions = entries
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort(compareVersions)
      .reverse()
    const version = versions[0]
    if (version) return path.join(buildTools, version)
  }
  return undefined
}

// Resolve a build-tools binary: prefer PATH, then the newest SDK build-tools dir.
async function resolveBuildTool(name: string, buildToolsDir: string | undefined): Promise<string | undefined> {
  const onPath = fromPath(name)
  if (onPath) return onPath
  if (!buildToolsDir) return undefined
  const bin = path.join(buildToolsDir, isWindows ? `${name}.bat` : name)
  if (await exists(bin)) return bin
  const exe = path.join(buildToolsDir, isWindows ? `${name}.exe` : name)
  if (await exists(exe)) return exe
  return undefined
}

function record(name: string, outcome: GateOutcome, detail: string): void {
  results.push({ name, outcome, detail })
  const badge = outcome === "pass" ? "PASS" : outcome === "fail" ? "FAIL" : "SKIP"
  console.log(`[${badge}] ${name} — ${detail}`)
}

async function main(): Promise<void> {
  const apkPath = process.argv[2]
  const cwd = process.cwd()

  console.log("DroidSeal Stage-B device-smoke harness")
  console.log("======================================")

  if (!apkPath) {
    record(
      "input-apk",
      "skip",
      "未提供 APK 路径。用法：bun run scripts/device-smoke.ts <path-to.apk>（可选连接设备做安装冒烟）。",
    )
  } else if (!(await exists(apkPath))) {
    record("input-apk", "fail", `找不到 APK：${apkPath}`)
  } else {
    record("input-apk", "pass", `目标 APK：${apkPath}`)
  }

  const buildToolsDir = await newestBuildTools()
  const apksigner = await resolveBuildTool("apksigner", buildToolsDir)
  const dexdump = await resolveBuildTool("dexdump", buildToolsDir)
  const aapt2 = await resolveBuildTool("aapt2", buildToolsDir)
  const aapt = await resolveBuildTool("aapt", buildToolsDir)
  const adb = fromPath("adb")

  const haveApk = Boolean(apkPath) && (await exists(apkPath))

  // Gate 1: apksigner verify — signature block is intact after rewrite/re-sign.
  if (!apksigner) {
    record("apksigner-verify", "skip", "未找到 apksigner。安装 Android SDK Build-Tools 或设置 ANDROID_SDK_ROOT。")
  } else if (!haveApk) {
    record("apksigner-verify", "skip", "无 APK 输入，跳过签名校验。")
  } else {
    const result = await runProcess({ command: apksigner, args: ["verify", "--verbose", apkPath!], cwd })
    if (result.exitCode === 0) record("apksigner-verify", "pass", "签名校验通过。")
    else record("apksigner-verify", "fail", `apksigner 退出码 ${result.exitCode}：${result.stderr.trim() || result.stdout.trim()}`)
  }

  // Gate 2: dexdump — the rewritten classesN.dex is accepted by the platform
  // disassembler (structural validity beyond our own parser).
  if (!dexdump) {
    record("dexdump-parse", "skip", "未找到 dexdump。安装 Android SDK Build-Tools 后重试。")
  } else if (!haveApk) {
    record("dexdump-parse", "skip", "无 APK 输入，跳过 DEX 结构校验。")
  } else {
    const result = await runProcess({ command: dexdump, args: ["-f", apkPath!], cwd, timeoutMs: 5 * 60_000 })
    if (result.exitCode === 0) record("dexdump-parse", "pass", "dexdump 成功解析 APK 内 DEX。")
    else record("dexdump-parse", "fail", `dexdump 退出码 ${result.exitCode}：${result.stderr.trim() || result.stdout.trim()}`)
  }

  // Gate 3: aapt/aapt2 dump badging — the rewritten AndroidManifest.xml still
  // yields a valid package/launchable-activity (validates AXML repointing).
  const badgingTool = aapt2 ?? aapt
  if (!badgingTool) {
    record("aapt-badging", "skip", "未找到 aapt/aapt2。安装 Android SDK Build-Tools 后重试。")
  } else if (!haveApk) {
    record("aapt-badging", "skip", "无 APK 输入，跳过清单校验。")
  } else {
    const result = await runProcess({ command: badgingTool, args: ["dump", "badging", apkPath!], cwd })
    if (result.exitCode === 0 && /package:\s*name=/.test(result.stdout)) {
      const match = /package:\s*name='([^']+)'/.exec(result.stdout)
      record("aapt-badging", "pass", `清单解析成功，包名：${match?.[1] ?? "<unknown>"}。`)
    } else {
      record("aapt-badging", "fail", `badging 退出码 ${result.exitCode}：${result.stderr.trim() || result.stdout.trim()}`)
    }
  }

  // Gate 4: adb install smoke — the APK installs on a connected device/emulator.
  if (!adb) {
    record("adb-install", "skip", "未找到 adb。安装 Android Platform-Tools 后重试。")
  } else if (!haveApk) {
    record("adb-install", "skip", "无 APK 输入，跳过安装冒烟。")
  } else {
    const devices = await runProcess({ command: adb, args: ["devices"], cwd })
    const online = devices.stdout
      .split(/\r?\n/)
      .slice(1)
      .map((line) => line.trim())
      .filter((line) => /\tdevice$/.test(line))
    if (online.length === 0) {
      record("adb-install", "skip", "无已连接设备（adb devices 为空）。连接设备或启动模拟器后重试。")
    } else {
      const install = await runProcess({ command: adb, args: ["install", "-r", apkPath!], cwd, timeoutMs: 5 * 60_000 })
      if (install.exitCode === 0 && /Success/i.test(install.stdout + install.stderr)) {
        record("adb-install", "pass", `安装成功（${online.length} 台设备在线）。`)
      } else {
        record("adb-install", "fail", `adb install 退出码 ${install.exitCode}：${install.stderr.trim() || install.stdout.trim()}`)
      }
    }
  }

  console.log("======================================")
  const passed = results.filter((r) => r.outcome === "pass").length
  const failed = results.filter((r) => r.outcome === "fail").length
  const skipped = results.filter((r) => r.outcome === "skip").length
  console.log(`gates: ${passed} pass / ${failed} fail / ${skipped} skip`)

  if (failed > 0) {
    console.error("Stage-B device-smoke FAILED（存在可运行但未通过的门禁）。")
    process.exit(1)
  }
  if (passed === 0) {
    console.log("Stage-B device-smoke SKIPPED：本环境缺少工具链/设备，无法执行真机门禁。")
    console.log("在具备 Android SDK Build-Tools + Platform-Tools + 设备的环境重跑本脚本以完成 Stage-B 验收。")
  } else {
    console.log("Stage-B device-smoke PASSED（所有可运行门禁均通过）。")
  }
  process.exit(0)
}

await main()
