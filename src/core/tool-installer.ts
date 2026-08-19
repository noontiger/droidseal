import path from "node:path"
import { mkdir, readFile, readdir, rename, rm, stat } from "node:fs/promises"
import { homedir } from "node:os"
import { sha256File } from "./apk-audit.ts"
import { runProcess } from "./process.ts"
import { discoverToolchain } from "./toolchain.ts"
import type { PipelineConfig, ToolLocation, Toolchain } from "./types.ts"

export type ToolInstallGroup = "jdk" | "android-build-tools" | "gradle"

export interface ToolRecoveryPlan {
  missing: ToolLocation[]
  autoGroups: ToolInstallGroup[]
  canAutoInstall: boolean
  manualInstructions: string[]
}

export interface ToolInstallOutcome {
  installed: string[]
  toolchain: Toolchain
  remaining: ToolRecoveryPlan
}

export interface ToolInstallOptions {
  onProgress?: (message: string) => void
}

interface DownloadAsset {
  url: string
  sha256: string
  fileName: string
  size?: number
}

interface AdoptiumAsset {
  binary?: {
    package?: {
      checksum?: string
      link?: string
      name?: string
      size?: number
    }
  }
}

const ANDROID_COMMAND_LINE_ASSETS: Record<string, DownloadAsset> = {
  "win32-x64": {
    url: "https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip",
    sha256: "90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a",
    fileName: "commandlinetools-win-15859902_latest.zip",
    size: 155_700_000,
  },
  "linux-x64": {
    url: "https://dl.google.com/android/repository/commandlinetools-linux-15859902_latest.zip",
    sha256: "4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583",
    fileName: "commandlinetools-linux-15859902_latest.zip",
    size: 181_800_000,
  },
  "darwin-x64": {
    url: "https://dl.google.com/android/repository/commandlinetools-mac_x86_64-15859902_latest.zip",
    sha256: "c5a6378ab5cf7e0d5701921405115befff13e9ff7417fb588389338f8bd050f3",
    fileName: "commandlinetools-mac_x86_64-15859902_latest.zip",
    size: 156_300_000,
  },
  "darwin-arm64": {
    url: "https://dl.google.com/android/repository/commandlinetools-mac_arm64-15859902_latest.zip",
    sha256: "835b62a26162b229b441d1f6d4680383815a270809eb33522c0d480fa5002c4e",
    fileName: "commandlinetools-mac_arm64-15859902_latest.zip",
    size: 156_100_000,
  },
}

export function managedToolsRoot(): string {
  return path.join(homedir(), ".droidseal", "tools")
}

function uniqueTools(tools: ToolLocation[]): ToolLocation[] {
  return [...new Map(tools.map((tool) => [tool.name, tool])).values()]
}

export function selectedMissingTools(
  config: PipelineConfig | undefined,
  toolchain: Toolchain,
): ToolLocation[] {
  const selected: ToolLocation[] = []
  const add = (tool: ToolLocation, enabled = true) => {
    if (enabled && !tool.path) selected.push(tool)
  }

  if (!config) {
    add(toolchain.java)
    add(toolchain.keytool)
    add(toolchain.aapt)
    add(toolchain.zipalign)
    add(toolchain.apksigner)
    return uniqueTools(selected)
  }

  const signingEnabled = config.signing.mode !== "skip"
  add(toolchain.java, config.inputKind === "project" || signingEnabled)
  add(toolchain.gradleWrapper, config.inputKind === "project")
  // aapt 缺失只降低 Manifest 审计深度；内置 ZIP/DEX 审计仍可继续，因此不阻断流水线。
  add(toolchain.zipalign, config.enableAlignment)
  add(toolchain.keytool, config.signing.mode === "create")
  add(toolchain.apksigner, signingEnabled)
  return uniqueTools(selected)
}

export function createToolRecoveryPlan(
  config: PipelineConfig | undefined,
  toolchain: Toolchain,
): ToolRecoveryPlan {
  const missing = selectedMissingTools(config, toolchain)
  const names = new Set(missing.map((tool) => tool.name))
  const autoGroups: ToolInstallGroup[] = []
  if (names.has("java") || names.has("keytool")) autoGroups.push("jdk")
  if (["aapt", "zipalign", "apksigner"].some((name) => names.has(name))) {
    autoGroups.push("android-build-tools")
  }
  if (names.has("gradle wrapper")) autoGroups.push("gradle")

  const manualInstructions: string[] = []
  if (autoGroups.includes("jdk")) {
    manualInstructions.push(
      "JDK：可由 droidseal 下载并校验 Eclipse Temurin 21；也可从 https://adoptium.net/temurin/releases 手动安装，随后重新诊断。",
    )
  }
  if (autoGroups.includes("android-build-tools")) {
    manualInstructions.push(
      "Android Build Tools：可由 droidseal 下载官方 Command-line Tools，再通过 sdkmanager 安装最新稳定版；也可在 Android Studio 的 SDK Manager 中安装。",
    )
  }
  if (names.has("gradle wrapper")) {
    manualInstructions.push(
      "Gradle Wrapper：可自动下载 Gradle 并生成项目 Wrapper（优先使用 gradle-wrapper.properties 指定的版本）；也可从项目版本库恢复 gradlew、gradlew.bat 与 gradle/wrapper。",
    )
  }
  if (missing.length > 0) {
    manualInstructions.push("完成手动安装后，点击“已安装，重新检测”，无需重新填写签名信息。")
  }

  return {
    missing,
    autoGroups,
    canAutoInstall: autoGroups.length > 0,
    manualInstructions,
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KiB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`
}

async function downloadVerified(
  asset: DownloadAsset,
  destination: string,
  onProgress?: (message: string) => void,
): Promise<void> {
  onProgress?.(`连接官方源：${asset.fileName}`)
  const response = await fetch(asset.url, { redirect: "follow" })
  if (!response.ok || !response.body) {
    throw new Error(`下载失败：HTTP ${response.status} ${response.statusText} (${asset.url})`)
  }

  const contentLength = Number(response.headers.get("content-length") ?? asset.size ?? 0)
  const reader = response.body.getReader()
  const writer = Bun.file(destination).writer()
  let received = 0
  let lastReported = 0
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      if (!value) continue
      await writer.write(value)
      received += value.byteLength
      if (received - lastReported >= 4 * 1024 * 1024) {
        lastReported = received
        const total = contentLength > 0 ? ` / ${formatBytes(contentLength)}` : ""
        onProgress?.(`下载 ${asset.fileName}：${formatBytes(received)}${total}`)
      }
    }
  } finally {
    await writer.end()
  }

  onProgress?.(`校验 SHA-256：${asset.fileName}`)
  const actual = await sha256File(destination)
  if (actual.toLowerCase() !== asset.sha256.toLowerCase()) {
    await rm(destination, { force: true }).catch(() => undefined)
    throw new Error(`下载校验失败：期望 ${asset.sha256}，实际 ${actual}；文件已删除。`)
  }
}

async function extractArchive(
  archive: string,
  destination: string,
  onProgress?: (message: string) => void,
): Promise<void> {
  const tar = Bun.which(process.platform === "win32" ? "tar.exe" : "tar") ?? Bun.which("tar")
  if (!tar) throw new Error("没有找到 tar，无法安全解压已校验的工具归档。请手动解压后重新诊断。")
  await mkdir(destination, { recursive: true })
  onProgress?.(`解压：${path.basename(archive)}`)
  const result = await runProcess({
    command: tar,
    args: ["-xf", archive, "-C", destination],
    cwd: path.dirname(archive),
    timeoutMs: 10 * 60_000,
  })
  if (result.exitCode !== 0) {
    throw new Error(`解压失败（exit ${result.exitCode}）：${result.stderr.trim() || result.stdout.trim()}`)
  }
}

export async function findFile(
  root: string,
  fileNames: Set<string>,
  depth = 5,
): Promise<string | undefined> {
  if (depth < 0) return undefined
  const entries = await readdir(root, { withFileTypes: true }).catch(() => [])
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name)
    if (entry.isFile() && fileNames.has(entry.name.toLowerCase())) return fullPath
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue
    const found = await findFile(path.join(root, entry.name), fileNames, depth - 1)
    if (found) return found
  }
  return undefined
}

async function adoptiumJdkAsset(): Promise<DownloadAsset> {
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "mac" : "linux"
  const architecture = process.arch === "arm64" ? "aarch64" : process.arch
  const url =
    `https://api.adoptium.net/v3/assets/latest/21/hotspot` +
    `?architecture=${encodeURIComponent(architecture)}&image_type=jdk&os=${encodeURIComponent(os)}&vendor=eclipse`
  const response = await fetch(url, { headers: { accept: "application/json" } })
  if (!response.ok) throw new Error(`无法查询 Eclipse Temurin 下载信息：HTTP ${response.status}`)
  const assets = (await response.json()) as AdoptiumAsset[]
  const packageInfo = assets[0]?.binary?.package
  if (!packageInfo?.link || !packageInfo.checksum || !packageInfo.name) {
    throw new Error("Eclipse Temurin API 没有返回可验证的 JDK 21 归档。")
  }
  const asset: DownloadAsset = {
    url: packageInfo.link,
    sha256: packageInfo.checksum,
    fileName: packageInfo.name,
  }
  if (packageInfo.size !== undefined) asset.size = packageInfo.size
  return asset
}

export async function installManagedJdk(
  onProgress?: (message: string) => void,
  rootOverride?: string,
): Promise<string> {
  const root = rootOverride ?? managedToolsRoot()
  const downloadDirectory = path.join(root, "downloads")
  await mkdir(downloadDirectory, { recursive: true })
  const asset = await adoptiumJdkAsset()
  const archive = path.join(downloadDirectory, asset.fileName)
  await downloadVerified(asset, archive, onProgress)
  const destination = path.join(root, `jdk-21-${Date.now()}`)
  try {
    await extractArchive(archive, destination, onProgress)
    const javaName = process.platform === "win32" ? "java.exe" : "java"
    const java = await findFile(destination, new Set([javaName]), 4)
    const keytoolName = process.platform === "win32" ? "keytool.exe" : "keytool"
    const keytool = await findFile(destination, new Set([keytoolName]), 4)
    if (!java || !keytool) throw new Error("JDK 归档已解压，但没有找到 java/keytool。")
    return path.dirname(path.dirname(java))
  } catch (error) {
    await rm(destination, { recursive: true, force: true }).catch(() => undefined)
    throw error
  }
}

async function findSdkManager(sdkRoot: string): Promise<string | undefined> {
  const names = process.platform === "win32"
    ? new Set(["sdkmanager.bat"])
    : new Set(["sdkmanager"])
  return await findFile(path.join(sdkRoot, "cmdline-tools"), names, 4)
}

function compareVersions(left: string, right: string): number {
  const a = left.split(".").map(Number)
  const b = right.split(".").map(Number)
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    const delta = (a[index] ?? 0) - (b[index] ?? 0)
    if (delta !== 0) return delta
  }
  return 0
}

export function latestStableBuildTools(output: string): string | undefined {
  const versions = [...output.matchAll(/build-tools;(\d+\.\d+\.\d+)(?![-\w])/g)]
    .map((match) => match[1]!)
    .sort(compareVersions)
  return versions.at(-1)
}

async function ensureSdkManager(
  sdkRoot: string,
  onProgress?: (message: string) => void,
): Promise<string> {
  const existing = await findSdkManager(sdkRoot)
  if (existing) return existing

  const key = `${process.platform}-${process.arch}`
  const asset = ANDROID_COMMAND_LINE_ASSETS[key]
  if (!asset) {
    throw new Error(`当前平台 ${key} 没有内置的 Android Command-line Tools 下载清单，请手动安装。`)
  }

  const root = path.dirname(sdkRoot)
  const downloadDirectory = path.join(root, "downloads")
  const staging = path.join(root, `.cmdline-tools-${Date.now()}`)
  await mkdir(downloadDirectory, { recursive: true })
  await mkdir(sdkRoot, { recursive: true })
  const archive = path.join(downloadDirectory, asset.fileName)
  await downloadVerified(asset, archive, onProgress)
  try {
    await extractArchive(archive, staging, onProgress)
    const extractedManager = await findSdkManager(staging)
    if (!extractedManager) throw new Error("Command-line Tools 归档中没有找到 sdkmanager。")
    const extractedRoot = path.dirname(path.dirname(extractedManager))
    const destination = path.join(sdkRoot, "cmdline-tools", `droidseal-${Date.now()}`)
    await mkdir(path.dirname(destination), { recursive: true })
    await rename(extractedRoot, destination)
    const installed = await findSdkManager(sdkRoot)
    if (!installed) throw new Error("Command-line Tools 已移动，但 sdkmanager 仍不可用。")
    return installed
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined)
  }
}

function javaEnvironment(javaPath: string): Record<string, string> {
  const javaHome = path.dirname(path.dirname(javaPath))
  return {
    JAVA_HOME: javaHome,
    PATH: `${path.join(javaHome, "bin")}${path.delimiter}${process.env.PATH ?? ""}`,
  }
}

export async function installAndroidBuildTools(
  params: { javaPath: string; sdkRoot?: string },
  onProgress?: (message: string) => void,
): Promise<string> {
  const sdkRoot = params.sdkRoot ?? path.join(managedToolsRoot(), "android-sdk")
  const sdkManager = await ensureSdkManager(sdkRoot, onProgress)
  const environment = javaEnvironment(params.javaPath)
  onProgress?.("读取 Android SDK 稳定软件包清单")
  const listing = await runProcess({
    command: sdkManager,
    args: ["--list", "--channel=0", `--sdk_root=${sdkRoot}`],
    cwd: path.dirname(sdkManager),
    env: environment,
    timeoutMs: 5 * 60_000,
  })
  if (listing.exitCode !== 0) {
    throw new Error(`sdkmanager 无法读取软件包清单：${listing.stderr.trim() || listing.stdout.trim()}`)
  }
  const version = latestStableBuildTools(`${listing.stdout}\n${listing.stderr}`)
  if (!version) throw new Error("sdkmanager 软件包清单中没有找到稳定版 Android Build Tools。")

  onProgress?.(`安装 Android Build Tools ${version}（已由用户确认官方许可）`)
  const installation = await runProcess({
    command: sdkManager,
    args: [`build-tools;${version}`, "--channel=0", `--sdk_root=${sdkRoot}`],
    cwd: path.dirname(sdkManager),
    env: environment,
    stdinInput: "y\n".repeat(64),
    timeoutMs: 20 * 60_000,
    onLine: (line) => {
      if (line.trim()) onProgress?.(`sdkmanager · ${line.trim().slice(0, 180)}`)
    },
  })
  if (installation.exitCode !== 0) {
    throw new Error(
      `Android Build Tools 安装失败（exit ${installation.exitCode}）：` +
      `${installation.stderr.trim() || installation.stdout.trim()}`,
    )
  }
  return version
}

async function pathExists(target: string): Promise<boolean> {
  return stat(target).then(() => true).catch(() => false)
}

// ---------- Gradle Wrapper ----------
// 项目输入缺少 gradlew/gradlew.bat 时,自动下载 Gradle 发行版(缓存到 managed tools
// 目录)并在项目内生成 Wrapper。优先使用 gradle-wrapper.properties 中固定的版本,
// 避免生成与项目 AGP 不兼容的 Wrapper。
const DEFAULT_GRADLE_VERSION = "8.13"

async function gradleVersionFromProperties(projectDir: string): Promise<string | undefined> {
  const candidates = [
    path.join(projectDir, "gradle", "wrapper", "gradle-wrapper.properties"),
    path.join(projectDir, "android", "gradle", "wrapper", "gradle-wrapper.properties"),
  ]
  for (const candidate of candidates) {
    const text = await readFile(candidate, "utf8").catch(() => undefined)
    const match = text?.match(/distributionUrl=.*gradle-(\d+\.\d+(?:\.\d+)?)[-a-z]*\.zip/i)
    if (match?.[1]) return match[1]
  }
  return undefined
}

async function gradleDistributionAsset(version: string): Promise<DownloadAsset> {
  const fileName = `gradle-${version}-bin.zip`
  const shaResponse = await fetch(`https://services.gradle.org/distributions/${fileName}.sha256`, {
    redirect: "follow",
  })
  if (!shaResponse.ok) {
    throw new Error(`无法获取 Gradle ${version} 校验和：HTTP ${shaResponse.status}`)
  }
  return {
    url: `https://services.gradle.org/distributions/${fileName}`,
    fileName,
    sha256: (await shaResponse.text()).trim().toLowerCase(),
  }
}

export async function installGradleWrapper(
  projectDir: string,
  onProgress?: (message: string) => void,
  javaHome?: string,
): Promise<string> {
  const version = (await gradleVersionFromProperties(projectDir)) ?? DEFAULT_GRADLE_VERSION
  const root = managedToolsRoot()
  const downloadDirectory = path.join(root, "downloads")
  await mkdir(downloadDirectory, { recursive: true })
  const asset = await gradleDistributionAsset(version)
  const archive = path.join(downloadDirectory, asset.fileName)
  if (!(await pathExists(archive))) {
    await downloadVerified(asset, archive, onProgress)
  }
  const extracted = path.join(root, `gradle-${version}`)
  if (!(await pathExists(extracted))) {
    await extractArchive(archive, root, onProgress)
  }
  const gradleBin = path.join(extracted, "bin", process.platform === "win32" ? "gradle.bat" : "gradle")
  if (!(await pathExists(gradleBin))) {
    throw new Error(`Gradle ${version} 解压后未找到可执行文件 ${gradleBin}`)
  }
  const androidDir = path.join(projectDir, "android")
  const androidGradleFile =
    (await readFile(path.join(androidDir, "settings.gradle"), "utf8").catch(() => undefined)) ??
    (await readFile(path.join(androidDir, "settings.gradle.kts"), "utf8").catch(() => undefined))
  const gradleCwd = androidGradleFile ? androidDir : projectDir
  onProgress?.(`生成 Gradle Wrapper（版本 ${version}）`)
  const result = await runProcess({
    command: gradleBin,
    args: ["wrapper", "--gradle-version", version, "--console=plain", "--no-daemon"],
    cwd: gradleCwd,
    timeoutMs: 10 * 60_000,
    env: { ...process.env, ...(javaHome ? { JAVA_HOME: javaHome } : {}) },
  })
  if (result.exitCode !== 0) {
    throw new Error(`生成 Gradle Wrapper 失败（exit ${result.exitCode}）：${result.stderr.trim() || result.stdout.trim()}`)
  }
  const wrapperName = process.platform === "win32" ? "gradlew.bat" : "gradlew"
  if (!(await pathExists(path.join(gradleCwd, wrapperName)))) {
    throw new Error("Gradle Wrapper 生成后未找到 gradlew 脚本")
  }
  return `Gradle ${version} Wrapper（生成于 ${gradleCwd}）`
}

export async function installMissingTools(
  config: PipelineConfig | undefined,
  initialToolchain: Toolchain,
  options: ToolInstallOptions = {},
): Promise<ToolInstallOutcome> {
  const plan = createToolRecoveryPlan(config, initialToolchain)
  const installed: string[] = []
  let current = initialToolchain

  // 离线优先：discoverToolchain 已优先解析 bundle 内工具，若此处仍需联网安装，
  // 说明 bundle 未覆盖所需工具。DROIDSEAL_OFFLINE=1 时直接给出清晰指引而非静默联网。
  if (plan.canAutoInstall && process.env.DROIDSEAL_OFFLINE === "1") {
    const names = plan.missing.map((tool) => tool.name).join("、")
    throw new Error(
      `离线模式（DROIDSEAL_OFFLINE=1）下仍缺少：${names}。` +
      "请在联网机器运行 `bun scripts/bundle-toolchain.ts` 生成离线包，" +
      "复制到 ~/.droidseal/bundle 或设置 DROIDSEAL_BUNDLE_DIR 后重试。",
    )
  }

  if (plan.autoGroups.includes("jdk")) {
    options.onProgress?.("准备下载并安装 Eclipse Temurin 21")
    const javaHome = await installManagedJdk(options.onProgress)
    installed.push(`Eclipse Temurin 21：${javaHome}`)
    current = await discoverToolchain(config)
  }

  if (plan.autoGroups.includes("android-build-tools")) {
    if (!current.java.path) {
      throw new Error("安装 Android Build Tools 需要 Java，但 JDK 安装后仍未发现 java。")
    }
    const version = await installAndroidBuildTools(
      current.androidSdkRoot
        ? { javaPath: current.java.path, sdkRoot: current.androidSdkRoot }
        : { javaPath: current.java.path },
      options.onProgress,
    )
    installed.push(`Android Build Tools ${version}`)
    current = await discoverToolchain(config)
  }

  if (plan.autoGroups.includes("gradle")) {
    if (!config?.inputPath) throw new Error("缺少项目输入，无法生成 Gradle Wrapper")
    if (!current.java.path) throw new Error("安装 Gradle 需要 Java，但 JDK 安装后仍未发现 java。")
    const summary = await installGradleWrapper(config.inputPath, options.onProgress, current.java.path)
    installed.push(summary)
    current = await discoverToolchain(config)
  }

  return {
    installed,
    toolchain: current,
    remaining: createToolRecoveryPlan(config, current),
  }
}
