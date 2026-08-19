import path from "node:path"
import { access, readdir } from "node:fs/promises"
import { homedir } from "node:os"
import { bundledSdkRoot, bundledToolPath, loadBundleManifest } from "./bundle.ts"
import type { BundleManifest, BundleToolName } from "./bundle.ts"
import type { PipelineConfig, ToolLocation, Toolchain } from "./types.ts"

const isWindows = process.platform === "win32"

async function exists(filePath: string | undefined): Promise<boolean> {
  if (!filePath) return false
  try {
    await access(filePath)
    return true
  } catch {
    return false
  }
}

function fromPath(name: string): string | undefined {
  return Bun.which(name) ?? undefined
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

async function sdkCandidates(): Promise<string[]> {
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

async function newestBuildTools(sdkRoot: string): Promise<{ directory: string; version: string } | undefined> {
  const root = path.join(sdkRoot, "build-tools")
  if (!(await exists(root))) return undefined
  const entries = await readdir(root, { withFileTypes: true })
  const versions = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort(compareVersions).reverse()
  const version = versions[0]
  if (!version) return undefined
  return { directory: path.join(root, version), version }
}

function location(
  name: string,
  filePath: string | undefined,
  source: ToolLocation["source"],
  requiredFor: ToolLocation["requiredFor"],
  detail: string,
): ToolLocation {
  return filePath
    ? { name, path: filePath, source, requiredFor, detail }
    : { name, source: "missing", requiredFor, detail }
}

async function managedJavaTool(name: "java" | "keytool"): Promise<string | undefined> {
  const root = path.join(homedir(), ".droidseal", "tools")
  const executable = isWindows ? `${name}.exe` : name
  const entries = await readdir(root, { withFileTypes: true }).catch(() => [])
  const directories = entries.filter((entry) => entry.isDirectory() && entry.name.startsWith("jdk-")).reverse()
  for (const directory of directories) {
    const installation = path.join(root, directory.name)
    const direct = path.join(installation, "bin", executable)
    if (await exists(direct)) return direct
    const children = await readdir(installation, { withFileTypes: true }).catch(() => [])
    for (const child of children) {
      if (child.isDirectory() && await exists(path.join(installation, child.name, "bin", executable))) {
        return path.join(installation, child.name, "bin", executable)
      }
    }
  }
}
async function javaTool(
  name: "java" | "keytool",
  bundle?: { root: string; manifest: BundleManifest },
): Promise<{ path?: string; source: ToolLocation["source"] }> {
  if (bundle) {
    const bundled = await bundledToolPath(bundle.manifest, bundle.root, name)
    if (bundled) return { path: bundled, source: "bundled" }
  }

  const onPath = fromPath(isWindows ? `${name}.exe` : name) ?? fromPath(name)
  if (onPath) return { path: onPath, source: "path" }

  const javaHome = process.env.JAVA_HOME
  const candidate = javaHome ? path.join(javaHome, "bin", isWindows ? `${name}.exe` : name) : undefined
  if (candidate && (await exists(candidate))) return { path: candidate, source: "java-home" }
  const managed = await managedJavaTool(name)
  if (managed) return { path: managed, source: "droidseal-managed" }
  return { source: "missing" }
}

async function gradleWrapper(projectPath: string): Promise<string | undefined> {
  const fileName = isWindows ? "gradlew.bat" : "gradlew"
  // Plain Android projects keep the wrapper at the root; Capacitor projects keep
  // it in the native android/ subfolder. Prefer the root, then fall back.
  for (const candidate of [path.join(projectPath, fileName), path.join(projectPath, "android", fileName)]) {
    if (await exists(candidate)) return candidate
  }
  return undefined
}

export async function discoverToolchain(config?: Pick<PipelineConfig, "inputKind" | "inputPath">): Promise<Toolchain> {
  const bundle = await loadBundleManifest()
  const java = await javaTool("java", bundle)
  const keytool = await javaTool("keytool", bundle)
  const roots = await sdkCandidates()
  const sdkRoot = roots[0]
  const buildTools = sdkRoot ? await newestBuildTools(sdkRoot) : undefined

  const toolPath = async (name: BundleToolName): Promise<{ path?: string; source: ToolLocation["source"] }> => {
    const extension = isWindows ? (name === "apksigner" ? ".bat" : ".exe") : ""
    if (bundle) {
      const bundled = await bundledToolPath(bundle.manifest, bundle.root, name)
      if (bundled) return { path: bundled, source: "bundled" }
    }
    const onPath = fromPath(name) ?? fromPath(`${name}${extension}`)
    if (onPath) return { path: onPath, source: "path" }
    const candidate = buildTools ? path.join(buildTools.directory, `${name}${extension}`) : undefined
    if (candidate && (await exists(candidate))) return { path: candidate, source: "android-sdk" }
    return { source: "missing" }
  }

  const [aapt, zipalign, apksigner] = await Promise.all([
    toolPath("aapt"),
    toolPath("zipalign"),
    toolPath("apksigner"),
  ])

  const wrapper =
    config?.inputKind === "project" ? await gradleWrapper(path.resolve(config.inputPath)) : undefined

  const result: Toolchain = {
    java: location("java", java.path, java.source, ["build", "sign", "verify"], "Java 运行时"),
    keytool: location("keytool", keytool.path, keytool.source, ["keystore"], "创建和检查签名库"),
    aapt: location("aapt", aapt.path, aapt.source, ["apk-audit"], "读取二进制 AndroidManifest"),
    zipalign: location("zipalign", zipalign.path, zipalign.source, ["align", "verify"], "APK ZIP 对齐"),
    apksigner: location("apksigner", apksigner.path, apksigner.source, ["sign", "verify"], "APK 签名与验证"),
    gradleWrapper: location(
      "gradle wrapper",
      wrapper,
      wrapper ? "project" : "missing",
      ["build"],
      config?.inputKind === "project" ? "项目自带 Gradle Wrapper" : "输入为 APK，无需 Gradle Wrapper",
    ),
  }

  const bundledSdk = bundle ? bundledSdkRoot(bundle.manifest, bundle.root) : undefined
  if (bundledSdk) result.androidSdkRoot = bundledSdk
  else if (sdkRoot) result.androidSdkRoot = sdkRoot
  if (bundle?.manifest.buildToolsVersion) result.buildToolsVersion = bundle.manifest.buildToolsVersion
  else if (buildTools) result.buildToolsVersion = buildTools.version
  return result
}

export function missingTools(toolchain: Toolchain): ToolLocation[] {
  return Object.values(toolchain).filter(
    (value): value is ToolLocation =>
      Boolean(value) && typeof value === "object" && "source" in value && value.source === "missing",
  )
}
