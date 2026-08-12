import path from "node:path"
import { access, copyFile, readFile, writeFile } from "node:fs/promises"

// Capacitor projects wrap a web app (www/) around a native Android project that
// lives in the `android/` subfolder. Producing an APK therefore needs a web
// layer the plain-Gradle path does not: a Node toolchain, `npm install`,
// `npx cap sync android` (copies www/ into android/app/src/main/assets/public),
// and — on machines whose JDK is older than what Capacitor's generated
// `capacitor.build.gradle` targets — a JavaVersion downgrade so Gradle can run.
// These helpers are pure/file-only; orchestration (runProcess + progress) lives
// in the pipeline build step.

const CAPACITOR_CONFIG_NAMES = ["capacitor.config.json", "capacitor.config.ts", "capacitor.config.js"] as const
const isWindows = process.platform === "win32"

export interface CapacitorDetection {
  isCapacitor: boolean
  androidDir: string
  configFile?: string
}

export interface NodeTools {
  node?: string
  npm?: string
  npx?: string
}

export interface JavaVersionPatch {
  changed: boolean
  from: string
  to: string
  filePath: string
  backupPath?: string
}

async function exists(target: string): Promise<boolean> {
  try {
    await access(target)
    return true
  } catch {
    return false
  }
}

// A directory is a Capacitor project when it carries a capacitor config AND an
// `android/` subfolder with a Gradle wrapper (the native project cap manages).
export async function detectCapacitorProject(projectDir: string): Promise<CapacitorDetection> {
  const root = path.resolve(projectDir)
  const androidDir = path.join(root, "android")
  let configFile: string | undefined
  for (const name of CAPACITOR_CONFIG_NAMES) {
    if (await exists(path.join(root, name))) {
      configFile = path.join(root, name)
      break
    }
  }
  const wrapper = path.join(androidDir, isWindows ? "gradlew.bat" : "gradlew")
  const isCapacitor = Boolean(configFile) && (await exists(wrapper))
  return configFile ? { isCapacitor, androidDir, configFile } : { isCapacitor, androidDir }
}

function whichWithFallback(name: string): string | undefined {
  const direct = Bun.which(name)
  if (direct) return direct
  if (isWindows) return Bun.which(`${name}.cmd`) ?? Bun.which(`${name}.exe`) ?? undefined
  return undefined
}

export function detectNodeTools(): NodeTools {
  const result: NodeTools = {}
  const node = whichWithFallback("node")
  const npm = whichWithFallback("npm")
  const npx = whichWithFallback("npx")
  if (node) result.node = node
  if (npm) result.npm = npm
  if (npx) result.npx = npx
  return result
}

// Parse the major version out of `java -version` text. `java` prints its banner
// to stderr, e.g. `openjdk version "21.0.2"` (→21) or `java version "1.8.0_401"`
// (→8). Returns undefined when no recognizable version token is present.
export function parseJavaMajor(versionOutput: string): number | undefined {
  const match = /version\s+"(\d+)(?:\.(\d+))?[._\d]*"/i.exec(versionOutput)
  if (!match) return undefined
  const first = Number.parseInt(match[1]!, 10)
  if (!Number.isFinite(first)) return undefined
  if (first === 1 && match[2] !== undefined) {
    const second = Number.parseInt(match[2], 10)
    return Number.isFinite(second) ? second : undefined
  }
  return first
}

function versionToken(major: number): string {
  return major <= 8 ? `1_${major}` : String(major)
}

// Rewrite every `JavaVersion.VERSION_<n>` token in android/app/capacitor.build.gradle
// to the local JDK major so Gradle's Java toolchain check passes. Fail-closed:
// returns undefined when the generated file or the token is absent (never creates
// or invents the file). Idempotent: no change → no backup written.
export async function patchCapacitorJavaVersion(
  androidDir: string,
  targetMajor: number,
): Promise<JavaVersionPatch | undefined> {
  const filePath = path.join(androidDir, "app", "capacitor.build.gradle")
  if (!(await exists(filePath))) return undefined
  const original = await readFile(filePath, "utf8")
  const tokenRe = /JavaVersion\.VERSION_(1_\d+|\d+)/g
  const found = [...original.matchAll(tokenRe)]
  if (found.length === 0) return undefined

  const target = versionToken(targetMajor)
  const fromTokens = [...new Set(found.map((match) => match[1]!))]
  const patched = original.replace(tokenRe, `JavaVersion.VERSION_${target}`)
  const from = fromTokens.join(",")
  if (patched === original) {
    return { changed: false, from, to: target, filePath }
  }
  const backupPath = `${filePath}.droidseal.bak`
  if (!(await exists(backupPath))) await copyFile(filePath, backupPath)
  await writeFile(filePath, patched)
  return { changed: true, from, to: target, filePath, backupPath }
}
