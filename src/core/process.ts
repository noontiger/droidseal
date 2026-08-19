import path from "node:path"
import type { CommandResult, ProcessOptions } from "./types.ts"

const MAX_CAPTURE_BYTES = 2 * 1024 * 1024

function redactText(value: string, secrets: string[]): string {
  let result = value
  for (const secret of secrets) {
    if (!secret) continue
    result = result.split(secret).join("<redacted>")
  }
  return result
}

async function consumeStream(
  stream: ReadableStream<Uint8Array>,
  streamName: "stdout" | "stderr",
  onLine?: ProcessOptions["onLine"],
): Promise<string> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let text = ""
  let pendingLine = ""
  let capturedBytes = 0
  let truncated = false

  while (true) {
    const { value, done } = await reader.read()
    if (done) break
    if (!value) continue

    const decoded = decoder.decode(value, { stream: true })
    if (capturedBytes < MAX_CAPTURE_BYTES) {
      const remaining = MAX_CAPTURE_BYTES - capturedBytes
      const slice = value.byteLength <= remaining ? decoded : decoded.slice(0, remaining)
      text += slice
      capturedBytes += Math.min(value.byteLength, remaining)
      if (value.byteLength > remaining) truncated = true
    } else {
      truncated = true
    }

    if (onLine) {
      pendingLine += decoded
      const lines = pendingLine.split(/\r?\n/)
      pendingLine = lines.pop() ?? ""
      for (const line of lines) {
        if (line.trim()) onLine(line, streamName)
      }
    }
  }

  const tail = decoder.decode()
  text += tail
  pendingLine += tail
  if (onLine && pendingLine.trim()) onLine(pendingLine, streamName)
  if (truncated) text += "\n[droidseal: output truncated at 2 MiB]"
  return text
}

const DEFAULT_WINDOWS_JVM_OPTIONS = "-Xmx256m -XX:MaxMetaspaceSize=128m"

// Gradle forks a long-lived daemon that compiles and lints the entire app. Its
// Metaspace requirement is an order of magnitude above light JVM tools, so the
// conservative default above makes the daemon OOM during lint/compile
// (java.lang.OutOfMemoryError: Metaspace → "Gradle daemon disappeared"). We
// therefore give the Gradle daemon a dedicated, much larger JVM footprint.
//   - Heap 2g + Metaspace 512m is the proven-good setting for AGP lint/compile/D8
//     on mid-size apps (verified to clear the Metaspace OOM end-to-end).
//   - Overridable via DROIDSEAL_GRADLE_JVM_OPTIONS (e.g. raise on huge multi-module apps).
const DEFAULT_GRADLE_WINDOWS_JVM_OPTIONS = "-Xmx2048m -XX:MaxMetaspaceSize=512m"

// JVM-backed tools (apksigner, keytool, jarsigner, sdkmanager) reserve their
// entire max heap at startup. On Windows the reservation counts against the
// system commit limit (RAM + page file), so on machines with a small page file
// the JVM fails to start with ERROR_COMMITMENT_LIMIT (errno=1455) before doing
// any work. We inject a conservative JAVA_TOOL_OPTIONS default so these tools
// start reliably out of the box. Native tools (aapt/zipalign) ignore it.
//   - Only applied on Windows (that is where the commit-limit error occurs).
//   - Skipped when the user already set JAVA_TOOL_OPTIONS or _JAVA_OPTIONS.
//   - Value overridable via DROIDSEAL_JVM_OPTIONS; set it to "off" (or empty) to disable.
export function resolveChildEnv(options: ProcessOptions): Record<string, string | undefined> {
  const merged: Record<string, string | undefined> = { ...process.env, ...options.env }
  if (process.platform !== "win32") return merged
  const hasInheritedToolOptions = merged.JAVA_TOOL_OPTIONS !== undefined || merged._JAVA_OPTIONS !== undefined

  // Gradle forks a long-lived daemon that compiles and lints the whole app and
  // needs an order of magnitude more Metaspace than light JVM tools. We ALWAYS
  // give it the dedicated larger footprint and deliberately ignore any inherited
  // JAVA_TOOL_OPTIONS (those are sized for apksigner/keytool and would OOM the
  // daemon with "Metaspace" otherwise). Disable with DROIDSEAL_GRADLE_JVM_OPTIONS=off.
  if (options.gradle) {
    const gradleOverride = process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    if (gradleOverride !== undefined && gradleOverride.trim() !== "" && gradleOverride.trim().toLowerCase() !== "off") {
      merged.JAVA_TOOL_OPTIONS = gradleOverride
    } else {
      merged.JAVA_TOOL_OPTIONS = DEFAULT_GRADLE_WINDOWS_JVM_OPTIONS
    }
    return merged
  }

  // Light JVM tools: honor an inherited JAVA_TOOL_OPTIONS / _JAVA_OPTIONS as-is.
  if (hasInheritedToolOptions) return merged
  const override = process.env.DROIDSEAL_JVM_OPTIONS
  if (override !== undefined) {
    if (override.trim() === "" || override.trim().toLowerCase() === "off") return merged
    merged.JAVA_TOOL_OPTIONS = override
    return merged
  }
  merged.JAVA_TOOL_OPTIONS = DEFAULT_WINDOWS_JVM_OPTIONS
  return merged
}

// Returns the JVM option string DroidSeal applies to Gradle invocations on
// Windows (empty on other platforms). Only meaningful for the Gradle/worker
// JVM; it is passed to Gradle via -Dorg.gradle.jvmargs so the setting reaches
// forked D8/lint worker processes (JAVA_TOOL_OPTIONS is not reliably inherited
// by Gradle workers). Honors DROIDSEAL_GRADLE_JVM_OPTIONS, or "off" to disable.
export function gradleJvmArgsString(): string {
  if (process.platform !== "win32") return ""
  const override = process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
  if (override !== undefined && override.trim() !== "" && override.trim().toLowerCase() !== "off") {
    return override.trim()
  }
  return DEFAULT_GRADLE_WINDOWS_JVM_OPTIONS
}

export async function runProcess(options: ProcessOptions): Promise<CommandResult> {
  const started = performance.now()
  const secrets = options.redact ?? []
  let timedOut = false

  const child = Bun.spawn([options.command, ...options.args], {
    cwd: options.cwd,
    env: resolveChildEnv(options),
    stdin: options.stdinInput === undefined ? "ignore" : "pipe",
    stdout: "pipe",
    stderr: "pipe",
    windowsHide: true,
  })

  if (options.stdinInput !== undefined && child.stdin && typeof child.stdin !== "number") {
    child.stdin.write(options.stdinInput)
    child.stdin.end()
  }

  const timeout = setTimeout(() => {
    timedOut = true
    child.kill()
  }, options.timeoutMs ?? 10 * 60_000)

  const [stdout, stderr, exitCode] = await Promise.all([
    consumeStream(child.stdout, "stdout", options.onLine),
    consumeStream(child.stderr, "stderr", options.onLine),
    child.exited,
  ]).finally(() => clearTimeout(timeout))

  return {
    command: path.basename(options.command),
    args: options.args.map((arg) => redactText(arg, secrets)),
    cwd: options.cwd,
    exitCode,
    stdout: redactText(stdout, secrets),
    stderr: redactText(stderr, secrets),
    durationMs: Math.round(performance.now() - started),
    timedOut,
  }
}
