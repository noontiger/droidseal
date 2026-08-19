import { describe, expect, test } from "bun:test"
import { resolveChildEnv } from "../src/core/process.ts"

const WIN = process.platform === "win32"

function opts(over: Partial<{ gradle: boolean; env: Record<string, string> }> = {}) {
  return {
    command: "java",
    args: ["-version"],
    cwd: ".",
    ...over,
  }
}

describe("resolveChildEnv", () => {
  test("non-Windows is left untouched (no JAVA_TOOL_OPTIONS injection)", () => {
    if (WIN) return
    const env = resolveChildEnv(opts())
    expect(env.JAVA_TOOL_OPTIONS).toBeUndefined()
  })

  test("on Windows injects a conservative default for light JVM tools", () => {
    if (!WIN) return
    // Ensure no override env pollutes the result.
    const prev = process.env.DROIDSEAL_JVM_OPTIONS
    delete process.env.DROIDSEAL_JVM_OPTIONS
    try {
      const env = resolveChildEnv(opts())
      expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx256m -XX:MaxMetaspaceSize=128m")
    } finally {
      if (prev !== undefined) process.env.DROIDSEAL_JVM_OPTIONS = prev
    }
  })

  test("on Windows the Gradle daemon gets a much larger Metaspace footprint", () => {
    if (!WIN) return
    const prev = process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    delete process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    try {
      const env = resolveChildEnv(opts({ gradle: true }))
      expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx2048m -XX:MaxMetaspaceSize=512m")
    } finally {
      if (prev !== undefined) process.env.DROIDSEAL_GRADLE_JVM_OPTIONS = prev
    }
  })

  test("DROIDSEAL_GRADLE_JVM_OPTIONS overrides the Gradle default", () => {
    if (!WIN) return
    const prev = process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    process.env.DROIDSEAL_GRADLE_JVM_OPTIONS = "-Xmx2048m -XX:MaxMetaspaceSize=768m"
    try {
      const env = resolveChildEnv(opts({ gradle: true }))
      expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx2048m -XX:MaxMetaspaceSize=768m")
    } finally {
      if (prev !== undefined) process.env.DROIDSEAL_JVM_OPTIONS = prev
      else delete process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    }
  })

  test("light JVM tools use the small default even when gradle override is set", () => {
    if (!WIN) return
    const prev = process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    process.env.DROIDSEAL_GRADLE_JVM_OPTIONS = "-Xmx2048m -XX:MaxMetaspaceSize=768m"
    try {
      const env = resolveChildEnv(opts({ gradle: false }))
      expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx256m -XX:MaxMetaspaceSize=128m")
    } finally {
      if (prev !== undefined) process.env.DROIDSEAL_GRADLE_JVM_OPTIONS = prev
      else delete process.env.DROIDSEAL_GRADLE_JVM_OPTIONS
    }
  })

  test("explicit JAVA_TOOL_OPTIONS is always honored and never overwritten", () => {
    if (!WIN) return
    const env = resolveChildEnv(opts({ env: { JAVA_TOOL_OPTIONS: "-Xmx4g" } }))
    expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx4g")
  })

  test("Gradle daemon ignores an inherited tiny JAVA_TOOL_OPTIONS (self-fixes Metaspace OOM)", () => {
    if (!WIN) return
    // Simulate a host shell that set a small default (e.g. a sandbox/dev tool).
    const env = resolveChildEnv(opts({ gradle: true, env: { JAVA_TOOL_OPTIONS: "-Xmx256m -XX:MaxMetaspaceSize=128m" } }))
    expect(env.JAVA_TOOL_OPTIONS).toBe("-Xmx2048m -XX:MaxMetaspaceSize=512m")
  })
})
