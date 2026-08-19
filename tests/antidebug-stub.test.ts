import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile, stat } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { ANTIDEBUG_STUB_FILES, installAntiDebugStub } from "../src/core/antidebug-stub.ts"

describe("anti-debug stub installer", () => {
  test("writes all stub files into a fresh module directory", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-antidebug-"))
    const result = await installAntiDebugStub(dir)
    expect(result.written.sort()).toEqual(ANTIDEBUG_STUB_FILES.map((file) => file.destination).sort())
    expect(result.skipped).toEqual([])
    for (const file of ANTIDEBUG_STUB_FILES) {
      const target = path.join(dir, file.destination)
      expect(await stat(target).then((info) => info.isFile())).toBe(true)
    }
    const nativeSource = await readFile(path.join(dir, "src/main/cpp/droidseal_antidebug.c"), "utf8")
    expect(nativeSource).toContain("TracerPid")
    const kotlin = await readFile(path.join(dir, "src/main/java/com/droidseal/antidebug/DroidSealAntiDebug.kt"), "utf8")
    expect(kotlin).toContain("object DroidSealAntiDebug")
    expect(kotlin).toContain("fun guardOnActivityResumed(")
    expect(kotlin).toContain("DEFAULT_RESUME_RECHECK_INTERVAL_MS")
  })

  test("documents a throttled resumed-Activity recheck with an opt-in exit policy", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-antidebug-"))
    await installAntiDebugStub(dir)
    const kotlin = await readFile(
      path.join(dir, "src/main/java/com/droidseal/antidebug/DroidSealAntiDebug.kt"),
      "utf8",
    )
    const guide = await readFile(path.join(dir, "droidseal-antidebug/INTEGRATION.md"), "utf8")

    expect(kotlin).toContain("SystemClock.elapsedRealtime()")
    expect(kotlin).toContain("AtomicLong(-1L)")
    expect(kotlin).toContain("now - previous < interval")
    expect(kotlin).toContain("return null")
    // EXIT 是显式启用的可选策略：kill 调用只存在于 ResponsePolicy.EXIT 分支
    expect(kotlin).toContain("ResponsePolicy.EXIT")
    expect(kotlin.indexOf("exitProcess(1)")).toBeGreaterThan(kotlin.indexOf("ResponsePolicy.EXIT"))
    expect(guide).toContain("override fun onResume()")
    expect(guide).toContain("guardOnActivityResumed")
    expect(guide).toContain("minIntervalMs")
  })

  test("is non-destructive by default and honors force", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-antidebug-"))
    await installAntiDebugStub(dir)
    const second = await installAntiDebugStub(dir)
    expect(second.written).toEqual([])
    expect(second.skipped.length).toBe(ANTIDEBUG_STUB_FILES.length)
    const forced = await installAntiDebugStub(dir, { force: true })
    expect(forced.written.length).toBe(ANTIDEBUG_STUB_FILES.length)
    expect(forced.skipped).toEqual([])
  })

  test("throws when target module directory does not exist", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-antidebug-"))
    await expect(installAntiDebugStub(path.join(dir, "does-not-exist"))).rejects.toThrow()
  })
})
