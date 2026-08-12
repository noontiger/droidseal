import { describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  detectCapacitorProject,
  parseJavaMajor,
  patchCapacitorJavaVersion,
} from "../src/core/capacitor-build.ts"

describe("parseJavaMajor", () => {
  test("parses modern JDK output (stderr)", () => {
    const output = `openjdk version "21.0.2" 2024-01-16
OpenJDK Runtime Environment (build 21.0.2+13)
OpenJDK 64-Bit Server VM (build 21.0.2+13, mixed mode)`
    expect(parseJavaMajor(output)).toBe(21)
  })

  test("parses legacy 1.8 output", () => {
    const output = `java version "1.8.0_401"
Java(TM) SE Runtime Environment (build 1.8.0_401-b10)
Java HotSpot(TM) 64-Bit Server VM (build 25.401-b10, mixed mode)`
    expect(parseJavaMajor(output)).toBe(8)
  })

  test("returns undefined for unrecognized output", () => {
    expect(parseJavaMajor("no version here")).toBeUndefined()
    expect(parseJavaMajor("")).toBeUndefined()
  })

  test("handles JDK 11", () => {
    const output = `openjdk version "11.0.22" 2024-01-16`
    expect(parseJavaMajor(output)).toBe(11)
  })
})

describe("detectCapacitorProject", () => {
  test("returns isCapacitor=false when no config file exists", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const result = await detectCapacitorProject(dir)
      expect(result.isCapacitor).toBe(false)
      expect(result.configFile).toBeUndefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("returns isCapacitor=false when config exists but no android/gradlew", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      await writeFile(path.join(dir, "capacitor.config.json"), "{}")
      const result = await detectCapacitorProject(dir)
      expect(result.isCapacitor).toBe(false)
      expect(result.configFile).toBeDefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("returns isCapacitor=true when config + android/gradlew exist", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      await writeFile(path.join(dir, "capacitor.config.json"), "{}")
      const androidDir = path.join(dir, "android")
      await mkdir(androidDir)
      const wrapperName = process.platform === "win32" ? "gradlew.bat" : "gradlew"
      await writeFile(path.join(androidDir, wrapperName), "#!/bin/sh", { mode: 0o755 })
      const result = await detectCapacitorProject(dir)
      expect(result.isCapacitor).toBe(true)
      expect(result.configFile).toBe(path.join(dir, "capacitor.config.json"))
      expect(result.androidDir).toBe(androidDir)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

describe("patchCapacitorJavaVersion", () => {
  test("returns undefined when capacitor.build.gradle does not exist", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const result = await patchCapacitorJavaVersion(dir, 20)
      expect(result).toBeUndefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("returns undefined when file exists but has no JavaVersion tokens", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const appDir = path.join(dir, "app")
      await mkdir(appDir)
      await writeFile(path.join(appDir, "capacitor.build.gradle"), "// no tokens here")
      const result = await patchCapacitorJavaVersion(dir, 20)
      expect(result).toBeUndefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("patches JavaVersion.VERSION_21 to VERSION_20 and creates backup", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const appDir = path.join(dir, "app")
      await mkdir(appDir)
      const filePath = path.join(appDir, "capacitor.build.gradle")
      const original = `compileOptions {
  sourceCompatibility JavaVersion.VERSION_21
  targetCompatibility JavaVersion.VERSION_21
}`
      await writeFile(filePath, original)
      const result = await patchCapacitorJavaVersion(dir, 20)
      expect(result).toBeDefined()
      expect(result!.changed).toBe(true)
      expect(result!.from).toBe("21")
      expect(result!.to).toBe("20")
      expect(result!.backupPath).toBe(`${filePath}.droidseal.bak`)
      const patched = await readFile(filePath, "utf8")
      expect(patched).toContain("JavaVersion.VERSION_20")
      expect(patched).not.toContain("JavaVersion.VERSION_21")
      const backup = await readFile(result!.backupPath!, "utf8")
      expect(backup).toBe(original)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("is idempotent: no change when already at target version", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const appDir = path.join(dir, "app")
      await mkdir(appDir)
      const filePath = path.join(appDir, "capacitor.build.gradle")
      const original = `compileOptions {
  sourceCompatibility JavaVersion.VERSION_20
  targetCompatibility JavaVersion.VERSION_20
}`
      await writeFile(filePath, original)
      const result = await patchCapacitorJavaVersion(dir, 20)
      expect(result).toBeDefined()
      expect(result!.changed).toBe(false)
      expect(result!.from).toBe("20")
      expect(result!.to).toBe("20")
      expect(result!.backupPath).toBeUndefined()
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })

  test("handles legacy 1.8 token format", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "ds-cap-"))
    try {
      const appDir = path.join(dir, "app")
      await mkdir(appDir)
      const filePath = path.join(appDir, "capacitor.build.gradle")
      const original = `compileOptions {
  sourceCompatibility JavaVersion.VERSION_1_8
  targetCompatibility JavaVersion.VERSION_1_8
}`
      await writeFile(filePath, original)
      const result = await patchCapacitorJavaVersion(dir, 8)
      expect(result).toBeDefined()
      expect(result!.changed).toBe(false)
      expect(result!.from).toBe("1_8")
      expect(result!.to).toBe("1_8")
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})
