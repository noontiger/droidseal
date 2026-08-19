import { describe, expect, test } from "bun:test"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { parseArsc } from "../src/core/arsc-model.ts"
import { buildZip, crc32Of, parseRawZip, type OutEntry } from "../src/core/harden-manifest.ts"
import { obfuscateArscInApk } from "../src/core/lossy-harden.ts"
import { sampleArsc } from "./arsc-fixtures.ts"

// Minimal parseable DEX carrying the given ASCII strings in its string pool.
function buildMinimalDex(strings: string[]): Uint8Array {
  const idsOff = 0x70
  const dataStart = idsOff + strings.length * 4
  const data: number[] = []
  const offsets: number[] = []
  for (const s of strings) {
    offsets.push(dataStart + data.length)
    data.push(s.length) // ULEB128 utf16 length (assumes < 0x80)
    for (let i = 0; i < s.length; i += 1) data.push(s.charCodeAt(i))
    data.push(0x00)
  }
  const total = Math.max(dataStart + data.length, 0x70)
  const bytes = new Uint8Array(total)
  bytes[0] = 0x64
  bytes[1] = 0x65
  bytes[2] = 0x78
  bytes[3] = 0x0a
  const view = new DataView(bytes.buffer)
  view.setUint32(0x38, strings.length, true)
  view.setUint32(0x3c, idsOff, true)
  for (let i = 0; i < strings.length; i += 1) view.setUint32(idsOff + i * 4, offsets[i]!, true)
  bytes.set(Uint8Array.from(data), dataStart)
  return bytes
}

function storedEntry(name: string, data: Uint8Array): OutEntry {
  return {
    name,
    method: 0,
    crc32: crc32Of(data),
    compressedSize: data.byteLength,
    uncompressedSize: data.byteLength,
    flags: 0,
    data,
  }
}

function buildSyntheticApk(dexStrings: string[]): Uint8Array {
  const entries: OutEntry[] = [
    storedEntry("AndroidManifest.xml", new Uint8Array([0x03, 0x00, 0x08, 0x00])),
    storedEntry("classes.dex", buildMinimalDex(dexStrings)),
    storedEntry("res/drawable/ic_launcher.png", new Uint8Array([0x89, 0x50, 0x4e, 0x47])),
    storedEntry("res/layout/activity_main.xml", new Uint8Array([0x3c, 0x3f, 0x78, 0x6d])),
    storedEntry("resources.arsc", sampleArsc()),
  ]
  return buildZip(entries)
}

async function withTempDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), "droidseal-arsc-"))
  try {
    return await fn(dir)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
}

describe("obfuscateArscInApk N4 end-to-end", () => {
  test("rewrites resources.arsc, renames file entries, keeps ZIP loadable", async () => {
    await withTempDir(async (dir) => {
      const input = path.join(dir, "in.apk")
      const output = path.join(dir, "out.apk")
      await Bun.write(input, buildSyntheticApk(["Lcom/x/Y;", "hello"]))

      const result = await obfuscateArscInApk(input, output, {})
      expect(result.changed).toBe(true)
      expect(result.keysRenamed).toBe(3)
      expect(result.pathsRenamed).toBe(2)
      expect(result.entriesRenamed).toBe(2)
      expect(result.usesGetIdentifier).toBe(false)
      expect(result.findings.some((f) => f.code === "LOSSY_ARSC_OBFUSCATED")).toBe(true)

      const outBytes = new Uint8Array(await Bun.file(output).arrayBuffer())
      const entries = parseRawZip(outBytes)
      const names = entries.map((e) => e.name)
      // File paths flattened and synchronized with the arsc string pool.
      expect(names).toContain("r/a.png")
      expect(names).toContain("r/b.xml")
      expect(names).not.toContain("res/drawable/ic_launcher.png")
      expect(names).not.toContain("res/layout/activity_main.xml")

      const arscEntry = entries.find((e) => e.name === "resources.arsc")!
      expect(arscEntry.method).toBe(0) // STORED
      const table = parseArsc(arscEntry.data)
      expect(table.packages[0]!.keyStrings.strings).toEqual(["a", "b", "c"])
      expect(table.globalStrings.strings).toEqual(["r/a.png", "r/b.xml"])
    })
  })

  test("getIdentifier reflection fail-safely preserves all resource names", async () => {
    await withTempDir(async (dir) => {
      const input = path.join(dir, "in.apk")
      const output = path.join(dir, "out.apk")
      await Bun.write(input, buildSyntheticApk(["getIdentifier", "app_name"]))

      const result = await obfuscateArscInApk(input, output, {})
      expect(result.usesGetIdentifier).toBe(true)
      // Dynamic names cannot be enumerated precisely, so no key is renamed.
      expect(result.keysRenamed).toBe(0)
      expect(result.findings.some((f) => f.code === "ARSC_RESOURCE_NAME_REFLECTION")).toBe(true)

      const arscEntry = parseRawZip(new Uint8Array(await Bun.file(output).arrayBuffer())).find(
        (e) => e.name === "resources.arsc",
      )!
      const keys = parseArsc(arscEntry.data).packages[0]!.keyStrings.strings
      expect(keys).toContain("app_name")
      expect(keys).toEqual(["app_name", "ic_launcher", "activity_main"])
    })
  })

  test("preserves resource paths referenced as DEX literals", async () => {
    await withTempDir(async (dir) => {
      const input = path.join(dir, "in.apk")
      const output = path.join(dir, "out.apk")
      await Bun.write(input, buildSyntheticApk(["res/drawable/ic_launcher.png"]))

      const result = await obfuscateArscInApk(input, output, {})
      expect(result.changed).toBe(true)
      expect(result.pathsRenamed).toBe(1)
      expect(result.findings.some((finding) => finding.code === "ARSC_LITERAL_PATHS_PRESERVED")).toBe(true)
      const names = parseRawZip(new Uint8Array(await Bun.file(output).arrayBuffer())).map((entry) => entry.name)
      expect(names).toContain("res/drawable/ic_launcher.png")
      expect(names).not.toContain("res/layout/activity_main.xml")
    })
  })
  test("no-op when resources.arsc is absent", async () => {
    await withTempDir(async (dir) => {
      const input = path.join(dir, "in.apk")
      const output = path.join(dir, "out.apk")
      await Bun.write(input, buildZip([storedEntry("AndroidManifest.xml", new Uint8Array([0x03, 0x00]))]))

      const result = await obfuscateArscInApk(input, output, {})
      expect(result.changed).toBe(false)
      expect(result.keysRenamed).toBe(0)
      expect(await Bun.file(output).exists()).toBe(false)
    })
  })

  test("shortenKeys/flattenPaths can be disabled independently", async () => {
    await withTempDir(async (dir) => {
      const input = path.join(dir, "in.apk")
      const output = path.join(dir, "out.apk")
      await Bun.write(input, buildSyntheticApk(["nope"]))

      const result = await obfuscateArscInApk(input, output, { shortenKeys: false })
      expect(result.keysRenamed).toBe(0)
      expect(result.pathsRenamed).toBe(2)
      expect(result.changed).toBe(true)
    })
  })
})
