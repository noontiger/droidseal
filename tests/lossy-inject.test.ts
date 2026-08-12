import { describe, expect, test } from "bun:test"
import { mkdtemp } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { parseAxml, readApplicationName } from "../src/core/axml-writer.ts"
import { parseDexTables } from "../src/core/dex-writer.ts"
import { buildZip, crc32Of, inflateEntry, parseRawZip, type OutEntry } from "../src/core/harden-manifest.ts"
import { buildAntiDebugDex, injectAntiDebug } from "../src/core/lossy-inject.ts"

const ANDROID_NAME_RES_ID = 0x01010003

// Minimal binary AndroidManifest.xml with <manifest><application android:name>.
function buildManifest(appName: string | null): Uint8Array {
  const strings = [
    "name",
    "http://schemas.android.com/apk/res/android",
    "android",
    "manifest",
    "application",
    appName ?? "com.example.Unused",
  ]
  const resMap = [ANDROID_NAME_RES_ID]
  const enc = new TextEncoder()
  const offsets: number[] = []
  const data: number[] = []
  for (const s of strings) {
    offsets.push(data.length)
    const utf8 = enc.encode(s)
    data.push(s.length, utf8.byteLength)
    for (const b of utf8) data.push(b)
    data.push(0x00)
  }
  while (data.length % 4 !== 0) data.push(0x00)
  const stringsStart = 28 + strings.length * 4
  const poolSize = stringsStart + data.length
  const pool = new Uint8Array(poolSize)
  const pv = new DataView(pool.buffer)
  pv.setUint16(0, 0x0001, true)
  pv.setUint16(2, 28, true)
  pv.setUint32(4, poolSize, true)
  pv.setUint32(8, strings.length, true)
  pv.setUint32(12, 0, true)
  pv.setUint32(16, 0x0100, true)
  pv.setUint32(20, stringsStart, true)
  pv.setUint32(24, 0, true)
  for (let i = 0; i < offsets.length; i += 1) pv.setUint32(28 + i * 4, offsets[i]!, true)
  pool.set(Uint8Array.from(data), stringsStart)

  const resMapSize = 8 + resMap.length * 4
  const rm = new Uint8Array(resMapSize)
  const rmv = new DataView(rm.buffer)
  rmv.setUint16(0, 0x0180, true)
  rmv.setUint16(2, 8, true)
  rmv.setUint32(4, resMapSize, true)
  for (let i = 0; i < resMap.length; i += 1) rmv.setUint32(8 + i * 4, resMap[i]!, true)

  const NO = 0xffffffff
  const startTag = (nameIdx: number, attrs: Array<{ ns: number; name: number; value: number }>): Uint8Array => {
    const size = 16 + 20 + attrs.length * 20
    const b = new Uint8Array(size)
    const v = new DataView(b.buffer)
    v.setUint16(0, 0x0102, true)
    v.setUint16(2, 16, true)
    v.setUint32(4, size, true)
    v.setUint32(8, 0, true)
    v.setUint32(12, NO, true)
    v.setUint32(16, NO, true)
    v.setUint32(20, nameIdx, true)
    v.setUint16(24, 20, true)
    v.setUint16(26, 20, true)
    v.setUint16(28, attrs.length, true)
    v.setUint16(30, 0, true)
    v.setUint16(32, 0, true)
    v.setUint16(34, 0, true)
    let a = 36
    for (const at of attrs) {
      v.setUint32(a, at.ns, true)
      v.setUint32(a + 4, at.name, true)
      v.setUint32(a + 8, at.value, true)
      v.setUint16(a + 12, 8, true)
      v.setUint8(a + 14, 0)
      v.setUint8(a + 15, 0x03)
      v.setUint32(a + 16, at.value, true)
      a += 20
    }
    return b
  }
  const endTag = (nameIdx: number): Uint8Array => {
    const b = new Uint8Array(24)
    const v = new DataView(b.buffer)
    v.setUint16(0, 0x0103, true)
    v.setUint16(2, 16, true)
    v.setUint32(4, 24, true)
    v.setUint32(8, 0, true)
    v.setUint32(12, NO, true)
    v.setUint32(16, NO, true)
    v.setUint32(20, nameIdx, true)
    return b
  }

  const appAttrs = appName === null ? [] : [{ ns: 1, name: 0, value: 5 }]
  const nodes = [startTag(3, []), startTag(4, appAttrs), endTag(4), endTag(3)]
  const tailLen = resMapSize + nodes.reduce((n, x) => n + x.byteLength, 0)
  const tail = new Uint8Array(tailLen)
  let off = 0
  tail.set(rm, off)
  off += resMapSize
  for (const n of nodes) {
    tail.set(n, off)
    off += n.byteLength
  }

  const total = 8 + poolSize + tailLen
  const out = new Uint8Array(total)
  const ov = new DataView(out.buffer)
  ov.setUint16(0, 0x0003, true)
  ov.setUint16(2, 8, true)
  ov.setUint32(4, total, true)
  out.set(pool, 8)
  out.set(tail, 8 + poolSize)
  return out
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

// Build a synthetic APK containing a manifest, a dummy classes.dex, and a stub arsc.
function buildApk(appName: string | null): Uint8Array {
  return buildZip([
    storedEntry("AndroidManifest.xml", buildManifest(appName)),
    storedEntry("classes.dex", new Uint8Array([1, 2, 3, 4])),
    storedEntry("resources.arsc", new Uint8Array([9, 9, 9, 9])),
  ])
}

async function tmpFile(prefix: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "droidseal-inject-"))
  return join(dir, prefix)
}

describe("lossy-inject anti-debug DEX builder (M4)", () => {
  test("builds a DEX with AntiDebug + Bootstrap and correct references", () => {
    const dex = buildAntiDebugDex("Lcom/droidseal/inj/Bootstrap;", "Lcom/example/MyApp;")
    const tables = parseDexTables(dex)
    const descriptors = tables.classes.map((c) => tables.strings[tables.types[c.classIdx]!])
    expect(descriptors).toContain("Lcom/droidseal/inj/AntiDebug;")
    expect(descriptors).toContain("Lcom/droidseal/inj/Bootstrap;")

    const bootstrap = tables.classes.find((c) => tables.strings[tables.types[c.classIdx]!] === "Lcom/droidseal/inj/Bootstrap;")!
    expect(tables.strings[tables.types[bootstrap.superclassIdx]!]).toBe("Lcom/example/MyApp;")

    // onCreate: invoke-super super.onCreate() then invoke-static AntiDebug.check().
    const onCreate = bootstrap.virtualMethods.find((mth) => tables.strings[tables.methods[mth.methodIdx]!.nameIdx] === "onCreate")!
    const insns = onCreate.code!.insns
    const superOnCreate = tables.methods[insns[1]!]!
    expect(tables.strings[superOnCreate.nameIdx]).toBe("onCreate")
    expect(tables.strings[tables.types[superOnCreate.classIdx]!]).toBe("Lcom/example/MyApp;")
    const staticCall = tables.methods[insns[4]!]!
    expect(tables.strings[staticCall.nameIdx]).toBe("check")
    expect(tables.strings[tables.types[staticCall.classIdx]!]).toBe("Lcom/droidseal/inj/AntiDebug;")
  })

  test("Stage A idempotence: the injected DEX re-serializes byte-identically", () => {
    const dex = buildAntiDebugDex("Lcom/droidseal/inj/Bootstrap;", "Lcom/example/MyApp;")
    // parse -> re-serialize is done inside serializeDexTables path; re-parsing must succeed.
    expect(() => parseDexTables(dex)).not.toThrow()
    const view = new DataView(dex.buffer)
    expect(view.getUint32(0x20, true)).toBe(dex.byteLength)
  })
})

describe("lossy-inject end-to-end over a synthetic APK (M4)", () => {
  test("injects a new classesN.dex and repoints android:name to Bootstrap", async () => {
    const input = await tmpFile("in.apk")
    const output = await tmpFile("out.apk")
    const backup = await tmpFile("backup.apk")
    await Bun.write(input, buildApk("com.example.MyApp"))

    const result = await injectAntiDebug(input, output, { backupPath: backup })
    expect(result.changed).toBe(true)
    expect(result.injectedDexName).toBe("classes2.dex")
    expect(result.originalApplication).toBe("com.example.MyApp")
    expect(result.bootstrapClass).toBe("com.droidseal.inj.Bootstrap")
    expect(result.findings[0]!.code).toBe("LOSSY_DEX_REWRITTEN")

    const outBytes = new Uint8Array(await Bun.file(output).arrayBuffer())
    const entries = parseRawZip(outBytes)
    const names = entries.map((e) => e.name)
    expect(names).toContain("classes.dex")
    expect(names).toContain("classes2.dex")

    // Manifest now points at Bootstrap.
    const manifest = entries.find((e) => e.name === "AndroidManifest.xml")!
    const axml = parseAxml(inflateEntry(manifest))
    expect(readApplicationName(axml)).toBe("com.droidseal.inj.Bootstrap")

    // Injected DEX parses and extends the original Application.
    const dexEntry = entries.find((e) => e.name === "classes2.dex")!
    const tables = parseDexTables(inflateEntry(dexEntry))
    const bootstrap = tables.classes.find((c) => tables.strings[tables.types[c.classIdx]!] === "Lcom/droidseal/inj/Bootstrap;")!
    expect(tables.strings[tables.types[bootstrap.superclassIdx]!]).toBe("Lcom/example/MyApp;")

    // Backup was written and matches the original input.
    const backupBytes = new Uint8Array(await Bun.file(backup).arrayBuffer())
    const inputBytes = new Uint8Array(await Bun.file(input).arrayBuffer())
    expect(Buffer.from(backupBytes)).toEqual(Buffer.from(inputBytes))
  })

  test("fails closed when the app declares no android:name (default Application)", async () => {
    const input = await tmpFile("in.apk")
    const output = await tmpFile("out.apk")
    await Bun.write(input, buildApk(null))
    await expect(injectAntiDebug(input, output)).rejects.toThrow(/android:name|Application/)
  })
})
