import { describe, expect, test } from "bun:test"
import {
  type AxmlModel,
  internAxmlString,
  parseAxml,
  readApplicationName,
  serializeAxml,
  setApplicationName,
} from "../src/core/axml-writer.ts"

const ANDROID_NAME_RES_ID = 0x01010003

// Build a synthetic binary AndroidManifest.xml: XML header + UTF-8 string pool +
// resource map + a minimal tree (manifest > application[android:name]).
function buildAxml(oldAppName: string): Uint8Array {
  const strings = [
    "name", // 0 -> attribute name (covered by resource map)
    "http://schemas.android.com/apk/res/android", // 1 -> namespace uri
    "android", // 2 -> namespace prefix
    "manifest", // 3
    "application", // 4
    oldAppName, // 5
  ]
  const resMap = [ANDROID_NAME_RES_ID] // one entry, for string index 0 ("name")

  // -- string pool (UTF-8) --
  const enc = new TextEncoder()
  const offsets: number[] = []
  const data: number[] = []
  for (const s of strings) {
    offsets.push(data.length)
    const utf8 = enc.encode(s)
    data.push(s.length, utf8.byteLength) // both < 0x80 here
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
  pv.setUint32(12, 0, true) // styleCount
  pv.setUint32(16, 0x0100, true) // UTF8_FLAG
  pv.setUint32(20, stringsStart, true)
  pv.setUint32(24, 0, true)
  for (let i = 0; i < offsets.length; i += 1) pv.setUint32(28 + i * 4, offsets[i]!, true)
  pool.set(Uint8Array.from(data), stringsStart)

  // -- resource map --
  const resMapSize = 8 + resMap.length * 4
  const rm = new Uint8Array(resMapSize)
  const rmv = new DataView(rm.buffer)
  rmv.setUint16(0, 0x0180, true)
  rmv.setUint16(2, 8, true)
  rmv.setUint32(4, resMapSize, true)
  for (let i = 0; i < resMap.length; i += 1) rmv.setUint32(8 + i * 4, resMap[i]!, true)

  // -- tree nodes --
  const nodes: Uint8Array[] = []
  const NO = 0xffffffff

  const startTag = (nameIdx: number, attrs: Array<{ ns: number; name: number; value: number }>): Uint8Array => {
    const size = 16 + 20 + attrs.length * 20
    const b = new Uint8Array(size)
    const v = new DataView(b.buffer)
    v.setUint16(0, 0x0102, true)
    v.setUint16(2, 16, true)
    v.setUint32(4, size, true)
    v.setUint32(8, 0, true) // lineNumber
    v.setUint32(12, NO, true) // comment
    v.setUint32(16, NO, true) // attrExt.ns
    v.setUint32(20, nameIdx, true) // attrExt.name
    v.setUint16(24, 20, true) // attributeStart
    v.setUint16(26, 20, true) // attributeSize
    v.setUint16(28, attrs.length, true) // attributeCount
    v.setUint16(30, 0, true) // idIndex
    v.setUint16(32, 0, true) // classIndex
    v.setUint16(34, 0, true) // styleIndex
    let a = 36
    for (const at of attrs) {
      v.setUint32(a, at.ns, true)
      v.setUint32(a + 4, at.name, true)
      v.setUint32(a + 8, at.value, true) // rawValue
      v.setUint16(a + 12, 8, true) // typedValue.size
      v.setUint8(a + 14, 0) // res0
      v.setUint8(a + 15, 0x03) // dataType = TYPE_STRING
      v.setUint32(a + 16, at.value, true) // data
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
    v.setUint32(16, NO, true) // ns
    v.setUint32(20, nameIdx, true) // name
    return b
  }

  nodes.push(startTag(3, [])) // <manifest>
  nodes.push(startTag(4, [{ ns: 1, name: 0, value: 5 }])) // <application android:name=strings[5]>
  nodes.push(endTag(4))
  nodes.push(endTag(3))

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

describe("axml-writer (M2)", () => {
  test("parses the string pool and reads android:name", () => {
    const model = parseAxml(buildAxml("com.example.OldApp"))
    expect(model.strings).toContain("application")
    expect(readApplicationName(model)).toBe("com.example.OldApp")
  })

  test("round-trips without mutation (pool rebuild is faithful)", () => {
    const original = buildAxml("com.example.OldApp")
    const model = parseAxml(original)
    const reparsed = parseAxml(serializeAxml(model))
    expect(reparsed.strings).toEqual(model.strings)
    expect(readApplicationName(reparsed)).toBe("com.example.OldApp")
  })

  test("repoints android:name to a longer injected class name (variable-length rebuild)", () => {
    const model = parseAxml(buildAxml("A")) // short original name
    setApplicationName(model, "com.droidseal.inj.BootstrapApplication")
    const out = serializeAxml(model)
    // XML chunk size field must equal the new total length.
    const view = new DataView(out.buffer)
    expect(view.getUint32(4, true)).toBe(out.byteLength)
    const reparsed = parseAxml(out)
    expect(readApplicationName(reparsed)).toBe("com.droidseal.inj.BootstrapApplication")
    // Existing indices are preserved; the new name was appended.
    expect(reparsed.strings.indexOf("application")).toBe(model.strings.indexOf("application"))
  })

  test("reuses an existing string index instead of duplicating", () => {
    const model = parseAxml(buildAxml("com.example.OldApp"))
    const before = model.strings.length
    const idx = internAxmlString(model, "application")
    expect(idx).toBe(model.strings.indexOf("application"))
    expect(model.strings.length).toBe(before)
  })

  test("fails closed when android:name is absent", () => {
    const model = parseAxml(buildAxml("com.example.OldApp"))
    // Remove the attribute by pointing the walker at a manifest with no app name:
    // simulate absence by searching a model whose application tag lacks the attr.
    const noAttr = parseAxml(buildNoAppName())
    expect(readApplicationName(noAttr)).toBeNull()
    expect(() => setApplicationName(noAttr, "com.droidseal.inj.App")).toThrow(/android:name/)
    void model
  })
})

// Variant with an <application> tag carrying zero attributes.
function buildNoAppName(): Uint8Array {
  const bytes = buildAxml("x")
  const model: AxmlModel = parseAxml(bytes)
  // Rebuild tail with the application tag's attributeCount forced to 0.
  const tail = model.tail.slice()
  const view = new DataView(tail.buffer)
  let cursor = 0
  const appIdx = model.strings.indexOf("application")
  while (cursor + 8 <= tail.byteLength) {
    const type = view.getUint16(cursor, true)
    const size = view.getUint32(cursor + 4, true)
    if (type === 0x0102 && view.getUint32(cursor + 20, true) === appIdx) {
      // Shrink node to drop its single attribute: size 16+20, attributeCount 0.
      const shrunk = tail.slice(0, cursor + 36)
      const rest = tail.slice(cursor + size)
      const merged = new Uint8Array(shrunk.byteLength + rest.byteLength)
      merged.set(shrunk, 0)
      merged.set(rest, shrunk.byteLength)
      const mv = new DataView(merged.buffer)
      mv.setUint32(cursor + 4, 36, true) // node size
      mv.setUint16(cursor + 28, 0, true) // attributeCount
      model.tail = merged
      break
    }
    cursor += size
  }
  return serializeAxml(model)
}
