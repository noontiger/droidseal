import { describe, expect, test } from "bun:test"
import { adler32, writeUleb128 } from "../src/core/dex-codec.ts"
import { MAP_TYPE_HEADER, parseDex, recomputeDexChecksums, serializeDex } from "../src/core/dex-model.ts"

// Build a minimal but structurally valid DEX: header + string_ids + string_data
// + map_list (HEADER, STRING_ID, STRING_DATA, MAP_LIST), with correct checksums.
function buildDex(strings: string[]): Uint8Array {
  const enc = new TextEncoder()
  const headerSize = 0x70
  const idsOff = headerSize
  const n = strings.length
  const dataStart = idsOff + n * 4
  const dataChunks: number[] = []
  const offsets: number[] = []
  let cursor = dataStart
  for (const s of strings) {
    offsets.push(cursor)
    const item = [...writeUleb128(s.length), ...enc.encode(s), 0x00]
    dataChunks.push(...item)
    cursor += item.length
  }
  while (cursor % 4 !== 0) {
    dataChunks.push(0x00)
    cursor += 1
  }
  const mapOff = cursor
  const mapItems: Array<[number, number, number]> = [
    [0x0000, 1, 0], // HEADER
    [0x0001, n, idsOff], // STRING_ID
    [0x2002, n, dataStart], // STRING_DATA
    [0x1000, 1, mapOff], // MAP_LIST
  ]
  const total = mapOff + 4 + mapItems.length * 12

  const bytes = new Uint8Array(total)
  const view = new DataView(bytes.buffer)
  bytes.set([0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00], 0) // "dex\n035\0"
  view.setUint32(0x20, total, true) // file_size
  view.setUint32(0x24, headerSize, true)
  view.setUint32(0x28, 0x12345678, true) // endian_tag
  view.setUint32(0x34, mapOff, true)
  view.setUint32(0x38, n, true) // string_ids_size
  view.setUint32(0x3c, idsOff, true) // string_ids_off
  for (let i = 0; i < n; i += 1) view.setUint32(idsOff + i * 4, offsets[i]!, true)
  bytes.set(Uint8Array.from(dataChunks), dataStart)
  view.setUint32(mapOff, mapItems.length, true)
  let mc = mapOff + 4
  for (const [type, size, off] of mapItems) {
    view.setUint16(mc, type, true)
    view.setUint32(mc + 4, size, true)
    view.setUint32(mc + 8, off, true)
    mc += 12
  }
  return recomputeDexChecksums(bytes)
}

describe("dex-model M0 parse", () => {
  test("parses header, string pool and map_list", () => {
    const dex = buildDex(["hello", "Lcom/x/Y;", "café"])
    const model = parseDex(dex)
    expect(model.header.version).toBe("035")
    expect(model.header.stringIdsSize).toBe(3)
    expect(model.strings).toEqual(["hello", "Lcom/x/Y;", "café"])
    expect(model.mapItems[0]!.type).toBe(MAP_TYPE_HEADER)
    expect(model.mapItems).toHaveLength(4)
  })

  test("rejects non-dex, bad endian and file-size mismatch", () => {
    expect(() => parseDex(new Uint8Array(0x70))).toThrow() // bad magic (all zero)

    const badEndian = buildDex(["a"])
    new DataView(badEndian.buffer).setUint32(0x28, 0xdeadbeef, true)
    expect(() => parseDex(badEndian)).toThrow()

    const badSize = buildDex(["a"])
    new DataView(badSize.buffer).setUint32(0x20, badSize.byteLength + 4, true)
    expect(() => parseDex(badSize)).toThrow()
  })
})

describe("dex-model M0 serialize (Stage A idempotence)", () => {
  test("parse -> serialize reproduces an unmodified DEX byte-for-byte", () => {
    const dex = buildDex(["alpha", "beta", "gamma", "Lorg/z/W;"])
    const model = parseDex(dex)
    expect(serializeDex(model)).toEqual(dex)
  })

  test("refuses to serialize a mutated model (mutation is M1+)", () => {
    const model = parseDex(buildDex(["x"]))
    model.dirty = true
    expect(() => serializeDex(model)).toThrow()
  })
})

describe("dex-model M0 checksum recompute", () => {
  test("writes an Adler-32 checksum consistent with the file body", () => {
    const dex = buildDex(["one", "two"])
    const view = new DataView(dex.buffer)
    expect(view.getUint32(0x08, true)).toBe(adler32(dex.subarray(0x0c)))
  })

  test("is idempotent on an already-correct DEX", () => {
    const dex = buildDex(["stable"])
    expect(recomputeDexChecksums(dex)).toEqual(dex)
  })

  test("recovers correct checksum after a body byte is corrupted", () => {
    const dex = buildDex(["corrupt", "me"])
    const broken = dex.slice()
    broken[broken.byteLength - 1] = (broken[broken.byteLength - 1]! ^ 0xff) & 0xff
    const fixed = recomputeDexChecksums(broken)
    const view = new DataView(fixed.buffer)
    expect(view.getUint32(0x08, true)).toBe(adler32(fixed.subarray(0x0c)))
    // Corrupting the body changes the checksum away from the original.
    expect(view.getUint32(0x08, true)).not.toBe(new DataView(dex.buffer).getUint32(0x08, true))
  })
})
