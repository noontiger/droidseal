import { describe, expect, test } from "bun:test"
import {
  adler32,
  decodeMutf8,
  encodeMutf8,
  readSleb128,
  readUleb128,
  readUleb128p1,
  writeSleb128,
  writeUleb128,
  writeUleb128p1,
} from "../src/core/dex-codec.ts"

describe("dex-codec ULEB128", () => {
  const cases = [0, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0x1fffff, 624485, 0xffffffff]
  test("write then read round-trips unsigned values", () => {
    for (const value of cases) {
      const bytes = Uint8Array.from(writeUleb128(value))
      const { value: got, next } = readUleb128(bytes, 0)
      expect(got).toBe(value >>> 0)
      expect(next).toBe(bytes.byteLength)
    }
  })
  test("matches the canonical 624485 -> E5 8E 26 encoding", () => {
    expect(writeUleb128(624485)).toEqual([0xe5, 0x8e, 0x26])
  })
})

describe("dex-codec ULEB128p1", () => {
  test("round-trips including the -1 sentinel", () => {
    for (const value of [-1, 0, 1, 100, 0x7fff]) {
      const bytes = Uint8Array.from(writeUleb128p1(value))
      expect(readUleb128p1(bytes, 0).value).toBe(value)
    }
    // -1 encodes as ULEB128 of 0 -> a single zero byte.
    expect(writeUleb128p1(-1)).toEqual([0x00])
  })
})

describe("dex-codec SLEB128", () => {
  const cases = [0, 1, -1, 63, 64, -64, -65, 127, -128, 8191, -8192, 0x3fffff, -0x400000, 2147483647, -2147483648]
  test("write then read round-trips signed values", () => {
    for (const value of cases) {
      const bytes = Uint8Array.from(writeSleb128(value))
      const { value: got, next } = readSleb128(bytes, 0)
      expect(got).toBe(value)
      expect(next).toBe(bytes.byteLength)
    }
  })
  test("matches canonical -2 -> 0x7e and 2 -> 0x02", () => {
    expect(writeSleb128(-2)).toEqual([0x7e])
    expect(writeSleb128(2)).toEqual([0x02])
  })
})

describe("dex-codec MUTF-8", () => {
  test("U+0000 encodes as C0 80 and round-trips", () => {
    const enc = encodeMutf8("\u0000")
    expect([...enc]).toEqual([0xc0, 0x80])
    expect(decodeMutf8(enc)).toBe("\u0000")
  })
  test("ASCII, 2-byte and 3-byte code points round-trip", () => {
    for (const s of ["hello", "café", "日本語", "Lcom/x/Y;", "a\u0000b"]) {
      expect(decodeMutf8(encodeMutf8(s))).toBe(s)
    }
  })
  test("supplementary plane encodes as 6 bytes (surrogate pair) and round-trips", () => {
    const emoji = "\uD83D\uDE00" // U+1F600, two surrogate halves
    const enc = encodeMutf8(emoji)
    expect(enc.byteLength).toBe(6)
    expect(decodeMutf8(enc)).toBe(emoji)
  })
})

describe("dex-codec Adler-32", () => {
  test("known vectors", () => {
    expect(adler32(new Uint8Array(0))).toBe(1)
    expect(adler32(new TextEncoder().encode("Wikipedia"))).toBe(0x11e60398)
    expect(adler32(new Uint8Array([0x00]))).toBe(0x00010001)
  })
  test("blocks large inputs without overflow", () => {
    const big = new Uint8Array(70000).fill(0xff)
    const value = adler32(big)
    expect(value).toBeGreaterThan(0)
    expect(Number.isInteger(value)).toBe(true)
  })
})
