// DEX write/read encoding primitives (pure TypeScript, no dependencies).
//
// The existing dex-scan.ts has a lenient read-only ULEB128 used for heuristic
// string-pool scanning. The write engine needs the full, exact codec: the LEB128
// family in both directions, a precise Modified UTF-8 (MUTF-8) codec, and Adler-32.

export interface LebRead {
  value: number
  next: number
}

// Unsigned LEB128. Up to 5 bytes (32-bit). Result is coerced to an unsigned u32.
export function writeUleb128(value: number): number[] {
  let remaining = value >>> 0
  const out: number[] = []
  do {
    let byte = remaining & 0x7f
    remaining >>>= 7
    if (remaining !== 0) byte |= 0x80
    out.push(byte)
  } while (remaining !== 0)
  return out
}

export function readUleb128(bytes: Uint8Array, at: number): LebRead {
  let result = 0
  let shift = 0
  let index = at
  while (true) {
    const byte = bytes[index]!
    index += 1
    result |= (byte & 0x7f) << shift
    if ((byte & 0x80) === 0) break
    shift += 7
    if (shift > 28) break
  }
  return { value: result >>> 0, next: index }
}

// ULEB128p1: encodes (value + 1) as ULEB128, allowing the sentinel value -1
// (encoded as 0). Used for optionally-absent indices (e.g. debug_info name_idx).
export function writeUleb128p1(value: number): number[] {
  return writeUleb128((value + 1) >>> 0)
}

export function readUleb128p1(bytes: Uint8Array, at: number): LebRead {
  const { value, next } = readUleb128(bytes, at)
  return { value: value - 1, next }
}

// Signed LEB128. Sign-extends the final byte.
export function writeSleb128(value: number): number[] {
  const out: number[] = []
  let remaining = value | 0
  while (true) {
    const byte = remaining & 0x7f
    const signBit = byte & 0x40
    remaining >>= 7 // arithmetic shift preserves sign
    const done = (remaining === 0 && signBit === 0) || (remaining === -1 && signBit !== 0)
    out.push(done ? byte : byte | 0x80)
    if (done) break
  }
  return out
}

export function readSleb128(bytes: Uint8Array, at: number): LebRead {
  let result = 0
  let shift = 0
  let index = at
  let byte = 0
  do {
    byte = bytes[index]!
    index += 1
    result |= (byte & 0x7f) << shift
    shift += 7
  } while ((byte & 0x80) !== 0 && shift < 35)
  // Sign-extend when the final continuation bit is clear and the sign bit is set.
  if (shift < 32 && (byte & 0x40) !== 0) result |= -(1 << shift)
  return { value: result | 0, next: index }
}

// -- Modified UTF-8 (MUTF-8) ------------------------------------------------
//
// Differences from standard UTF-8:
//  * U+0000 is encoded as the two bytes 0xC0 0x80 (never a bare 0x00, which is
//    the string terminator).
//  * Supplementary characters (U+10000+) are NOT 4-byte encoded; each UTF-16
//    surrogate half is encoded independently as 3 bytes (6 bytes total). Because
//    JS strings are already UTF-16, iterating char codes yields this for free.

export function encodeMutf8(text: string): Uint8Array {
  const out: number[] = []
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i)
    if (c === 0) {
      out.push(0xc0, 0x80)
    } else if (c < 0x80) {
      out.push(c)
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
    }
  }
  return Uint8Array.from(out)
}

export function decodeMutf8(bytes: Uint8Array): string {
  let out = ""
  let i = 0
  const n = bytes.byteLength
  while (i < n) {
    const b = bytes[i]!
    if (b < 0x80) {
      out += String.fromCharCode(b)
      i += 1
    } else if ((b & 0xe0) === 0xc0) {
      const c = ((b & 0x1f) << 6) | (bytes[i + 1]! & 0x3f)
      out += String.fromCharCode(c)
      i += 2
    } else if ((b & 0xf0) === 0xe0) {
      const c = ((b & 0x0f) << 12) | ((bytes[i + 1]! & 0x3f) << 6) | (bytes[i + 2]! & 0x3f)
      out += String.fromCharCode(c)
      i += 3
    } else {
      // Defensive: emit the raw byte rather than throwing on malformed input.
      out += String.fromCharCode(b)
      i += 1
    }
  }
  return out
}

// -- Adler-32 ---------------------------------------------------------------
//
// DEX header checksum. Modulo the largest prime < 65536; block the inner loop to
// keep the accumulators within safe-integer range before each modulo.
const ADLER_MOD = 65521
const ADLER_BLOCK = 5552

export function adler32(bytes: Uint8Array): number {
  let a = 1
  let b = 0
  let i = 0
  const n = bytes.byteLength
  while (i < n) {
    const end = Math.min(i + ADLER_BLOCK, n)
    for (; i < end; i += 1) {
      a += bytes[i]!
      b += a
    }
    a %= ADLER_MOD
    b %= ADLER_MOD
  }
  return (((b << 16) | a) >>> 0)
}
