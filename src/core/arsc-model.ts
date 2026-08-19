import { DroidSealError } from "./errors.ts"

// resources.arsc binary format. All little-endian. Every chunk begins with a
// ResChunk_header { type: u16, headerSize: u16, size: u32 }.
export const RES_STRING_POOL_TYPE = 0x0001
export const RES_TABLE_TYPE = 0x0002
export const RES_TABLE_PACKAGE_TYPE = 0x0200

// ResStringPool_header flags.
const SORTED_FLAG = 0x0001
const UTF8_FLAG = 0x0100

function arscError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["确认传入的是 resources.arsc", "从可信构建产物重新导出 APK"],
    stepId: "harden",
  })
}

function align4(value: number): number {
  return (value + 3) & ~3
}

// A parsed ResStringPool. Strings are decoded to JS strings; style spans and the
// raw style-data block are preserved verbatim so a rebuild stays byte-faithful.
export interface ArscStringPool {
  isUtf8: boolean
  sorted: boolean
  strings: string[]
  styleCount: number
  // Raw style-data region (between stylesStart and end of chunk), preserved as-is.
  styleData: Uint8Array
  // Style offset array (styleCount u32 values, relative to stylesStart), preserved.
  styleOffsets: Uint32Array
  // Original chunk bytes; returned unchanged by serialize() unless `dirty` is set.
  raw: Uint8Array
  dirty: boolean
}

export interface ArscPackage {
  id: number
  // Full package header bytes (headerSize long), patched on serialize.
  headerBytes: Uint8Array
  headerSize: number
  // Bytes between header end and type string pool (normally empty).
  gapBeforeTypePool: Uint8Array
  typeStrings: ArscStringPool
  // Bytes between type pool and key pool (normally empty).
  gapBeforeKeyPool: Uint8Array
  keyStrings: ArscStringPool
  // Everything after the key string pool: typeSpec/type chunks, preserved raw.
  body: Uint8Array
}

export interface ArscTable {
  headerBytes: Uint8Array // ResTable_header (headerSize long)
  headerSize: number
  gapBeforeGlobalPool: Uint8Array
  globalStrings: ArscStringPool
  packages: ArscPackage[]
  trailing: Uint8Array // any bytes after the last package (normally empty)
}

function readChunkHeader(view: DataView, offset: number): { type: number; headerSize: number; size: number } {
  const type = view.getUint16(offset, true)
  const headerSize = view.getUint16(offset + 2, true)
  const size = view.getUint32(offset + 4, true)
  return { type, headerSize, size }
}

// -- String pool -----------------------------------------------------------

function decodeStringPool(bytes: Uint8Array, start: number): { pool: ArscStringPool; size: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const { type, size } = readChunkHeader(view, start)
  if (type !== RES_STRING_POOL_TYPE) {
    throw arscError("ARSC_EXPECTED_STRING_POOL", "期望字符串池 chunk", `在偏移 ${start} 处 type=0x${type.toString(16)}`)
  }
  const stringCount = view.getUint32(start + 8, true)
  const styleCount = view.getUint32(start + 12, true)
  const flags = view.getUint32(start + 16, true)
  const stringsStart = view.getUint32(start + 20, true)
  const stylesStart = view.getUint32(start + 24, true)
  const isUtf8 = (flags & UTF8_FLAG) !== 0
  const sorted = (flags & SORTED_FLAG) !== 0

  const offsetsBase = start + 28
  const strings: string[] = []
  for (let i = 0; i < stringCount; i += 1) {
    const strOff = view.getUint32(offsetsBase + i * 4, true)
    strings.push(decodeString(bytes, start + stringsStart + strOff, isUtf8))
  }

  const styleOffsets = new Uint32Array(styleCount)
  for (let i = 0; i < styleCount; i += 1) {
    styleOffsets[i] = view.getUint32(offsetsBase + stringCount * 4 + i * 4, true)
  }
  const styleData =
    styleCount > 0 && stylesStart > 0
      ? bytes.subarray(start + stylesStart, start + size)
      : new Uint8Array(0)

  const raw = bytes.subarray(start, start + size)
  return { pool: { isUtf8, sorted, strings, styleCount, styleData, styleOffsets, raw, dirty: false }, size }
}

function decodeString(bytes: Uint8Array, at: number, isUtf8: boolean): string {
  if (isUtf8) {
    let cursor = at
    // First length = number of UTF-16 code units (unused here), then byte length.
    cursor += lenPrefixSize(bytes, cursor)
    const [byteLen, adv] = readUtf8Len(bytes, cursor)
    cursor += adv
    const slice = bytes.subarray(cursor, cursor + byteLen)
    return decodeMutf8(slice)
  }
  let cursor = at
  const [u16Len, adv] = readUtf16Len(bytes, cursor)
  cursor += adv
  let out = ""
  for (let i = 0; i < u16Len; i += 1) {
    out += String.fromCharCode(bytes[cursor + i * 2]! | (bytes[cursor + i * 2 + 1]! << 8))
  }
  return out
}

// UTF-8 pool: the char-count prefix (1 or 2 bytes). Returns its byte size.
function lenPrefixSize(bytes: Uint8Array, at: number): number {
  return (bytes[at]! & 0x80) !== 0 ? 2 : 1
}

function readUtf8Len(bytes: Uint8Array, at: number): [number, number] {
  const first = bytes[at]!
  if ((first & 0x80) !== 0) return [((first & 0x7f) << 8) | bytes[at + 1]!, 2]
  return [first, 1]
}

function readUtf16Len(bytes: Uint8Array, at: number): [number, number] {
  const first = bytes[at]! | (bytes[at + 1]! << 8)
  if ((first & 0x8000) !== 0) {
    const second = bytes[at + 2]! | (bytes[at + 3]! << 8)
    return [((first & 0x7fff) << 16) | second, 4]
  }
  return [first, 2]
}

// Modified UTF-8 decode (0xC0 0x80 -> U+0000; 6-byte surrogate pairs -> supplementary).
function decodeMutf8(bytes: Uint8Array): string {
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
      // Fallback: treat as raw byte to avoid throwing on unexpected data.
      out += String.fromCharCode(b)
      i += 1
    }
  }
  return out
}

function encodeMutf8(text: string): Uint8Array {
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

function utf16Units(text: string): number {
  return text.length
}

function writeUtf8Len(value: number, out: number[]): void {
  if (value > 0x7f) out.push(0x80 | (value >> 8), value & 0xff)
  else out.push(value)
}

function writeUtf16Len(value: number, out: number[]): void {
  if (value > 0x7fff) {
    out.push(((value >> 16) & 0x7f) | 0x80, (value >> 24) & 0xff, value & 0xff, (value >> 8) & 0xff)
  } else {
    out.push(value & 0xff, (value >> 8) & 0xff)
  }
}

// Rebuild string-pool bytes from the model (used only when the pool is mutated).
function buildStringPool(pool: ArscStringPool): Uint8Array {
  const stringCount = pool.strings.length
  const styleCount = pool.styleCount
  const flags = (pool.isUtf8 ? UTF8_FLAG : 0) | (pool.sorted ? SORTED_FLAG : 0)

  const stringData: number[] = []
  const offsets: number[] = []
  for (const s of pool.strings) {
    offsets.push(stringData.length)
    if (pool.isUtf8) {
      const enc = encodeMutf8(s)
      writeUtf8Len(utf16Units(s), stringData)
      writeUtf8Len(enc.byteLength, stringData)
      for (const byte of enc) stringData.push(byte)
      stringData.push(0x00)
    } else {
      writeUtf16Len(utf16Units(s), stringData)
      for (let i = 0; i < s.length; i += 1) {
        const c = s.charCodeAt(i)
        stringData.push(c & 0xff, (c >> 8) & 0xff)
      }
      stringData.push(0x00, 0x00)
    }
  }
  while (stringData.length % 4 !== 0) stringData.push(0x00)

  const headerSize = 28
  const offsetsSize = (stringCount + styleCount) * 4
  const stringsStart = headerSize + offsetsSize
  const hasStyles = styleCount > 0 && pool.styleData.byteLength > 0
  const stylesStart = hasStyles ? stringsStart + stringData.length : 0
  const styleLen = hasStyles ? pool.styleData.byteLength : 0
  const size = stringsStart + stringData.length + styleLen

  const bytes = new Uint8Array(size)
  const view = new DataView(bytes.buffer)
  view.setUint16(0, RES_STRING_POOL_TYPE, true)
  view.setUint16(2, headerSize, true)
  view.setUint32(4, size, true)
  view.setUint32(8, stringCount, true)
  view.setUint32(12, styleCount, true)
  view.setUint32(16, flags, true)
  view.setUint32(20, stringsStart, true)
  view.setUint32(24, stylesStart, true)
  for (let i = 0; i < stringCount; i += 1) view.setUint32(headerSize + i * 4, offsets[i]!, true)
  for (let i = 0; i < styleCount; i += 1) {
    view.setUint32(headerSize + stringCount * 4 + i * 4, pool.styleOffsets[i]!, true)
  }
  bytes.set(Uint8Array.from(stringData), stringsStart)
  if (hasStyles) bytes.set(pool.styleData, stylesStart)
  return bytes
}

function serializeStringPool(pool: ArscStringPool): Uint8Array {
  return pool.dirty ? buildStringPool(pool) : pool.raw
}

// -- Package ---------------------------------------------------------------

function decodePackage(bytes: Uint8Array, start: number): { pkg: ArscPackage; size: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const { type, headerSize, size } = readChunkHeader(view, start)
  if (type !== RES_TABLE_PACKAGE_TYPE) {
    throw arscError("ARSC_EXPECTED_PACKAGE", "期望 package chunk", `在偏移 ${start} 处 type=0x${type.toString(16)}`)
  }
  const id = view.getUint32(start + 8, true)
  const typeStringsOff = view.getUint32(start + 268, true)
  const keyStringsOff = view.getUint32(start + 276, true)

  const headerBytes = bytes.subarray(start, start + headerSize).slice()
  const gapBeforeTypePool = bytes.subarray(start + headerSize, start + typeStringsOff).slice()

  const { pool: typeStrings, size: typeSize } = decodeStringPool(bytes, start + typeStringsOff)
  const typePoolEnd = start + typeStringsOff + typeSize
  const gapBeforeKeyPool = bytes.subarray(typePoolEnd, start + keyStringsOff).slice()

  const { pool: keyStrings, size: keySize } = decodeStringPool(bytes, start + keyStringsOff)
  const keyPoolEnd = start + keyStringsOff + keySize
  const body = bytes.subarray(keyPoolEnd, start + size).slice()

  return {
    pkg: { id, headerBytes, headerSize, gapBeforeTypePool, typeStrings, gapBeforeKeyPool, keyStrings, body },
    size,
  }
}

function serializePackage(pkg: ArscPackage): Uint8Array {
  const typePool = serializeStringPool(pkg.typeStrings)
  const keyPool = serializeStringPool(pkg.keyStrings)

  const typeStringsOff = pkg.headerSize + pkg.gapBeforeTypePool.byteLength
  const keyStringsOff = typeStringsOff + typePool.byteLength + pkg.gapBeforeKeyPool.byteLength
  const size =
    pkg.headerSize +
    pkg.gapBeforeTypePool.byteLength +
    typePool.byteLength +
    pkg.gapBeforeKeyPool.byteLength +
    keyPool.byteLength +
    pkg.body.byteLength

  const header = pkg.headerBytes.slice()
  const hv = new DataView(header.buffer, header.byteOffset, header.byteLength)
  hv.setUint32(4, size, true)
  hv.setUint32(268, typeStringsOff, true)
  hv.setUint32(276, keyStringsOff, true)

  const out = new Uint8Array(size)
  let pos = 0
  out.set(header, pos)
  pos += header.byteLength
  out.set(pkg.gapBeforeTypePool, pos)
  pos += pkg.gapBeforeTypePool.byteLength
  out.set(typePool, pos)
  pos += typePool.byteLength
  out.set(pkg.gapBeforeKeyPool, pos)
  pos += pkg.gapBeforeKeyPool.byteLength
  out.set(keyPool, pos)
  pos += keyPool.byteLength
  out.set(pkg.body, pos)
  return out
}

// -- Table -----------------------------------------------------------------

export function parseArsc(bytes: Uint8Array): ArscTable {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (bytes.byteLength < 12) {
    throw arscError("ARSC_TOO_SMALL", "resources.arsc 太小", "至少需要 ResTable_header。")
  }
  const { type, headerSize, size } = readChunkHeader(view, 0)
  if (type !== RES_TABLE_TYPE) {
    throw arscError("ARSC_BAD_MAGIC", "不是有效的 resources.arsc", `顶层 type=0x${type.toString(16)}，应为 0x0002。`)
  }
  const packageCount = view.getUint32(8, true)
  const headerBytes = bytes.subarray(0, headerSize).slice()

  let cursor = headerSize
  // Global string pool is the first chunk after the table header.
  const poolChunk = readChunkHeader(view, cursor)
  if (poolChunk.type !== RES_STRING_POOL_TYPE) {
    throw arscError("ARSC_NO_GLOBAL_POOL", "缺少全局字符串池", "ResTable_header 后应紧跟字符串池。")
  }
  const gapBeforeGlobalPool = bytes.subarray(headerSize, cursor).slice()
  const { pool: globalStrings, size: poolSize } = decodeStringPool(bytes, cursor)
  cursor += poolSize

  const packages: ArscPackage[] = []
  for (let i = 0; i < packageCount; i += 1) {
    const { pkg, size: pkgSize } = decodePackage(bytes, cursor)
    packages.push(pkg)
    cursor += pkgSize
  }
  const trailing = bytes.subarray(cursor, size).slice()

  return { headerBytes, headerSize, gapBeforeGlobalPool, globalStrings, packages, trailing }
}

export function serializeArsc(table: ArscTable): Uint8Array {
  const globalPool = serializeStringPool(table.globalStrings)
  const packageBlobs = table.packages.map(serializePackage)

  let size = table.headerSize + table.gapBeforeGlobalPool.byteLength + globalPool.byteLength
  for (const blob of packageBlobs) size += blob.byteLength
  size += table.trailing.byteLength

  const header = table.headerBytes.slice()
  const hv = new DataView(header.buffer, header.byteOffset, header.byteLength)
  hv.setUint32(4, size, true)
  hv.setUint32(8, table.packages.length, true)

  const out = new Uint8Array(size)
  let pos = 0
  out.set(header, pos)
  pos += header.byteLength
  out.set(table.gapBeforeGlobalPool, pos)
  pos += table.gapBeforeGlobalPool.byteLength
  out.set(globalPool, pos)
  pos += globalPool.byteLength
  for (const blob of packageBlobs) {
    out.set(blob, pos)
    pos += blob.byteLength
  }
  out.set(table.trailing, pos)
  return out
}

// Resolve a compiled resource ID (0xpptteeee) to the file path stored in the
// table's global string pool. XML-valued entries are ordinary simple Res_value
// records, so this remains a small, read-only complement to the lossless ARSC
// model rather than a second table parser.
export function resolveArscFilePath(bytes: Uint8Array, resourceId: number): string | undefined {
  try {
    const table = parseArsc(bytes)
    const packageId = (resourceId >>> 24) & 0xff
    const requestedTypeId = (resourceId >>> 16) & 0xff
    const entryIndex = resourceId & 0xffff
    const pkg = table.packages.find((candidate) => candidate.id === packageId)
    if (!pkg) return undefined

    const typeIdOffset = pkg.headerSize >= 288
      ? new DataView(pkg.headerBytes.buffer, pkg.headerBytes.byteOffset, pkg.headerBytes.byteLength)
        .getUint32(284, true)
      : 0
    const body = pkg.body
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength)
    let cursor = 0
    while (cursor + 8 <= body.byteLength) {
      const chunkType = view.getUint16(cursor, true)
      const headerSize = view.getUint16(cursor + 2, true)
      const chunkSize = view.getUint32(cursor + 4, true)
      if (chunkSize < 8 || cursor + chunkSize > body.byteLength) {
        cursor += 4
        continue
      }
      if (chunkType !== 0x0201) {
        cursor += chunkSize
        continue
      }

      const typeId = view.getUint8(cursor + 8) + typeIdOffset
      const entryCount = view.getUint32(cursor + 12, true)
      const entriesStart = view.getUint32(cursor + 16, true)
      if (typeId !== requestedTypeId || entryIndex >= entryCount) {
        cursor += chunkSize
        continue
      }
      const offsetPos = cursor + headerSize + entryIndex * 4
      if (offsetPos + 4 > cursor + chunkSize) return undefined
      const entryOffset = view.getUint32(offsetPos, true)
      if (entryOffset === 0xffffffff) return undefined
      const entryPos = cursor + entriesStart + entryOffset
      if (entryPos + 8 > cursor + chunkSize) return undefined
      const entrySize = view.getUint16(entryPos, true)
      const flags = view.getUint16(entryPos + 2, true)
      if ((flags & 0x0001) !== 0) return undefined
      const valuePos = entryPos + entrySize
      if (valuePos + 8 > cursor + chunkSize) return undefined
      const dataType = view.getUint8(valuePos + 3)
      if (dataType !== 0x03) return undefined
      return table.globalStrings.strings[view.getUint32(valuePos + 4, true)]
    }
    return undefined
  } catch {
    return undefined
  }
}

// Mark a string pool as mutated so serialize() rebuilds it from `strings`.
export function markPoolDirty(pool: ArscStringPool): void {
  pool.dirty = true
}

export { align4 }
