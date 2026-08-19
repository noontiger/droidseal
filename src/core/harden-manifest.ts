import { deflateRawSync, inflateRawSync } from "node:zlib"
import { DroidSealError } from "./errors.ts"

// Android binary AndroidManifest.xml (AXML) attribute resource id for android:debuggable.
const DEBUGGABLE_RES_ID = 0x0101000f
// Compact resource types used in AXML typed values.
const TYPE_INT_BOOLEAN = 0x12
const BOOL_TRUE = 0xffffffff
const BOOL_FALSE = 0x00000000

// AXML chunk types.
const CHUNK_XML = 0x0003
const CHUNK_STRING_POOL = 0x0001
const CHUNK_RESOURCE_MAP = 0x0180
const CHUNK_START_TAG = 0x0102

// ZIP signatures.
const EOCD_SIGNATURE = 0x06054b50
const CENTRAL_SIGNATURE = 0x02014b50
const LOCAL_SIGNATURE = 0x04034b50
const MAX_EOCD_SEARCH = 65_557
const MANIFEST_NAME = "AndroidManifest.xml"

export interface RawZipEntry {
  name: string
  method: number
  compressedSize: number
  uncompressedSize: number
  crc32: number
  localHeaderOffset: number
  flags: number
  data: Uint8Array
}

function zipError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["用 zipalign -c 验证 APK", "从可信构建产物重新导出 APK"],
    stepId: "harden",
  })
}

async function readWholeFile(apkPath: string): Promise<Uint8Array> {
  return new Uint8Array(await Bun.file(apkPath).arrayBuffer())
}

function findEocd(view: DataView, size: number): number {
  const searchStart = Math.max(0, size - MAX_EOCD_SEARCH)
  for (let offset = size - 22; offset >= searchStart; offset -= 1) {
    if (view.getUint32(offset, true) === EOCD_SIGNATURE) return offset
  }
  return -1
}

export function parseRawZip(bytes: Uint8Array): RawZipEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const size = bytes.byteLength
  if (size < 22) {
    throw zipError("APK_TOO_SMALL", "文件太小，不可能是有效 APK", "ZIP 结束记录至少需要 22 字节。")
  }
  const eocd = findEocd(view, size)
  if (eocd < 0) {
    throw zipError("ZIP_EOCD_MISSING", "APK 缺少 ZIP 中央目录结束记录", "文件可能损坏或不是 APK。")
  }
  const entryCount = view.getUint16(eocd + 10, true)
  const centralOffset = view.getUint32(eocd + 16, true)
  if (entryCount === 0xffff || centralOffset === 0xffffffff) {
    throw zipError("ZIP64_UNSUPPORTED", "暂不支持 ZIP64 格式的 APK", "常规 APK 不应需要 ZIP64。")
  }

  const decoder = new TextDecoder("utf-8", { fatal: false })
  const entries: RawZipEntry[] = []
  let cursor = centralOffset
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > size || view.getUint32(cursor, true) !== CENTRAL_SIGNATURE) {
      throw zipError("ZIP_ENTRY_INVALID", `APK 中央目录第 ${index + 1} 项无效`, "ZIP 条目结构不完整或签名不匹配。")
    }
    const flags = view.getUint16(cursor + 8, true)
    const method = view.getUint16(cursor + 10, true)
    const crc32 = view.getUint32(cursor + 16, true)
    const compressedSize = view.getUint32(cursor + 20, true)
    const uncompressedSize = view.getUint32(cursor + 24, true)
    const nameLength = view.getUint16(cursor + 28, true)
    const extraLength = view.getUint16(cursor + 30, true)
    const commentLength = view.getUint16(cursor + 32, true)
    const localHeaderOffset = view.getUint32(cursor + 42, true)
    const nameStart = cursor + 46
    const name = decoder.decode(bytes.subarray(nameStart, nameStart + nameLength))

    if (localHeaderOffset + 30 > size || view.getUint32(localHeaderOffset, true) !== LOCAL_SIGNATURE) {
      throw zipError("ZIP_LOCAL_HEADER_INVALID", `条目 ${name} 的本地头无效`, "本地文件头签名不匹配。")
    }
    const localNameLength = view.getUint16(localHeaderOffset + 26, true)
    const localExtraLength = view.getUint16(localHeaderOffset + 28, true)
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength
    if (dataStart + compressedSize > size) {
      throw zipError("ZIP_ENTRY_TRUNCATED", `条目 ${name} 的数据超出文件边界`, "压缩数据范围无效。")
    }
    const data = bytes.subarray(dataStart, dataStart + compressedSize)

    entries.push({ name, method, compressedSize, uncompressedSize, crc32, localHeaderOffset, flags, data })
    cursor = nameStart + nameLength + extraLength + commentLength
  }
  return entries
}

export function inflateEntry(entry: RawZipEntry): Uint8Array {
  if (entry.method === 0) return entry.data
  if (entry.method === 8) return new Uint8Array(inflateRawSync(entry.data))
  throw zipError(
    "ZIP_METHOD_UNSUPPORTED",
    `条目 ${entry.name} 使用了不支持的压缩方式 ${entry.method}`,
    "仅支持 stored(0) 与 deflate(8)。",
  )
}

// Locate the resource-map index whose value equals DEBUGGABLE_RES_ID, then flip any
// matching START_TAG boolean attribute from true to false in place. Length-preserving.
function flipDebuggableInAxml(axml: Uint8Array): boolean {
  const view = new DataView(axml.buffer, axml.byteOffset, axml.byteLength)
  if (axml.byteLength < 8 || view.getUint16(0, true) !== CHUNK_XML) {
    throw zipError("AXML_INVALID", "AndroidManifest.xml 不是有效的二进制 XML", "文件头 magic 不匹配。")
  }

  let debuggableAttrIndex = -1
  let cursor = 8 // skip XML chunk header (type + headerSize + fileSize)
  const end = axml.byteLength

  while (cursor + 8 <= end) {
    const type = view.getUint16(cursor, true)
    const chunkSize = view.getUint32(cursor + 4, true)
    if (chunkSize < 8 || cursor + chunkSize > end) break

    if (type === CHUNK_RESOURCE_MAP) {
      const count = (chunkSize - 8) / 4
      for (let i = 0; i < count; i += 1) {
        if (view.getUint32(cursor + 8 + i * 4, true) === DEBUGGABLE_RES_ID) {
          debuggableAttrIndex = i
          break
        }
      }
    } else if (type === CHUNK_START_TAG && debuggableAttrIndex >= 0) {
      // START_TAG: 8-byte chunk header, then ResXMLTree_node (lineNumber 4, comment 4),
      // then ResXMLTree_attrExt at cursor+16: ns(4) name(4) attributeStart(2) attributeSize(2)
      // attributeCount(2)... Attributes begin at cursor+16+attributeStart, each 20 bytes:
      // ns(4) name(4) rawValue(4) typedValue{ size(2) res0(1) dataType(1) data(4) }.
      const attrStart = view.getUint16(cursor + 24, true)
      const attrCount = view.getUint16(cursor + 28, true)
      const attrBase = cursor + 16 + attrStart
      for (let a = 0; a < attrCount; a += 1) {
        const attr = attrBase + a * 20
        if (attr + 20 > end) break
        const nameIndex = view.getUint32(attr + 4, true)
        if (nameIndex !== debuggableAttrIndex) continue
        const valueType = view.getUint8(attr + 15)
        const data = view.getUint32(attr + 16, true)
        if (valueType === TYPE_INT_BOOLEAN && data === BOOL_TRUE) {
          view.setUint32(attr + 16, BOOL_FALSE, true)
          return true
        }
      }
    }
    cursor += chunkSize
  }
  return false
}

export function crc32Of(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.byteLength; i += 1) {
    crc ^= bytes[i] as number
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1))
    }
  }
  return (crc ^ 0xffffffff) >>> 0
}

export interface OutEntry {
  name: string
  method: number
  crc32: number
  compressedSize: number
  uncompressedSize: number
  flags: number
  data: Uint8Array
}

export function buildZip(entries: OutEntry[]): Uint8Array {
  const encoder = new TextEncoder()
  const localParts: Uint8Array[] = []
  const centralParts: Uint8Array[] = []
  let offset = 0

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name)
    const local = new Uint8Array(30 + nameBytes.byteLength)
    const lv = new DataView(local.buffer)
    lv.setUint32(0, LOCAL_SIGNATURE, true)
    lv.setUint16(4, 20, true) // version needed
    lv.setUint16(6, entry.flags, true)
    lv.setUint16(8, entry.method, true)
    lv.setUint16(10, 0, true) // mod time
    lv.setUint16(12, 0, true) // mod date
    lv.setUint32(14, entry.crc32, true)
    lv.setUint32(18, entry.compressedSize, true)
    lv.setUint32(22, entry.uncompressedSize, true)
    lv.setUint16(26, nameBytes.byteLength, true)
    lv.setUint16(28, 0, true) // extra length
    local.set(nameBytes, 30)
    localParts.push(local, entry.data)

    const central = new Uint8Array(46 + nameBytes.byteLength)
    const cv = new DataView(central.buffer)
    cv.setUint32(0, CENTRAL_SIGNATURE, true)
    cv.setUint16(4, 20, true) // version made by
    cv.setUint16(6, 20, true) // version needed
    cv.setUint16(8, entry.flags, true)
    cv.setUint16(10, entry.method, true)
    cv.setUint16(12, 0, true)
    cv.setUint16(14, 0, true)
    cv.setUint32(16, entry.crc32, true)
    cv.setUint32(20, entry.compressedSize, true)
    cv.setUint32(24, entry.uncompressedSize, true)
    cv.setUint16(28, nameBytes.byteLength, true)
    cv.setUint16(30, 0, true) // extra
    cv.setUint16(32, 0, true) // comment
    cv.setUint16(34, 0, true) // disk number
    cv.setUint16(36, 0, true) // internal attrs
    cv.setUint32(38, 0, true) // external attrs
    cv.setUint32(42, offset, true) // local header offset
    central.set(nameBytes, 46)
    centralParts.push(central)

    offset += local.byteLength + entry.data.byteLength
  }

  const centralStart = offset
  let centralSize = 0
  for (const part of centralParts) centralSize += part.byteLength

  const eocd = new Uint8Array(22)
  const ev = new DataView(eocd.buffer)
  ev.setUint32(0, EOCD_SIGNATURE, true)
  ev.setUint16(4, 0, true)
  ev.setUint16(6, 0, true)
  ev.setUint16(8, entries.length, true)
  ev.setUint16(10, entries.length, true)
  ev.setUint32(12, centralSize, true)
  ev.setUint32(16, centralStart, true)
  ev.setUint16(20, 0, true)

  let total = centralStart + centralSize + eocd.byteLength
  const out = new Uint8Array(total)
  let pos = 0
  for (const part of localParts) {
    out.set(part, pos)
    pos += part.byteLength
  }
  for (const part of centralParts) {
    out.set(part, pos)
    pos += part.byteLength
  }
  out.set(eocd, pos)
  return out
}

// Read the plaintext bytes of AndroidManifest.xml from an APK (inflating if needed).
export async function readManifestXmlBytes(apkPath: string): Promise<Uint8Array> {
  const bytes = await readWholeFile(apkPath)
  const entries = parseRawZip(bytes)
  const manifest = entries.find((entry) => entry.name === MANIFEST_NAME)
  if (!manifest) {
    throw zipError("MANIFEST_MISSING", "APK 内缺少 AndroidManifest.xml", "该文件可能不是标准 APK。")
  }
  return inflateEntry(manifest)
}

// Return true if the binary manifest declares android:debuggable=true.
export function manifestBytesAreDebuggable(axml: Uint8Array): boolean {
  const view = new DataView(axml.buffer, axml.byteOffset, axml.byteLength)
  if (axml.byteLength < 8 || view.getUint16(0, true) !== CHUNK_XML) return false
  let debuggableAttrIndex = -1
  let cursor = 8
  const end = axml.byteLength
  while (cursor + 8 <= end) {
    const type = view.getUint16(cursor, true)
    const chunkSize = view.getUint32(cursor + 4, true)
    if (chunkSize < 8 || cursor + chunkSize > end) break
    if (type === CHUNK_RESOURCE_MAP) {
      const count = (chunkSize - 8) / 4
      for (let i = 0; i < count; i += 1) {
        if (view.getUint32(cursor + 8 + i * 4, true) === DEBUGGABLE_RES_ID) {
          debuggableAttrIndex = i
          break
        }
      }
    } else if (type === CHUNK_START_TAG && debuggableAttrIndex >= 0) {
      const attrStart = view.getUint16(cursor + 24, true)
      const attrCount = view.getUint16(cursor + 28, true)
      const attrBase = cursor + 16 + attrStart
      for (let a = 0; a < attrCount; a += 1) {
        const attr = attrBase + a * 20
        if (attr + 20 > end) break
        if (view.getUint32(attr + 4, true) !== debuggableAttrIndex) continue
        if (view.getUint8(attr + 15) === TYPE_INT_BOOLEAN && view.getUint32(attr + 16, true) === BOOL_TRUE) {
          return true
        }
      }
    }
    cursor += chunkSize
  }
  return false
}

// Flip android:debuggable from true to false in the APK's binary manifest and write a new APK.
// Returns { changed:false } when the attribute is absent or already false.
export async function flipDebuggableFalse(
  inputApk: string,
  outputApk: string,
): Promise<{ changed: boolean }> {
  const bytes = await readWholeFile(inputApk)
  const entries = parseRawZip(bytes)
  const manifest = entries.find((entry) => entry.name === MANIFEST_NAME)
  if (!manifest) {
    throw zipError("MANIFEST_MISSING", "APK 内缺少 AndroidManifest.xml", "该文件可能不是标准 APK。")
  }

  const axml = inflateEntry(manifest)
  const changed = flipDebuggableInAxml(axml)
  if (!changed) return { changed: false }

  const out: OutEntry[] = entries.map((entry) => {
    if (entry.name !== MANIFEST_NAME) {
      return {
        name: entry.name,
        method: entry.method,
        crc32: entry.crc32,
        compressedSize: entry.compressedSize,
        uncompressedSize: entry.uncompressedSize,
        flags: entry.flags,
        data: entry.data,
      }
    }
    if (entry.method === 8) {
      const deflated = new Uint8Array(deflateRawSync(axml, { level: 9 }))
      return {
        name: entry.name,
        method: 8,
        crc32: crc32Of(axml),
        compressedSize: deflated.byteLength,
        uncompressedSize: axml.byteLength,
        flags: entry.flags,
        data: deflated,
      }
    }
    return {
      name: entry.name,
      method: 0,
      crc32: crc32Of(axml),
      compressedSize: axml.byteLength,
      uncompressedSize: axml.byteLength,
      flags: entry.flags,
      data: axml,
    }
  })

  await Bun.write(outputApk, buildZip(out))
  return { changed: true }
}
