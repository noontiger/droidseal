// DEX parse -> in-memory model -> serialize (M0, no mutation).
//
// M0 goal (see docs/dex-write-engine.md §6.5): a full structural parse of the
// header + map_list + string index into a model that round-trips byte-for-byte
// for an unmodified DEX (raw + dirty, mirroring arsc-model.ts), plus a correct
// checksum/signature recompute layer. The semantic re-sort layout planner needed
// for mutation (§6.2/§6.3) is deferred to M1, where it is first required.

import { adler32, decodeMutf8, readUleb128 } from "./dex-codec.ts"
import { DroidSealError } from "./errors.ts"

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a] // "dex\n"
const ENDIAN_TAG = 0x12345678
const HEADER_SIZE = 0x70

// map_item type codes (subset used for validation; see §3.4).
export const MAP_TYPE_HEADER = 0x0000
export const MAP_TYPE_STRING_ID = 0x0001
export const MAP_TYPE_TYPE_ID = 0x0002
export const MAP_TYPE_PROTO_ID = 0x0003
export const MAP_TYPE_FIELD_ID = 0x0004
export const MAP_TYPE_METHOD_ID = 0x0005
export const MAP_TYPE_CLASS_DEF = 0x0006
export const MAP_TYPE_MAP_LIST = 0x1000

export interface DexHeader {
  version: string
  checksum: number
  signature: Uint8Array
  fileSize: number
  headerSize: number
  endianTag: number
  linkSize: number
  linkOff: number
  mapOff: number
  stringIdsSize: number
  stringIdsOff: number
  typeIdsSize: number
  typeIdsOff: number
  protoIdsSize: number
  protoIdsOff: number
  fieldIdsSize: number
  fieldIdsOff: number
  methodIdsSize: number
  methodIdsOff: number
  classDefsSize: number
  classDefsOff: number
  dataSize: number
  dataOff: number
}

export interface DexMapItem {
  type: number
  size: number
  offset: number
}

export interface DexModel {
  header: DexHeader
  mapItems: DexMapItem[]
  // string_ids offsets (u32 each) and the decoded string values (exact MUTF-8).
  stringOffsets: Uint32Array
  strings: string[]
  // Original file bytes; serialize() returns these verbatim unless `dirty` is set.
  raw: Uint8Array
  dirty: boolean
}

function dexError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["确认传入的是 classes.dex", "从可信构建产物重新导出 DEX"],
    stepId: "harden",
  })
}

function readHeader(view: DataView, bytes: Uint8Array): DexHeader {
  const version = String.fromCharCode(bytes[4]!, bytes[5]!, bytes[6]!)
  return {
    version,
    checksum: view.getUint32(0x08, true),
    signature: bytes.subarray(0x0c, 0x20).slice(),
    fileSize: view.getUint32(0x20, true),
    headerSize: view.getUint32(0x24, true),
    endianTag: view.getUint32(0x28, true),
    linkSize: view.getUint32(0x2c, true),
    linkOff: view.getUint32(0x30, true),
    mapOff: view.getUint32(0x34, true),
    stringIdsSize: view.getUint32(0x38, true),
    stringIdsOff: view.getUint32(0x3c, true),
    typeIdsSize: view.getUint32(0x40, true),
    typeIdsOff: view.getUint32(0x44, true),
    protoIdsSize: view.getUint32(0x48, true),
    protoIdsOff: view.getUint32(0x4c, true),
    fieldIdsSize: view.getUint32(0x50, true),
    fieldIdsOff: view.getUint32(0x54, true),
    methodIdsSize: view.getUint32(0x58, true),
    methodIdsOff: view.getUint32(0x5c, true),
    classDefsSize: view.getUint32(0x60, true),
    classDefsOff: view.getUint32(0x64, true),
    dataSize: view.getUint32(0x68, true),
    dataOff: view.getUint32(0x6c, true),
  }
}

// Decode a string_data_item: ULEB128 utf16 length prefix, then MUTF-8 bytes up to
// (but not including) the 0x00 terminator.
function decodeStringDataItem(bytes: Uint8Array, at: number): string {
  const { next } = readUleb128(bytes, at)
  let end = next
  while (end < bytes.byteLength && bytes[end] !== 0x00) end += 1
  return decodeMutf8(bytes.subarray(next, end))
}

function readMapList(view: DataView, bytes: Uint8Array, mapOff: number): DexMapItem[] {
  if (mapOff + 4 > bytes.byteLength) {
    throw dexError("DEX_MAP_OUT_OF_RANGE", "map_list 偏移越界", `map_off=${mapOff} 超出文件大小。`)
  }
  const size = view.getUint32(mapOff, true)
  const items: DexMapItem[] = []
  let cursor = mapOff + 4
  for (let i = 0; i < size; i += 1) {
    if (cursor + 12 > bytes.byteLength) {
      throw dexError("DEX_MAP_TRUNCATED", "map_list 条目越界", `第 ${i + 1} 个 map_item 超出文件大小。`)
    }
    const type = view.getUint16(cursor, true)
    const itemSize = view.getUint32(cursor + 4, true)
    const offset = view.getUint32(cursor + 8, true)
    items.push({ type, size: itemSize, offset })
    cursor += 12
  }
  return items
}

function validateMapList(items: DexMapItem[], header: DexHeader): void {
  if (items.length === 0 || items[0]!.type !== MAP_TYPE_HEADER) {
    throw dexError("DEX_MAP_NO_HEADER", "map_list 首项不是 header", "ART 要求 HEADER_ITEM 位于 map_list 最前。")
  }
  let previousOffset = -1
  const seen = new Set<number>()
  for (const item of items) {
    if (item.offset < previousOffset) {
      throw dexError("DEX_MAP_UNORDERED", "map_list 未按 offset 升序", "各 section 偏移必须单调递增。")
    }
    previousOffset = item.offset
    if (seen.has(item.type)) {
      throw dexError("DEX_MAP_DUPLICATE", "map_list 存在重复 section", `type=0x${item.type.toString(16)} 出现多次。`)
    }
    seen.add(item.type)
  }
  // Cross-check the sizes the header also records.
  const bySize: Array<[number, number]> = [
    [MAP_TYPE_STRING_ID, header.stringIdsSize],
    [MAP_TYPE_TYPE_ID, header.typeIdsSize],
    [MAP_TYPE_PROTO_ID, header.protoIdsSize],
    [MAP_TYPE_FIELD_ID, header.fieldIdsSize],
    [MAP_TYPE_METHOD_ID, header.methodIdsSize],
    [MAP_TYPE_CLASS_DEF, header.classDefsSize],
  ]
  for (const [type, headerSize] of bySize) {
    const item = items.find((candidate) => candidate.type === type)
    const mapSize = item?.size ?? 0
    if (mapSize !== headerSize) {
      throw dexError(
        "DEX_MAP_SIZE_MISMATCH",
        "map_list 与 header 的 section 大小不一致",
        `type=0x${type.toString(16)}：header=${headerSize}，map=${mapSize}。`,
      )
    }
  }
}

export function parseDex(bytes: Uint8Array): DexModel {
  if (bytes.byteLength < HEADER_SIZE) {
    throw dexError("DEX_TOO_SMALL", "DEX 太小", `至少需要 ${HEADER_SIZE} 字节的 header。`)
  }
  for (let i = 0; i < DEX_MAGIC.length; i += 1) {
    if (bytes[i] !== DEX_MAGIC[i]) {
      throw dexError("DEX_BAD_MAGIC", "不是有效的 DEX 文件", "文件头 magic 不是 \"dex\\n\"。")
    }
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const header = readHeader(view, bytes)

  if (header.endianTag !== ENDIAN_TAG) {
    throw dexError("DEX_UNSUPPORTED_ENDIAN", "不支持的字节序", `endian_tag=0x${header.endianTag.toString(16)}，仅支持小端 0x12345678。`)
  }
  if (header.fileSize !== bytes.byteLength) {
    throw dexError("DEX_FILE_SIZE_MISMATCH", "header.file_size 与实际大小不符", `file_size=${header.fileSize}，实际=${bytes.byteLength}。`)
  }

  const stringOffsets = new Uint32Array(header.stringIdsSize)
  const strings: string[] = new Array(header.stringIdsSize)
  for (let i = 0; i < header.stringIdsSize; i += 1) {
    const idOff = header.stringIdsOff + i * 4
    if (idOff + 4 > bytes.byteLength) {
      throw dexError("DEX_STRING_IDS_TRUNCATED", "string_ids 越界", `第 ${i + 1} 个 string_id 超出文件大小。`)
    }
    const dataOff = view.getUint32(idOff, true)
    stringOffsets[i] = dataOff
    strings[i] = decodeStringDataItem(bytes, dataOff)
  }

  const mapItems = readMapList(view, bytes, header.mapOff)
  validateMapList(mapItems, header)

  return { header, mapItems, stringOffsets, strings, raw: bytes.slice(), dirty: false }
}

// M0 serialize: byte-exact for an unmutated model. Mutation (M1+) requires the
// re-sort/re-map layout planner, which is intentionally not part of M0.
export function serializeDex(model: DexModel): Uint8Array {
  if (model.dirty) {
    throw dexError(
      "DEX_MUTATION_UNSUPPORTED",
      "M0 不支持序列化已修改的 DEX",
      "重排/重映射布局规划器属于 M1 及以后；M0 仅保证未修改 DEX 的逐字节 round-trip。",
    )
  }
  return model.raw
}

// Recompute the DEX header integrity fields in the mandatory order (§4):
//   1) SHA-1 signature over [0x20, end) -> bytes 0x0c..0x1f
//   2) Adler-32 checksum over [0x0c, end) -> bytes 0x08..0x0b
// Operates on a copy; returns the corrected bytes.
export function recomputeDexChecksums(input: Uint8Array): Uint8Array {
  if (input.byteLength < HEADER_SIZE) {
    throw dexError("DEX_TOO_SMALL", "DEX 太小", `至少需要 ${HEADER_SIZE} 字节的 header。`)
  }
  const bytes = input.slice()
  const hasher = new Bun.CryptoHasher("sha1")
  hasher.update(bytes.subarray(0x20))
  const digest = new Uint8Array(hasher.digest().buffer)
  bytes.set(digest.subarray(0, 20), 0x0c)

  const checksum = adler32(bytes.subarray(0x0c))
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  view.setUint32(0x08, checksum, true)
  return bytes
}
