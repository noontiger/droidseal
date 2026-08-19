// Variable-length binary AndroidManifest.xml (AXML) write engine (M2, see
// docs/dex-write-engine.md §7.2 path (b) / §13.2). The existing
// flipDebuggableInAxml only does length-preserving in-place edits; this engine
// rebuilds the string pool so new strings (e.g. an injected Application class
// name) can be added, then repoints an attribute value at the new string.
//
// Key simplification vs. DEX: the AXML string pool is NOT required to be sorted,
// so newly interned strings are APPENDED and every existing string index stays
// valid. Only the string-pool chunk grows; the resource-map + XML-tree region
// (which references strings by index) is preserved verbatim, and attribute value
// repointing is a length-preserving 4-byte edit within it.

import { DroidSealError } from "./errors.ts"

const CHUNK_XML = 0x0003
const CHUNK_STRING_POOL = 0x0001
const CHUNK_RESOURCE_MAP = 0x0180
const CHUNK_START_TAG = 0x0102
const UTF8_FLAG = 0x0100
const TYPE_STRING = 0x03
// android:name resource id (framework attribute).
const ANDROID_NAME_RES_ID = 0x01010003

function axmlError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["确认传入的是二进制 AndroidManifest.xml", "该清单含本引擎暂不支持的结构时会安全回退，不改写原包"],
    stepId: "harden",
  })
}

export interface AxmlModel {
  header: Uint8Array // 8-byte XML chunk header (size field patched on serialize)
  isUtf8: boolean
  flags: number
  strings: string[]
  styleOffsets: number[]
  styleData: Uint8Array
  tail: Uint8Array // resource-map + XML tree, referencing strings by index only
}

function readLen8(bytes: Uint8Array, p: number): { value: number; next: number } {
  const v = bytes[p]!
  if (v & 0x80) return { value: ((v & 0x7f) << 8) | bytes[p + 1]!, next: p + 2 }
  return { value: v, next: p + 1 }
}

function readLen16(view: DataView, p: number): { value: number; next: number } {
  const v = view.getUint16(p, true)
  if (v & 0x8000) return { value: ((v & 0x7fff) << 16) | view.getUint16(p + 2, true), next: p + 4 }
  return { value: v, next: p + 2 }
}

export function parseAxml(bytes: Uint8Array): AxmlModel {
  if (bytes.byteLength < 8) throw axmlError("AXML_TOO_SMALL", "AXML 太小", "至少需要 8 字节 XML chunk 头。")
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (view.getUint16(0, true) !== CHUNK_XML) throw axmlError("AXML_INVALID", "不是有效的二进制 XML", "文件头 magic 不匹配。")

  const poolStart = 8
  if (view.getUint16(poolStart, true) !== CHUNK_STRING_POOL) {
    throw axmlError("AXML_NO_STRING_POOL", "AXML 首个 chunk 不是字符串池", "无法定位 ResStringPool。")
  }
  const poolSize = view.getUint32(poolStart + 4, true)
  const stringCount = view.getUint32(poolStart + 8, true)
  const styleCount = view.getUint32(poolStart + 12, true)
  const flags = view.getUint32(poolStart + 16, true)
  const stringsStart = view.getUint32(poolStart + 20, true)
  const stylesStart = view.getUint32(poolStart + 24, true)
  const isUtf8 = (flags & UTF8_FLAG) !== 0

  const offsets: number[] = new Array(stringCount)
  for (let i = 0; i < stringCount; i += 1) offsets[i] = view.getUint32(poolStart + 28 + i * 4, true)
  const styleOffsets: number[] = new Array(styleCount)
  for (let i = 0; i < styleCount; i += 1) styleOffsets[i] = view.getUint32(poolStart + 28 + stringCount * 4 + i * 4, true)

  const decoder = new TextDecoder("utf-8", { fatal: false })
  const strings: string[] = new Array(stringCount)
  const dataBase = poolStart + stringsStart
  for (let i = 0; i < stringCount; i += 1) {
    let p = dataBase + offsets[i]!
    if (isUtf8) {
      const chars = readLen8(bytes, p)
      const nbytes = readLen8(bytes, chars.next)
      p = nbytes.next
      strings[i] = decoder.decode(bytes.subarray(p, p + nbytes.value))
    } else {
      const len = readLen16(view, p)
      p = len.next
      let s = ""
      for (let c = 0; c < len.value; c += 1) s += String.fromCharCode(view.getUint16(p + c * 2, true))
      strings[i] = s
    }
  }

  const styleData =
    styleCount > 0 ? bytes.slice(poolStart + stylesStart, poolStart + poolSize) : new Uint8Array(0)
  const tail = bytes.slice(poolStart + poolSize)
  return { header: bytes.slice(0, 8), isUtf8, flags, strings, styleOffsets, styleData, tail }
}

// Append a string, returning its (possibly existing) index. Never reorders, so
// all existing indices — including the resource-map attribute region — stay valid.
export function internAxmlString(model: AxmlModel, value: string): number {
  const found = model.strings.indexOf(value)
  if (found >= 0) return found
  model.strings.push(value)
  return model.strings.length - 1
}

function writeLen8(value: number, out: number[]): void {
  if (value > 0x7f) out.push((value >> 8) | 0x80, value & 0xff)
  else out.push(value)
}

function encodeStringData(model: AxmlModel): { offsets: number[]; data: number[] } {
  const encoder = new TextEncoder()
  const offsets: number[] = new Array(model.strings.length)
  const data: number[] = []
  for (let i = 0; i < model.strings.length; i += 1) {
    offsets[i] = data.length
    const s = model.strings[i]!
    if (model.isUtf8) {
      const utf8 = encoder.encode(s)
      writeLen8(s.length, data)
      writeLen8(utf8.byteLength, data)
      for (const b of utf8) data.push(b)
      data.push(0x00)
    } else {
      if (s.length > 0x7fff) {
        const hi = ((s.length >> 16) & 0x7fff) | 0x8000
        data.push(hi & 0xff, (hi >> 8) & 0xff, s.length & 0xff, (s.length >> 8) & 0xff)
      } else {
        data.push(s.length & 0xff, (s.length >> 8) & 0xff)
      }
      for (let c = 0; c < s.length; c += 1) {
        const u = s.charCodeAt(c)
        data.push(u & 0xff, (u >> 8) & 0xff)
      }
      data.push(0x00, 0x00)
    }
  }
  while (data.length % 4 !== 0) data.push(0x00)
  return { offsets, data }
}

// Locate the <application> START_TAG's android:name attribute and repoint its
// value at the given string index (length-preserving edit inside `tail`).
function setAppNameInTail(model: AxmlModel, newIndex: number): boolean {
  const tail = model.tail
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength)
  const end = tail.byteLength
  let nameAttrIndex = -1
  let cursor = 0
  const applicationStrIdx = model.strings.indexOf("application")

  while (cursor + 8 <= end) {
    const type = view.getUint16(cursor, true)
    const chunkSize = view.getUint32(cursor + 4, true)
    if (chunkSize < 8 || cursor + chunkSize > end) break

    if (type === CHUNK_RESOURCE_MAP) {
      const count = (chunkSize - 8) / 4
      for (let i = 0; i < count; i += 1) {
        if (view.getUint32(cursor + 8 + i * 4, true) === ANDROID_NAME_RES_ID) {
          nameAttrIndex = i
          break
        }
      }
    } else if (type === CHUNK_START_TAG) {
      const tagNameIdx = view.getUint32(cursor + 20, true) // attrExt.name at node+16+4
      if (tagNameIdx === applicationStrIdx && nameAttrIndex >= 0) {
        const attrStart = view.getUint16(cursor + 24, true)
        const attrCount = view.getUint16(cursor + 28, true)
        const attrBase = cursor + 16 + attrStart
        for (let a = 0; a < attrCount; a += 1) {
          const attr = attrBase + a * 20
          if (attr + 20 > end) break
          if (view.getUint32(attr + 4, true) !== nameAttrIndex) continue
          view.setUint32(attr + 8, newIndex, true) // rawValue
          view.setUint8(attr + 15, TYPE_STRING) // typedValue.dataType
          view.setUint32(attr + 16, newIndex, true) // typedValue.data
          return true
        }
      }
    }
    cursor += chunkSize
  }
  return false
}

// Read the current <application android:name> value, or null if absent.
export function readApplicationName(model: AxmlModel): string | null {
  const tail = model.tail
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength)
  const end = tail.byteLength
  let nameAttrIndex = -1
  let cursor = 0
  const applicationStrIdx = model.strings.indexOf("application")
  while (cursor + 8 <= end) {
    const type = view.getUint16(cursor, true)
    const chunkSize = view.getUint32(cursor + 4, true)
    if (chunkSize < 8 || cursor + chunkSize > end) break
    if (type === CHUNK_RESOURCE_MAP) {
      const count = (chunkSize - 8) / 4
      for (let i = 0; i < count; i += 1) {
        if (view.getUint32(cursor + 8 + i * 4, true) === ANDROID_NAME_RES_ID) {
          nameAttrIndex = i
          break
        }
      }
    } else if (type === CHUNK_START_TAG && view.getUint32(cursor + 20, true) === applicationStrIdx && nameAttrIndex >= 0) {
      const attrStart = view.getUint16(cursor + 24, true)
      const attrCount = view.getUint16(cursor + 28, true)
      const attrBase = cursor + 16 + attrStart
      for (let a = 0; a < attrCount; a += 1) {
        const attr = attrBase + a * 20
        if (attr + 20 > end) break
        if (view.getUint32(attr + 4, true) !== nameAttrIndex) continue
        return model.strings[view.getUint32(attr + 16, true)] ?? null
      }
    }
    cursor += chunkSize
  }
  return null
}

// Point <application android:name> at the given class name (dotted form, e.g.
// "com.droidseal.inj.App"). Throws (fail-closed) if the attribute is absent, so
// the default-Application insertion case is deferred rather than mis-emitted.
export function setApplicationName(model: AxmlModel, className: string): void {
  const idx = internAxmlString(model, className)
  if (!setAppNameInTail(model, idx)) {
    throw axmlError(
      "AXML_APP_NAME_ABSENT",
      "<application> 缺少 android:name 属性",
      "本引擎当前仅支持重指向已存在的 android:name；新增属性（默认 Application 情形）留待后续。",
    )
  }
}

export function serializeAxml(model: AxmlModel): Uint8Array {
  const { offsets, data } = encodeStringData(model)
  const stringCount = model.strings.length
  const styleCount = model.styleOffsets.length
  const stringsStart = 28 + stringCount * 4 + styleCount * 4
  const stylesStart = styleCount > 0 ? stringsStart + data.length : 0
  const poolSize = stringsStart + data.length + model.styleData.byteLength

  const pool = new Uint8Array(poolSize)
  const pv = new DataView(pool.buffer)
  pv.setUint16(0, CHUNK_STRING_POOL, true)
  pv.setUint16(2, 28, true) // headerSize
  pv.setUint32(4, poolSize, true)
  pv.setUint32(8, stringCount, true)
  pv.setUint32(12, styleCount, true)
  pv.setUint32(16, model.flags, true)
  pv.setUint32(20, stringsStart, true)
  pv.setUint32(24, stylesStart, true)
  for (let i = 0; i < stringCount; i += 1) pv.setUint32(28 + i * 4, offsets[i]!, true)
  for (let i = 0; i < styleCount; i += 1) pv.setUint32(28 + stringCount * 4 + i * 4, model.styleOffsets[i]!, true)
  pool.set(Uint8Array.from(data), stringsStart)
  if (styleCount > 0) pool.set(model.styleData, stylesStart)

  const total = 8 + poolSize + model.tail.byteLength
  const out = new Uint8Array(total)
  out.set(model.header, 0)
  const ov = new DataView(out.buffer)
  ov.setUint16(0, CHUNK_XML, true)
  ov.setUint16(2, 8, true) // headerSize
  ov.setUint32(4, total, true) // patched file size
  out.set(pool, 8)
  out.set(model.tail, 8 + poolSize)
  return out
}
