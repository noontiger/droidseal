// APK-side Network Security Config audit via direct AXML parsing.
//
// In an APK the NSC lives as a compiled (binary) XML resource under
// res/xml/*.xml. Its boolean attribute values are stored as typed values
// (e.g. cleartextTrafficPermitted="true" is a typed boolean, not the literal
// string "true"), so a plaintext regex won't match the raw bytes. We reuse
// DroidSeal's AXML reader (parseAxml), walk the compiled tree into a normalized
// element/attribute structure, reconstruct a faithful plaintext XML, and feed it
// to the same auditNetworkSecurityConfig used by the source-side audit — so both
// input modes share one NSC rule set. Fully offline; no aapt needed.

import { parseAxml, type AxmlModel } from "./axml-writer.ts"
import { auditNetworkSecurityConfig } from "./nsc-audit.ts"
import type { Finding } from "./types.ts"

// ResXMLTree attribute value type codes (androidfw Res_value::dataType).
const TYPE_STRING = 0x03
const TYPE_REFERENCE = 0x01
const TYPE_INT_DEC = 0x10
const TYPE_INT_HEX = 0x11
const TYPE_INT_BOOLEAN = 0x12

// START_TAG / END_TAG chunk types.
const CHUNK_START_TAG = 0x0102
const CHUNK_END_TAG = 0x0103

export interface AxmlAttribute {
  name: string
  value: string
  dataType: number
  data: number
}

export interface AxmlElement {
  tag: string
  attributes: AxmlAttribute[]
  children: AxmlElement[]
}

// Resolve a compiled attribute's typed value back to a plaintext string usable
// by auditNetworkSecurityConfig (which expects e.g. cleartextTrafficPermitted="true").
function resolveValue(
  dataType: number,
  data: number,
  rawValueIndex: number,
  strings: string[],
): string {
  const u = data >>> 0
  switch (dataType) {
    case TYPE_STRING:
      // Compiled XML stores a string-valued attribute's index in `rawValue`
      // (and mirrors it in typedValue.data); prefer the raw value index.
      return strings[rawValueIndex] ?? strings[data] ?? ""
    case TYPE_INT_BOOLEAN:
      return u !== 0 ? "true" : "false"
    case TYPE_INT_DEC:
      return String(u)
    case TYPE_INT_HEX:
      return `0x${u.toString(16)}`
    case TYPE_REFERENCE:
      return strings[rawValueIndex] ?? `@0x${u.toString(16)}`
    default: {
      const raw = strings[rawValueIndex]
      return raw ?? String(u)
    }
  }
}

// Walk the compiled XML tree (model.tail) into a nested element structure.
// Offsets mirror the proven axml-writer reader (readApplicationName / setAppNameInTail)
// which is exercised against real aapt2-produced manifests.
export function parseAxmlTree(model: AxmlModel): AxmlElement[] {
  const tail = model.tail
  const view = new DataView(tail.buffer, tail.byteOffset, tail.byteLength)
  const end = tail.byteLength
  const roots: AxmlElement[] = []
  const stack: AxmlElement[] = []
  let cursor = 0

  while (cursor + 8 <= end) {
    const type = view.getUint16(cursor, true)
    const chunkSize = view.getUint32(cursor + 4, true)
    if (chunkSize < 8 || cursor + chunkSize > end) break

    if (type === CHUNK_START_TAG) {
      const nameIdx = view.getUint32(cursor + 20, true)
      const attrStart = view.getUint16(cursor + 24, true)
      const attrCount = view.getUint16(cursor + 28, true)
      const attrBase = cursor + 16 + attrStart
      const attributes: AxmlAttribute[] = []
      for (let a = 0; a < attrCount; a += 1) {
        const attr = attrBase + a * 20
        if (attr + 20 > end) break
        const namespaceIndex = view.getUint32(attr, true)
        const nameIndex = view.getUint32(attr + 4, true)
        const rawValueIndex = view.getUint32(attr + 8, true)
        const dataType = view.getUint8(attr + 15)
        const data = view.getUint32(attr + 16, true)
        const rawName = model.strings[nameIndex]
        if (rawName === undefined || rawName.length === 0) continue
        const namespace = model.strings[namespaceIndex]
        const name = namespace === "http://schemas.android.com/apk/res/android"
          ? `android:${rawName}`
          : rawName
        attributes.push({
          name,
          value: resolveValue(dataType, data, rawValueIndex, model.strings),
          dataType,
          data: data >>> 0,
        })
      }
      const element: AxmlElement = { tag: model.strings[nameIdx] ?? "", attributes, children: [] }
      if (stack.length > 0) stack[stack.length - 1]!.children.push(element)
      else roots.push(element)
      stack.push(element)
    } else if (type === CHUNK_END_TAG) {
      stack.pop()
    }
    cursor += chunkSize
  }
  return roots
}

function escapeAttr(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")
}

// Reconstruct a faithful plaintext XML so the existing source-side NSC auditor
// (auditNetworkSecurityConfig) can be reused unchanged.
export function reconstructXml(elements: AxmlElement[]): string {
  const parts: string[] = []
  const emit = (els: AxmlElement[]): void => {
    for (const el of els) {
      const attrs = el.attributes
        .map((attribute) => `${attribute.name}="${escapeAttr(attribute.value)}"`)
        .join(" ")
      const open = `<${el.tag}${attrs ? " " + attrs : ""}`
      if (el.children.length === 0) {
        parts.push(`${open}/>`)
      } else {
        parts.push(`${open}>`)
        emit(el.children)
        parts.push(`</${el.tag}>`)
      }
    }
  }
  emit(elements)
  return parts.join("\n")
}

// Map a manifest @xml/... reference (or a res/xml path) to the APK entry name.
export function nscEntryName(reference: string): string | undefined {
  let name = reference.trim()
  const atMatch = /^@(?:[\w.]+:)?xml\/(.+)$/.exec(name)
  if (atMatch) name = atMatch[1]!
  name = name.replace(/^res\/xml\//i, "").replace(/\.xml$/i, "")
  if (!/^[A-Za-z0-9_.-]+$/.test(name)) return undefined
  if (name.length === 0) return undefined
  return `res/xml/${name}.xml`
}

// Generic alias used by the manifest NSC and backup-rule resolvers.
export const xmlResourceEntryName = nscEntryName

export function parseAxmlElements(bytes: Uint8Array): AxmlElement[] {
  return parseAxmlTree(parseAxml(bytes))
}

// Audit a compiled NSC resource (bytes of res/xml/*.xml) in an APK. Degrades to
// [] if the bytes aren't parseable, so a malformed/obfuscated resource never
// breaks the overall audit.
export function auditApkNetworkSecurityConfig(axmlBytes: Uint8Array, evidence: string): Finding[] {
  try {
    const model = parseAxml(axmlBytes)
    const tree = parseAxmlTree(model)
    if (tree.length === 0) return []
    return auditNetworkSecurityConfig(reconstructXml(tree), evidence)
  } catch {
    return []
  }
}
