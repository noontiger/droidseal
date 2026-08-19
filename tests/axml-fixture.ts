import { serializeAxml, type AxmlModel } from "../src/core/axml-writer.ts"

const NO_INDEX = 0xffffffff
const ANDROID_NS = "http://schemas.android.com/apk/res/android"

export interface FixtureAttribute {
  name: string
  value: string | boolean | number
  type?: "string" | "boolean" | "reference" | "int"
  android?: boolean
  rawValue?: string
}

export interface FixtureElement {
  tag: string
  attributes?: FixtureAttribute[]
  children?: FixtureElement[]
}

function concat(parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.byteLength
  }
  return output
}

export function buildAxmlFixture(roots: FixtureElement[]): Uint8Array {
  const strings: string[] = []
  const intern = (value: string): number => {
    const existing = strings.indexOf(value)
    if (existing >= 0) return existing
    strings.push(value)
    return strings.length - 1
  }
  const collect = (nodes: FixtureElement[]): void => {
    for (const node of nodes) {
      intern(node.tag)
      for (const attribute of node.attributes ?? []) {
        intern(attribute.name)
        if (attribute.android) intern(ANDROID_NS)
        if ((attribute.type ?? "string") === "string") intern(String(attribute.value))
        if (attribute.rawValue !== undefined) intern(attribute.rawValue)
      }
      collect(node.children ?? [])
    }
  }
  collect(roots)

  const startTag = (node: FixtureElement): Uint8Array => {
    const attributes = node.attributes ?? []
    const size = 36 + attributes.length * 20
    const bytes = new Uint8Array(size)
    const view = new DataView(bytes.buffer)
    view.setUint16(0, 0x0102, true)
    view.setUint16(2, 16, true)
    view.setUint32(4, size, true)
    view.setUint32(8, 1, true)
    view.setUint32(12, NO_INDEX, true)
    view.setUint32(16, NO_INDEX, true)
    view.setUint32(20, intern(node.tag), true)
    view.setUint16(24, 20, true)
    view.setUint16(26, 20, true)
    view.setUint16(28, attributes.length, true)
    let offset = 36
    for (const attribute of attributes) {
      const type = attribute.type ?? "string"
      const dataType = type === "string" ? 0x03 : type === "boolean" ? 0x12 : type === "reference" ? 0x01 : 0x10
      const data = type === "string"
        ? intern(String(attribute.value))
        : type === "boolean"
          ? attribute.value ? 0xffffffff : 0
          : Number(attribute.value) >>> 0
      view.setUint32(offset, attribute.android ? intern(ANDROID_NS) : NO_INDEX, true)
      view.setUint32(offset + 4, intern(attribute.name), true)
      view.setUint32(offset + 8, attribute.rawValue === undefined ? NO_INDEX : intern(attribute.rawValue), true)
      view.setUint16(offset + 12, 8, true)
      view.setUint8(offset + 14, 0)
      view.setUint8(offset + 15, dataType)
      view.setUint32(offset + 16, data, true)
      offset += 20
    }
    return bytes
  }
  const endTag = (node: FixtureElement): Uint8Array => {
    const bytes = new Uint8Array(24)
    const view = new DataView(bytes.buffer)
    view.setUint16(0, 0x0103, true)
    view.setUint16(2, 16, true)
    view.setUint32(4, 24, true)
    view.setUint32(8, 1, true)
    view.setUint32(12, NO_INDEX, true)
    view.setUint32(16, NO_INDEX, true)
    view.setUint32(20, intern(node.tag), true)
    return bytes
  }
  const chunks: Uint8Array[] = []
  const emit = (nodes: FixtureElement[]): void => {
    for (const node of nodes) {
      chunks.push(startTag(node))
      emit(node.children ?? [])
      chunks.push(endTag(node))
    }
  }
  emit(roots)

  const model: AxmlModel = {
    header: new Uint8Array(8),
    isUtf8: true,
    flags: 0x0100,
    strings,
    styleOffsets: [],
    styleData: new Uint8Array(0),
    tail: concat(chunks),
  }
  return serializeAxml(model)
}
