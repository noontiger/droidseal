// DEX write engine — full-table parse + semantic re-sort/re-map layout planner
// (M1, see docs/dex-write-engine.md §6.2/§6.3). Builds on the M0 codec
// (dex-codec.ts) and checksum layer (dex-model.ts).
//
// Design: the model keeps the *flat* DEX tables (strings/types/protos/fields/
// methods/classes) with cross-references as indices, and keeps code_item insns
// as raw u16 with their ORIGINAL operand indices. The layout planner re-sorts
// every index table (§3.2 invariants), builds old->new index maps, and remaps
// every reference — including string/type/field/method operands buried inside
// code_item instructions via a complete Dalvik width/reference table.
//
// Scope (M1 automated core): a well-defined DEX subset — no debug_info, no
// annotations, no static values, no try/catch. Anything outside the subset is
// rejected (fail-closed) so a real APK that we cannot faithfully round-trip
// falls back safely rather than producing a DEX that "installs but crashes".
// Real-device `pm install` / `dexdump` equivalence (Stage B) is manual.

import { readUleb128, writeUleb128 } from "./dex-codec.ts"
import { recomputeDexChecksums } from "./dex-model.ts"
import { DroidSealError } from "./errors.ts"

const DEX_MAGIC = [0x64, 0x65, 0x78, 0x0a] // "dex\n"
const ENDIAN_TAG = 0x12345678
const HEADER_SIZE = 0x70
export const NO_INDEX = 0xffffffff

// map_item type codes (§3.4).
const MAP_HEADER = 0x0000
const MAP_STRING_ID = 0x0001
const MAP_TYPE_ID = 0x0002
const MAP_PROTO_ID = 0x0003
const MAP_FIELD_ID = 0x0004
const MAP_METHOD_ID = 0x0005
const MAP_CLASS_DEF = 0x0006
const MAP_MAP_LIST = 0x1000
const MAP_TYPE_LIST = 0x1001
const MAP_CLASS_DATA = 0x2000
const MAP_CODE_ITEM = 0x2001
const MAP_STRING_DATA = 0x2002

// -- Dalvik instruction tables ----------------------------------------------
// WIDTH[op] = instruction size in 16-bit code units; 0 = unsupported (fail-closed).
// REF[op] = reference kind carried at insns[pc+1]: 0 none, 1 string(u16),
// 2 type, 3 field, 4 method, 5 string/jumbo(u32 across pc+1..pc+2).
const WIDTH = new Uint8Array(256)
const REF = new Uint8Array(256)

function setRange(from: number, to: number, width: number, ref = 0): void {
  for (let op = from; op <= to; op += 1) {
    WIDTH[op] = width
    REF[op] = ref
  }
}

// Populate from the canonical v035 opcode -> format mapping.
WIDTH[0x00] = 1 // nop (payloads handled separately)
setRange(0x01, 0x01, 1) // move 12x
WIDTH[0x02] = 2 // move/from16 22x
WIDTH[0x03] = 3 // move/16 32x
WIDTH[0x04] = 1
WIDTH[0x05] = 2
WIDTH[0x06] = 3
WIDTH[0x07] = 1
WIDTH[0x08] = 2
WIDTH[0x09] = 3
setRange(0x0a, 0x0d, 1) // move-result* / move-exception 11x
setRange(0x0e, 0x11, 1) // return* 10x/11x
WIDTH[0x12] = 1 // const/4 11n
WIDTH[0x13] = 2 // const/16 21s
WIDTH[0x14] = 3 // const 31i
WIDTH[0x15] = 2 // const/high16 21h
WIDTH[0x16] = 2 // const-wide/16 21s
WIDTH[0x17] = 3 // const-wide/32 31i
WIDTH[0x18] = 5 // const-wide 51l
WIDTH[0x19] = 2 // const-wide/high16 21h
WIDTH[0x1a] = 2
REF[0x1a] = 1 // const-string 21c (string)
WIDTH[0x1b] = 3
REF[0x1b] = 5 // const-string/jumbo 31c (string)
WIDTH[0x1c] = 2
REF[0x1c] = 2 // const-class 21c (type)
WIDTH[0x1d] = 1 // monitor-enter
WIDTH[0x1e] = 1 // monitor-exit
WIDTH[0x1f] = 2
REF[0x1f] = 2 // check-cast 21c (type)
WIDTH[0x20] = 2
REF[0x20] = 2 // instance-of 22c (type)
WIDTH[0x21] = 1 // array-length 12x
WIDTH[0x22] = 2
REF[0x22] = 2 // new-instance 21c (type)
WIDTH[0x23] = 2
REF[0x23] = 2 // new-array 22c (type)
WIDTH[0x24] = 3
REF[0x24] = 2 // filled-new-array 35c (type)
WIDTH[0x25] = 3
REF[0x25] = 2 // filled-new-array/range 3rc (type)
WIDTH[0x26] = 3 // fill-array-data 31t
WIDTH[0x27] = 1 // throw 11x
WIDTH[0x28] = 1 // goto 10t
WIDTH[0x29] = 2 // goto/16 20t
WIDTH[0x2a] = 3 // goto/32 30t
WIDTH[0x2b] = 3 // packed-switch 31t
WIDTH[0x2c] = 3 // sparse-switch 31t
setRange(0x2d, 0x31, 2) // cmp* 23x
setRange(0x32, 0x37, 2) // if-test 22t
setRange(0x38, 0x3d, 2) // if-testz 21t
// 0x3e..0x43 unused -> WIDTH 0 (fail-closed)
setRange(0x44, 0x51, 2) // array get/put 23x
setRange(0x52, 0x5f, 2, 3) // iinstanceop 22c (field)
setRange(0x60, 0x6d, 2, 3) // sstaticop 21c (field)
setRange(0x6e, 0x72, 3, 4) // invoke-kind 35c (method)
// 0x73 unused
setRange(0x74, 0x78, 3, 4) // invoke-kind/range 3rc (method)
// 0x79..0x7a unused
setRange(0x7b, 0x8f, 1) // unop 12x
setRange(0x90, 0xaf, 2) // binop 23x
setRange(0xb0, 0xcf, 1) // binop/2addr 12x
setRange(0xd0, 0xd7, 2) // binop/lit16 22s
setRange(0xd8, 0xe2, 2) // binop/lit8 22b
// 0xe3..0xff unused / newer (invoke-polymorphic/custom, const-method-*) -> fail-closed

// -- Model ------------------------------------------------------------------

export interface DexProtoRec {
  shortyIdx: number // string idx
  returnTypeIdx: number // type idx
  paramTypeIdxs: number[] // type idxs
}
export interface DexFieldRec {
  classIdx: number // type idx
  typeIdx: number // type idx
  nameIdx: number // string idx
}
export interface DexMethodRec {
  classIdx: number // type idx
  protoIdx: number // proto idx
  nameIdx: number // string idx
}
export interface DexCodeRec {
  registersSize: number
  insSize: number
  outsSize: number
  insns: Uint16Array // raw, operands remapped at serialize
}
export interface EncodedFieldRec {
  fieldIdx: number
  accessFlags: number
}
export interface EncodedMethodRec {
  methodIdx: number
  accessFlags: number
  code: DexCodeRec | null
}
export interface DexClassRec {
  classIdx: number // type idx
  accessFlags: number
  superclassIdx: number // type idx or NO_INDEX
  interfaces: number[] // type idxs
  sourceFileIdx: number // string idx or NO_INDEX
  staticFields: EncodedFieldRec[]
  instanceFields: EncodedFieldRec[]
  directMethods: EncodedMethodRec[]
  virtualMethods: EncodedMethodRec[]
  hasClassData: boolean
}
export interface DexTables {
  version: string
  strings: string[]
  types: number[] // type idx -> string idx of descriptor
  protos: DexProtoRec[]
  fields: DexFieldRec[]
  methods: DexMethodRec[]
  classes: DexClassRec[]
  dirty: boolean
}

function dexError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["确认传入的是 classes.dex", "该 DEX 含本引擎暂不支持的结构时会安全回退，不改写原包"],
    stepId: "harden",
  })
}

// -- Parse ------------------------------------------------------------------

function readTypeList(view: DataView, off: number): number[] {
  if (off === 0) return []
  const size = view.getUint32(off, true)
  const out: number[] = new Array(size)
  for (let i = 0; i < size; i += 1) out[i] = view.getUint16(off + 4 + i * 2, true)
  return out
}

function readCode(view: DataView, bytes: Uint8Array, off: number): DexCodeRec {
  const registersSize = view.getUint16(off, true)
  const insSize = view.getUint16(off + 2, true)
  const outsSize = view.getUint16(off + 4, true)
  const triesSize = view.getUint16(off + 6, true)
  const debugInfoOff = view.getUint32(off + 8, true)
  const insnsSize = view.getUint32(off + 12, true)
  if (triesSize !== 0) {
    throw dexError("DEX_TRIES_UNSUPPORTED", "暂不支持含 try/catch 的方法", "M1 子集不改写带异常处理表的 code_item。")
  }
  if (debugInfoOff !== 0) {
    throw dexError("DEX_DEBUG_UNSUPPORTED", "暂不支持含调试信息的方法", "M1 子集要求 debug_info_off=0（release 剥离调试信息）。")
  }
  const insns = new Uint16Array(insnsSize)
  for (let i = 0; i < insnsSize; i += 1) insns[i] = view.getUint16(off + 16 + i * 2, true)
  void bytes
  return { registersSize, insSize, outsSize, insns }
}

function readEncodedFields(bytes: Uint8Array, at: number, count: number): { list: EncodedFieldRec[]; next: number } {
  const list: EncodedFieldRec[] = []
  let cursor = at
  let idx = 0
  for (let i = 0; i < count; i += 1) {
    const diff = readUleb128(bytes, cursor)
    cursor = diff.next
    const flags = readUleb128(bytes, cursor)
    cursor = flags.next
    idx += diff.value
    list.push({ fieldIdx: idx, accessFlags: flags.value })
  }
  return { list, next: cursor }
}

function readEncodedMethods(
  view: DataView,
  bytes: Uint8Array,
  at: number,
  count: number,
): { list: EncodedMethodRec[]; next: number } {
  const list: EncodedMethodRec[] = []
  let cursor = at
  let idx = 0
  for (let i = 0; i < count; i += 1) {
    const diff = readUleb128(bytes, cursor)
    cursor = diff.next
    const flags = readUleb128(bytes, cursor)
    cursor = flags.next
    const codeOff = readUleb128(bytes, cursor)
    cursor = codeOff.next
    idx += diff.value
    const code = codeOff.value === 0 ? null : readCode(view, bytes, codeOff.value)
    list.push({ methodIdx: idx, accessFlags: flags.value, code })
  }
  return { list, next: cursor }
}

export function parseDexTables(bytes: Uint8Array): DexTables {
  if (bytes.byteLength < HEADER_SIZE) throw dexError("DEX_TOO_SMALL", "DEX 太小", `至少需要 ${HEADER_SIZE} 字节。`)
  for (let i = 0; i < DEX_MAGIC.length; i += 1) {
    if (bytes[i] !== DEX_MAGIC[i]) throw dexError("DEX_BAD_MAGIC", "不是有效的 DEX 文件", 'magic 不是 "dex\\n"。')
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  if (view.getUint32(0x28, true) !== ENDIAN_TAG) {
    throw dexError("DEX_UNSUPPORTED_ENDIAN", "不支持的字节序", "仅支持小端 0x12345678。")
  }
  if (view.getUint32(0x20, true) !== bytes.byteLength) {
    throw dexError("DEX_FILE_SIZE_MISMATCH", "file_size 与实际大小不符", "文件可能被截断。")
  }
  const version = String.fromCharCode(bytes[4]!, bytes[5]!, bytes[6]!)

  const stringIdsSize = view.getUint32(0x38, true)
  const stringIdsOff = view.getUint32(0x3c, true)
  const typeIdsSize = view.getUint32(0x40, true)
  const typeIdsOff = view.getUint32(0x44, true)
  const protoIdsSize = view.getUint32(0x48, true)
  const protoIdsOff = view.getUint32(0x4c, true)
  const fieldIdsSize = view.getUint32(0x50, true)
  const fieldIdsOff = view.getUint32(0x54, true)
  const methodIdsSize = view.getUint32(0x58, true)
  const methodIdsOff = view.getUint32(0x5c, true)
  const classDefsSize = view.getUint32(0x60, true)
  const classDefsOff = view.getUint32(0x64, true)

  const strings: string[] = new Array(stringIdsSize)
  for (let i = 0; i < stringIdsSize; i += 1) {
    const dataOff = view.getUint32(stringIdsOff + i * 4, true)
    const prefix = readUleb128(bytes, dataOff)
    let end = prefix.next
    while (end < bytes.byteLength && bytes[end] !== 0x00) end += 1
    strings[i] = decodeString(bytes.subarray(prefix.next, end))
  }

  const types: number[] = new Array(typeIdsSize)
  for (let i = 0; i < typeIdsSize; i += 1) types[i] = view.getUint32(typeIdsOff + i * 4, true)

  const protos: DexProtoRec[] = new Array(protoIdsSize)
  for (let i = 0; i < protoIdsSize; i += 1) {
    const base = protoIdsOff + i * 12
    protos[i] = {
      shortyIdx: view.getUint32(base, true),
      returnTypeIdx: view.getUint32(base + 4, true),
      paramTypeIdxs: readTypeList(view, view.getUint32(base + 8, true)),
    }
  }

  const fields: DexFieldRec[] = new Array(fieldIdsSize)
  for (let i = 0; i < fieldIdsSize; i += 1) {
    const base = fieldIdsOff + i * 8
    fields[i] = {
      classIdx: view.getUint16(base, true),
      typeIdx: view.getUint16(base + 2, true),
      nameIdx: view.getUint32(base + 4, true),
    }
  }

  const methods: DexMethodRec[] = new Array(methodIdsSize)
  for (let i = 0; i < methodIdsSize; i += 1) {
    const base = methodIdsOff + i * 8
    methods[i] = {
      classIdx: view.getUint16(base, true),
      protoIdx: view.getUint16(base + 2, true),
      nameIdx: view.getUint32(base + 4, true),
    }
  }

  const classes: DexClassRec[] = new Array(classDefsSize)
  for (let i = 0; i < classDefsSize; i += 1) {
    const base = classDefsOff + i * 32
    const classIdx = view.getUint32(base, true)
    const accessFlags = view.getUint32(base + 4, true)
    const superclassIdx = view.getUint32(base + 8, true)
    const interfacesOff = view.getUint32(base + 12, true)
    const sourceFileIdx = view.getUint32(base + 16, true)
    const annotationsOff = view.getUint32(base + 20, true)
    const classDataOff = view.getUint32(base + 24, true)
    const staticValuesOff = view.getUint32(base + 28, true)
    if (annotationsOff !== 0 || staticValuesOff !== 0) {
      throw dexError("DEX_ANNOTATIONS_UNSUPPORTED", "暂不支持注解/静态初始值", "M1 子集要求 annotations_off=0 且 static_values_off=0。")
    }
    let staticFields: EncodedFieldRec[] = []
    let instanceFields: EncodedFieldRec[] = []
    let directMethods: EncodedMethodRec[] = []
    let virtualMethods: EncodedMethodRec[] = []
    const hasClassData = classDataOff !== 0
    if (hasClassData) {
      let cursor = classDataOff
      const sf = readUleb128(bytes, cursor)
      cursor = sf.next
      const ifn = readUleb128(bytes, cursor)
      cursor = ifn.next
      const dm = readUleb128(bytes, cursor)
      cursor = dm.next
      const vm = readUleb128(bytes, cursor)
      cursor = vm.next
      const sfr = readEncodedFields(bytes, cursor, sf.value)
      staticFields = sfr.list
      cursor = sfr.next
      const ifr = readEncodedFields(bytes, cursor, ifn.value)
      instanceFields = ifr.list
      cursor = ifr.next
      const dmr = readEncodedMethods(view, bytes, cursor, dm.value)
      directMethods = dmr.list
      cursor = dmr.next
      const vmr = readEncodedMethods(view, bytes, cursor, vm.value)
      virtualMethods = vmr.list
    }
    classes[i] = {
      classIdx,
      accessFlags,
      superclassIdx,
      interfaces: readTypeList(view, interfacesOff),
      sourceFileIdx,
      staticFields,
      instanceFields,
      directMethods,
      virtualMethods,
      hasClassData,
    }
  }

  return { version, strings, types, protos, fields, methods, classes, dirty: false }
}

function decodeString(bytes: Uint8Array): string {
  let out = ""
  let i = 0
  const n = bytes.byteLength
  while (i < n) {
    const b = bytes[i]!
    if (b < 0x80) {
      out += String.fromCharCode(b)
      i += 1
    } else if ((b & 0xe0) === 0xc0) {
      out += String.fromCharCode(((b & 0x1f) << 6) | (bytes[i + 1]! & 0x3f))
      i += 2
    } else {
      out += String.fromCharCode(((b & 0x0f) << 12) | ((bytes[i + 1]! & 0x3f) << 6) | (bytes[i + 2]! & 0x3f))
      i += 3
    }
  }
  return out
}

function encodeString(text: string): number[] {
  const out: number[] = []
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i)
    if (c !== 0 && c < 0x80) out.push(c)
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f))
    else out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f))
  }
  return out
}

// -- Intern helpers (mutation building blocks) ------------------------------

export function internString(model: DexTables, value: string): number {
  const found = model.strings.indexOf(value)
  if (found >= 0) return found
  model.strings.push(value)
  return model.strings.length - 1
}

export function internType(model: DexTables, descriptor: string): number {
  const sIdx = internString(model, descriptor)
  const found = model.types.indexOf(sIdx)
  if (found >= 0) return found
  model.types.push(sIdx)
  return model.types.length - 1
}

function shortyChar(descriptor: string): string {
  const c = descriptor[0]!
  if (c === "[") return "L"
  if ("VZBSCIJFD".includes(c)) return c
  return "L"
}

export function internProto(model: DexTables, returnDescriptor: string, paramDescriptors: string[]): number {
  const returnTypeIdx = internType(model, returnDescriptor)
  const paramTypeIdxs = paramDescriptors.map((d) => internType(model, d))
  const key = `${returnTypeIdx}(${paramTypeIdxs.join(",")})`
  const found = model.protos.findIndex((p) => `${p.returnTypeIdx}(${p.paramTypeIdxs.join(",")})` === key)
  if (found >= 0) return found
  const shorty = shortyChar(returnDescriptor) + paramDescriptors.map(shortyChar).join("")
  model.protos.push({ shortyIdx: internString(model, shorty), returnTypeIdx, paramTypeIdxs })
  return model.protos.length - 1
}

export function internMethod(
  model: DexTables,
  classDescriptor: string,
  name: string,
  returnDescriptor: string,
  paramDescriptors: string[],
): number {
  const classIdx = internType(model, classDescriptor)
  const protoIdx = internProto(model, returnDescriptor, paramDescriptors)
  const nameIdx = internString(model, name)
  const found = model.methods.findIndex((m) => m.classIdx === classIdx && m.protoIdx === protoIdx && m.nameIdx === nameIdx)
  if (found >= 0) return found
  model.methods.push({ classIdx, protoIdx, nameIdx })
  return model.methods.length - 1
}

// Add an empty (no fields/methods) class extending the given superclass.
export function addEmptyClass(
  model: DexTables,
  descriptor: string,
  superDescriptor = "Ljava/lang/Object;",
  accessFlags = 0x1,
): void {
  if (model.types.some((s) => model.strings[s] === descriptor)) {
    const already = model.classes.some((c) => model.strings[model.types[c.classIdx]!] === descriptor)
    if (already) throw dexError("DEX_CLASS_EXISTS", "类已存在", `${descriptor} 已在此 DEX 中定义。`)
  }
  const classIdx = internType(model, descriptor)
  const superclassIdx = internType(model, superDescriptor)
  model.classes.push({
    classIdx,
    accessFlags,
    superclassIdx,
    interfaces: [],
    sourceFileIdx: NO_INDEX,
    staticFields: [],
    instanceFields: [],
    directMethods: [],
    virtualMethods: [],
    hasClassData: false,
  })
  model.dirty = true
}

// -- Serialize (layout planner, §6.3) ---------------------------------------

class ByteSink {
  private buf: number[] = []
  get length(): number {
    return this.buf.length
  }
  u8(v: number): void {
    this.buf.push(v & 0xff)
  }
  u16(v: number): void {
    this.buf.push(v & 0xff, (v >>> 8) & 0xff)
  }
  u32(v: number): void {
    this.buf.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff)
  }
  uleb(v: number): void {
    for (const b of writeUleb128(v)) this.buf.push(b)
  }
  bytes(arr: number[]): void {
    for (const b of arr) this.buf.push(b)
  }
  align4(): void {
    while (this.buf.length % 4 !== 0) this.buf.push(0x00)
  }
  toArray(): number[] {
    return this.buf
  }
}

function compareStr(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function remapInsns(insns: Uint16Array, maps: {
  str: number[]
  type: number[]
  field: number[]
  method: number[]
}): Uint16Array {
  const out = insns.slice()
  let pc = 0
  const n = out.length
  while (pc < n) {
    const unit = out[pc]!
    const op = unit & 0xff
    // Switch / fill-array-data payloads masquerade as opcode 0x00 with a nonzero high byte.
    if (op === 0x00 && unit !== 0x0000) {
      const ident = unit
      if (ident === 0x0100) {
        pc += (out[pc + 1]! * 2) + 4 // packed-switch-payload
      } else if (ident === 0x0200) {
        pc += (out[pc + 1]! * 4) + 2 // sparse-switch-payload
      } else if (ident === 0x0300) {
        const elementWidth = out[pc + 1]!
        const size = out[pc + 2]! | (out[pc + 3]! << 16)
        const dataUnits = Math.ceil((size * elementWidth) / 2)
        pc += 4 + dataUnits // fill-array-data-payload
      } else {
        throw dexError("DEX_UNKNOWN_PAYLOAD", "未知的内联数据载荷", `ident=0x${ident.toString(16)}。`)
      }
      continue
    }
    const width = WIDTH[op]!
    if (width === 0) {
      throw dexError("DEX_UNSUPPORTED_OPCODE", "遇到暂不支持的指令", `opcode=0x${op.toString(16)}，为安全起见拒绝改写。`)
    }
    const ref = REF[op]!
    if (ref === 5) {
      const old = out[pc + 1]! | (out[pc + 2]! << 16)
      const mapped = maps.str[old]!
      out[pc + 1] = mapped & 0xffff
      out[pc + 2] = (mapped >>> 16) & 0xffff
    } else if (ref !== 0) {
      const old = out[pc + 1]!
      const table = ref === 1 ? maps.str : ref === 2 ? maps.type : ref === 3 ? maps.field : maps.method
      out[pc + 1] = table[old]!
    }
    pc += width
  }
  return out
}

// Walk a code_item's instructions and return the string_ids indices referenced by
// const-string (0x1a) and const-string/jumbo (0x1b). Reuses the WIDTH/REF/payload
// logic so PC advancement stays correct across every supported opcode. Used by the
// M3 string-encryption safe-subset builder (§8.2). Fails closed on unsupported ops.
export function collectStringOperands(insns: Uint16Array): number[] {
  const out: number[] = []
  let pc = 0
  const n = insns.length
  while (pc < n) {
    const unit = insns[pc]!
    const op = unit & 0xff
    if (op === 0x00 && unit !== 0x0000) {
      const ident = unit
      if (ident === 0x0100) pc += insns[pc + 1]! * 2 + 4
      else if (ident === 0x0200) pc += insns[pc + 1]! * 4 + 2
      else if (ident === 0x0300) {
        const elementWidth = insns[pc + 1]!
        const size = insns[pc + 2]! | (insns[pc + 3]! << 16)
        pc += 4 + Math.ceil((size * elementWidth) / 2)
      } else throw dexError("DEX_UNKNOWN_PAYLOAD", "未知的内联数据载荷", `ident=0x${ident.toString(16)}。`)
      continue
    }
    const width = WIDTH[op]!
    if (width === 0) {
      throw dexError("DEX_UNSUPPORTED_OPCODE", "遇到暂不支持的指令", `opcode=0x${op.toString(16)}，为安全起见拒绝改写。`)
    }
    const ref = REF[op]!
    if (ref === 1) out.push(insns[pc + 1]!)
    else if (ref === 5) out.push(insns[pc + 1]! | (insns[pc + 2]! << 16))
    pc += width
  }
  return out
}

export function serializeDexTables(model: DexTables): Uint8Array {
  const S = model.strings.length
  const T = model.types.length
  const P = model.protos.length
  const F = model.fields.length
  const M = model.methods.length
  const C = model.classes.length

  // 1) Sort each index table and build old->new maps (§3.2 invariants).
  const strOrder = [...Array(S).keys()].sort((a, b) => compareStr(model.strings[a]!, model.strings[b]!))
  const strNew = new Array<number>(S)
  const newStrings = new Array<string>(S)
  for (let k = 0; k < S; k += 1) {
    strNew[strOrder[k]!] = k
    newStrings[k] = model.strings[strOrder[k]!]!
  }

  const typeVal = (t: number): string => model.strings[model.types[t]!]!
  const typeOrder = [...Array(T).keys()].sort((a, b) => compareStr(typeVal(a), typeVal(b)))
  const typeNew = new Array<number>(T)
  for (let k = 0; k < T; k += 1) typeNew[typeOrder[k]!] = k

  const cmpTypeIdxList = (a: number[], b: number[]): number => {
    const len = Math.min(a.length, b.length)
    for (let i = 0; i < len; i += 1) {
      const d = typeNew[a[i]!]! - typeNew[b[i]!]!
      if (d !== 0) return d
    }
    return a.length - b.length
  }
  const protoOrder = [...Array(P).keys()].sort((a, b) => {
    const pa = model.protos[a]!
    const pb = model.protos[b]!
    const d = typeNew[pa.returnTypeIdx]! - typeNew[pb.returnTypeIdx]!
    if (d !== 0) return d
    return cmpTypeIdxList(pa.paramTypeIdxs, pb.paramTypeIdxs)
  })
  const protoNew = new Array<number>(P)
  for (let k = 0; k < P; k += 1) protoNew[protoOrder[k]!] = k

  const fieldOrder = [...Array(F).keys()].sort((a, b) => {
    const fa = model.fields[a]!
    const fb = model.fields[b]!
    return (
      typeNew[fa.classIdx]! - typeNew[fb.classIdx]! ||
      strNew[fa.nameIdx]! - strNew[fb.nameIdx]! ||
      typeNew[fa.typeIdx]! - typeNew[fb.typeIdx]!
    )
  })
  const fieldNew = new Array<number>(F)
  for (let k = 0; k < F; k += 1) fieldNew[fieldOrder[k]!] = k

  const methodOrder = [...Array(M).keys()].sort((a, b) => {
    const ma = model.methods[a]!
    const mb = model.methods[b]!
    return (
      typeNew[ma.classIdx]! - typeNew[mb.classIdx]! ||
      strNew[ma.nameIdx]! - strNew[mb.nameIdx]! ||
      protoNew[ma.protoIdx]! - protoNew[mb.protoIdx]!
    )
  })
  const methodNew = new Array<number>(M)
  for (let k = 0; k < M; k += 1) methodNew[methodOrder[k]!] = k

  const maps = { str: strNew, type: typeNew, field: fieldNew, method: methodNew }

  // 2) Fixed-region offsets (all section sizes are multiples of 4).
  let cursor = HEADER_SIZE
  const stringIdsOff = cursor
  cursor += 4 * S
  const typeIdsOff = cursor
  cursor += 4 * T
  const protoIdsOff = cursor
  cursor += 12 * P
  const fieldIdsOff = cursor
  cursor += 8 * F
  const methodIdsOff = cursor
  cursor += 8 * M
  const classDefsOff = cursor
  cursor += 32 * C
  const dataStart = cursor

  // 3) Build the data region, assigning offsets as we go.
  const sink = new ByteSink()
  const typeListOffByKey = new Map<string, number>()
  let typeListSectionOff = 0
  let typeListCount = 0
  const internTypeList = (typeIdxsOld: number[]): number => {
    if (typeIdxsOld.length === 0) return 0
    const mapped = typeIdxsOld.map((t) => typeNew[t]!)
    const key = mapped.join(",")
    const existing = typeListOffByKey.get(key)
    if (existing !== undefined) return existing
    sink.align4()
    const off = dataStart + sink.length
    if (typeListSectionOff === 0) typeListSectionOff = off
    sink.u32(mapped.length)
    for (const t of mapped) sink.u16(t)
    typeListOffByKey.set(key, off)
    typeListCount += 1
    return off
  }

  const protoParamOff = new Array<number>(P)
  for (let k = 0; k < P; k += 1) protoParamOff[k] = internTypeList(model.protos[protoOrder[k]!]!.paramTypeIdxs)
  const classInterfacesOff = new Array<number>(C)
  for (let c = 0; c < C; c += 1) classInterfacesOff[c] = internTypeList(model.classes[c]!.interfaces)

  // code_items
  let codeSectionOff = 0
  let codeCount = 0
  const methodCodeOff = new Map<EncodedMethodRec, number>()
  for (const clazz of model.classes) {
    for (const m of [...clazz.directMethods, ...clazz.virtualMethods]) {
      if (!m.code) continue
      sink.align4()
      const off = dataStart + sink.length
      if (codeSectionOff === 0) codeSectionOff = off
      const remapped = remapInsns(m.code.insns, maps)
      sink.u16(m.code.registersSize)
      sink.u16(m.code.insSize)
      sink.u16(m.code.outsSize)
      sink.u16(0) // tries_size
      sink.u32(0) // debug_info_off
      sink.u32(remapped.length)
      for (const unit of remapped) sink.u16(unit)
      methodCodeOff.set(m, off)
      codeCount += 1
    }
  }

  // class_data
  let classDataSectionOff = 0
  let classDataCount = 0
  const classDataOff = new Array<number>(C).fill(0)
  const remapFields = (list: EncodedFieldRec[]): EncodedFieldRec[] =>
    list.map((f) => ({ fieldIdx: fieldNew[f.fieldIdx]!, accessFlags: f.accessFlags })).sort((a, b) => a.fieldIdx - b.fieldIdx)
  const remapMethods = (list: EncodedMethodRec[]): Array<{ methodIdx: number; accessFlags: number; codeOff: number }> =>
    list
      .map((m) => ({ methodIdx: methodNew[m.methodIdx]!, accessFlags: m.accessFlags, codeOff: m.code ? methodCodeOff.get(m)! : 0 }))
      .sort((a, b) => a.methodIdx - b.methodIdx)
  const emitEncodedFields = (list: EncodedFieldRec[]): void => {
    let prev = 0
    for (const f of list) {
      sink.uleb(f.fieldIdx - prev)
      sink.uleb(f.accessFlags)
      prev = f.fieldIdx
    }
  }
  const emitEncodedMethods = (list: Array<{ methodIdx: number; accessFlags: number; codeOff: number }>): void => {
    let prev = 0
    for (const m of list) {
      sink.uleb(m.methodIdx - prev)
      sink.uleb(m.accessFlags)
      sink.uleb(m.codeOff)
      prev = m.methodIdx
    }
  }
  for (let c = 0; c < C; c += 1) {
    const clazz = model.classes[c]!
    if (!clazz.hasClassData) continue
    const off = dataStart + sink.length
    if (classDataSectionOff === 0) classDataSectionOff = off
    const sf = remapFields(clazz.staticFields)
    const inf = remapFields(clazz.instanceFields)
    const dm = remapMethods(clazz.directMethods)
    const vm = remapMethods(clazz.virtualMethods)
    sink.uleb(sf.length)
    sink.uleb(inf.length)
    sink.uleb(dm.length)
    sink.uleb(vm.length)
    emitEncodedFields(sf)
    emitEncodedFields(inf)
    emitEncodedMethods(dm)
    emitEncodedMethods(vm)
    classDataOff[c] = off
    classDataCount += 1
  }

  // string_data
  const stringDataOff = new Array<number>(S)
  const stringDataSectionOff = dataStart + sink.length
  for (let k = 0; k < S; k += 1) {
    stringDataOff[k] = dataStart + sink.length
    sink.uleb(newStrings[k]!.length)
    sink.bytes(encodeString(newStrings[k]!))
    sink.u8(0x00)
  }

  // map_list
  sink.align4()
  const mapOff = dataStart + sink.length
  const mapEntries: Array<{ type: number; size: number; offset: number }> = [
    { type: MAP_HEADER, size: 1, offset: 0 },
    { type: MAP_STRING_ID, size: S, offset: stringIdsOff },
    { type: MAP_TYPE_ID, size: T, offset: typeIdsOff },
    { type: MAP_PROTO_ID, size: P, offset: protoIdsOff },
    { type: MAP_FIELD_ID, size: F, offset: fieldIdsOff },
    { type: MAP_METHOD_ID, size: M, offset: methodIdsOff },
    { type: MAP_CLASS_DEF, size: C, offset: classDefsOff },
  ]
  if (typeListCount > 0) mapEntries.push({ type: MAP_TYPE_LIST, size: typeListCount, offset: typeListSectionOff })
  if (codeCount > 0) mapEntries.push({ type: MAP_CODE_ITEM, size: codeCount, offset: codeSectionOff })
  if (classDataCount > 0) mapEntries.push({ type: MAP_CLASS_DATA, size: classDataCount, offset: classDataSectionOff })
  mapEntries.push({ type: MAP_STRING_DATA, size: S, offset: stringDataSectionOff })
  mapEntries.push({ type: MAP_MAP_LIST, size: 1, offset: mapOff })
  mapEntries.sort((a, b) => a.offset - b.offset)
  sink.u32(mapEntries.length)
  for (const e of mapEntries) {
    sink.u16(e.type)
    sink.u16(0)
    sink.u32(e.size)
    sink.u32(e.offset)
  }

  const dataBytes = sink.toArray()
  const fileSize = dataStart + dataBytes.length
  const out = new Uint8Array(fileSize)
  const view = new DataView(out.buffer)

  // 4) Header + fixed tables.
  out.set(DEX_MAGIC, 0)
  out[4] = model.version.charCodeAt(0)
  out[5] = model.version.charCodeAt(1)
  out[6] = model.version.charCodeAt(2)
  out[7] = 0x00
  view.setUint32(0x20, fileSize, true)
  view.setUint32(0x24, HEADER_SIZE, true)
  view.setUint32(0x28, ENDIAN_TAG, true)
  view.setUint32(0x2c, 0, true) // link_size
  view.setUint32(0x30, 0, true) // link_off
  view.setUint32(0x34, mapOff, true)
  view.setUint32(0x38, S, true)
  view.setUint32(0x3c, S === 0 ? 0 : stringIdsOff, true)
  view.setUint32(0x40, T, true)
  view.setUint32(0x44, T === 0 ? 0 : typeIdsOff, true)
  view.setUint32(0x48, P, true)
  view.setUint32(0x4c, P === 0 ? 0 : protoIdsOff, true)
  view.setUint32(0x50, F, true)
  view.setUint32(0x54, F === 0 ? 0 : fieldIdsOff, true)
  view.setUint32(0x58, M, true)
  view.setUint32(0x5c, M === 0 ? 0 : methodIdsOff, true)
  view.setUint32(0x60, C, true)
  view.setUint32(0x64, C === 0 ? 0 : classDefsOff, true)
  view.setUint32(0x68, fileSize - dataStart, true)
  view.setUint32(0x6c, dataStart, true)

  for (let k = 0; k < S; k += 1) view.setUint32(stringIdsOff + k * 4, stringDataOff[k]!, true)
  for (let k = 0; k < T; k += 1) view.setUint32(typeIdsOff + k * 4, strNew[model.types[typeOrder[k]!]!]!, true)
  for (let k = 0; k < P; k += 1) {
    const p = model.protos[protoOrder[k]!]!
    const base = protoIdsOff + k * 12
    view.setUint32(base, strNew[p.shortyIdx]!, true)
    view.setUint32(base + 4, typeNew[p.returnTypeIdx]!, true)
    view.setUint32(base + 8, protoParamOff[k]!, true)
  }
  for (let k = 0; k < F; k += 1) {
    const f = model.fields[fieldOrder[k]!]!
    const base = fieldIdsOff + k * 8
    view.setUint16(base, typeNew[f.classIdx]!, true)
    view.setUint16(base + 2, typeNew[f.typeIdx]!, true)
    view.setUint32(base + 4, strNew[f.nameIdx]!, true)
  }
  for (let k = 0; k < M; k += 1) {
    const m = model.methods[methodOrder[k]!]!
    const base = methodIdsOff + k * 8
    view.setUint16(base, typeNew[m.classIdx]!, true)
    view.setUint16(base + 2, protoNew[m.protoIdx]!, true)
    view.setUint32(base + 4, strNew[m.nameIdx]!, true)
  }
  for (let c = 0; c < C; c += 1) {
    const clazz = model.classes[c]!
    const base = classDefsOff + c * 32
    view.setUint32(base, typeNew[clazz.classIdx]!, true)
    view.setUint32(base + 4, clazz.accessFlags, true)
    view.setUint32(base + 8, clazz.superclassIdx === NO_INDEX ? NO_INDEX : typeNew[clazz.superclassIdx]!, true)
    view.setUint32(base + 12, classInterfacesOff[c]!, true)
    view.setUint32(base + 16, clazz.sourceFileIdx === NO_INDEX ? NO_INDEX : strNew[clazz.sourceFileIdx]!, true)
    view.setUint32(base + 20, 0, true) // annotations_off
    view.setUint32(base + 24, clazz.hasClassData ? classDataOff[c]! : 0, true)
    view.setUint32(base + 28, 0, true) // static_values_off
  }

  out.set(Uint8Array.from(dataBytes), dataStart)
  return recomputeDexChecksums(out)
}
