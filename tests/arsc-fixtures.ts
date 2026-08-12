// Synthetic resources.arsc builders for tests (mirror the on-disk format).

function writeUtf8Len(value: number, out: number[]): void {
  if (value > 0x7f) out.push(0x80 | (value >> 8), value & 0xff)
  else out.push(value)
}

// Build a UTF-8 ResStringPool chunk carrying the given strings (ASCII only in tests).
export function buildPool(strings: string[]): Uint8Array {
  const stringData: number[] = []
  const offsets: number[] = []
  for (const s of strings) {
    offsets.push(stringData.length)
    writeUtf8Len(s.length, stringData) // utf16 units
    writeUtf8Len(s.length, stringData) // byte length (ASCII)
    for (let i = 0; i < s.length; i += 1) stringData.push(s.charCodeAt(i))
    stringData.push(0x00)
  }
  while (stringData.length % 4 !== 0) stringData.push(0x00)

  const headerSize = 28
  const stringsStart = headerSize + strings.length * 4
  const size = stringsStart + stringData.length
  const bytes = new Uint8Array(size)
  const view = new DataView(bytes.buffer)
  view.setUint16(0, 0x0001, true)
  view.setUint16(2, headerSize, true)
  view.setUint32(4, size, true)
  view.setUint32(8, strings.length, true)
  view.setUint32(12, 0, true) // styleCount
  view.setUint32(16, 0x0100, true) // UTF8_FLAG
  view.setUint32(20, stringsStart, true)
  view.setUint32(24, 0, true) // stylesStart
  for (let i = 0; i < offsets.length; i += 1) view.setUint32(headerSize + i * 4, offsets[i]!, true)
  bytes.set(Uint8Array.from(stringData), stringsStart)
  return bytes
}

export function buildPackage(id: number, typeNames: string[], keyNames: string[], body: Uint8Array): Uint8Array {
  const headerSize = 288
  const typePool = buildPool(typeNames)
  const keyPool = buildPool(keyNames)
  const typeStrings = headerSize
  const keyStrings = headerSize + typePool.byteLength
  const size = headerSize + typePool.byteLength + keyPool.byteLength + body.byteLength

  const bytes = new Uint8Array(size)
  const view = new DataView(bytes.buffer)
  view.setUint16(0, 0x0200, true)
  view.setUint16(2, headerSize, true)
  view.setUint32(4, size, true)
  view.setUint32(8, id, true)
  view.setUint32(268, typeStrings, true)
  view.setUint32(276, keyStrings, true)
  bytes.set(typePool, typeStrings)
  bytes.set(keyPool, keyStrings)
  bytes.set(body, keyStrings + keyPool.byteLength)
  return bytes
}

export function buildArsc(globalStrings: string[], pkg: Uint8Array): Uint8Array {
  const headerSize = 12
  const globalPool = buildPool(globalStrings)
  const size = headerSize + globalPool.byteLength + pkg.byteLength
  const bytes = new Uint8Array(size)
  const view = new DataView(bytes.buffer)
  view.setUint16(0, 0x0002, true)
  view.setUint16(2, headerSize, true)
  view.setUint32(4, size, true)
  view.setUint32(8, 1, true) // packageCount
  bytes.set(globalPool, headerSize)
  bytes.set(pkg, headerSize + globalPool.byteLength)
  return bytes
}

// A minimal ResTable_type chunk with one entry whose Res_value is a string
// reference (dataType=0x03) pointing at global-pool index `stringIndex`.
// Used to exercise mode B (file-path flattening).
export function buildTypeChunkWithFileValue(typeId: number, keyIndex: number, stringIndex: number): Uint8Array {
  // ResTable_type header is 0x14 + sizeof(ResTable_config). Use a 56-byte config.
  const configSize = 56
  const headerSize = 20 + configSize
  const entryCount = 1
  const entriesStart = headerSize + entryCount * 4
  // ResTable_entry (8 bytes) + Res_value (8 bytes).
  const entryBlock = 8 + 8
  const size = entriesStart + entryBlock

  const bytes = new Uint8Array(size)
  const view = new DataView(bytes.buffer)
  view.setUint16(0, 0x0201, true) // RES_TABLE_TYPE_TYPE
  view.setUint16(2, headerSize, true)
  view.setUint32(4, size, true)
  view.setUint8(8, typeId)
  view.setUint8(9, 0) // flags
  view.setUint16(10, 0, true) // reserved
  view.setUint32(12, entryCount, true)
  view.setUint32(16, entriesStart, true)
  view.setUint32(20, configSize, true) // ResTable_config.size
  // entry offset array
  view.setUint32(headerSize, 0, true)
  // ResTable_entry
  const e = entriesStart
  view.setUint16(e, 8, true) // size
  view.setUint16(e + 2, 0, true) // flags (not complex)
  view.setUint32(e + 4, keyIndex, true) // key index
  // Res_value
  const v = e + 8
  view.setUint16(v, 8, true) // size
  view.setUint8(v + 2, 0) // res0
  view.setUint8(v + 3, 0x03) // dataType = TYPE_STRING
  view.setUint32(v + 4, stringIndex, true) // data = global string-pool index
  return bytes
}

export function sampleArsc(): Uint8Array {
  const pkg = buildPackage(
    0x7f,
    ["string", "drawable", "layout"],
    ["app_name", "ic_launcher", "activity_main"],
    new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
  )
  return buildArsc(["res/drawable/ic_launcher.png", "res/layout/activity_main.xml"], pkg)
}
