import { describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  auditApkNetworkSecurityConfig,
  nscEntryName,
  parseAxmlTree,
  reconstructXml,
} from "../src/core/axml-nsc.ts"
import { parseAxml } from "../src/core/axml-writer.ts"
import { extractApkEntryBytes } from "../src/core/apk-strip.ts"
import { buildZip, crc32Of, type OutEntry } from "../src/core/harden-manifest.ts"

// Build a real binary AXML for a Network Security Config, reusing the same chunk
// layout as the proven lossy-inject AXML builder (validated against aapt2 output).
const N = 0xffffffff

function buildNscXml(): Uint8Array {
  const strings = [
    "name",
    "http://schemas.android.com/apk/res/android",
    "android",
    "base-config",
    "trust-anchors",
    "certificates",
    "domain-config",
    "domain",
    "pin-set",
    "pin",
    "debug-overrides",
    "cleartextTrafficPermitted",
    "src",
    "user",
    "includeSubdomains",
    "true",
    "expiration",
    "2024-01-01",
    "digest",
    "sha256",
    "abc123=",
    "example.com",
  ]
  // string index helper
  const s = (name: string) => strings.indexOf(name)

  const enc = new TextEncoder()
  const offsets: number[] = []
  const data: number[] = []
  for (const str of strings) {
    offsets.push(data.length)
    const utf8 = enc.encode(str)
    data.push(str.length, utf8.byteLength)
    for (const b of utf8) data.push(b)
    data.push(0x00)
  }
  while (data.length % 4 !== 0) data.push(0x00)
  const stringsStart = 28 + strings.length * 4
  const poolSize = stringsStart + data.length
  const pool = new Uint8Array(poolSize)
  const pv = new DataView(pool.buffer)
  pv.setUint16(0, 0x0001, true)
  pv.setUint16(2, 28, true)
  pv.setUint32(4, poolSize, true)
  pv.setUint32(8, strings.length, true)
  pv.setUint32(12, 0, true)
  pv.setUint32(16, 0x0100, true)
  pv.setUint32(20, stringsStart, true)
  pv.setUint32(24, 0, true)
  for (let i = 0; i < offsets.length; i += 1) pv.setUint32(28 + i * 4, offsets[i]!, true)
  pool.set(Uint8Array.from(data), stringsStart)

  const resMap = [0x010104e5, 0x010104e6, 0x010104e7, 0x010104e8]
  const resMapSize = 8 + resMap.length * 4
  const rm = new Uint8Array(resMapSize)
  const rmv = new DataView(rm.buffer)
  rmv.setUint16(0, 0x0180, true)
  rmv.setUint16(2, 8, true)
  rmv.setUint32(4, resMapSize, true)
  for (let i = 0; i < resMap.length; i += 1) rmv.setUint32(8 + i * 4, resMap[i]!, true)

  const attr = (
    nameIdx: number,
    dataType: number,
    dataIdx: number,
  ): Array<{ ns: number; name: number; value: number; type: number; data: number }> => [
    { ns: N, name: nameIdx, value: dataIdx, type: dataType, data: dataIdx },
  ]

  const startTag = (
    nameIdx: number,
    attrs: Array<{ ns: number; name: number; value: number; type: number; data: number }>,
  ): Uint8Array => {
    const size = 16 + 20 + attrs.length * 20
    const b = new Uint8Array(size)
    const v = new DataView(b.buffer)
    v.setUint16(0, 0x0102, true)
    v.setUint16(2, 16, true)
    v.setUint32(4, size, true)
    v.setUint32(8, 0, true)
    v.setUint32(12, N, true)
    v.setUint32(16, N, true)
    v.setUint32(20, nameIdx, true)
    v.setUint16(24, 20, true)
    v.setUint16(26, 20, true)
    v.setUint16(28, attrs.length, true)
    v.setUint16(30, 0, true)
    v.setUint16(32, 0, true)
    v.setUint16(34, 0, true)
    let a = 36
    for (const at of attrs) {
      v.setUint32(a, at.ns, true)
      v.setUint32(a + 4, at.name, true)
      v.setUint32(a + 8, at.value, true)
      v.setUint16(a + 12, 8, true)
      v.setUint8(a + 14, 0)
      v.setUint8(a + 15, at.type)
      v.setUint32(a + 16, at.type === 0x03 ? at.data : at.data === s("true") ? 0xffffffff : 0x0)
      a += 20
    }
    return b
  }
  const endTag = (nameIdx: number): Uint8Array => {
    const b = new Uint8Array(24)
    const v = new DataView(b.buffer)
    v.setUint16(0, 0x0103, true)
    v.setUint16(2, 16, true)
    v.setUint32(4, 24, true)
    v.setUint32(8, 0, true)
    v.setUint32(12, N, true)
    v.setUint32(16, N, true)
    v.setUint32(20, nameIdx, true)
    return b
  }

  // <base-config cleartextTrafficPermitted="true">
  //   <trust-anchors><certificates src="user"/></trust-anchors>
  // </base-config>
  // <domain-config>
  //   <domain includeSubdomains="true">example.com</domain>
  //   <pin-set expiration="2024-01-01">
  //     <pin digest="sha256">abc123=</pin>
  //   </pin-set>
  // </domain-config>
  // <debug-overrides>
  //   <trust-anchors><certificates src="user"/></trust-anchors>
  // </debug-overrides>
  const boolTrue = (nameIdx: number) => attr(nameIdx, 0x12, s("true"))
  const strAttr = (nameIdx: number, valueIdx: number) => attr(nameIdx, 0x03, valueIdx)

  const nodes = [
    startTag(s("base-config"), boolTrue(s("cleartextTrafficPermitted"))),
    startTag(s("trust-anchors"), []),
    startTag(s("certificates"), strAttr(s("src"), s("user"))),
    endTag(s("certificates")),
    endTag(s("trust-anchors")),
    endTag(s("base-config")),
    startTag(s("domain-config"), []),
    startTag(s("domain"), strAttr(s("includeSubdomains"), s("true"))),
    endTag(s("domain")),
    startTag(s("pin-set"), strAttr(s("expiration"), s("2024-01-01"))),
    startTag(s("pin"), strAttr(s("digest"), s("sha256"))),
    endTag(s("pin")),
    endTag(s("pin-set")),
    endTag(s("domain-config")),
    startTag(s("debug-overrides"), []),
    startTag(s("trust-anchors"), []),
    startTag(s("certificates"), strAttr(s("src"), s("user"))),
    endTag(s("certificates")),
    endTag(s("trust-anchors")),
    endTag(s("debug-overrides")),
  ]
  const tailLen = resMapSize + nodes.reduce((n, x) => n + x.byteLength, 0)
  const tail = new Uint8Array(tailLen)
  let off = 0
  tail.set(rm, off)
  off += resMapSize
  for (const n of nodes) {
    tail.set(n, off)
    off += n.byteLength
  }
  const total = 8 + poolSize + tailLen
  const out = new Uint8Array(total)
  const ov = new DataView(out.buffer)
  ov.setUint16(0, 0x0003, true)
  ov.setUint16(2, 8, true)
  ov.setUint32(4, total, true)
  out.set(pool, 8)
  out.set(tail, 8 + poolSize)
  return out
}

function storedEntry(name: string, data: Uint8Array): OutEntry {
  return {
    name,
    method: 0,
    crc32: crc32Of(data),
    compressedSize: data.byteLength,
    uncompressedSize: data.byteLength,
    flags: 0,
    data,
  }
}

describe("nscEntryName", () => {
  test("maps @xml/ and res/xml/ references to the APK entry", () => {
    expect(nscEntryName("@xml/network_security_config")).toBe("res/xml/network_security_config.xml")
    expect(nscEntryName("res/xml/network_security_config.xml")).toBe("res/xml/network_security_config.xml")
    expect(nscEntryName("@android:xml/network_security_config")).toBe("res/xml/network_security_config.xml")
  })
})

describe("parseAxmlTree + reconstructXml", () => {
  test("decodes boolean and string attribute values and rebuilds XML", () => {
    const model = parseAxml(buildNscXml())
    const tree = parseAxmlTree(model)
    const xml = reconstructXml(tree)
    expect(xml).toContain('cleartextTrafficPermitted="true"')
    expect(xml).toContain('<certificates src="user"/>')
    expect(xml).toContain('<debug-overrides>')
    expect(xml).toContain('expiration="2024-01-01"')
    expect(xml).toContain("<pin ")
  })
})

describe("auditApkNetworkSecurityConfig", () => {
  test("flags cleartext, user CA, debug overrides, weak/expired pinning", () => {
    const findings = auditApkNetworkSecurityConfig(buildNscXml(), "res/xml/network_security_config.xml")
    const codes = findings.map((f) => f.code)
    expect(codes).toContain("NSC_CLEARTEXT_PERMITTED")
    expect(codes).toContain("NSC_TRUSTS_USER_CA")
    expect(codes).toContain("NSC_DEBUG_OVERRIDES_PRESENT")
    // single pin + past expiration => weak
    expect(codes).toContain("NSC_PINNING_WEAK")
  })

  test("degrades gracefully on non-AXML input", () => {
    expect(auditApkNetworkSecurityConfig(new Uint8Array([1, 2, 3, 4]), "x")).toEqual([])
  })
})

describe("APK integration: NSC content pulled from the zip", () => {
  test("NSC resource is read back via extractApkEntryBytes and audited", async () => {
    const apk = buildZip([
      storedEntry("AndroidManifest.xml", new TextEncoder().encode("manifest")),
      storedEntry("res/xml/network_security_config.xml", buildNscXml()),
    ])
    const dir = await mkdtemp(path.join(tmpdir(), "droidseal-nsc-"))
    const apkPath = path.join(dir, "sample.apk")
    await writeFile(apkPath, apk)
    const bytes = await extractApkEntryBytes(apkPath, "res/xml/network_security_config.xml")
    expect(bytes).toBeDefined()
    const findings = auditApkNetworkSecurityConfig(bytes!, "res/xml/network_security_config.xml")
    expect(findings.map((f) => f.code)).toContain("NSC_CLEARTEXT_PERMITTED")
  })
})
