// Pure-TypeScript ELF hardening scanner for Android native libraries (.so).
// No external dependencies. Parses the ELF header, program headers and the
// PT_DYNAMIC segment to infer common hardening properties. Symbol-name based
// checks (stack canary / FORTIFY) use a byte scan of the file, which is a
// reasonable proxy for .dynstr contents without full section parsing.

import type { Finding } from "./types.ts"

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46] // \x7fELF

const PT_LOAD = 1
const PT_DYNAMIC = 2
const PT_GNU_STACK = 0x6474e551
const PT_GNU_RELRO = 0x6474e552
const PF_X = 0x1

const DT_NULL = 0
const DT_BIND_NOW = 24
const DT_FLAGS = 30
const DT_TEXTREL = 22
const DT_FLAGS_1 = 0x6ffffffb
const DF_BIND_NOW = 0x8
const DF_TEXTREL = 0x4
const DF_1_NOW = 0x1

export type RelroLevel = "none" | "partial" | "full"

export interface ElfHardening {
  bits: 32 | 64
  executableStack: boolean
  relro: RelroLevel
  stackCanary: boolean
  fortify: boolean
  textRelocations: boolean
}

function bytesContainAscii(bytes: Uint8Array, needle: string): boolean {
  const target = new TextEncoder().encode(needle)
  if (target.length === 0 || bytes.length < target.length) return false
  const first = target[0]!
  const limit = bytes.length - target.length
  for (let i = 0; i <= limit; i += 1) {
    if (bytes[i] !== first) continue
    let matched = true
    for (let j = 1; j < target.length; j += 1) {
      if (bytes[i + j] !== target[j]) {
        matched = false
        break
      }
    }
    if (matched) return true
  }
  return false
}

// Parse an ELF buffer and infer hardening properties. Throws when the buffer is
// not a valid ELF container (bad magic / truncated header).
export function analyzeElf(bytes: Uint8Array): ElfHardening {
  if (bytes.length < 64) throw new Error("elf too small")
  for (let i = 0; i < ELF_MAGIC.length; i += 1) {
    if (bytes[i] !== ELF_MAGIC[i]) throw new Error("not an elf file")
  }
  const eiClass = bytes[4]
  const eiData = bytes[5]
  const is64 = eiClass === 2
  const little = eiData !== 2 // 1 = LE, 2 = BE; default to LE
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)

  const readU32 = (offset: number) => view.getUint32(offset, little)
  // Program header table location differs between ELF32 and ELF64.
  const phoff = is64 ? Number(view.getBigUint64(0x20, little)) : readU32(0x1c)
  const phentsize = view.getUint16(is64 ? 0x36 : 0x2a, little)
  const phnum = view.getUint16(is64 ? 0x38 : 0x2c, little)

  let executableStack = false
  let hasRelro = false
  let dynamicOffset = -1
  let dynamicSize = 0

  for (let i = 0; i < phnum; i += 1) {
    const base = phoff + i * phentsize
    if (base + phentsize > bytes.length) break
    const pType = readU32(base)
    if (is64) {
      const pFlags = readU32(base + 4)
      const pOffset = Number(view.getBigUint64(base + 8, little))
      const pFilesz = Number(view.getBigUint64(base + 32, little))
      if (pType === PT_GNU_STACK && (pFlags & PF_X) !== 0) executableStack = true
      if (pType === PT_GNU_RELRO) hasRelro = true
      if (pType === PT_DYNAMIC) {
        dynamicOffset = pOffset
        dynamicSize = pFilesz
      }
    } else {
      const pOffset = readU32(base + 4)
      const pFilesz = readU32(base + 16)
      const pFlags = readU32(base + 24)
      if (pType === PT_GNU_STACK && (pFlags & PF_X) !== 0) executableStack = true
      if (pType === PT_GNU_RELRO) hasRelro = true
      if (pType === PT_DYNAMIC) {
        dynamicOffset = pOffset
        dynamicSize = pFilesz
      }
    }
    void PT_LOAD
  }

  let bindNow = false
  let textRelocations = false
  if (dynamicOffset >= 0) {
    const entrySize = is64 ? 16 : 8
    const maxEntries = Math.min(4096, Math.floor(dynamicSize / entrySize) || 4096)
    for (let i = 0; i < maxEntries; i += 1) {
      const base = dynamicOffset + i * entrySize
      if (base + entrySize > bytes.length) break
      // Read the low 32 bits of tag/value; ELF tags and the flags we care about fit.
      const tag = readU32(base)
      const valOffset = is64 ? base + 8 : base + 4
      const val = readU32(valOffset)
      if (tag === DT_NULL) break
      if (tag === DT_BIND_NOW) bindNow = true
      if (tag === DT_TEXTREL) textRelocations = true
      if (tag === DT_FLAGS) {
        if ((val & DF_BIND_NOW) !== 0) bindNow = true
        if ((val & DF_TEXTREL) !== 0) textRelocations = true
      }
      if (tag === DT_FLAGS_1 && (val & DF_1_NOW) !== 0) bindNow = true
    }
  }

  const relro: RelroLevel = !hasRelro ? "none" : bindNow ? "full" : "partial"
  const stackCanary = bytesContainAscii(bytes, "__stack_chk_fail")
  const fortify = bytesContainAscii(bytes, "_chk")

  return {
    bits: is64 ? 64 : 32,
    executableStack,
    relro,
    stackCanary,
    fortify,
    textRelocations,
  }
}

// Map hardening gaps of a single native library to findings.
export function buildSoFindings(library: string, hardening: ElfHardening): Finding[] {
  const findings: Finding[] = []
  if (hardening.executableStack) {
    findings.push({
      severity: "medium",
      code: "SO_EXECUTABLE_STACK",
      title: "Native 库启用了可执行栈",
      detail: `${library} 的 PT_GNU_STACK 段带可执行标志。可执行栈会削弱 NX/DEP 保护，为栈溢出利用提供便利。`,
      recommendation: "重新编译时移除可执行栈需求（避免嵌套函数/内联汇编触发），链接时确保 -z noexecstack。",
      evidence: library,
    })
  }
  if (hardening.relro === "none") {
    findings.push({
      severity: "low",
      code: "SO_NO_RELRO",
      title: "Native 库缺少 RELRO",
      detail: `${library} 未发现 PT_GNU_RELRO 段。GOT/重定位区可写，增加了 GOT 覆写利用面。`,
      recommendation: "链接时启用完整 RELRO：-Wl,-z,relro,-z,now。",
      evidence: library,
    })
  } else if (hardening.relro === "partial") {
    findings.push({
      severity: "info",
      code: "SO_PARTIAL_RELRO",
      title: "Native 库仅部分 RELRO",
      detail: `${library} 有 RELRO 段但未标记 BIND_NOW，属部分 RELRO，GOT 仍可能延迟绑定后被覆写。`,
      recommendation: "启用完整 RELRO：链接时加 -z now（配合 -z relro）。",
      evidence: library,
    })
  }
  if (!hardening.stackCanary) {
    findings.push({
      severity: "low",
      code: "SO_NO_STACK_CANARY",
      title: "Native 库疑似未启用栈保护",
      detail: `${library} 未发现 __stack_chk_fail 符号（启发式）。缺少栈金丝雀会降低对栈溢出的检测能力。`,
      recommendation: "编译时启用 -fstack-protector-strong。",
      evidence: library,
    })
  }
  if (!hardening.fortify) {
    findings.push({
      severity: "info",
      code: "SO_NO_FORTIFY",
      title: "Native 库疑似未启用 FORTIFY_SOURCE",
      detail: `${library} 未发现 *_chk 加固符号（启发式）。FORTIFY_SOURCE 可在编译期/运行期捕获部分缓冲区溢出。`,
      recommendation: "编译时启用 -D_FORTIFY_SOURCE=2（release 优化级别下生效）。",
      evidence: library,
    })
  }
  if (hardening.textRelocations) {
    findings.push({
      severity: "medium",
      code: "SO_TEXT_RELOCATIONS",
      title: "Native 库存在文本重定位",
      detail: `${library} 含 DT_TEXTREL/DF_TEXTREL。文本重定位要求代码段可写，破坏 W^X，并在新版 Android 上可能被拒绝加载。`,
      recommendation: "编译为位置无关代码（-fPIC）以消除文本重定位。",
      evidence: library,
    })
  }
  return findings
}
