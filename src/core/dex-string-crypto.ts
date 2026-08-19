// #3 DEX 字符串加密 — 安全子集选取 + 轻量对称密码 + 加密计划（M3，见
// docs/dex-write-engine.md §8）。
//
// 交付「自动化核心」：§8.2 的安全子集构建（可加密集 = 字面量串 − 标识符串）
// 与 §8.4 的密钥/密码原语（XOR + 位旋转、crypto.getRandomValues 随机密钥、
// 非密钥指纹），并产出一份**不改写字节码**的加密计划（哪些 string_ids 可加密、
// 各自密文、密钥指纹、统计）。
//
// fail-closed：§8.3 的 code_item 深度重写（把每处 const-string 改写为
// const #idx + invoke-static 解密器 + move-result，并因插入指令而做寄存器重
// 分配与分支/switch 偏移全量修正）属研究级、失败面最大的一步，本模块**不自动
// 施加**该重写——只产出可审计的计划与可往返验证的密文，避免产出"装得上但运行
// 崩"的 DEX。真机运行时解密（Stage B）随解密器注入接线与人工冒烟推进。

import { collectStringOperands, type DexTables, NO_INDEX } from "./dex-writer.ts"
import type { Finding } from "./types.ts"

// -- 密码原语（§8.4）--------------------------------------------------------

// 每包随机对称密钥。crypto.getRandomValues（非 Math.random），长度默认 16 字节。
export function generateKey(length = 16): Uint8Array {
  const key = new Uint8Array(length)
  crypto.getRandomValues(key)
  return key
}

function rotl8(v: number, r: number): number {
  const x = v & 0xff
  return ((x << r) | (x >>> (8 - r))) & 0xff
}
function rotr8(v: number, r: number): number {
  const x = v & 0xff
  return ((x >>> r) | (x << (8 - r))) & 0xff
}

// UTF-8 字节流上的可逆变换：encrypt = XOR(key) 后 rotl；decrypt = rotr 后 XOR(key)。
// 旋转量随位置变化 (i%7)+1，避免整段同一旋转；密钥按位置循环。
export function encryptBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i += 1) {
    const r = (i % 7) + 1
    out[i] = rotl8(data[i]! ^ key[i % key.length]!, r)
  }
  return out
}
export function decryptBytes(data: Uint8Array, key: Uint8Array): Uint8Array {
  const out = new Uint8Array(data.length)
  for (let i = 0; i < data.length; i += 1) {
    const r = (i % 7) + 1
    out[i] = rotr8(data[i]!, r) ^ key[i % key.length]!
  }
  return out
}

export function encryptString(text: string, key: Uint8Array): Uint8Array {
  return encryptBytes(new TextEncoder().encode(text), key)
}
export function decryptToString(data: Uint8Array, key: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(decryptBytes(data, key))
}

// 非密钥指纹：SHA-256(key) 的前 16 个十六进制字符，供报告/备份元数据关联而不泄露密钥。
export function keyFingerprint(key: Uint8Array): string {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(key)
  return hasher.digest("hex").slice(0, 16)
}

// -- 安全子集构建（§8.2）----------------------------------------------------

// 所有被当作“标识符”引用的 string_idx：类型描述符、proto shorty、字段名、方法名、
// 源文件名。加密这些会破坏类加载/反射，绝对排除。
export function computeIdentifierStrings(tables: DexTables): Set<number> {
  const ids = new Set<number>()
  for (const s of tables.types) ids.add(s) // 每个 type -> 描述符 string_idx
  for (const p of tables.protos) ids.add(p.shortyIdx)
  for (const f of tables.fields) ids.add(f.nameIdx)
  for (const m of tables.methods) ids.add(m.nameIdx)
  for (const c of tables.classes) {
    if (c.sourceFileIdx !== NO_INDEX) ids.add(c.sourceFileIdx)
  }
  return ids
}

// 所有 const-string / const-string/jumbo 操作数引用的 string_idx（字面量集）。
export function computeLiteralStrings(tables: DexTables): Set<number> {
  const lits = new Set<number>()
  for (const c of tables.classes) {
    for (const m of [...c.directMethods, ...c.virtualMethods]) {
      if (!m.code) continue
      for (const idx of collectStringOperands(m.code.insns)) lits.add(idx)
    }
  }
  return lits
}

// 可加密集 = 字面量集 − 标识符集（升序 string_idx 列表）。
export function computeEncryptableStrings(tables: DexTables): number[] {
  const ids = computeIdentifierStrings(tables)
  const lits = computeLiteralStrings(tables)
  const out: number[] = []
  for (const idx of lits) {
    if (!ids.has(idx)) out.push(idx)
  }
  return out.sort((a, b) => a - b)
}

// -- 加密计划（不改写字节码）------------------------------------------------

export interface StringEncryptionOptions {
  // 显式复用同一密钥（默认每次随机生成）。
  key?: Uint8Array
  // 可选“疑似敏感”过滤：仅对返回 true 的明文加密（复用 secret-scan/dex-scan 启发式）。
  filter?: (plaintext: string) => boolean
}

export interface StringEncryptionEntry {
  stringIndex: number
  plaintext: string
  ciphertext: Uint8Array
}

export interface StringEncryptionPlan {
  key: Uint8Array
  keyFingerprint: string
  entries: StringEncryptionEntry[]
  literalCount: number
  identifierCount: number
  encryptableCount: number
  findings: Finding[]
}

// 产出加密计划：选出安全子集、生成/复用密钥、逐串加密（保留可往返的密文）。
// 不修改传入的 DexTables，也不产出加密后的 DEX 字节（§8.3 的深度重写留待接线）。
export function planStringEncryption(
  tables: DexTables,
  options: StringEncryptionOptions = {},
): StringEncryptionPlan {
  const key = options.key ?? generateKey()
  const identifiers = computeIdentifierStrings(tables)
  const literals = computeLiteralStrings(tables)

  const entries: StringEncryptionEntry[] = []
  const sorted = [...literals].filter((idx) => !identifiers.has(idx)).sort((a, b) => a - b)
  for (const stringIndex of sorted) {
    const plaintext = tables.strings[stringIndex]!
    if (options.filter && !options.filter(plaintext)) continue
    entries.push({ stringIndex, plaintext, ciphertext: encryptString(plaintext, key) })
  }

  const fingerprint = keyFingerprint(key)
  const findings: Finding[] = [
    {
      severity: "info",
      code: "LOSSY_DEX_STRINGS_PLANNED",
      title: "已生成 DEX 字符串加密计划（安全子集，未改写字节码）",
      detail:
        `DroidSeal 从 ${literals.size} 个字面量串中排除了同时作标识符的部分，选出 ${entries.length} 个可加密串` +
        `（密钥指纹 ${fingerprint}）。标识符串（类/方法/字段名、proto shorty、源文件名）一律保留，不加密。` +
        `密文可用相同密钥往返还原。运行时解密所需的解密器注入与每处 const-string 深度重写（含寄存器重分配、` +
        `分支/switch 偏移修正）为研究级步骤，本步骤不自动施加以避免产出"装得上但运行崩"的包。`,
      recommendation:
        "纯客户端加密的解密逻辑与密文同处明文 DEX，仅抬高静态扫描成本、非强保护；如需运行时解密请结合解密器注入接线并做真机冒烟。",
    },
  ]

  return {
    key,
    keyFingerprint: fingerprint,
    entries,
    literalCount: literals.size,
    identifierCount: identifiers.size,
    encryptableCount: entries.length,
    findings,
  }
}
