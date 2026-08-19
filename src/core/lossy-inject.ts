// #1 DEX 注入反调试 — 端到端有损加固（M4，见 docs/dex-write-engine.md §7）。
//
// 采用 §7.2 路径 (b)：不改写应用既有方法字节码，而是新建一个独立的
// classesN.dex，内含 AntiDebug.check() 与一个继承原 Application 的 Bootstrap
// 子类；再把 AndroidManifest 的 <application android:name> 重指向 Bootstrap。
// Bootstrap.onCreate 先 super.onCreate()，再调用 AntiDebug.check()。跨 dex 的
// 类型/方法引用在装载期解析，故新 DEX 完整落在 dex-writer 的受支持子集内
// （无 try/catch、无 debug_info、无注解/静态初始值）。
//
// fail-closed：若原清单缺少 <application android:name>（默认 Application 情形
// 需新增属性，M2 的 AXML 写引擎尚未支持插入新属性），或原包无法解析，均安全
// 报错回退，不产出"装得上但运行崩"的包。调用方负责随后重新对齐与签名。

import { parseAxml, readApplicationName, serializeAxml, setApplicationName } from "./axml-writer.ts"
import {
  type DexTables,
  internMethod,
  internType,
  NO_INDEX,
  serializeDexTables,
} from "./dex-writer.ts"
import { DroidSealError } from "./errors.ts"
import { buildZip, crc32Of, inflateEntry, parseRawZip, type OutEntry, type RawZipEntry } from "./harden-manifest.ts"
import type { Finding } from "./types.ts"

const MANIFEST_NAME = "AndroidManifest.xml"
const DEX_NAME_RE = /^classes(\d*)\.dex$/
const DEFAULT_BOOTSTRAP = "com.droidseal.inj.Bootstrap"
const DEFAULT_APPLICATION = "android.app.Application"

function injectError(code: string, message: string, explanation: string): DroidSealError {
  return new DroidSealError({
    code,
    message,
    explanation,
    suggestions: ["确认传入的是标准 APK", "该包含本引擎暂不支持的结构时会安全回退，不改写原包"],
    stepId: "harden",
  })
}

function dottedToDescriptor(name: string): string {
  return `L${name.replace(/\./g, "/")};`
}

function newDexModel(): DexTables {
  return { version: "035", strings: [], types: [], protos: [], fields: [], methods: [], classes: [], dirty: false }
}

// Build a fresh single-DEX blob containing:
//   Lcom/droidseal/inj/AntiDebug;  static check()V -> Debug.isDebuggerConnected()
//   <bootstrapDescriptor> extends <superAppDescriptor> with <init>()V + onCreate()V
// The bytecode uses only invoke-* / move-result / return-void, all inside the
// dex-writer supported subset. Cross-dex refs (Debug, the super Application)
// resolve at load time.
export function buildAntiDebugDex(bootstrapDescriptor: string, superAppDescriptor: string): Uint8Array {
  const m = newDexModel()

  // -- Lcom/droidseal/inj/AntiDebug; ----------------------------------------
  const antiDebugType = internType(m, "Lcom/droidseal/inj/AntiDebug;")
  const isDebuggerConnected = internMethod(m, "Landroid/os/Debug;", "isDebuggerConnected", "Z", [])
  const checkMethod = internMethod(m, "Lcom/droidseal/inj/AntiDebug;", "check", "V", [])
  // invoke-static {}, Debug.isDebuggerConnected()Z ; move-result v0 ; return-void
  const checkInsns = Uint16Array.from([
    0x0071, isDebuggerConnected, 0x0000,
    0x000a,
    0x000e,
  ])
  m.classes.push({
    classIdx: antiDebugType,
    accessFlags: 0x1, // public
    superclassIdx: internType(m, "Ljava/lang/Object;"),
    interfaces: [],
    sourceFileIdx: NO_INDEX,
    staticFields: [],
    instanceFields: [],
    directMethods: [
      { methodIdx: checkMethod, accessFlags: 0x9, code: { registersSize: 1, insSize: 0, outsSize: 0, insns: checkInsns } },
    ],
    virtualMethods: [],
    hasClassData: true,
  })

  // -- Bootstrap extends the app's original Application ----------------------
  const bootstrapType = internType(m, bootstrapDescriptor)
  const superType = internType(m, superAppDescriptor)
  const superInit = internMethod(m, superAppDescriptor, "<init>", "V", [])
  const superOnCreate = internMethod(m, superAppDescriptor, "onCreate", "V", [])
  const checkRef = internMethod(m, "Lcom/droidseal/inj/AntiDebug;", "check", "V", [])
  const bootstrapInit = internMethod(m, bootstrapDescriptor, "<init>", "V", [])
  const bootstrapOnCreate = internMethod(m, bootstrapDescriptor, "onCreate", "V", [])
  // <init>()V: invoke-direct {v0}, super.<init>()V ; return-void
  const initInsns = Uint16Array.from([
    0x1070, superInit, 0x0000,
    0x000e,
  ])
  // onCreate()V: invoke-super {v0}, super.onCreate()V ; invoke-static {}, check()V ; return-void
  const onCreateInsns = Uint16Array.from([
    0x106f, superOnCreate, 0x0000,
    0x0071, checkRef, 0x0000,
    0x000e,
  ])
  m.classes.push({
    classIdx: bootstrapType,
    accessFlags: 0x1, // public
    superclassIdx: superType,
    interfaces: [],
    sourceFileIdx: NO_INDEX,
    staticFields: [],
    instanceFields: [],
    directMethods: [
      { methodIdx: bootstrapInit, accessFlags: 0x10001, code: { registersSize: 1, insSize: 1, outsSize: 1, insns: initInsns } },
    ],
    virtualMethods: [
      { methodIdx: bootstrapOnCreate, accessFlags: 0x1, code: { registersSize: 1, insSize: 1, outsSize: 1, insns: onCreateInsns } },
    ],
    hasClassData: true,
  })

  return serializeDexTables(m)
}

function nextDexName(entries: RawZipEntry[]): string {
  let max = 1
  for (const entry of entries) {
    const match = DEX_NAME_RE.exec(entry.name)
    if (!match) continue
    const suffix = match[1] ?? ""
    const index = suffix === "" ? 1 : Number.parseInt(suffix, 10)
    if (index > max) max = index
  }
  return `classes${max + 1}.dex`
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const hasher = new Bun.CryptoHasher("sha256")
  hasher.update(bytes)
  return hasher.digest("hex")
}

export interface InjectAntiDebugOptions {
  // Where to copy the original APK before writing the output. When omitted, no
  // on-disk backup is written (the original SHA-256 is still reported).
  backupPath?: string
  // Dotted class name for the injected bootstrap Application. Default
  // "com.droidseal.inj.Bootstrap".
  bootstrapClass?: string
}

export interface InjectAntiDebugResult {
  changed: boolean
  injectedDexName: string
  originalApplication: string | null
  bootstrapClass: string
  originalSha256: string
  backupPath: string | null
  findings: Finding[]
}

// End-to-end opt-in anti-debug injection over a whole APK. Reads the binary
// manifest, extends the app's declared Application with a Bootstrap subclass,
// authors a fresh classesN.dex, repoints android:name at Bootstrap, and repacks.
// Writes `outputApk` only on success; on any unsupported construct it throws
// (fail-closed) so the original package is never left half-rewritten.
export async function injectAntiDebug(
  inputApk: string,
  outputApk: string,
  options: InjectAntiDebugOptions = {},
): Promise<InjectAntiDebugResult> {
  const bootstrapClass = options.bootstrapClass ?? DEFAULT_BOOTSTRAP
  const bytes = new Uint8Array(await Bun.file(inputApk).arrayBuffer())
  const originalSha256 = await sha256Hex(bytes)
  const entries = parseRawZip(bytes)

  const manifest = entries.find((entry) => entry.name === MANIFEST_NAME)
  if (!manifest) {
    throw injectError("INJECT_MANIFEST_MISSING", "APK 内缺少 AndroidManifest.xml", "该文件可能不是标准 APK。")
  }

  const axmlBytes = inflateEntry(manifest)
  const axml = parseAxml(axmlBytes)
  const originalApplication = readApplicationName(axml)
  if (originalApplication === null) {
    // 默认 Application：需要向 <application> 新增 android:name 属性，M2 的 AXML
    // 写引擎尚未支持插入新属性，故安全回退，不改写原包。
    throw injectError(
      "INJECT_NO_APPLICATION_NAME",
      "<application> 未声明 android:name（默认 Application）",
      `注入路径 (b) 目前要求应用已有自定义 Application 以便被继承；` +
        `默认 ${DEFAULT_APPLICATION} 情形需向清单新增属性，留待后续接线。`,
    )
  }

  const superAppDescriptor = dottedToDescriptor(originalApplication)
  const bootstrapDescriptor = dottedToDescriptor(bootstrapClass)
  const injectedDex = buildAntiDebugDex(bootstrapDescriptor, superAppDescriptor)

  // Repoint the manifest and serialize the variable-length AXML.
  setApplicationName(axml, bootstrapClass)
  const newAxml = serializeAxml(axml)

  const injectedDexName = nextDexName(entries)

  // Rebuild the ZIP: replace the manifest, append the injected DEX (STORED),
  // copy every other entry verbatim.
  const outEntries: OutEntry[] = []
  for (const entry of entries) {
    if (entry.name === MANIFEST_NAME) {
      outEntries.push({
        name: MANIFEST_NAME,
        method: 0,
        crc32: crc32Of(newAxml),
        compressedSize: newAxml.byteLength,
        uncompressedSize: newAxml.byteLength,
        flags: 0,
        data: newAxml,
      })
      continue
    }
    outEntries.push({
      name: entry.name,
      method: entry.method,
      crc32: entry.crc32,
      compressedSize: entry.compressedSize,
      uncompressedSize: entry.uncompressedSize,
      flags: entry.flags,
      data: entry.data,
    })
  }
  outEntries.push({
    name: injectedDexName,
    method: 0,
    crc32: crc32Of(injectedDex),
    compressedSize: injectedDex.byteLength,
    uncompressedSize: injectedDex.byteLength,
    flags: 0,
    data: injectedDex,
  })

  let backupPath: string | null = null
  if (options.backupPath !== undefined) {
    await Bun.write(options.backupPath, bytes)
    backupPath = options.backupPath
  }

  await Bun.write(outputApk, buildZip(outEntries))

  const findings: Finding[] = [
    {
      severity: "info",
      code: "LOSSY_DEX_REWRITTEN",
      title: "已注入反调试引导类（有损、可选）",
      detail:
        `DroidSeal 新增了 ${injectedDexName}（含 Lcom/droidseal/inj/AntiDebug; 与继承原 Application ` +
        `${originalApplication} 的引导类 ${bootstrapClass}），并将 <application android:name> 重指向该引导类。` +
        `启动时 Bootstrap.onCreate 先调用 super.onCreate() 再执行 AntiDebug.check()（默认仅检测、不主动崩溃）。` +
        `此为有损操作，已在对齐前生成新包，随后必须重新对齐与签名。原包 SHA-256=${originalSha256}` +
        (backupPath ? `，备份位于 ${backupPath}` : "") + "。",
      recommendation:
        "若应用自带完整性校验（签名/DEX 哈希自检），注入会触发自毁，请在向导中关闭本步骤或将检测改为构建期集成 stub。",
    },
  ]

  return {
    changed: true,
    injectedDexName,
    originalApplication,
    bootstrapClass,
    originalSha256,
    backupPath,
    findings,
  }
}
