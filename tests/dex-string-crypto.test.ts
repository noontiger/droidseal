import { describe, expect, test } from "bun:test"
import {
  computeEncryptableStrings,
  computeIdentifierStrings,
  computeLiteralStrings,
  decryptToString,
  encryptString,
  generateKey,
  keyFingerprint,
  planStringEncryption,
} from "../src/core/dex-string-crypto.ts"
import {
  type DexTables,
  internMethod,
  internString,
  internType,
  NO_INDEX,
} from "../src/core/dex-writer.ts"

function emptyModel(): DexTables {
  return { version: "035", strings: [], types: [], protos: [], fields: [], methods: [], classes: [], dirty: false }
}

// A model whose method loads two literals: one unique ("secret-token") and one
// that ALSO happens to be an identifier collision ("run" — a method name).
function modelWithLiterals(): DexTables {
  const m = emptyModel()
  const selfType = internType(m, "Lcom/example/Main;")
  internType(m, "Ljava/lang/Object;")
  const secretIdx = internString(m, "secret-token")
  // "run" is both a method name (identifier) and used as a const-string literal.
  const runIdx = internString(m, "run")
  internMethod(m, "Lcom/example/Log;", "print", "V", ["Ljava/lang/String;"])
  const logMethod = m.methods.length - 1
  // const-string v0, "secret-token"; const-string v0, "run"; invoke-static; return-void
  const insns = Uint16Array.from([
    0x001a, secretIdx,
    0x001a, runIdx,
    0x1035, logMethod, 0x0000,
    0x000e,
  ])
  m.classes.push({
    classIdx: selfType,
    accessFlags: 0x1,
    superclassIdx: internType(m, "Ljava/lang/Object;"),
    interfaces: [],
    sourceFileIdx: NO_INDEX,
    staticFields: [],
    instanceFields: [],
    directMethods: [
      { methodIdx: internMethod(m, "Lcom/example/Main;", "run", "V", []), accessFlags: 0x9, code: { registersSize: 1, insSize: 0, outsSize: 1, insns } },
    ],
    virtualMethods: [],
    hasClassData: true,
  })
  return m
}

describe("dex-string-crypto cipher (M3 §8.4)", () => {
  test("encrypt/decrypt round-trips, including empty and unicode", () => {
    const key = generateKey()
    for (const s of ["", "hello", "secret-token", "\u0000\u00e9\u4e2d\u6587", "a".repeat(300)]) {
      expect(decryptToString(encryptString(s, key), key)).toBe(s)
    }
  })

  test("ciphertext differs from plaintext bytes", () => {
    const key = generateKey()
    const ct = encryptString("secret-token", key)
    const pt = new TextEncoder().encode("secret-token")
    expect(Buffer.from(ct)).not.toEqual(Buffer.from(pt))
  })

  test("key fingerprint is stable, 16 hex chars, and not the key itself", () => {
    const key = generateKey()
    const fp = keyFingerprint(key)
    expect(fp).toMatch(/^[0-9a-f]{16}$/)
    expect(keyFingerprint(key)).toBe(fp)
  })

  test("wrong key does not recover the plaintext", () => {
    const a = generateKey()
    const b = generateKey()
    const recovered = decryptToString(encryptString("secret-token", a), b)
    expect(recovered).not.toBe("secret-token")
  })
})

describe("dex-string-crypto safe subset (M3 §8.2)", () => {
  test("identifier strings include type/method/field names", () => {
    const m = modelWithLiterals()
    const ids = computeIdentifierStrings(m)
    const idValues = [...ids].map((i) => m.strings[i])
    expect(idValues).toContain("Lcom/example/Main;")
    expect(idValues).toContain("print")
    expect(idValues).toContain("run") // method name
  })

  test("literal strings come from const-string operands", () => {
    const m = modelWithLiterals()
    const lits = computeLiteralStrings(m)
    const litValues = [...lits].map((i) => m.strings[i])
    expect(litValues).toContain("secret-token")
    expect(litValues).toContain("run")
  })

  test("encryptable set = literals minus identifiers (excludes 'run')", () => {
    const m = modelWithLiterals()
    const encryptable = computeEncryptableStrings(m).map((i) => m.strings[i])
    expect(encryptable).toContain("secret-token")
    expect(encryptable).not.toContain("run") // collides with a method name -> excluded
  })
})

describe("dex-string-crypto plan (M3)", () => {
  test("plans encryption over the safe subset with round-trippable ciphertext", () => {
    const m = modelWithLiterals()
    const plan = planStringEncryption(m)
    expect(plan.encryptableCount).toBe(1)
    const entry = plan.entries[0]!
    expect(entry.plaintext).toBe("secret-token")
    expect(decryptToString(entry.ciphertext, plan.key)).toBe("secret-token")
    expect(plan.findings[0]!.code).toBe("LOSSY_DEX_STRINGS_PLANNED")
  })

  test("does not mutate the input tables", () => {
    const m = modelWithLiterals()
    const before = m.strings.length
    planStringEncryption(m)
    expect(m.strings.length).toBe(before)
    expect(m.dirty).toBe(false)
  })

  test("filter narrows the encryptable set", () => {
    const m = modelWithLiterals()
    const plan = planStringEncryption(m, { filter: (s) => s.startsWith("nope") })
    expect(plan.encryptableCount).toBe(0)
  })
})
