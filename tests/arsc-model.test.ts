import { describe, expect, test } from "bun:test"
import { parseArsc, resolveArscFilePath, serializeArsc, markPoolDirty } from "../src/core/arsc-model.ts"
import {
  buildArsc,
  buildPackage,
  buildTypeChunkWithFileValue,
  sampleArsc,
} from "./arsc-fixtures.ts"

describe("arsc-model N0 round-trip", () => {
  test("parse then serialize reproduces the input byte-for-byte", () => {
    const input = sampleArsc()
    const table = parseArsc(input)
    const output = serializeArsc(table)
    expect(output).toEqual(input)
  })

  test("parses the model structure", () => {
    const table = parseArsc(sampleArsc())
    expect(table.packages.length).toBe(1)
    expect(table.packages[0]!.id).toBe(0x7f)
    expect(table.globalStrings.strings).toContain("res/layout/activity_main.xml")
    expect(table.packages[0]!.keyStrings.strings).toEqual(["app_name", "ic_launcher", "activity_main"])
    expect(table.packages[0]!.typeStrings.strings).toEqual(["string", "drawable", "layout"])
  })

  test("throws on non-arsc buffers", () => {
    expect(() => parseArsc(new Uint8Array(64))).toThrow()
  })
})

describe("arsc-model string-pool rebuild", () => {
  test("renaming key strings survives a serialize/parse cycle and keeps 1:1 order", () => {
    const table = parseArsc(sampleArsc())
    const keyPool = table.packages[0]!.keyStrings
    keyPool.strings = ["a", "b", "c"]
    markPoolDirty(keyPool)

    const rebuilt = serializeArsc(table)
    const reparsed = parseArsc(rebuilt)
    expect(reparsed.packages[0]!.keyStrings.strings).toEqual(["a", "b", "c"])
    expect(reparsed.packages[0]!.typeStrings.strings).toEqual(["string", "drawable", "layout"])
    expect(reparsed.globalStrings.strings).toContain("res/drawable/ic_launcher.png")
    expect(reparsed.packages[0]!.body).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  })
})

describe("arsc-model file reference resolution", () => {
  test("maps 0xpptteeee to the global-pool XML path", () => {
    const table = buildArsc(
      ["res/xml/backup_rules.xml"],
      buildPackage(0x7f, ["xml"], ["backup_rules"], buildTypeChunkWithFileValue(1, 0, 0)),
    )
    expect(resolveArscFilePath(table, 0x7f010000)).toBe("res/xml/backup_rules.xml")
    expect(resolveArscFilePath(table, 0x7f010001)).toBeUndefined()
  })
})
