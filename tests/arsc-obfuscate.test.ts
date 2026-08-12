import { describe, expect, test } from "bun:test"
import { parseArsc, serializeArsc } from "../src/core/arsc-model.ts"
import { analyzeResourceReflection, flattenFilePaths, shortName, shortenKeyNames } from "../src/core/arsc-obfuscate.ts"
import { buildArsc, buildPackage, buildTypeChunkWithFileValue, sampleArsc } from "./arsc-fixtures.ts"

describe("shortName generator", () => {
  test("produces base-26 sequence a..z, aa, ab", () => {
    expect(shortName(0)).toBe("a")
    expect(shortName(25)).toBe("z")
    expect(shortName(26)).toBe("aa")
    expect(shortName(27)).toBe("ab")
  })
})

describe("arsc-obfuscate N1 key-name shortening", () => {
  test("shortens every key name and survives a serialize/parse cycle", () => {
    const table = parseArsc(sampleArsc())
    const result = shortenKeyNames(table)
    expect(result.renamed).toBe(3)

    const reparsed = parseArsc(serializeArsc(table))
    const keys = reparsed.packages[0]!.keyStrings.strings
    expect(keys).toEqual(["a", "b", "c"])
    // Type names and package id (part of the resource ID) are untouched.
    expect(reparsed.packages[0]!.typeStrings.strings).toEqual(["string", "drawable", "layout"])
    expect(reparsed.packages[0]!.id).toBe(0x7f)
  })

  test("preserves whitelisted names", () => {
    const table = parseArsc(sampleArsc())
    const result = shortenKeyNames(table, { keep: new Set(["ic_launcher"]) })
    const keys = table.packages[0]!.keyStrings.strings
    expect(keys).toContain("ic_launcher")
    expect(keys).not.toContain("app_name")
    expect(result.mapping.has("ic_launcher")).toBe(false)
    expect(result.mapping.get("app_name")).toBeDefined()
  })
})

function fileValueArsc(): Uint8Array {
  const body = buildTypeChunkWithFileValue(2, 0, 0) // Res_value -> global index 0
  const pkg = buildPackage(0x7f, ["drawable", "layout"], ["ic_launcher"], body)
  return buildArsc(["res/drawable/ic_launcher.png", "res/layout/activity_main.xml"], pkg)
}

describe("arsc-obfuscate N2 file-path flattening", () => {
  test("flattens res/ paths while keeping Res_value indices stable", () => {
    const table = parseArsc(fileValueArsc())
    const originalBody = table.packages[0]!.body.slice()

    const result = flattenFilePaths(table)
    expect(result.renamed).toBe(2)
    expect(result.mapping.get("res/drawable/ic_launcher.png")).toBe("r/a.png")
    expect(result.mapping.get("res/layout/activity_main.xml")).toBe("r/b.xml")

    // The Res_value still points at global index 0; body bytes are untouched.
    expect(table.packages[0]!.body).toEqual(originalBody)
    expect(table.globalStrings.strings[0]).toBe("r/a.png")

    const reparsed = parseArsc(serializeArsc(table))
    expect(reparsed.globalStrings.strings[0]).toBe("r/a.png")
    expect(reparsed.globalStrings.strings[1]).toBe("r/b.xml")
    expect(reparsed.packages[0]!.body).toEqual(originalBody)
  })

  test("preserves whitelisted paths", () => {
    const table = parseArsc(fileValueArsc())
    const result = flattenFilePaths(table, { keep: new Set(["res/layout/activity_main.xml"]) })
    expect(result.renamed).toBe(1)
    expect(table.globalStrings.strings).toContain("res/layout/activity_main.xml")
    expect(table.globalStrings.strings[0]).toBe("r/a.png")
  })
})

describe("arsc-obfuscate N3 getIdentifier whitelist", () => {
  test("no getIdentifier means empty keep-set and no finding", () => {
    const analysis = analyzeResourceReflection(["app_name", "ic_launcher"], ["Lcom/x/Y;", "some literal"])
    expect(analysis.usesGetIdentifier).toBe(false)
    expect(analysis.keep.size).toBe(0)
    expect(analysis.finding).toBeUndefined()
  })

  test("flags getIdentifier and fail-safely keeps every resource name", () => {
    const analysis = analyzeResourceReflection(
      ["app_name", "ic_launcher"],
      ["getIdentifier", "app_name", "Landroid/content/res/Resources;"],
    )
    expect(analysis.usesGetIdentifier).toBe(true)
    expect(analysis.keep.has("app_name")).toBe(true)
    expect(analysis.keep.has("ic_launcher")).toBe(true)
    expect(analysis.finding?.code).toBe("ARSC_RESOURCE_NAME_REFLECTION")
    expect(analysis.finding?.evidence).toContain("app_name")
  })

  test("keep-set prevents all key shortening when names may be dynamic", () => {
    const table = parseArsc(sampleArsc())
    const analysis = analyzeResourceReflection(
      table.packages[0]!.keyStrings.strings,
      ["getIdentifier", "app_name"],
    )
    shortenKeyNames(table, { keep: analysis.keep })
    expect(table.packages[0]!.keyStrings.strings).toContain("app_name")
    expect(table.packages[0]!.keyStrings.strings).toContain("ic_launcher")
  })
})
