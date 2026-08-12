import { describe, expect, test } from "bun:test"
import { buildMinSdkFinding, manifestFindings } from "../src/core/apk-audit.ts"

const XMLTREE_WITH_EXTRACT = [
  "N: android=http://schemas.android.com/apk/res/android",
  "  E: manifest (line=1)",
  "    E: application (line=2)",
  "      A: android:extractNativeLibs(0x010104d4)=(type 0x12)0xffffffff",
  "      A: android:debuggable(0x0101000f)=(type 0x12)0x0",
  "      A: android:allowBackup(0x01010000)=(type 0x12)0x0",
].join("\n")

describe("manifestFindings", () => {
  test("flags explicit extractNativeLibs=true", () => {
    const codes = manifestFindings(XMLTREE_WITH_EXTRACT).map((f) => f.code)
    expect(codes).toContain("MANIFEST_EXTRACT_NATIVE_LIBS")
  })

  test("does not flag when extractNativeLibs is absent", () => {
    const codes = manifestFindings("E: manifest\n  E: application").map((f) => f.code)
    expect(codes).not.toContain("MANIFEST_EXTRACT_NATIVE_LIBS")
  })
})

describe("buildMinSdkFinding", () => {
  test("flags very old minSdk (<21) as medium", () => {
    const finding = buildMinSdkFinding(19, "COMPLIANCE")
    expect(finding).toHaveLength(1)
    expect(finding[0]!.code).toBe("COMPLIANCE_MIN_SDK_OUTDATED")
    expect(finding[0]!.severity).toBe("medium")
  })

  test("flags pre-runtime-permission minSdk (<23) as low", () => {
    const finding = buildMinSdkFinding(21, "SOURCE")
    expect(finding[0]!.code).toBe("SOURCE_MIN_SDK_OUTDATED")
    expect(finding[0]!.severity).toBe("low")
  })

  test("no finding at/above baseline", () => {
    expect(buildMinSdkFinding(24, "COMPLIANCE")).toHaveLength(0)
  })
})
