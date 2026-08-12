import { describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  analyzeSigningMaterials,
  auditSigningMaterials,
  type SigningMaterialInput,
} from "../src/core/signing-material-audit.ts"
import { writeRemediationBundle } from "../src/core/remediation.ts"

function codes(inputs: SigningMaterialInput[]): string[] {
  return analyzeSigningMaterials(inputs).map((finding) => finding.code)
}

describe("signing material exposure audit", () => {
  test("finds short literal passwords, documentation disclosure, and Git-exposed keystores without leaking values", () => {
    const inputs: SigningMaterialInput[] = [
      {
        relativePath: "android/keystore.properties",
        kind: "properties",
        gitExposure: "tracked",
        content: "storePassword=textseg123\nkeyPassword=AnotherSecret9",
      },
      {
        relativePath: "安卓网安措施TextSeg.md",
        kind: "documentation",
        gitExposure: "tracked",
        content: "发布说明：storePassword=textseg123",
      },
      {
        relativePath: "android/release-key.jks",
        kind: "keystore",
        gitExposure: "history",
      },
    ]
    const findings = analyzeSigningMaterials(inputs)
    expect(findings.map((finding) => finding.code)).toEqual([
      "SIGNING_PASSWORD_LITERAL_IN_PROPERTIES",
      "SIGNING_PASSWORD_LITERAL_IN_DOCUMENTATION",
      "SIGNING_KEYSTORE_GIT_EXPOSED",
    ])
    const serialized = JSON.stringify(findings)
    expect(serialized).not.toContain("textseg123")
    expect(serialized).not.toContain("AnotherSecret9")
    expect(serialized).toContain("storePassword=<redacted>")
    expect(serialized).toContain("Git 历史出现")
  })

  test("does not flag environment references, Gradle properties, or explicit placeholders as passwords", () => {
    expect(codes([
      {
        relativePath: "android/keystore.properties",
        kind: "properties",
        gitExposure: "untracked",
        content: [
          "storePassword=System.getenv(\"RELEASE_STORE_PASSWORD\")",
          "keyPassword=${KEY_PASSWORD}",
        ].join("\n"),
      },
      {
        relativePath: "docs/signing.md",
        kind: "documentation",
        gitExposure: "untracked",
        content: "storePassword=changeme",
      },
    ])).toEqual([])
  })

  test("keeps an untracked or unknown keystore at high severity and records Git degradation", () => {
    const findings = analyzeSigningMaterials([
      { relativePath: "release/release.p12", kind: "keystore", gitExposure: "unknown" },
    ])
    expect(findings).toContainEqual(expect.objectContaining({
      code: "SIGNING_KEYSTORE_IN_PROJECT",
      severity: "high",
      confidence: "confirmed",
    }))
    expect(findings).toContainEqual(expect.objectContaining({
      code: "SIGNING_MATERIAL_GIT_STATUS_UNAVAILABLE",
      severity: "info",
    }))
  })

  test("collects exact property/doc/keystore candidates from a project and never reports the password", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-signing-material-"))
    await mkdir(path.join(root, "android"), { recursive: true })
    await writeFile(
      path.join(root, "android", "keystore.properties"),
      "storePassword=ShortButReal7\nkeyPassword=ShortButReal8",
      "utf8",
    )
    await writeFile(path.join(root, "android", "release-key.jks"), new Uint8Array([1, 2, 3]))
    await writeFile(path.join(root, "安全说明.md"), "keyPassword=DocumentReal9", "utf8")
    await writeFile(path.join(root, "android", "safe.properties"), "storePassword=NotScannedValue9", "utf8")

    const findings = await auditSigningMaterials(root)
    const serialized = JSON.stringify(findings)
    expect(findings.map((finding) => finding.code)).toContain("SIGNING_PASSWORD_LITERAL_IN_PROPERTIES")
    expect(findings.map((finding) => finding.code)).toContain("SIGNING_PASSWORD_LITERAL_IN_DOCUMENTATION")
    expect(findings.map((finding) => finding.code)).toContain("SIGNING_KEYSTORE_IN_PROJECT")
    expect(serialized).not.toContain("ShortButReal7")
    expect(serialized).not.toContain("ShortButReal8")
    expect(serialized).not.toContain("DocumentReal9")
    expect(serialized).not.toContain("NotScannedValue9")
  })

  test("generates review-only signing response and gitignore artifacts", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-signing-remediation-"))
    const finding = analyzeSigningMaterials([{
      relativePath: "android/release.jks",
      kind: "keystore",
      gitExposure: "tracked",
    }])[0]!
    const bundle = await writeRemediationBundle(root, [finding])
    expect(bundle?.artifacts.map((artifact) => artifact.path)).toEqual([
      "signing/signing-material-response.md",
      "signing/.gitignore.droidseal.example",
    ])
    const guide = await readFile(path.join(root, "remediation", "signing", "signing-material-response.md"), "utf8")
    const ignore = await readFile(path.join(root, "remediation", "signing", ".gitignore.droidseal.example"), "utf8")
    expect(guide).toContain("不能撤销已经发生的泄露")
    expect(guide).toContain("apksigner verify")
    expect(ignore).toContain("*.jks")
    expect(ignore).toContain("keystore.properties")
  })
})
