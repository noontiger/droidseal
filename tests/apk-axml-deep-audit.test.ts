import { describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { auditApk, auditManifestAxml } from "../src/core/apk-audit.ts"
import { buildArsc, buildPackage, buildTypeChunkWithFileValue } from "./arsc-fixtures.ts"
import { buildAxmlFixture, type FixtureElement } from "./axml-fixture.ts"
import { buildZip, crc32Of, type OutEntry } from "../src/core/harden-manifest.ts"
import type { ToolLocation, Toolchain } from "../src/core/types.ts"

const MANIFEST: FixtureElement = {
  tag: "manifest",
  attributes: [{ name: "package", value: "com.example.axml" }],
  children: [
    {
      tag: "uses-sdk",
      attributes: [
        { name: "minSdkVersion", value: 21, type: "int", android: true },
        { name: "targetSdkVersion", value: 34, type: "int", android: true },
      ],
    },
    {
      tag: "uses-permission",
      attributes: [{ name: "name", value: "android.permission.CAMERA", android: true }],
    },
    {
      tag: "application",
      attributes: [
        { name: "allowBackup", value: true, type: "boolean", android: true },
        { name: "fullBackupContent", value: 0x7f010000, type: "reference", android: true },
      ],
      children: [{
        tag: "activity",
        attributes: [
          { name: "name", value: ".DeepLinkActivity", android: true },
          { name: "exported", value: true, type: "boolean", android: true },
          { name: "taskAffinity", value: "evil.task", android: true },
        ],
        children: [{
          tag: "intent-filter",
          attributes: [{ name: "autoVerify", value: false, type: "boolean", android: true }],
          children: [
            {
              tag: "category",
              attributes: [{ name: "name", value: "android.intent.category.BROWSABLE", android: true }],
            },
            {
              tag: "data",
              attributes: [{ name: "scheme", value: "https", android: true }],
            },
          ],
        }],
      }],
    },
  ],
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

function missingTool(name: string): ToolLocation {
  return { name, source: "missing", requiredFor: [], detail: "test" }
}

const TOOLCHAIN_WITHOUT_AAPT: Toolchain = {
  java: missingTool("java"),
  keytool: missingTool("keytool"),
  aapt: missingTool("aapt"),
  zipalign: missingTool("zipalign"),
  apksigner: missingTool("apksigner"),
  gradleWrapper: missingTool("gradle"),
}

describe("direct APK Manifest AXML audit", () => {
  test("reuses component, permission, and manifest rules without aapt", () => {
    const result = auditManifestAxml(buildAxmlFixture([MANIFEST]))
    const codes = result.findings.map((finding) => finding.code)
    expect(result.metadata.packageName).toBe("com.example.axml")
    expect(result.metadata.minSdk).toBe("21")
    expect(result.xmlTree).toContain("android:exported=(type 0x12)0xffffffff")
    expect(codes).toContain("MANIFEST_BACKUP_ENABLED")
    expect(codes).toContain("MANIFEST_EXPORTED_COMPONENT_UNPROTECTED")
    expect(codes).toContain("MANIFEST_DEEPLINK_NO_AUTOVERIFY")
    expect(codes).toContain("MANIFEST_BROWSABLE_EXPORTED_ACTIVITY")
    expect(codes).toContain("MANIFEST_CUSTOM_TASK_AFFINITY")
    expect(codes).toContain("MANIFEST_DANGEROUS_PERMISSIONS")
  })

  test("resolves a typed @0x resource through resources.arsc and audits backup AXML", async () => {
    const manifest = buildAxmlFixture([MANIFEST])
    const weakBackupRules = buildAxmlFixture([{
      tag: "full-backup-content",
      children: [{
        tag: "exclude",
        attributes: [
          { name: "domain", value: "file" },
          { name: "path", value: "cache" },
        ],
      }],
    }])
    const typeChunk = buildTypeChunkWithFileValue(1, 0, 0)
    const resources = buildArsc(
      ["res/xml/backup_rules.xml"],
      buildPackage(0x7f, ["xml"], ["backup_rules"], typeChunk),
    )
    const apk = buildZip([
      storedEntry("AndroidManifest.xml", manifest),
      storedEntry("resources.arsc", resources),
      storedEntry("res/xml/backup_rules.xml", weakBackupRules),
    ])
    const directory = await mkdtemp(path.join(tmpdir(), "droidseal-axml-deep-"))
    const apkPath = path.join(directory, "fixture.apk")
    await writeFile(apkPath, apk)

    const audit = await auditApk(apkPath, TOOLCHAIN_WITHOUT_AAPT)
    const codes = audit.findings.map((finding) => finding.code)
    expect(codes).toContain("BACKUP_SENSITIVE_NOT_EXCLUDED")
    expect(codes).not.toContain("APK_XML_RESOURCE_UNRESOLVED")
    expect(codes).not.toContain("AAPT_NOT_AVAILABLE")
  })
})
