import { describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  classifyCsp,
  detectClipboardPlugin,
  parseExportedComponents,
  parseZipEntries,
} from "../src/core/apk-audit.ts"
import { extractApkEntryBytes, stripApkEntries } from "../src/core/apk-strip.ts"
import { buildZip, crc32Of, type OutEntry } from "../src/core/harden-manifest.ts"

const XMLTREE = [
  "N: android=http://schemas.android.com/apk/res/android",
  "  E: manifest (line=1)",
  '    A: package="com.textsplitter.app" (Raw: "com.textsplitter.app")',
  "    E: application (line=2)",
  "      E: activity (line=3)",
  '        A: android:name(0x01010003)="com.textsplitter.app.MainActivity" (Raw: "com.textsplitter.app.MainActivity")',
  "        A: android:exported(0x01010010)=(type 0x12)0xffffffff",
  "        E: intent-filter (line=4)",
  "          E: action (line=5)",
  '            A: android:name(0x01010003)="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")',
  "          E: category (line=6)",
  '            A: android:name(0x01010003)="android.intent.category.LAUNCHER" (Raw: "android.intent.category.LAUNCHER")',
  "      E: receiver (line=7)",
  '        A: android:name(0x01010003)="androidx.profileinstaller.ProfileInstallReceiver" (Raw: "androidx.profileinstaller.ProfileInstallReceiver")',
  '        A: android:permission(0x01010006)="android.permission.DUMP" (Raw: "android.permission.DUMP")',
  "        A: android:exported(0x01010010)=(type 0x12)0xffffffff",
  "      E: service (line=8)",
  '        A: android:name(0x01010003)="com.textsplitter.app.OpenService" (Raw: "com.textsplitter.app.OpenService")',
  "        A: android:exported(0x01010010)=(type 0x12)0xffffffff",
].join("\n")

const XMLTREE_LAUNCHER_ONLY = [
  "N: android=http://schemas.android.com/apk/res/android",
  "  E: manifest (line=1)",
  "    E: application (line=2)",
  "      E: activity (line=3)",
  '        A: android:name(0x01010003)="com.textsplitter.app.MainActivity" (Raw: "com.textsplitter.app.MainActivity")',
  "        A: android:exported(0x01010010)=(type 0x12)0xffffffff",
  "        E: intent-filter (line=4)",
  "          E: action (line=5)",
  '            A: android:name(0x01010003)="android.intent.action.MAIN" (Raw: "android.intent.action.MAIN")',
  "          E: category (line=6)",
  '            A: android:name(0x01010003)="android.intent.category.LAUNCHER" (Raw: "android.intent.category.LAUNCHER")',
  "      E: provider (line=7)",
  '        A: android:name(0x01010003)="androidx.core.content.FileProvider" (Raw: "androidx.core.content.FileProvider")',
  "        A: android:exported(0x01010010)=(type 0x12)0x0",
].join("\n")

describe("parseExportedComponents", () => {
  test("classifies launcher, permission-protected, and unprotected exports", () => {
    const findings = parseExportedComponents(XMLTREE)
    const codes = findings.map((finding) => finding.code)
    expect(codes).toContain("MANIFEST_EXPORTED_COMPONENT_PROTECTED")
    expect(codes).toContain("MANIFEST_EXPORTED_COMPONENT_UNPROTECTED")
    expect(codes).toContain("MANIFEST_EXPORTED_SURFACE_OVERVIEW")

    const protectedFinding = findings.find((finding) => finding.code === "MANIFEST_EXPORTED_COMPONENT_PROTECTED")!
    expect(protectedFinding.severity).toBe("info")
    expect(protectedFinding.detail).toContain("ProfileInstallReceiver")
    expect(protectedFinding.detail).toContain("特权权限")

    const unprotectedFinding = findings.find((finding) => finding.code === "MANIFEST_EXPORTED_COMPONENT_UNPROTECTED")!
    expect(unprotectedFinding.severity).toBe("medium")
    expect(unprotectedFinding.detail).toContain("OpenService")
    expect(unprotectedFinding.detail).not.toContain("MainActivity")
  })

  test("launcher + non-exported provider produce no risk findings", () => {
    const findings = parseExportedComponents(XMLTREE_LAUNCHER_ONLY)
    const codes = findings.map((finding) => finding.code)
    expect(codes).not.toContain("MANIFEST_EXPORTED_COMPONENT_UNPROTECTED")
    expect(codes).not.toContain("MANIFEST_EXPORTED_COMPONENT_PROTECTED")
    expect(codes).toContain("MANIFEST_EXPORTED_SURFACE_OVERVIEW")
  })
})

describe("classifyCsp", () => {
  test("flags unsafe-inline", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'">`
    expect(classifyCsp(html)).toBe("unsafe")
  })
  test("flags unsafe-eval", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-eval'">`
    expect(classifyCsp(html)).toBe("unsafe")
  })
  test("accepts a nonce-based policy as safe", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-abc'">`
    expect(classifyCsp(html)).toBe("safe")
  })
  test("reports absent when no CSP meta present", () => {
    expect(classifyCsp("<html><head></head><body></body></html>")).toBe("absent")
  })
})

describe("detectClipboardPlugin", () => {
  test("detects @capacitor/clipboard in plugin registry", () => {
    const json = JSON.stringify([
      { pkg: "@capacitor/app", classpath: "com.capacitorjs.plugins.app.AppPlugin" },
      { pkg: "@capacitor/clipboard", classpath: "com.capacitorjs.plugins.clipboard.ClipboardPlugin" },
    ])
    expect(detectClipboardPlugin(json)).toBe(true)
  })
  test("returns false when clipboard plugin absent", () => {
    const json = JSON.stringify([{ pkg: "@capacitor/app" }])
    expect(detectClipboardPlugin(json)).toBe(false)
  })
  test("falls back to substring match on malformed JSON", () => {
    expect(detectClipboardPlugin('not json but @capacitor/clipboard appears')).toBe(true)
  })
})

function storedEntry(name: string, content: string): OutEntry {
  const data = new TextEncoder().encode(content)
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

async function writeMinimalApk(entries: OutEntry[]): Promise<string> {
  const dir = await mkdtemp(path.join(tmpdir(), "droidseal-strip-"))
  const apkPath = path.join(dir, "sample.apk")
  await writeFile(apkPath, buildZip(entries))
  return apkPath
}

describe("stripApkEntries", () => {
  test("removes only the named entry and keeps the rest parseable", async () => {
    const apkPath = await writeMinimalApk([
      storedEntry("AndroidManifest.xml", "manifest-bytes"),
      storedEntry("classes.dex", "dex-bytes"),
      storedEntry("DebugProbesKt.bin", "debug-probes"),
    ])
    const outPath = apkPath.replace(/\.apk$/, "-stripped.apk")
    const { removed } = await stripApkEntries(apkPath, outPath, ["DebugProbesKt.bin"])
    expect(removed).toEqual(["DebugProbesKt.bin"])

    const after = await parseZipEntries(outPath)
    const names = after.map((entry) => entry.name).sort()
    expect(names).toEqual(["AndroidManifest.xml", "classes.dex"])
  })

  test("writes nothing and reports empty when no entry matches", async () => {
    const apkPath = await writeMinimalApk([
      storedEntry("AndroidManifest.xml", "manifest-bytes"),
      storedEntry("classes.dex", "dex-bytes"),
    ])
    const outPath = apkPath.replace(/\.apk$/, "-noop.apk")
    const { removed } = await stripApkEntries(apkPath, outPath, ["DebugProbesKt.bin"])
    expect(removed).toEqual([])
    expect(await Bun.file(outPath).exists()).toBe(false)
  })
})

describe("extractApkEntryBytes", () => {
  test("returns inflated bytes for a present entry and undefined otherwise", async () => {
    const apkPath = await writeMinimalApk([
      storedEntry("assets/capacitor.plugins.json", '[{"pkg":"@capacitor/clipboard"}]'),
      storedEntry("AndroidManifest.xml", "manifest-bytes"),
    ])
    const bytes = await extractApkEntryBytes(apkPath, "assets/capacitor.plugins.json")
    expect(bytes).not.toBeUndefined()
    expect(new TextDecoder().decode(bytes!)).toBe('[{"pkg":"@capacitor/clipboard"}]')
    expect(await extractApkEntryBytes(apkPath, "assets/missing.json")).toBeUndefined()
  })
})
