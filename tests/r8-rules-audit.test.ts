import { describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { auditProject } from "../src/core/project-audit.ts"

async function writeTree(root: string, files: Record<string, string>): Promise<void> {
  for (const [relative, content] of Object.entries(files)) {
    const full = path.join(root, relative)
    await mkdir(path.dirname(full), { recursive: true })
    await writeFile(full, content, "utf8")
  }
}

const MANIFEST = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application android:allowBackup="false" />
</manifest>`

const RELEASE_BUILD = `plugins { id 'com.android.application' }
android {
  buildTypes {
    release {
      minifyEnabled true
      shrinkResources true
      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
        'proguard-rules.pro',
        'missing-rules.pro'
    }
  }
}`

const WEAKENING_CODES = [
  "R8_OBFUSCATION_DISABLED",
  "R8_SHRINKING_DISABLED",
  "R8_OPTIMIZATION_DISABLED",
  "R8_GLOBAL_KEEP_RULE",
  "R8_BROAD_PACKAGE_KEEP_RULE",
]

describe("R8 rule quality audit", () => {
  test("reports confirmed weakening rules and a missing release reference", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-r8-rules-"))
    await writeTree(root, {
      "app/build.gradle": RELEASE_BUILD,
      "app/src/main/AndroidManifest.xml": MANIFEST,
      "app/proguard-rules.pro": `# -dontobfuscate
-dontobfuscate
-dontshrink
-dontoptimize
-keep class ** { *; }
-keep class com.example.internal.** {
  *;
}
-keep class com.example.SafeModel { *; }
-keepclasseswithmembernames class * {
  native <methods>;
}`,
      "app/src/main/keepRules/reflection.keep":
        "-keepclassmembers class com.example.JsonModel { @com.google.gson.annotations.SerializedName <fields>; }",
      "app/src/debug/debug-rules.pro": "-dontobfuscate",
      "app/build/outputs/mapping/release/configuration.txt": "-dontobfuscate",
      "library/build.gradle": "plugins { id 'com.android.library' }",
      "library/proguard-rules.pro": "-dontobfuscate",
    })

    const audit = await auditProject(root)
    const codes = audit.findings.map((finding) => finding.code)

    for (const code of WEAKENING_CODES) expect(codes).toContain(code)
    expect(codes).toContain("R8_RULE_FILE_REFERENCE_MISSING")
    expect(codes).toContain("R8_RULE_FILES_AUDITED")

    const global = audit.findings.find((finding) => finding.code === "R8_GLOBAL_KEEP_RULE")
    const broad = audit.findings.find((finding) => finding.code === "R8_BROAD_PACKAGE_KEEP_RULE")
    const missing = audit.findings.find((finding) => finding.code === "R8_RULE_FILE_REFERENCE_MISSING")
    const inventory = audit.findings.find((finding) => finding.code === "R8_RULE_FILES_AUDITED")

    expect(global?.evidence).toContain("app/proguard-rules.pro:5")
    expect(broad?.evidence).toContain("app/proguard-rules.pro:6")
    expect(missing?.evidence).toContain("app/build.gradle")
    expect(missing?.evidence).toContain("missing-rules.pro")
    expect(inventory?.evidence).toContain("app/proguard-rules.pro")
    expect(inventory?.evidence).toContain("app/src/main/keepRules/reflection.keep")
    expect(inventory?.evidence).not.toContain("src/debug")
    expect(inventory?.evidence).not.toContain("library/")
    expect(inventory?.evidence).not.toContain("build/outputs")
  })

  test("ignores comments and semantically narrow keep rules", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-r8-narrow-"))
    await writeTree(root, {
      "app/build.gradle": `plugins { id 'com.android.application' }
android { buildTypes { release {
  minifyEnabled true
  shrinkResources true
  proguardFiles getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro"
} } }`,
      "app/src/main/AndroidManifest.xml": MANIFEST,
      "app/proguard-rules.pro": `# -dontobfuscate
# -keep class ** { *; }
-keepclasseswithmembernames class * { native <methods>; }
-keep @com.example.Keep class * { *; }
-keep class * extends android.app.Activity { *; }
-keep,allowobfuscation,allowoptimization,allowshrinking class com.example.generated.** { *; }
-keep,allowobfuscation class com.example.Model { <fields>; }`,
    })

    const audit = await auditProject(root)
    const codes = audit.findings.map((finding) => finding.code)

    for (const code of WEAKENING_CODES) expect(codes).not.toContain(code)
    expect(codes).not.toContain("R8_RULE_FILE_REFERENCE_MISSING")
    expect(codes).toContain("R8_RULE_FILES_AUDITED")
  })

  test("does not describe allowobfuscation as an obfuscation ban", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-r8-options-"))
    await writeTree(root, {
      "app/build.gradle": `plugins { id 'com.android.application' }
android { buildTypes { release {
  minifyEnabled true
  shrinkResources true
  proguardFiles "proguard-rules.pro"
} } }`,
      "app/src/main/AndroidManifest.xml": MANIFEST,
      "app/proguard-rules.pro":
        "-keep,allowobfuscation class com.example.generated.** { *; }",
    })

    const audit = await auditProject(root)
    const broad = audit.findings.find((finding) => finding.code === "R8_BROAD_PACKAGE_KEEP_RULE")

    expect(broad).toBeDefined()
    expect(broad?.detail).toContain("代码裁剪")
    expect(broad?.detail).toContain("代码优化")
    expect(broad?.detail).not.toContain("名称混淆")
    expect(audit.findings.map((finding) => finding.code)).not.toContain("R8_OBFUSCATION_DISABLED")
  })
})
