import { describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { auditNetworkSecurityConfig } from "../src/core/nsc-audit.ts"
import { auditProject } from "../src/core/project-audit.ts"

describe("auditNetworkSecurityConfig", () => {
  test("flags cleartext, user CA trust, and debug overrides", () => {
    const xml = `<?xml version="1.0"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="system"/>
      <certificates src="user"/>
    </trust-anchors>
  </base-config>
  <debug-overrides>
    <trust-anchors><certificates src="user"/></trust-anchors>
  </debug-overrides>
</network-security-config>`
    const codes = auditNetworkSecurityConfig(xml).map((f) => f.code)
    expect(codes).toContain("NSC_CLEARTEXT_PERMITTED")
    expect(codes).toContain("NSC_TRUSTS_USER_CA")
    expect(codes).toContain("NSC_DEBUG_OVERRIDES_PRESENT")
  })

  test("reports no-pinning as info when pin-set absent", () => {
    const xml = `<network-security-config><base-config><trust-anchors><certificates src="system"/></trust-anchors></base-config></network-security-config>`
    expect(auditNetworkSecurityConfig(xml).map((f) => f.code)).toContain("NSC_NO_PINNING")
  })

  test("flags single-pin and expired pin-set as weak", () => {
    const single = `<network-security-config><domain-config><domain>example.com</domain><pin-set><pin digest="SHA-256">AAAA</pin></pin-set></domain-config></network-security-config>`
    expect(auditNetworkSecurityConfig(single).map((f) => f.code)).toContain("NSC_PINNING_WEAK")

    const expired = `<network-security-config><domain-config><pin-set expiration="2000-01-01"><pin digest="SHA-256">A</pin><pin digest="SHA-256">B</pin></pin-set></domain-config></network-security-config>`
    const now = new Date("2026-01-01T00:00:00Z")
    expect(auditNetworkSecurityConfig(expired, undefined, now).map((f) => f.code)).toContain("NSC_PINNING_WEAK")
  })

  test("two pins with future expiration produce no weak finding", () => {
    const strong = `<network-security-config><domain-config><pin-set expiration="2999-01-01"><pin digest="SHA-256">A</pin><pin digest="SHA-256">B</pin></pin-set></domain-config></network-security-config>`
    const now = new Date("2026-01-01T00:00:00Z")
    expect(auditNetworkSecurityConfig(strong, undefined, now).map((f) => f.code)).not.toContain("NSC_PINNING_WEAK")
  })
})

async function scaffoldProject(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "droidseal-tier3-"))
  const appMain = path.join(root, "app", "src", "main")
  await mkdir(path.join(appMain, "res", "xml"), { recursive: true })
  await writeFile(
    path.join(root, "app", "build.gradle"),
    [
      "plugins { id 'com.android.application' }",
      "android { buildTypes { release { minifyEnabled true } } }",
      "dependencies {",
      "  implementation 'com.squareup.okhttp3:okhttp:4.12.0'",
      "  implementation 'androidx.core:core-ktx:1.12.0'",
      "}",
    ].join("\n"),
  )
  await writeFile(
    path.join(appMain, "AndroidManifest.xml"),
    `<?xml version="1.0"?>
<manifest package="com.example.app">
  <application android:allowBackup="true"
    android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
    </activity>
  </application>
</manifest>`,
  )
  await writeFile(
    path.join(appMain, "res", "xml", "network_security_config.xml"),
    `<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>`,
  )
  return root
}

describe("auditProject Tier 3 integration", () => {
  test("resolves NSC, backup exclusion, and dependency inventory", async () => {
    const root = await scaffoldProject()
    const audit = await auditProject(root)
    const codes = audit.findings.map((f) => f.code)
    expect(codes).toContain("NSC_CLEARTEXT_PERMITTED")
    expect(codes).toContain("NSC_TRUSTS_USER_CA")
    expect(codes).toContain("BACKUP_NO_EXCLUSION_RULES")
    expect(codes).toContain("SUPPLYCHAIN_SDK_INVENTORY")
    const sbom = audit.findings.find((f) => f.code === "SUPPLYCHAIN_SDK_INVENTORY")
    expect(sbom?.evidence).toContain("com.squareup.okhttp3:okhttp")
  })
})
