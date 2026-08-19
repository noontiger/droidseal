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
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app"
    android:minSdkVersion="19"
    android:targetSdkVersion="34">
    <application android:allowBackup="true" android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity"
            android:exported="true"
            android:taskAffinity="com.evil.affinity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity android:name=".Exported"
            android:exported="true"
            android:taskAffinity="com.evil.affinity2" />
    </application>
</manifest>`

const MAIN_ACTIVITY_KT = `package com.example.app

import android.app.PendingIntent
import android.webkit.WebSettings

class MainActivity {
    fun setup(webView: android.webkit.WebView) {
        webView.settings.javaScriptEnabled = true
        webView.settings.domStorageEnabled = true
        webView.loadUrl("file:///android_asset/index.html")
        val apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuvwxyz0"
        val pi = PendingIntent.getActivity(this, 0, android.content.Intent(this, MainActivity::class.java), 0)
    }
}
`

describe("auditProject source-side heuristics", () => {
  test("flags WebView, secret, PendingIntent, minSdk and task affinity", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-src-"))
    await writeTree(root, {
      "settings.gradle": "include ':app'",
      "app/build.gradle": "plugins { id 'com.android.application' }",
      "app/src/main/AndroidManifest.xml": MANIFEST,
      "app/src/main/java/com/example/security/ui/MainActivity.kt": MAIN_ACTIVITY_KT,
      // NSC referenced by manifest; give it plaintext content so auditManifest runs it.
      "app/src/main/res/xml/network_security_config.xml":
        '<network-security-config><base-config cleartextTrafficPermitted="true"><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>',
    })
    const audit = await auditProject(root)
    const codes = audit.findings.map((f) => f.code)

    expect(codes).toContain("SOURCE_WEBVIEW_JS_ENABLED")
    expect(codes).toContain("SOURCE_WEBVIEW_DOM_STORAGE")
    expect(codes).toContain("SOURCE_WEBVIEW_FILE_URL_LOAD")
    expect(codes).toContain("SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED")
    expect(codes).toContain("SOURCE_HARDCODED_SECRET")
    expect(codes).toContain("SOURCE_PENDING_INTENT_NO_MUTABILITY_FLAG")
    expect(codes).toContain("SOURCE_MIN_SDK_OUTDATED")
    expect(codes).toContain("SOURCE_CUSTOM_TASK_AFFINITY")
    // referenced NSC plaintext content is still audited on the source side
    expect(codes).toContain("NSC_CLEARTEXT_PERMITTED")
    expect(codes).toContain("NSC_TRUSTS_USER_CA")
  })

  test("records a complete startup signature self-check for each application module", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-signature-source-"))
    const fingerprint = "0123456789abcdef".repeat(4)
    await writeTree(root, {
      "settings.gradle": "include ':app'",
      "app/build.gradle": "plugins { id 'com.android.application' }",
      "app/src/main/AndroidManifest.xml": MANIFEST,
      "app/src/main/java/com/example/security/ui/MainActivity.kt": `package com.example.app

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import java.security.MessageDigest

object SignatureGuard {
    private val EXPECTED_SIGNATURES = setOf("${fingerprint}")
    fun verifySignature(context: Context): Boolean {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES
        )
        val digest = MessageDigest.getInstance("SHA-256")
        return EXPECTED_SIGNATURES.contains(digest.digest(info.signingInfo.apkContentsSigners[0].toByteArray()).toString())
    }
}

class MainActivity : Activity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        if (!SignatureGuard.verifySignature(this)) {
            finishAffinity()
            kotlin.system.exitProcess(0)
        }
    }
}
`,
    })

    const audit = await auditProject(root)
    expect(audit.findings.map((finding) => finding.code)).toContain("SIGNATURE_SELF_CHECK_OBSERVED")
    expect(audit.signatureSelfChecks).toHaveLength(1)
    expect(audit.signatureSelfChecks?.[0]).toMatchObject({
      modulePath: "app",
      expectedStatus: "literal",
      startupInvoked: true,
      forcedDisposition: true,
    })
    expect(audit.signatureSelfChecks?.[0]?.expectedFingerprints).toEqual([fingerprint])
  })
})
