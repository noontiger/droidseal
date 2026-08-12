import { describe, expect, test } from "bun:test"
import {
  analyzeSignatureSelfChecks,
  compareSignatureSelfCheckFingerprints,
  type SignatureSourceFile,
} from "../src/core/signature-self-check.ts"

const fingerprintA = "0123456789abcdef".repeat(4)
const fingerprintB = "fedcba9876543210".repeat(4)
const fingerprintC = "a1b2c3d4e5f60718".repeat(4)

function colonFingerprint(value: string): string {
  return value.match(/../g)!.join(":").toUpperCase()
}

function kotlin(config: string, startup: string): SignatureSourceFile[] {
  return [{
    relativePath: "app/src/main/java/com/example/MainActivity.kt",
    content: `
      object SignatureGuard {
        ${config}
        fun verifySignature(context: Context): Boolean {
          val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_SIGNING_CERTIFICATES
          )
          val digest = MessageDigest.getInstance("SHA-256")
          return EXPECTED_SIGNATURES.contains(digest.digest(info.signingInfo.apkContentsSigners[0].toByteArray()).toHex())
        }
      }
      class MainActivity : Activity() {
        override fun onCreate(state: Bundle?) {
          super.onCreate(state)
          ${startup}
        }
      }
    `,
  }]
}

describe("App signature self-check evidence", () => {
  test("requires and records literal fingerprints, signing API, SHA-256, startup invocation, and disposition", () => {
    const files = kotlin(
      `private val EXPECTED_SIGNATURES = setOf("${fingerprintA}", "${colonFingerprint(fingerprintB)}")`,
      "if (!SignatureGuard.verifySignature(this)) { finishAffinity(); kotlin.system.exitProcess(0) }",
    )
    const result = analyzeSignatureSelfChecks(files, "app")

    expect(result.evidence).toMatchObject({
      modulePath: "app",
      expectedStatus: "literal",
      startupInvoked: true,
      forcedDisposition: true,
    })
    expect(result.evidence?.expectedFingerprints).toEqual([fingerprintA, fingerprintB].sort())
    expect(result.findings.map((finding) => finding.code)).toEqual(["SIGNATURE_SELF_CHECK_OBSERVED"])
    expect(result.findings[0]?.evidence).toContain("startup=app/src/main")
    expect(result.findings[0]?.evidence).not.toContain(fingerprintA)
  })

  test("distinguishes placeholders and unresolved BuildConfig/environment values", () => {
    const placeholder = analyzeSignatureSelfChecks(
      kotlin(
        `private val EXPECTED_SIGNATURES = setOf("${"0".repeat(64)}")`,
        "if (!SignatureGuard.verifySignature(this)) throw SecurityException(\"invalid\")",
      ),
      "app",
    )
    expect(placeholder.evidence?.expectedStatus).toBe("placeholder")
    expect(placeholder.findings.map((finding) => finding.code)).toContain("SIGNATURE_SELF_CHECK_PLACEHOLDER")

    const buildConfig = analyzeSignatureSelfChecks(
      kotlin(
        "private val EXPECTED_SIGNATURES = setOf(BuildConfig.RELEASE_CERT_SHA256)",
        "if (!SignatureGuard.verifySignature(this)) finishAndRemoveTask()",
      ),
      "app",
    )
    expect(buildConfig.evidence?.expectedStatus).toBe("unresolved")
    expect(buildConfig.findings.map((finding) => finding.code)).toContain("SIGNATURE_SELF_CHECK_EXPECTED_UNRESOLVED")

    const environmentFiles = kotlin(
      "private val EXPECTED_SIGNATURES = setOf(System.getenv(\"RELEASE_CERT_SHA256\"))",
      "if (!SignatureGuard.verifySignature(this)) finishAffinity()",
    )
    expect(analyzeSignatureSelfChecks(environmentFiles, "app").evidence?.expectedStatus).toBe("unresolved")
  })

  test("reports missing startup calls and missing forced disposition separately", () => {
    const noStartup = kotlin(
      `private val EXPECTED_SIGNATURES = setOf("${fingerprintA}")`,
      "Log.i(\"App\", \"started\")",
    )
    expect(analyzeSignatureSelfChecks(noStartup, "app").findings.map((finding) => finding.code)).toContain(
      "SIGNATURE_SELF_CHECK_STARTUP_NOT_CONFIRMED",
    )

    const noDisposition = kotlin(
      `private val EXPECTED_SIGNATURES = setOf("${fingerprintA}")`,
      "if (!SignatureGuard.verifySignature(this)) Log.e(\"Guard\", \"invalid\")",
    )
    expect(analyzeSignatureSelfChecks(noDisposition, "app").findings.map((finding) => finding.code)).toContain(
      "SIGNATURE_SELF_CHECK_DISPOSITION_NOT_CONFIRMED",
    )
  })

  test("accepts a rotation-list match and emits a confirmed critical mismatch with masked evidence", () => {
    const evidence = analyzeSignatureSelfChecks(
      kotlin(
        `private val EXPECTED_SIGNATURES = setOf("${fingerprintA}", "${fingerprintB}")`,
        "if (!SignatureGuard.verifySignature(this)) finishAffinity()",
      ),
      "app",
    ).evidence!

    const matched = compareSignatureSelfCheckFingerprints([evidence], [fingerprintB])
    expect(matched.map((finding) => finding.code)).toEqual(["SIGNATURE_SELF_CHECK_CERT_MATCH"])
    expect(matched[0]?.detail).toContain("不证明客户端校验不可被补丁或 Hook 绕过")

    expect(compareSignatureSelfCheckFingerprints([
      { ...evidence, startupInvoked: false },
      { ...evidence, forcedDisposition: false },
    ], [fingerprintC])).toEqual([])

    const mismatched = compareSignatureSelfCheckFingerprints([evidence], [fingerprintC])
    expect(mismatched[0]).toMatchObject({
      code: "SIGNATURE_SELF_CHECK_CERT_MISMATCH",
      severity: "critical",
      confidence: "confirmed",
    })
    const serialized = JSON.stringify(mismatched)
    expect(serialized).not.toContain(fingerprintA)
    expect(serialized).not.toContain(fingerprintB)
    expect(serialized).not.toContain(fingerprintC)
    expect(serialized).toContain("…")
  })
})
