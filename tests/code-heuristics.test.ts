import { describe, expect, test } from "bun:test"
import { scanCodeStrings, pendingIntentImmutableFinding, CODE_HEURISTIC_RULES } from "../src/core/code-heuristics.ts"

const SUFFIXES = CODE_HEURISTIC_RULES.map((rule) => rule.suffix)

describe("scanCodeStrings strict DEX evidence", () => {
  test("requires corroborating API and action signals", () => {
    const findings = scanCodeStrings(
      [
        "AES/ECB/PKCS5Padding",
        "Ljavax/crypto/Cipher;",
        "ALLOW_ALL_HOSTNAME_VERIFIER",
        "Ldalvik/system/DexClassLoader;",
        "https://example.invalid/payload.dex",
        "Ljava/lang/Runtime;",
        "exec",
        "addJavascriptInterface",
      ],
      "DEX",
    )
    const codes = findings.map((finding) => finding.code)
    expect(codes).toContain("DEX_WEAK_CRYPTO")
    expect(codes).toContain("DEX_INSECURE_TLS")
    expect(codes).toContain("DEX_DYNAMIC_CODE_LOADING")
    expect(codes).toContain("DEX_RUNTIME_EXEC")
    expect(codes).toContain("DEX_WEBVIEW_JS_BRIDGE")
    expect(findings.every((finding) => finding.confidence === "medium")).toBe(true)
  })

  test("suppresses presence-only false positives", () => {
    const codes = scanCodeStrings(
      ["MD5", "Ljava/lang/Runtime;", "ProcessBuilder", "setJavaScriptEnabled", "checkServerTrusted", "DexClassLoader"],
      "DEX",
    ).map((finding) => finding.code)
    expect(codes).not.toContain("DEX_WEAK_HASH")
    expect(codes).not.toContain("DEX_RUNTIME_EXEC")
    expect(codes).not.toContain("DEX_WEBVIEW_JS_ENABLED")
    expect(codes).not.toContain("DEX_INSECURE_TLS")
    expect(codes).not.toContain("DEX_DYNAMIC_CODE_LOADING")
  })

  test("captures a bounded evidence snippet", () => {
    const big = "x".repeat(500) + "addJavascriptInterface" + "y".repeat(500)
    const finding = scanCodeStrings([big], "DEX").find((item) => item.code === "DEX_WEBVIEW_JS_BRIDGE")
    expect(finding).toBeDefined()
    expect(finding!.evidence!.length).toBeLessThanOrEqual(200)
    expect(finding!.evidence).toContain("addJavascriptInterface")
  })
})

describe("scanCodeStrings strict source evidence", () => {
  test("matches concrete unsafe source calls", () => {
    const findings = scanCodeStrings(
      [
        "webView.settings.javaScriptEnabled = true",
        'MessageDigest.getInstance("MD5")',
        'Cipher.getInstance("AES/ECB/PKCS5Padding")',
        'Runtime.getRuntime().exec("sh")',
        "Intent.parseUri(uri, Intent.URI_INTENT_SCHEME)",
      ],
      "SOURCE",
    )
    const codes = findings.map((finding) => finding.code)
    expect(codes).toContain("SOURCE_WEBVIEW_JS_ENABLED")
    expect(codes).toContain("SOURCE_WEAK_HASH")
    expect(codes).toContain("SOURCE_WEAK_CRYPTO")
    expect(codes).toContain("SOURCE_RUNTIME_EXEC")
    expect(codes).toContain("SOURCE_COMPONENT_INTENT_SCHEME")
    expect(findings.every((finding) => finding.confidence === "high")).toBe(true)
  })

  test("does not treat safe setters or custom TLS APIs alone as vulnerabilities", () => {
    const codes = scanCodeStrings(
      [
        "webView.settings.javaScriptEnabled = false",
        "settings.setAllowFileAccess(false)",
        "settings.setDomStorageEnabled(false)",
        "override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) { validator.check(chain) }",
      ],
      "SOURCE",
    ).map((finding) => finding.code)
    expect(codes).not.toContain("SOURCE_WEBVIEW_JS_ENABLED")
    expect(codes).not.toContain("SOURCE_WEBVIEW_FILE_ACCESS")
    expect(codes).not.toContain("SOURCE_WEBVIEW_DOM_STORAGE")
    expect(codes).not.toContain("SOURCE_INSECURE_TLS")
  })

  test("keeps positive protection signals informational", () => {
    const findings = scanCodeStrings(
      ["com.scottyab.rootbeer.RootBeer(this)", "BiometricPrompt(this, executor, callback)"],
      "SOURCE",
    )
    expect(findings.find((finding) => finding.code === "SOURCE_RUNTIME_ROOT_DETECTION")?.severity).toBe("info")
    expect(findings.find((finding) => finding.code === "SOURCE_OTHER_BIOMETRIC")?.severity).toBe("info")
  })
})

describe("pendingIntentImmutableFinding", () => {
  test("flags a concrete source call with legacy flags", () => {
    const findings = pendingIntentImmutableFinding("SOURCE", [
      "val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT)",
    ])
    expect(findings.map((finding) => finding.code)).toContain("SOURCE_PENDING_INTENT_NO_MUTABILITY_FLAG")
    expect(findings[0]?.confidence).toBe("high")
  })

  test("accepts explicit immutable or mutable flags", () => {
    expect(pendingIntentImmutableFinding("SOURCE", [
      "PendingIntent.getActivity(this, 0, intent, FLAG_UPDATE_CURRENT or FLAG_IMMUTABLE)",
    ])).toHaveLength(0)
    expect(pendingIntentImmutableFinding("SOURCE", [
      "PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_MUTABLE)",
    ])).toHaveLength(0)
  })

  test("does not guess from DEX strings or unresolved source variables", () => {
    expect(pendingIntentImmutableFinding("DEX", ["Landroid/app/PendingIntent;", "getActivity"])).toHaveLength(0)
    expect(pendingIntentImmutableFinding("SOURCE", [
      "PendingIntent.getActivity(this, requestCode, intent, computedFlags)",
    ])).toHaveLength(0)
  })
})

describe("catalog invariants", () => {
  test("every suffix is unique so DEX/SOURCE codes never collide", () => {
    expect(new Set(SUFFIXES).size).toBe(SUFFIXES.length)
  })
})
