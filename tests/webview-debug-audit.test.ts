import { describe, expect, test } from "bun:test"
import {
  analyzeWebViewDebugging,
  type WebViewDebugSourceFile,
} from "../src/core/webview-debug-audit.ts"

function file(content: string, sourceSet = "main"): WebViewDebugSourceFile {
  return {
    relativePath: `app/src/${sourceSet}/java/com/example/App.kt`,
    content: `
      package com.example
      import android.webkit.WebView
      class App { ${content} }
    `,
  }
}

describe("WebView debugging source audit", () => {
  test("recognizes an explicit release false even when debug builds opt in", () => {
    const result = analyzeWebViewDebugging([
      file(`fun configure() {
        WebView.setWebContentsDebuggingEnabled(false)
        if (BuildConfig.DEBUG) {
          WebView.setWebContentsDebuggingEnabled(true)
        }
      }`),
    ], "app")

    expect(result.state).toBe("explicit-disabled")
    expect(result.findings).toEqual([
      expect.objectContaining({
        code: "SOURCE_WEBVIEW_DEBUGGING_EXPLICITLY_DISABLED",
        confidence: "confirmed",
      }),
    ])
  })

  test("recognizes BuildConfig and src/debug enablement as debug-only", () => {
    const result = analyzeWebViewDebugging([
      file("fun configure() = WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG)"),
      file("fun configureEquivalent() = WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG != false)"),
      file("fun configureDebug() = WebView.setWebContentsDebuggingEnabled(true)", "debug"),
    ], "app")

    expect(result.state).toBe("debug-only-enabled")
    expect(result.findings[0]).toMatchObject({
      code: "SOURCE_WEBVIEW_DEBUGGING_DEBUG_ONLY",
      severity: "info",
      confidence: "confirmed",
    })
  })

  test("reports an unguarded release true and ignores comments and strings", () => {
    const result = analyzeWebViewDebugging([
      file(`fun configure() {
        // WebView.setWebContentsDebuggingEnabled(false)
        val example = "WebView.setWebContentsDebuggingEnabled(false)"
        WebView.setWebContentsDebuggingEnabled(true)
        WebView.setWebContentsDebuggingEnabled(!BuildConfig.DEBUG)
      }`),
    ], "app")

    expect(result.state).toBe("release-enabled")
    expect(result.findings[0]).toMatchObject({
      code: "SOURCE_WEBVIEW_DEBUGGING_ENABLED_IN_RELEASE",
      severity: "high",
      confidence: "confirmed",
    })
    expect(result.locations.explicitFalse).toEqual([])
    expect(result.locations.releaseTrue).toHaveLength(2)
  })

  test("keeps absence or a dynamic value low-confidence and non-assertive", () => {
    const absent = analyzeWebViewDebugging([
      file("fun open(view: WebView) { view.loadUrl(url) }"),
    ], "app")
    expect(absent.state).toBe("not-explicitly-disabled")
    expect(absent.findings[0]).toMatchObject({
      code: "SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED",
      severity: "info",
      confidence: "low",
    })

    const dynamic = analyzeWebViewDebugging([
      file("fun configure(flag: Boolean) = WebView.setWebContentsDebuggingEnabled(flag)"),
    ], "app")
    expect(dynamic.state).toBe("not-explicitly-disabled")
    expect(dynamic.locations.unresolved).toHaveLength(1)
  })

  test("does not emit a WebView finding for an unrelated Android module", () => {
    const result = analyzeWebViewDebugging([{
      relativePath: "app/src/main/java/com/example/App.kt",
      content: "class App { fun start() = Unit }",
    }], "app")
    expect(result.state).toBe("not-applicable")
    expect(result.findings).toEqual([])
  })
})
