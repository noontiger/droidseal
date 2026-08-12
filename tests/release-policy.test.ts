import { describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  buildControlCoverage,
  evaluateReleaseDecision,
  RELEASE_POLICY_VERSION,
} from "../src/core/release-policy.ts"
import { writeReports } from "../src/core/report.ts"
import type {
  Finding,
  FindingConfidence,
  FindingSeverity,
  PipelineConfig,
  RunContext,
  StepId,
  StepResult,
} from "../src/core/types.ts"

function config(root = "C:/project"): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind: "apk",
    inputPath: path.join(root, "input.apk"),
    outputDirectory: path.join(root, "out"),
    gradleTask: "assembleRelease",
    enableAlignment: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

function finding(severity: FindingSeverity, confidence: FindingConfidence, code = "TEST_FINDING"): Finding {
  return {
    severity,
    confidence,
    code,
    title: code,
    detail: `${severity}/${confidence}`,
    recommendation: "review",
  }
}

function step(id: StepId, status: StepResult["status"]): StepResult {
  return {
    id,
    status,
    title: id,
    summary: `${id}-${status}`,
    detail: [],
    startedAt: "2026-08-02T00:00:00.000Z",
    finishedAt: "2026-08-02T00:00:01.000Z",
    durationMs: 1000,
  }
}

function context(input: {
  root?: string
  findings?: Finding[]
  steps?: StepResult[]
  finalArtifact?: string | null
  signatureVerified?: boolean
} = {}): RunContext {
  const root = input.root ?? "C:/project"
  const finalArtifact = input.finalArtifact === null
    ? undefined
    : input.finalArtifact ?? path.join(root, "out", "final.apk")
  return {
    runId: "release-policy-test",
    runDirectory: path.join(root, "run"),
    artifactDirectory: path.join(root, "run", "artifacts"),
    reportDirectory: path.join(root, "run", "reports"),
    currentArtifact: finalArtifact,
    originalArtifact: path.join(root, "input.apk"),
    finalArtifact,
    toolchain: undefined,
    audit: { findings: input.findings ?? [] },
    stepResults: input.steps ?? [],
    ...(input.signatureVerified === undefined ? {} : { signatureVerified: input.signatureVerified }),
  }
}

describe("confidence-aware release policy", () => {
  test("covers the complete severity by confidence decision matrix", () => {
    const severities: FindingSeverity[] = ["critical", "high", "medium", "low", "info"]
    const confidences: FindingConfidence[] = ["confirmed", "high", "medium", "low"]
    for (const severity of severities) {
      for (const confidence of confidences) {
        const decision = evaluateReleaseDecision(context({
          findings: [finding(severity, confidence)],
          signatureVerified: true,
        }))
        const expected = severity === "critical"
          ? confidence === "confirmed" || confidence === "high" ? "block" : "review"
          : severity === "high" && (confidence === "confirmed" || confidence === "high")
            ? "review"
            : "pass"
        expect(decision.status).toBe(expected)
      }
    }
  })

  test("reviews explicit release WebView debugging but keeps a missing-close gap advisory", () => {
    const enabled = evaluateReleaseDecision(context({
      signatureVerified: true,
      findings: [finding("high", "confirmed", "SOURCE_WEBVIEW_DEBUGGING_ENABLED_IN_RELEASE")],
    }))
    expect(enabled.status).toBe("review")
    expect(enabled.reviewReasons).toContainEqual(expect.objectContaining({
      findingCode: "SOURCE_WEBVIEW_DEBUGGING_ENABLED_IN_RELEASE",
    }))

    const missingClose = evaluateReleaseDecision(context({
      signatureVerified: true,
      findings: [finding("info", "low", "SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED")],
    }))
    expect(missingClose.status).toBe("pass")
    expect(missingClose.advisoryReasons).toContainEqual(expect.objectContaining({
      findingCode: "SOURCE_WEBVIEW_DEBUGGING_NOT_EXPLICITLY_DISABLED",
    }))
  })

  test("distinguishes invalid, unverified, valid, and missing release artifacts", () => {
    const invalid = evaluateReleaseDecision(context({ signatureVerified: false }))
    expect(invalid.status).toBe("block")
    expect(invalid.reasonCodes).toContain("RELEASE_SIGNATURE_INVALID_OR_MISSING")

    const unverified = evaluateReleaseDecision(context())
    expect(unverified.status).toBe("review")
    expect(unverified.reasonCodes).toContain("RELEASE_SIGNATURE_NOT_VERIFIED")

    expect(evaluateReleaseDecision(context({ signatureVerified: true })).status).toBe("pass")

    const missing = evaluateReleaseDecision(context({ finalArtifact: null, signatureVerified: false }))
    expect(missing.status).toBe("block")
    expect(missing.reasonCodes).toContain("FINAL_ARTIFACT_MISSING")
  })

  test("blocks failed steps but never blocks a skipped step by itself", () => {
    const failed = evaluateReleaseDecision(context({
      steps: [step("build", "failed")],
      signatureVerified: true,
    }))
    expect(failed.status).toBe("block")
    expect(failed.blockingReasons[0]).toMatchObject({ code: "PIPELINE_STEP_FAILED", stepId: "build" })

    const skipped = evaluateReleaseDecision(context({
      steps: [step("align", "skipped")],
      signatureVerified: true,
    }))
    expect(skipped.status).toBe("pass")
    expect(skipped.reasonCodes).toEqual([])
  })

  test("keeps low-confidence not-observed findings advisory and external controls incomplete", () => {
    const notObserved = finding("info", "low", "RUNTIME_INTEGRITY_NOT_OBSERVED")
    const runContext = context({ findings: [notObserved], signatureVerified: true })
    const decision = evaluateReleaseDecision(runContext)
    expect(decision.status).toBe("pass")
    expect(decision.advisoryReasons).toContainEqual(expect.objectContaining({
      code: "EXTERNAL_CONTROL_NOT_OBSERVED",
      findingCode: "RUNTIME_INTEGRITY_NOT_OBSERVED",
    }))

    const coverage = buildControlCoverage(config(), runContext)
    const external = coverage.controls.filter((control) => control.requiresExternalValidation)
    expect(external.map((control) => control.id)).toEqual([
      "app-signature-self-check",
      "play-integrity",
      "key-attestation",
      "challenge-replay",
      "server-risk-decision",
      "native-jni-omvll",
      "device-compatibility-matrix",
    ])
    expect(external.filter((control) => control.id !== "app-signature-self-check")
      .every((control) => control.status === "external-required")).toBe(true)
    expect(external.find((control) => control.id === "app-signature-self-check")?.status).toBe("not-applicable")
    expect(external.every((control) => control.status !== "verified")).toBe(true)
  })

  test("blocks a confirmed final-certificate mismatch and never labels a client check as verified", () => {
    const mismatch = finding("critical", "confirmed", "SIGNATURE_SELF_CHECK_CERT_MISMATCH")
    const mismatchContext = context({ findings: [mismatch], signatureVerified: true })
    const decision = evaluateReleaseDecision(mismatchContext)
    expect(decision.status).toBe("block")
    expect(decision.blockingReasons).toContainEqual(expect.objectContaining({
      findingCode: "SIGNATURE_SELF_CHECK_CERT_MISMATCH",
    }))

    const projectConfig: PipelineConfig = { ...config(), inputKind: "project" }
    expect(buildControlCoverage(projectConfig, mismatchContext).controls
      .find((control) => control.id === "app-signature-self-check")).toMatchObject({
        status: "not-verified",
        requiresExternalValidation: true,
      })

    const matched = context({
      findings: [finding("info", "confirmed", "SIGNATURE_SELF_CHECK_CERT_MATCH")],
      signatureVerified: true,
    })
    expect(buildControlCoverage(projectConfig, matched).controls
      .find((control) => control.id === "app-signature-self-check")).toMatchObject({
        status: "observed",
        requiresExternalValidation: true,
      })
  })

  test("labels exact artifact signals observed without claiming external closure", () => {
    const integrity = {
      ...finding("info", "high", "DEX_RUNTIME_INTEGRITY_ATTESTATION"),
      evidence: "Lcom/google/android/play/core/integrity/IntegrityManager;->requestIntegrityToken",
    }
    const coverage = buildControlCoverage(config(), context({
      findings: [integrity],
      signatureVerified: true,
    }))
    const playIntegrity = coverage.controls.find((control) => control.id === "play-integrity")
    expect(playIntegrity).toMatchObject({
      status: "observed",
      requiresExternalValidation: true,
      evidenceCodes: ["DEX_RUNTIME_INTEGRITY_ATTESTATION"],
    })
    expect(coverage.controls.filter((control) => control.requiresExternalValidation)
      .every((control) => control.status !== "verified")).toBe(true)
  })

  test("requires successful source audit before marking release R8 verified", () => {
    const projectConfig: PipelineConfig = { ...config(), inputKind: "project" }
    const complete = context({
      signatureVerified: true,
      steps: [step("source-audit", "success"), step("build", "success")],
    })
    expect(buildControlCoverage(projectConfig, complete).controls
      .find((control) => control.id === "droidseal-release-r8")?.status).toBe("verified")

    const auditSkipped = context({
      signatureVerified: true,
      steps: [step("source-audit", "skipped"), step("build", "success")],
    })
    expect(buildControlCoverage(projectConfig, auditSkipped).controls
      .find((control) => control.id === "droidseal-release-r8")?.status).toBe("not-verified")

    const disabled = context({
      signatureVerified: true,
      findings: [finding("high", "confirmed", "R8_OBFUSCATION_DISABLED")],
      steps: [step("source-audit", "success"), step("build", "success")],
    })
    expect(buildControlCoverage(projectConfig, disabled).controls
      .find((control) => control.id === "droidseal-release-r8")?.status).toBe("not-verified")
  })

  test("writes the same policy version, status, and reason codes to JSON and Markdown", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-release-policy-"))
    const output = path.join(root, "out")
    const finalArtifact = path.join(output, "final.apk")
    await mkdir(output, { recursive: true })
    await writeFile(path.join(root, "input.apk"), "input", "utf8")
    await writeFile(finalArtifact, "final", "utf8")
    const runContext = context({
      root,
      finalArtifact,
      signatureVerified: true,
      findings: [finding("critical", "confirmed", "CONFIRMED_CRITICAL")],
      steps: [step("verify", "success")],
    })
    const expectedFingerprint = "0123456789abcdef".repeat(4)
    runContext.audit.signatureSelfChecks = [{
      modulePath: "app",
      expectedStatus: "literal",
      expectedFingerprints: [expectedFingerprint],
      checkMethodNames: ["verifySignature"],
      hasSigningApi: true,
      hasSha256Digest: true,
      startupInvoked: true,
      forcedDisposition: true,
      locations: {
        configuration: ["app/src/main/java/com/example/SignatureGuard.kt:4"],
        signingApi: ["app/src/main/java/com/example/SignatureGuard.kt:7"],
        digest: ["app/src/main/java/com/example/SignatureGuard.kt:8"],
        startup: ["app/src/main/java/com/example/MainActivity.kt:12"],
        disposition: ["app/src/main/java/com/example/MainActivity.kt:12"],
      },
    }]

    const paths = await writeReports(config(root), runContext)
    const rawJson = await readFile(paths.json, "utf8")
    const report = JSON.parse(rawJson) as {
      schemaVersion: number
      releaseDecision: { ruleVersion: string; status: string; reasonCodes: string[] }
      controlCoverage: { ruleVersion: string; controls: Array<{ status: string }> }
      audit: { signatureSelfChecks: Array<{ expectedFingerprintCount: number }> }
    }
    const markdown = await readFile(paths.markdown, "utf8")

    expect(report.schemaVersion).toBe(7)
    expect(report.releaseDecision).toMatchObject({
      ruleVersion: RELEASE_POLICY_VERSION,
      status: "block",
    })
    expect(report.releaseDecision.reasonCodes).toContain("CRITICAL_FINDING_CONFIRMED")
    expect(report.controlCoverage.ruleVersion).toBe(RELEASE_POLICY_VERSION)
    expect(report.audit.signatureSelfChecks).toEqual([
      expect.objectContaining({ expectedFingerprintCount: 1 }),
    ])
    expect(rawJson).not.toContain(expectedFingerprint)
    expect(paths.releaseDecisionStatus).toBe("block")
    expect(markdown).toContain("## 发布门禁")
    expect(markdown).toContain("**阻断发布**（`block`）")
    expect(markdown).toContain("`CRITICAL_FINDING_CONFIRMED`")
    expect(markdown).toContain(`\`${RELEASE_POLICY_VERSION}\``)
    expect(markdown).toContain("## 纵深防御控制覆盖")
    expect(markdown).not.toContain("| Play Integrity 服务端校验 | server-team | 已验证")
  })
})
