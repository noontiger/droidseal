import { describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { Pipeline, STEP_DEFINITIONS, stepGuidance } from "../src/core/pipeline.ts"
import type { PipelineConfig } from "../src/core/types.ts"
import { buildPipelineConfig, createDraft, questionsFor, summaryLines, type WizardDraft } from "../src/ui/wizard.ts"
import { setLanguage } from "../src/ui/i18n.ts"

// 断言依赖默认语言:固定为英文,避免受系统语言检测影响
setLanguage("en")

function config(): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind: "apk",
    inputPath: "example.apk",
    outputDirectory: "output",
    gradleTask: "assembleRelease",
    enableAlignment: true,
    enableWebAssetMinification: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

describe("step guidance and skip explanations", () => {
  test("provides concise guidance for every pipeline step", () => {
    const current = config()
    for (const step of STEP_DEFINITIONS) {
      expect(stepGuidance(step.id, current).join(" ")).not.toBe("")
    }
  })

  test("keeps professional terminology while explaining inapplicable steps", () => {
    const current = config()
    expect(stepGuidance("source-audit", current).join(" ")).toContain("Manifest")
    expect(stepGuidance("source-audit", current).join(" ")).toContain("跳过·不适用")
    expect(stepGuidance("align", current).join(" ")).toContain("zipalign")
    expect(stepGuidance("verify", current).join(" ")).toContain("SHA-256")
  })

  test("classifies automatic and manual skips", async () => {
    const automatic = new Pipeline(config())
    const sourceAudit = await automatic.runStep("source-audit")
    expect(sourceAudit.status).toBe("skipped")
    expect(sourceAudit.skipKind).toBe("not-applicable")
    expect(sourceAudit.detail.join(" ")).toContain("不是失败")

    const manual = new Pipeline(config())
    const doctor = await manual.skipStep("doctor")
    expect(doctor.skipKind).toBe("user-choice")
    expect(doctor.detail.join(" ")).toContain("用户选择")
  })

  test("uses the local-safe profile without adding a risky injection question", () => {
    const draft: WizardDraft = {
      ...createDraft("guided"),
      inputKind: "apk",
      inputPath: "example.apk",
      outputDirectory: "output",
      enableAlignment: true,
    enableWebAssetMinification: false,
      enableArscObfuscation: false,
      signingMode: "skip",
    }
    // Unknown-APK runtime injection stays outside the safe default flow.
    expect(questionsFor(draft).some((question) => question.id === "protectionProfile")).toBe(false)
    expect(summaryLines(draft).join(" ")).toContain("never injects startup code")

    const built = buildPipelineConfig(draft)
    expect(built.protection.mode).toBe("local-safe")
    expect(built.enableWebAssetMinification).toBe(false)
    const webQuestion = questionsFor(draft).find((question) => question.id === "enableWebAssetMinification")!
    expect(webQuestion.choices?.[0]?.value).toBe("yes")
    expect(summaryLines(draft).join(" ")).toContain("Web JavaScript: not processed")
  })

  test("protect step evaluates evidence without claiming absence as fact", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "droidseal-test-"))
    const inputApk = path.join(workspace, "example.apk")
    await writeFile(inputApk, "PK\u0003\u0004fake-apk-bytes")
    const pipeline = new Pipeline({ ...config(), inputPath: inputApk, outputDirectory: path.join(workspace, "out") })
    await pipeline.runStep("prepare")
    const protect = await pipeline.runStep("protect")
    expect(protect.status).toBe("success")
    expect(protect.skipKind).toBeUndefined()
    const codes = (protect.findings ?? []).map((finding) => finding.code)
    expect(codes).not.toContain("DEX_STANDARD_FORMAT_PRESENT")
    expect(codes).toContain("ANTI_DEBUG_NOT_OBSERVED")
    expect(codes).toContain("RUNTIME_INTEGRITY_NOT_OBSERVED")
    expect((protect.findings ?? []).filter((finding) => finding.code.endsWith("_NOT_OBSERVED")).every((finding) => finding.confidence === "low")).toBe(true)
  })
})
