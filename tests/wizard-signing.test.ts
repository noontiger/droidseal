import path from "node:path"
import { describe, expect, test } from "bun:test"
import { buildPipelineConfig, createDraft, questionsFor, applyAnswer, summaryLines, type WizardDraft } from "../src/ui/wizard.ts"
import type { WizardQuestion } from "../src/ui/wizard.ts"
import { stepColor, theme } from "../src/ui/theme.ts"

function baseDraft(): WizardDraft {
  return {
    ...createDraft("guided"),
    inputKind: "project",
    inputPath: "C:\\work\\app",
    gradleTask: "assembleRelease",
    buildMode: "full",
    outputDirectory: "C:\\work\\app\\droidseal-output",
    enableAlignment: true,
    enableWebAssetMinification: false,
    enableArscObfuscation: false,
  }
}

function answer(draft: WizardDraft, question: WizardQuestion, value: string): WizardDraft {
  return applyAnswer(draft, question, value).draft
}

describe("wizard signing flow", () => {
  test("create mode emits a CreateSigningConfig with DN and key parameters", () => {
    let draft = { ...baseDraft(), signingMode: "create" as const, keystorePath: "C:\\keys\\new.p12", keyAlias: "release", storePassword: "secret1", keyPassword: "secret1", commonName: "Acme", country: "CN", validityDays: 9125, keyAlgorithm: "RSA" as const }
    const config = buildPipelineConfig(draft)
    expect(config.signing.mode).toBe("create")
    if (config.signing.mode !== "create") throw new Error("unreachable")
    expect(config.signing.keystorePath).toBe("C:\\keys\\new.p12")
    expect(config.signing.keyAlias).toBe("release")
    expect(config.signing.storePassword).toBe("secret1")
    expect(config.signing.keyPassword).toBe("secret1")
    expect(config.signing.validityDays).toBe(9125)
    expect(config.signing.keyAlgorithm).toBe("RSA")
    expect(config.signing.keySize).toBe(4096)
    expect(config.signing.distinguishedName.commonName).toBe("Acme")
    expect(config.signing.distinguishedName.country).toBe("CN")
    // Default renewKey is false → create mode must NOT overwrite an existing file.
    expect(config.signing.overwrite).toBe(false)
  })

  test("existing mode emits an ExistingSigningConfig", () => {
    const draft = { ...baseDraft(), signingMode: "existing" as const, keystorePath: "C:\\keys\\release.jks", keyAlias: "release", storePassword: "secret1", keyPassword: "secret1" }
    const config = buildPipelineConfig(draft)
    expect(config.signing.mode).toBe("existing")
    if (config.signing.mode !== "existing") throw new Error("unreachable")
    expect(config.signing.keystorePath).toBe("C:\\keys\\release.jks")
    expect(config.signing.keyAlias).toBe("release")
  })

  test("existing + renewKey emits a CreateSigningConfig with overwrite=true", () => {
    const draft = { ...baseDraft(), signingMode: "existing" as const, renewKey: true, keystorePath: "C:\\keys\\release.jks", keyAlias: "release", storePassword: "secret1", keyPassword: "secret1", commonName: "Acme", country: "CN", validityDays: 9125, keyAlgorithm: "RSA" as const }
    const config = buildPipelineConfig(draft)
    expect(config.signing.mode).toBe("create")
    if (config.signing.mode !== "create") throw new Error("unreachable")
    // Critical: renewing over an existing keystore must set overwrite so the
    // pipeline deletes the old keystore before generating the replacement.
    expect(config.signing.overwrite).toBe(true)
    expect(config.signing.keystorePath).toBe("C:\\keys\\release.jks")
    expect(config.signing.distinguishedName.commonName).toBe("Acme")
  })

  test("renewKey question only appears when signingMode is existing", () => {
    expect(questionsFor({ ...baseDraft(), signingMode: "existing" }).some((q) => q.id === "renewKey")).toBe(true)
    expect(questionsFor({ ...baseDraft(), signingMode: "create" }).some((q) => q.id === "renewKey")).toBe(false)
    expect(questionsFor({ ...baseDraft(), signingMode: "skip" }).some((q) => q.id === "renewKey")).toBe(false)
  })

  test("DN questions appear for create and for existing+renewKey, but not for plain existing", () => {
    const hasDn = (d: WizardDraft) => questionsFor(d).some((q) => q.id === "commonName")
    expect(hasDn({ ...baseDraft(), signingMode: "create" })).toBe(true)
    expect(hasDn({ ...baseDraft(), signingMode: "existing" })).toBe(false)
    expect(hasDn({ ...baseDraft(), signingMode: "existing", renewKey: true })).toBe(true)
  })

  test("applyAnswer parses renewKey and resets it when leaving existing mode", () => {
    let draft = baseDraft()
    const sm = questionsFor(draft).find((q) => q.id === "signingMode")!
    draft = answer(draft, sm, "existing")
    const rk = questionsFor(draft).find((q) => q.id === "renewKey")!
    draft = answer(draft, rk, "yes")
    expect(draft.renewKey).toBe(true)

    // Switching to "create" must clear renewKey so a later build does not
    // accidentally emit overwrite:true against an unrelated path.
    draft = answer(draft, sm, "create")
    expect(draft.renewKey).toBe(false)
  })

  test("rejects a project release label mistaken for a Gradle task", () => {
    // 输入路径用平台无关的相对路径：path.basename(path.resolve(...)) 在
    // Windows 与 Linux CI 上都解析为 "app"，保证 "app-release" 稳定触发拒绝逻辑。
    const draft = { ...baseDraft(), inputPath: path.join("work", "app") }
    const question = questionsFor(draft).find((q) => q.id === "gradleTask")!

    expect(() => applyAnswer(draft, question, "app-release")).toThrow("不是 Gradle 任务")
    expect(applyAnswer(draft, question, "assembleRelease").draft.gradleTask).toBe("assembleRelease")
  })

  test("APK output override accepts only a concrete APK file or blank", () => {
    const draft = baseDraft()
    const question = questionsFor(draft).find((q) => q.id === "explicitBuiltApkPath")!

    expect(() => applyAnswer(draft, question, "C:\\work\\app")).toThrow("具体的 .apk 文件")
    expect(applyAnswer(draft, question, "").draft.explicitBuiltApkPath).toBe("")
    expect(applyAnswer(draft, question, "app\\build\\outputs\\apk\\release\\app-release.apk").draft.explicitBuiltApkPath)
      .toBe("app\\build\\outputs\\apk\\release\\app-release.apk")
  })

  test("output directory exposes and applies a default address", () => {
    const projectDraft = baseDraft()
    const projectQuestion = questionsFor(projectDraft).find((q) => q.id === "outputDirectory")!
    const projectDefault = path.join(path.resolve(projectDraft.inputPath), "droidseal-output")

    expect(projectQuestion.defaultValue).toBe(projectDefault)
    expect(projectQuestion.title).toContain("默认地址")
    expect(applyAnswer(projectDraft, projectQuestion, "").draft.outputDirectory).toBe(projectDefault)

    const apkDraft = {
      ...projectDraft,
      inputKind: "apk" as const,
      inputPath: "C:\\work\\app-release.apk",
    }
    const apkQuestion = questionsFor(apkDraft).find((q) => q.id === "outputDirectory")!
    expect(apkQuestion.defaultValue).toBe(
      path.join(path.dirname(path.resolve(apkDraft.inputPath)), "droidseal-output"),
    )
  })

  test("completed steps use the bright yellow completion color", () => {
    expect(theme.complete).toBe("#ffdf4d")
    expect(stepColor("success")).toBe(theme.complete)
  })

  test("summaryLines flags overwrite for existing+renewKey", () => {
    const plain = summaryLines({ ...baseDraft(), signingMode: "existing", keystorePath: "C:\\keys\\release.jks" })
    expect(plain.join(" ")).toContain("使用现有签名库重新签名")
    expect(plain.join(" ")).not.toContain("将覆盖原文件")

    const renew = summaryLines({ ...baseDraft(), signingMode: "existing", renewKey: true, keystorePath: "C:\\keys\\release.jks" })
    expect(renew.join(" ")).toContain("换新密钥")
    expect(renew.join(" ")).toContain("将覆盖原文件")
  })
})
