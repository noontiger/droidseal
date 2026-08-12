import { describe, expect, test } from "bun:test"
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { apkSoftwareComponents } from "../src/core/apk-audit.ts"
import { collectGradleSoftwareComponents } from "../src/core/gradle-components.ts"
import { writeReports } from "../src/core/report.ts"
import { normalizeSoftwareComponents, writeSupplyChainArtifacts } from "../src/core/sbom.ts"
import type {
  Finding,
  PipelineConfig,
  RunContext,
  SoftwareComponent,
} from "../src/core/types.ts"

function component(
  components: readonly SoftwareComponent[],
  name: string,
): SoftwareComponent | undefined {
  return components.find((item) => item.name === name)
}

function config(inputPath: string, outputDirectory: string): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind: "apk",
    inputPath,
    outputDirectory,
    gradleTask: "assembleRelease",
    enableAlignment: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

function context(
  root: string,
  softwareComponents: SoftwareComponent[],
  finalArtifact?: string,
): RunContext {
  return {
    runId: "sbom-test",
    runDirectory: path.join(root, "run"),
    artifactDirectory: path.join(root, "run", "artifacts"),
    reportDirectory: path.join(root, "run", "reports"),
    currentArtifact: finalArtifact,
    originalArtifact: path.join(root, "input.apk"),
    finalArtifact,
    toolchain: undefined,
    audit: {
      findings: [],
      softwareComponents,
      apkMetadata: {
        packageName: "com.example.secure",
        versionName: "1.2.3",
      },
    },
    stepResults: [],
  }
}

describe("Gradle component inventory", () => {
  test("emits purls only for exact literals and leaves dynamic/version-ref unresolved", () => {
    const sources = [
      {
        relativePath: "app/build.gradle.kts",
        source: [
          "dependencies {",
          "  implementation(\"com.squareup.okhttp3:okhttp:4.12.0\")",
          "  implementation(\"com.example:dynamic:1.+\")",
          "  implementation(\"com.example:variable:${libVersion}\")",
          "  classpath(\"com.android.tools.build:gradle:8.6.1\")",
          "}",
        ].join("\n"),
      },
      {
        relativePath: "gradle/libs.versions.toml",
        source: [
          "[versions]",
          "retrofit = \"2.11.0\"",
          "[libraries]",
          "retrofit = { module = \"com.squareup.retrofit2:retrofit\", version.ref = \"retrofit\" }",
          "gson = { module = \"com.google.code.gson:gson\", version = \"2.11.0\" }",
          "coil = \"io.coil-kt:coil:2.6.0\"",
        ].join("\n"),
      },
    ]

    const components = collectGradleSoftwareComponents(sources)
    const reversed = collectGradleSoftwareComponents([...sources].reverse())

    expect(reversed).toEqual(components)
    expect(components.map((item) => item.name)).toEqual(
      [...components.map((item) => item.name)].sort((left, right) => {
        const leftComponent = components.find((item) => item.name === left)!
        const rightComponent = components.find((item) => item.name === right)!
        return [
          leftComponent.kind,
          leftComponent.namespace ?? "",
          leftComponent.name,
          leftComponent.version ?? "",
          leftComponent.resolution,
          leftComponent.scope,
        ].join("|").localeCompare([
          rightComponent.kind,
          rightComponent.namespace ?? "",
          rightComponent.name,
          rightComponent.version ?? "",
          rightComponent.resolution,
          rightComponent.scope,
        ].join("|"))
      }),
    )

    expect(component(components, "okhttp")).toMatchObject({
      namespace: "com.squareup.okhttp3",
      version: "4.12.0",
      resolution: "declared-exact",
      purl: "pkg:maven/com.squareup.okhttp3/okhttp@4.12.0",
    })
    expect(component(components, "gson")).toMatchObject({
      version: "2.11.0",
      resolution: "declared-exact",
    })
    expect(component(components, "coil")).toMatchObject({
      version: "2.6.0",
      resolution: "declared-exact",
    })
    expect(component(components, "dynamic")).toMatchObject({
      resolution: "declared-unresolved",
    })
    expect(component(components, "dynamic")?.version).toBeUndefined()
    expect(component(components, "dynamic")?.purl).toBeUndefined()
    expect(component(components, "variable")?.version).toBeUndefined()
    expect(component(components, "retrofit")).toMatchObject({
      resolution: "declared-unresolved",
    })
    expect(component(components, "retrofit")?.version).toBeUndefined()
    expect(component(components, "gradle")?.scope).toBe("build")
    expect(components.some((item) => item.name.includes("opentui"))).toBe(false)
  })
})

describe("APK observed component inventory", () => {
  test("keeps DEX SDK families unresolved and de-duplicates native libraries across ABIs", () => {
    const sdkFinding: Finding = {
      severity: "info",
      confidence: "confirmed",
      code: "SUPPLYCHAIN_SDK_INVENTORY",
      title: "SDK inventory",
      detail: "Observed from DEX descriptors",
      recommendation: "Resolve versions from the source lockfile.",
      evidence: "Google Firebase, OkHttp",
    }
    const components = apkSoftwareComponents([sdkFinding], [
      "lib/arm64-v8a/libsecure.so",
      "lib/armeabi-v7a/libsecure.so",
      "lib/arm64-v8a/libother.so",
    ])

    const firebase = component(components, "Google Firebase")
    const secure = component(components, "libsecure.so")
    expect(firebase).toMatchObject({
      kind: "sdk-family",
      resolution: "observed",
      scope: "runtime",
    })
    expect(firebase?.version).toBeUndefined()
    expect(firebase?.purl).toBeUndefined()
    expect(components.filter((item) => item.name === "libsecure.so")).toHaveLength(1)
    expect(secure?.architectures).toEqual(["arm64-v8a", "armeabi-v7a"])
    expect(secure?.evidence).toEqual([
      "lib/arm64-v8a/libsecure.so",
      "lib/armeabi-v7a/libsecure.so",
    ])
  })
})

describe("CycloneDX and license review artifacts", () => {
  test("sorts components deterministically and never invents versions or licenses", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-sbom-"))
    const output = path.join(root, "out")
    const finalArtifact = path.join(output, "final.apk")
    await mkdir(output, { recursive: true })
    await writeFile(path.join(root, "input.apk"), "input", "utf8")
    await writeFile(finalArtifact, "final", "utf8")

    const gradle = collectGradleSoftwareComponents([{
      relativePath: "app/build.gradle",
      source: [
        "implementation \"com.squareup.okhttp3:okhttp:4.12.0\"",
        "implementation \"com.example:dynamic:latest.release\"",
      ].join("\n"),
    }])
    const observed = apkSoftwareComponents([
      {
        severity: "info",
        code: "SUPPLYCHAIN_SDK_INVENTORY",
        title: "SDK",
        detail: "DEX",
        recommendation: "Review",
        evidence: "Google Firebase",
      },
    ], [
      "lib/x86_64/libsecure.so",
      "lib/arm64-v8a/libsecure.so",
    ])
    const all = [...observed, ...gradle, observed[0]!]
    expect(normalizeSoftwareComponents(all)).toEqual(
      normalizeSoftwareComponents([...all].reverse()),
    )

    const runContext = context(root, all, finalArtifact)
    const result = await writeSupplyChainArtifacts(
      config(path.join(root, "input.apk"), output),
      runContext,
      "2026-08-02T00:00:00.000Z",
    )
    const sbom = JSON.parse(await readFile(result.sbomPath, "utf8")) as {
      bomFormat: string
      specVersion: string
      components: Array<{
        name: string
        version?: string
        purl?: string
        properties: Array<{ name: string; value: string }>
      }>
    }
    const license = JSON.parse(await readFile(result.licenseReviewPath, "utf8")) as {
      summary: { componentCount: number; noAssertionCount: number }
      components: Array<{
        name: string
        licenseConcluded: string
        reviewStatus: string
      }>
    }

    expect(sbom.bomFormat).toBe("CycloneDX")
    expect(sbom.specVersion).toBe("1.5")
    expect(sbom.components.map((item) => item.name)).toEqual([
      "dynamic",
      "okhttp",
      "libsecure.so",
      "Google Firebase",
    ])
    expect(sbom.components.find((item) => item.name === "okhttp")?.purl)
      .toBe("pkg:maven/com.squareup.okhttp3/okhttp@4.12.0")
    expect(sbom.components.find((item) => item.name === "dynamic")?.version).toBeUndefined()
    expect(sbom.components.find((item) => item.name === "Google Firebase")?.purl).toBeUndefined()
    expect(sbom.components.find((item) => item.name === "libsecure.so")?.properties)
      .toContainEqual({ name: "droidseal:android-abis", value: "arm64-v8a,x86_64" })
    expect(result.unresolvedCount).toBe(3)
    expect(license.summary.componentCount).toBe(4)
    expect(license.summary.noAssertionCount).toBe(4)
    expect(license.components.every((item) =>
      item.licenseConcluded === "NOASSERTION" && item.reviewStatus === "required"
    )).toBe(true)
  })

  test("links SBOM and license review from JSON and Markdown reports", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-sbom-report-"))
    const output = path.join(root, "out")
    const finalArtifact = path.join(output, "final.apk")
    await mkdir(output, { recursive: true })
    await writeFile(path.join(root, "input.apk"), "input", "utf8")
    await writeFile(finalArtifact, "final", "utf8")
    const components = collectGradleSoftwareComponents([{
      relativePath: "app/build.gradle",
      source: "implementation \"com.example:library:1.0.0\"",
    }])
    const runContext = context(root, components, finalArtifact)

    const paths = await writeReports(config(path.join(root, "input.apk"), output), runContext)
    const report = JSON.parse(await readFile(paths.json, "utf8")) as {
      schemaVersion: number
      supplyChain: {
        sbom: string
        licenseReview: string
        componentCount: number
        unresolvedCount: number
      }
    }
    const markdown = await readFile(paths.markdown, "utf8")

    expect(report.schemaVersion).toBe(7)
    expect(report.supplyChain.sbom).toBe(paths.sbom)
    expect(report.supplyChain.licenseReview).toBe(paths.licenseReview)
    expect(report.supplyChain.componentCount).toBe(1)
    expect(report.supplyChain.unresolvedCount).toBe(0)
    expect(markdown).toContain("## 供应链制品")
    expect(markdown).toContain(paths.sbom)
    expect(markdown).toContain(paths.licenseReview)
    expect(markdown).toContain("NOASSERTION")
  })
})
