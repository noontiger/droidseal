import { describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import {
  inferGradleArtifactIdentity,
  writeReleaseEvidence,
  type ReleaseEvidenceManifest,
} from "../src/core/release-evidence.ts"
import { writeReports } from "../src/core/report.ts"
import type { PipelineConfig, RunContext } from "../src/core/types.ts"

async function writeTree(root: string, files: Record<string, string>): Promise<void> {
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative)
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, content, "utf8")
  }
}

function config(
  inputKind: PipelineConfig["inputKind"],
  inputPath: string,
  outputDirectory: string,
): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind,
    inputPath,
    outputDirectory,
    gradleTask: "assembleRelease",
    enableAlignment: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

function context(input: {
  runDirectory: string
  reportDirectory: string
  artifactDirectory: string
  originalArtifact?: string
  finalArtifact?: string
}): RunContext {
  return {
    runId: "release-evidence-test",
    runDirectory: input.runDirectory,
    reportDirectory: input.reportDirectory,
    artifactDirectory: input.artifactDirectory,
    currentArtifact: input.finalArtifact,
    originalArtifact: input.originalArtifact,
    finalArtifact: input.finalArtifact,
    toolchain: undefined,
    audit: { findings: [] },
    stepResults: [],
  }
}

async function readManifest(manifestPath: string): Promise<ReleaseEvidenceManifest> {
  return JSON.parse(await readFile(manifestPath, "utf8")) as ReleaseEvidenceManifest
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

const REQUIRED_R8_FILES = ["mapping.txt", "configuration.txt", "seeds.txt", "usage.txt"]

describe("release evidence archive", () => {
  test("archives only the exact selected flavor variant and verifies hashes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-"))
    const output = path.join(root, "dist")
    const runDirectory = path.join(root, ".droidseal", "runs", "one")
    const artifactDirectory = path.join(runDirectory, "artifacts")
    const reportDirectory = path.join(runDirectory, "reports")
    const sourceApk = path.join(root, "app", "build", "outputs", "apk", "free", "release", "app-free-release.apk")
    const finalArtifact = path.join(output, "app-sealed.apk")

    await writeTree(root, {
      "app/build/outputs/apk/free/release/app-free-release.apk": "selected-apk",
      "app/build/outputs/mapping/freeRelease/mapping.txt": "selected-mapping",
      "app/build/outputs/mapping/freeRelease/configuration.txt": "selected-configuration",
      "app/build/outputs/mapping/freeRelease/seeds.txt": "selected-seeds",
      "app/build/outputs/mapping/freeRelease/usage.txt": "selected-usage",
      "app/build/outputs/mapping/freeRelease/missing_rules.txt": "selected-missing-rules",
      "app/build/outputs/mapping/release/mapping.txt": "old-release-mapping",
      "dist/app-sealed.apk": "final-apk",
      ".droidseal/runs/one/artifacts/droidseal-force-r8.init.gradle": "forced-r8-overlay",
    })

    const identity = inferGradleArtifactIdentity(root, sourceApk)
    expect(identity?.variant).toBe("freeRelease")
    expect(identity?.mappingDirectory).toBe("app/build/outputs/mapping/freeRelease")

    const result = await writeReleaseEvidence(
      config("project", root, output),
      context({ runDirectory, reportDirectory, artifactDirectory, originalArtifact: sourceApk, finalArtifact }),
      "2026-08-02T00:00:00.000Z",
    )
    const manifest = await readManifest(result.manifestPath)

    expect(result.status).toBe("complete")
    expect(result.variant).toBe("freeRelease")
    expect(manifest.gradle?.sourceApkPath).toBe("app/build/outputs/apk/free/release/app-free-release.apk")
    expect(manifest.files.map((file) => file.archivePath)).toEqual([
      "build/droidseal-force-r8.init.gradle",
      "r8/configuration.txt",
      "r8/mapping.txt",
      "r8/missing_rules.txt",
      "r8/seeds.txt",
      "r8/usage.txt",
    ])
    expect(await readFile(path.join(result.directory, "r8", "mapping.txt"), "utf8")).toBe("selected-mapping")
    expect(await readFile(path.join(result.directory, "r8", "mapping.txt"), "utf8")).not.toBe("old-release-mapping")

    const mapping = manifest.files.find((file) => file.kind === "r8-mapping")
    expect(mapping?.sha256).toBe(createHash("sha256").update("selected-mapping").digest("hex"))
    expect(manifest.artifact?.sha256).toBe(createHash("sha256").update("final-apk").digest("hex"))
    expect(manifest.files.every((file) => !path.isAbsolute(file.sourcePath))).toBe(true)
    expect(manifest.files.every((file) => !file.sourcePath.includes(".."))).toBe(true)
    expect(JSON.stringify(manifest)).not.toContain("old-release-mapping")
  })

  test("marks missing required outputs as partial and explains optional absence", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-partial-"))
    const output = path.join(root, "out")
    const runDirectory = path.join(root, ".droidseal", "runs", "partial")
    const sourceApk = path.join(root, "app", "build", "outputs", "apk", "release", "app-release.apk")
    const finalArtifact = path.join(output, "app.apk")
    await writeTree(root, {
      "app/build/outputs/apk/release/app-release.apk": "apk",
      "app/build/outputs/mapping/release/mapping.txt": "mapping",
      "app/build/outputs/mapping/release/configuration.txt": "configuration",
      "app/build/outputs/mapping/debug/seeds.txt": "stale-debug-seeds",
      "out/app.apk": "final",
    })

    const result = await writeReleaseEvidence(
      config("project", root, output),
      context({
        runDirectory,
        reportDirectory: path.join(runDirectory, "reports"),
        artifactDirectory: path.join(runDirectory, "artifacts"),
        originalArtifact: sourceApk,
        finalArtifact,
      }),
    )
    const manifest = await readManifest(result.manifestPath)

    expect(result.status).toBe("partial")
    expect(manifest.files.map((file) => file.archivePath)).toEqual([
      "r8/configuration.txt",
      "r8/mapping.txt",
    ])
    expect(manifest.missing.filter((item) => item.required).map((item) => item.fileName).sort()).toEqual([
      "seeds.txt",
      "usage.txt",
    ])
    expect(manifest.missing.find((item) => item.fileName === "missing_rules.txt")?.required).toBe(false)
    expect(JSON.stringify(manifest)).not.toContain("stale-debug-seeds")
  })

  test("marks APK input as not applicable without pretending R8 outputs exist", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-apk-"))
    const output = path.join(root, "out")
    const runDirectory = path.join(root, "run")
    const inputApk = path.join(root, "input.apk")
    const finalArtifact = path.join(output, "final.apk")
    await writeTree(root, {
      "input.apk": "input",
      "out/final.apk": "final",
      "run/artifacts/droidseal-force-r8.init.gradle": "should-not-be-used-for-apk-input",
    })

    const result = await writeReleaseEvidence(
      config("apk", inputApk, output),
      context({
        runDirectory,
        reportDirectory: path.join(runDirectory, "reports"),
        artifactDirectory: path.join(runDirectory, "artifacts"),
        originalArtifact: inputApk,
        finalArtifact,
      }),
    )
    const manifest = await readManifest(result.manifestPath)

    expect(result.status).toBe("not-applicable")
    expect(manifest.gradle).toBeNull()
    expect(manifest.files).toEqual([])
    expect(manifest.missing).toEqual([])
    expect(manifest.artifact?.path).toBe("final.apk")
  })

  test("refuses an APK outside the project and never falls back to stale mapping", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-boundary-"))
    const external = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-external-"))
    const output = path.join(root, "out")
    const runDirectory = path.join(root, "run")
    const sourceApk = path.join(external, "app", "build", "outputs", "apk", "release", "outside.apk")
    const finalArtifact = path.join(output, "final.apk")
    await writeTree(external, {
      "app/build/outputs/apk/release/outside.apk": "outside",
    })
    await writeTree(root, {
      "app/build/outputs/mapping/release/mapping.txt": "stale-project-mapping",
      "out/final.apk": "final",
    })

    expect(inferGradleArtifactIdentity(root, sourceApk)).toBeUndefined()
    const result = await writeReleaseEvidence(
      config("project", root, output),
      context({
        runDirectory,
        reportDirectory: path.join(runDirectory, "reports"),
        artifactDirectory: path.join(runDirectory, "artifacts"),
        originalArtifact: sourceApk,
        finalArtifact,
      }),
    )
    const manifest = await readManifest(result.manifestPath)

    expect(result.status).toBe("unresolved")
    expect(result.archivedFiles).toEqual([])
    expect(JSON.stringify(manifest)).not.toContain("stale-project-mapping")
    expect(manifest.missing.filter((item) => item.required).map((item) => item.fileName)).toEqual(
      expect.arrayContaining(REQUIRED_R8_FILES),
    )
  })

  test("links the evidence manifest from JSON and Markdown reports", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "droidseal-evidence-report-"))
    const output = path.join(root, "out")
    const runDirectory = path.join(root, "run")
    const reportDirectory = path.join(runDirectory, "reports")
    const sourceApk = path.join(root, "app", "build", "outputs", "apk", "release", "app-release.apk")
    const finalArtifact = path.join(output, "final.apk")
    const files: Record<string, string> = {
      "app/build/outputs/apk/release/app-release.apk": "source",
      "out/final.apk": "final",
    }
    for (const fileName of REQUIRED_R8_FILES) {
      files["app/build/outputs/mapping/release/" + fileName] = fileName
    }
    await writeTree(root, files)

    const reportPaths = await writeReports(
      config("project", root, output),
      context({
        runDirectory,
        reportDirectory,
        artifactDirectory: path.join(runDirectory, "artifacts"),
        originalArtifact: sourceApk,
        finalArtifact,
      }),
    )
    const json = JSON.parse(await readFile(reportPaths.json, "utf8")) as {
      schemaVersion: number
      releaseEvidence: { status: string; manifest: string; variant: string }
    }
    const markdown = await readFile(reportPaths.markdown, "utf8")

    expect(json.schemaVersion).toBe(7)
    expect(json.releaseEvidence.status).toBe("complete")
    expect(json.releaseEvidence.variant).toBe("release")
    expect(json.releaseEvidence.manifest).toBe(reportPaths.releaseEvidenceManifest)
    expect(markdown).toContain("## 发布证据")
    expect(markdown).toContain(reportPaths.releaseEvidenceManifest)
    expect(markdown).toContain("`release`")
  })
})
