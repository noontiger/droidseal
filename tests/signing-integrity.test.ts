import { describe, expect, test } from "bun:test"
import { mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { Pipeline, STEP_DEFINITIONS } from "../src/core/pipeline.ts"
import { buildZip, crc32Of, type OutEntry } from "../src/core/harden-manifest.ts"
import { runProcess } from "../src/core/process.ts"
import { discoverToolchain } from "../src/core/toolchain.ts"
import type { PipelineConfig } from "../src/core/types.ts"
import { buildAxmlFixture, type FixtureElement } from "./axml-fixture.ts"

function storedEntry(name: string, data: Uint8Array): OutEntry {
  return {
    name,
    method: 0,
    crc32: crc32Of(data),
    compressedSize: data.byteLength,
    uncompressedSize: data.byteLength,
    flags: 0,
    data,
  }
}

// A release-shaped manifest: no android:debuggable, so the only thing harden could
// rewrite is the strippable residual entry.
const RELEASE_MANIFEST: FixtureElement = {
  tag: "manifest",
  attributes: [{ name: "package", value: "com.example.app", android: false }],
  children: [{ tag: "application", attributes: [{ name: "label", value: "Example" }] }],
}

function syntheticReleaseApk(): Uint8Array {
  return buildZip([
    storedEntry("AndroidManifest.xml", buildAxmlFixture([RELEASE_MANIFEST])),
    storedEntry("classes.dex", new Uint8Array([0x64, 0x65, 0x78, 0x0a])),
    // The one entry on harden's strip allowlist.
    storedEntry("DebugProbesKt.bin", new Uint8Array([0x01, 0x02, 0x03, 0x04])),
  ])
}

function apkConfig(inputPath: string, outputDirectory: string): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind: "apk",
    inputPath,
    outputDirectory,
    gradleTask: "assembleRelease",
    enableAlignment: true,
    enableArscObfuscation: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

async function runAll(pipeline: Pipeline): Promise<void> {
  for (const definition of STEP_DEFINITIONS) await pipeline.runStep(definition.id)
}

describe("signing integrity", () => {
  test("a failed keystore step short-circuits signing instead of re-reporting a vaguer error", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "droidseal-signing-"))
    const inputApk = path.join(workspace, "example.apk")
    await writeFile(inputApk, "PK\u0003\u0004fake-apk-bytes")

    const pipeline = new Pipeline({
      ...apkConfig(inputApk, path.join(workspace, "out")),
      signing: {
        mode: "existing",
        keystorePath: path.join(workspace, "does-not-exist.jks"),
        keyAlias: "release",
        storePassword: "irrelevant",
        keyPassword: "irrelevant",
      },
    })
    await runAll(pipeline)

    expect(pipeline.getStep("keystore").status).toBe("failed")

    // apksigner cannot tell a missing alias from a wrong password, so retrying it here used to
    // overwrite the real cause with a misleading KEYSTORE_PASSWORD_INVALID.
    const sign = pipeline.getStep("sign").result!
    expect(sign.status).toBe("skipped")
    expect(sign.skipKind).toBe("missing-input")

    const verify = pipeline.getStep("verify").result!
    expect(verify.status).toBe("failed")
    expect(verify.summary).toContain("SIGNATURE_MISSING_AFTER_FAILED_SIGNING")
  })

  test("the final artifact is never named guarded-signed when signing did not succeed", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "droidseal-signing-"))
    const inputApk = path.join(workspace, "example.apk")
    await writeFile(inputApk, "PK\u0003\u0004fake-apk-bytes")

    const pipeline = new Pipeline({
      ...apkConfig(inputApk, path.join(workspace, "out")),
      signing: {
        mode: "existing",
        keystorePath: path.join(workspace, "does-not-exist.jks"),
        keyAlias: "release",
        storePassword: "irrelevant",
        keyPassword: "irrelevant",
      },
    })
    await runAll(pipeline)

    // The suffix is a claim about the bytes, so it must follow verification, not configuration.
    expect(pipeline.context.signatureVerified).toBeFalsy()
    expect(path.basename(pipeline.context.finalArtifact!)).toBe("example-guarded-unsigned.apk")
  })

  test("harden keeps a signed APK installable instead of stripping residual entries", async () => {
    const toolchain = await discoverToolchain()
    // Producing a genuinely signed fixture needs the real signing tools; without them the
    // scenario under test cannot be constructed.
    if (!toolchain.keytool.path || !toolchain.apksigner.path) return

    const workspace = await mkdtemp(path.join(tmpdir(), "droidseal-signing-"))
    const unsigned = path.join(workspace, "example.apk")
    await writeFile(unsigned, syntheticReleaseApk())

    const keystorePath = path.join(workspace, "test.jks")
    const password = "test-store-password"
    const created = await runProcess({
      command: toolchain.keytool.path,
      args: [
        "-J-Duser.language=en",
        "-genkeypair",
        "-keystore", keystorePath,
        "-storetype", "JKS",
        "-alias", "release",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-sigalg", "SHA256withRSA",
        "-validity", "3650",
        "-dname", "CN=DroidSeal Test",
        "-storepass:env", "DROIDSEAL_TEST_PASSWORD",
        "-keypass:env", "DROIDSEAL_TEST_PASSWORD",
      ],
      cwd: workspace,
      env: { DROIDSEAL_TEST_PASSWORD: password },
      redact: [password],
      timeoutMs: 120_000,
    })
    expect(created.exitCode).toBe(0)

    const signedInput = path.join(workspace, "signed.apk")
    const signed = await runProcess({
      command: toolchain.apksigner.path,
      args: [
        "sign",
        "--ks", keystorePath,
        "--ks-key-alias", "release",
        "--ks-pass", "env:DROIDSEAL_TEST_PASSWORD",
        "--key-pass", "env:DROIDSEAL_TEST_PASSWORD",
        "--out", signedInput,
        unsigned,
      ],
      cwd: workspace,
      env: { DROIDSEAL_TEST_PASSWORD: password },
      redact: [password],
      timeoutMs: 120_000,
    })
    expect(signed.exitCode).toBe(0)

    const pipeline = new Pipeline(apkConfig(signedInput, path.join(workspace, "out")))
    await runAll(pipeline)

    // Stripping DebugProbesKt.bin is hygiene; it must never cost a signature the pipeline
    // has not been configured to rebuild, because the result is an uninstallable APK.
    const harden = pipeline.getStep("harden").result!
    expect(harden.status).toBe("skipped")
    expect(harden.skipKind).toBe("safety")
    expect((harden.findings ?? []).map((finding) => finding.code)).toContain(
      "HARDEN_SKIPPED_TO_PRESERVE_SIGNATURE",
    )

    expect(pipeline.context.signatureVerified).toBe(true)
    expect(path.basename(pipeline.context.finalArtifact!)).toBe("signed-guarded-signed-preserved.apk")

    const finalCheck = await runProcess({
      command: toolchain.apksigner.path,
      args: ["verify", pipeline.context.finalArtifact!],
      cwd: workspace,
      timeoutMs: 120_000,
    })
    expect(finalCheck.exitCode).toBe(0)
    // Generating an RSA keypair and running apksigner twice exceeds the default 5s budget.
  }, 180_000)
})
