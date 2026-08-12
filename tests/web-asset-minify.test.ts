import { describe, expect, test } from "bun:test"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { buildZip, crc32Of, inflateEntry, parseRawZip, type OutEntry } from "../src/core/harden-manifest.ts"
import { Pipeline } from "../src/core/pipeline.ts"
import type { PipelineConfig, ToolLocation, Toolchain } from "../src/core/types.ts"
import { minifyHybridWebAssetsInApk } from "../src/core/web-asset-minify.ts"

const encoder = new TextEncoder()

function stored(name: string, value: string | Uint8Array): OutEntry {
  const data = typeof value === "string" ? encoder.encode(value) : value
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

function apk(entries: OutEntry[]): Uint8Array {
  return buildZip([
    stored("AndroidManifest.xml", new Uint8Array([0x03, 0x00, 0x08, 0x00])),
    stored("classes.dex", new Uint8Array([0x64, 0x65, 0x78, 0x0a])),
    ...entries,
  ])
}

async function withTempDir<T>(fn: (directory: string) => Promise<T>): Promise<T> {
  const directory = await mkdtemp(path.join(tmpdir(), "droidseal-web-assets-"))
  try {
    return await fn(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function textOf(bytes: Uint8Array, name: string): string {
  const entry = parseRawZip(bytes).find((candidate) => candidate.name === name)
  if (!entry) throw new Error(`missing fixture entry ${name}`)
  return new TextDecoder().decode(inflateEntry(entry))
}

function missingTool(name: ToolLocation["name"]): ToolLocation {
  return { name, source: "missing", requiredFor: [], detail: "test" }
}

function fakeToolchain(apksignerPath: string): Toolchain {
  return {
    java: missingTool("java"),
    keytool: missingTool("keytool"),
    aapt: missingTool("aapt"),
    zipalign: missingTool("zipalign"),
    apksigner: { ...missingTool("apksigner"), path: apksignerPath, source: "path" },
    gradleWrapper: missingTool("gradle-wrapper"),
  }
}

function config(inputPath: string, outputDirectory: string): PipelineConfig {
  return {
    runMode: "one-click",
    inputKind: "apk",
    inputPath,
    outputDirectory,
    gradleTask: "assembleRelease",
    enableAlignment: false,
    enableWebAssetMinification: true,
    enableArscObfuscation: false,
    signing: { mode: "skip" },
    protection: { mode: "local-safe" },
  }
}

describe("hybrid Web JavaScript release processing", () => {
  test("handles classic and module scripts conservatively, keeps licenses, removes maps, and validates ZIP", async () => {
    await withTempDir(async (directory) => {
      const input = path.join(directory, "input.apk")
      const output = path.join(directory, "output.apk")
      const untouched = "function untouchedReadableName() { return 7 }\n"
      await writeFile(input, apk([
        stored(
          "assets/public/index.html",
          `<script src="classic.js"></script><script defer src='./module.js?v=1' TYPE="module"></script>`,
        ),
        stored(
          "assets/public/classic.js",
          "/*! @license classic-fixture */ function PublicApi(longArgument){var internalLocalName=longArgument+1;return internalLocalName} window.PublicApi=PublicApi; //# sourceMappingURL=classic.js.map",
        ),
        stored(
          "assets/public/module.js",
          "/*! @license module-fixture */ const moduleTopLevelName=41; export function answer(){const moduleLocalName=moduleTopLevelName+1;return moduleLocalName} //# sourceMappingURL=module.js.map",
        ),
        stored("assets/public/classic.js.map", "{\"sourcesContent\":[\"classic source\"]}"),
        stored("assets/public/module.js.map", "{\"sourcesContent\":[\"module source\"]}"),
        stored("assets/public/orphan.map", "{\"sourcesContent\":[\"orphan source\"]}"),
        stored("assets/other/untouched.js", untouched),
      ]))

      const result = await minifyHybridWebAssetsInApk(input, output)
      expect(result.changed).toBe(true)
      expect(result.filesProcessed).toBe(2)
      expect(result.moduleFiles).toBe(1)
      expect(result.mapsRemoved).toBe(3)
      expect(result.afterBytes).toBeLessThan(result.beforeBytes)
      expect(result.findings.map((finding) => finding.code)).toContain("HYBRID_WEB_ASSETS_MINIFIED")

      const outputBytes = new Uint8Array(await readFile(output))
      const names = parseRawZip(outputBytes).map((entry) => entry.name)
      expect(names).toContain("AndroidManifest.xml")
      expect(names).not.toContain("assets/public/classic.js.map")
      expect(names).not.toContain("assets/public/module.js.map")
      expect(names).not.toContain("assets/public/orphan.map")

      const classic = textOf(outputBytes, "assets/public/classic.js")
      const module = textOf(outputBytes, "assets/public/module.js")
      expect(classic).toContain("@license classic-fixture")
      expect(classic).toContain("PublicApi")
      expect(classic).not.toContain("internalLocalName")
      expect(module).toContain("@license module-fixture")
      expect(module).not.toContain("moduleTopLevelName")
      expect(`${classic}\n${module}`).not.toContain("sourceMappingURL")
      expect(textOf(outputBytes, "assets/other/untouched.js")).toBe(untouched)
    })
  })

  test("supports the Cordova assets/www root", async () => {
    await withTempDir(async (directory) => {
      const input = path.join(directory, "input.apk")
      const output = path.join(directory, "output.apk")
      await writeFile(input, apk([
        stored("assets/www/index.html", "<script src='/cordova.js'></script>"),
        stored("assets/www/cordova.js", "function CordovaGlobal(verboseArgument){return verboseArgument+1} window.CordovaGlobal=CordovaGlobal"),
      ]))

      const result = await minifyHybridWebAssetsInApk(input, output)
      expect(result.roots).toEqual(["assets/www/"])
      expect(result.filesProcessed).toBe(1)
      expect(textOf(new Uint8Array(await readFile(output)), "assets/www/cordova.js")).toContain("CordovaGlobal")
    })
  })

  test("a syntax failure rolls back the whole operation and writes no output", async () => {
    await withTempDir(async (directory) => {
      const input = path.join(directory, "input.apk")
      const output = path.join(directory, "output.apk")
      const original = apk([
        stored("assets/public/good.js", "function good(){return 1}"),
        stored("assets/public/broken.js", "function broken("),
      ])
      await writeFile(input, original)

      await expect(minifyHybridWebAssetsInApk(input, output)).rejects.toMatchObject({
        code: "WEB_ASSET_MINIFY_FAILED",
      })
      expect(await Bun.file(output).exists()).toBe(false)
      expect(Array.from(new Uint8Array(await readFile(input)))).toEqual(Array.from(original))
    })
  })

  test("non-hybrid assets are not guessed or rewritten", async () => {
    await withTempDir(async (directory) => {
      const input = path.join(directory, "input.apk")
      const output = path.join(directory, "output.apk")
      await writeFile(input, apk([stored("assets/custom/app.js", "function readable(){return 1}")]))

      const result = await minifyHybridWebAssetsInApk(input, output)
      expect(result.changed).toBe(false)
      expect(result.filesProcessed).toBe(0)
      expect(await Bun.file(output).exists()).toBe(false)
    })
  })

  test("pipeline preserves an apksigner-accepted artifact when re-signing is disabled", async () => {
    await withTempDir(async (directory) => {
      const input = path.join(directory, "input.apk")
      const outputDirectory = path.join(directory, "out")
      await writeFile(input, apk([stored("assets/public/app.js", "function PublicApi(){return 1}")]))

      const pipeline = new Pipeline(config(input, outputDirectory))
      await pipeline.runStep("prepare")
      // existingSignatureState invokes: bun <cwd>/verify <artifact>. This fixture
      // isolates the preservation branch while the real apksigner integration is
      // already covered by signing-integrity tests.
      await writeFile(path.join(pipeline.context.artifactDirectory, "verify"), "process.exit(0)\n")
      pipeline.context.toolchain = fakeToolchain(process.execPath)
      const before = pipeline.context.currentArtifact
      const result = await pipeline.runStep("web-assets")

      expect(result.status).toBe("skipped")
      expect(result.skipKind).toBe("safety")
      expect(result.findings?.map((finding) => finding.code)).toContain(
        "WEB_ASSET_MINIFY_SKIPPED_TO_PRESERVE_SIGNATURE",
      )
      expect(pipeline.context.currentArtifact).toBe(before)
      expect(await Bun.file(path.join(pipeline.context.artifactDirectory, "03d-web-assets.apk")).exists()).toBe(false)
    })
  })
})
