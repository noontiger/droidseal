import { describe, expect, test } from "bun:test"
import { readFile } from "node:fs/promises"
import path from "node:path"
import { minify } from "terser"

const projectRoot = path.resolve(import.meta.dir, "..")

describe("release bundle hardening", () => {
  test("publishes a Windows x64 executable without DroidSeal source files", async () => {
    const packageJson = JSON.parse(
      await readFile(path.join(projectRoot, "package.json"), "utf8"),
    ) as {
      bin?: { droidseal?: string }
      files?: string[]
      dependencies?: Record<string, string>
      devDependencies?: { terser?: string }
      engines?: Record<string, string>
      os?: string[]
      cpu?: string[]
    }
    const buildScript = await readFile(path.join(projectRoot, "scripts/build.ts"), "utf8")
    const launcher = await readFile(path.join(projectRoot, "bin/droidseal.cjs"), "utf8")

    expect(packageJson.bin?.droidseal).toBe("./bin/droidseal.cjs")
    expect(packageJson.files).toContain("dist")
    expect(packageJson.files).toContain("bin/droidseal.cjs")
    expect(packageJson.files).not.toContain("src")
    expect(packageJson.files).not.toContain("scripts")
    expect(packageJson.files).not.toContain("docs")
    expect(packageJson.dependencies).toBeUndefined()
    expect(packageJson.devDependencies?.terser).toBe("5.49.0")
    expect(packageJson.engines?.node).toBe(">=18")
    expect(packageJson.os).toEqual(["win32", "linux"])
    expect(packageJson.cpu).toEqual(["x64"])

    expect(buildScript).toContain('sourcemap: "none"')
    expect(buildScript).toMatch(/mangle:\s*\{\s*toplevel:\s*true/)
    expect(buildScript).toContain("sourceMap: false")
    expect(buildScript).toContain('"--compile"')
    expect(buildScript).toContain('"--no-compile-autoload-dotenv"')
    expect(buildScript).toContain("droidseal.exe")
    expect(buildScript).toContain("sourceIncluded: false")

    expect(launcher).toContain("metadata.artifact.sha256")
    expect(launcher).toContain("createHash")
    expect(launcher).toContain("spawnSync")
    expect(launcher).toContain("OTUI_ASSET_ROOT")
  })

  test("keeps license notices while mangling representative top-level names", async () => {
    const result = await minify(
      "/*! @license fixture */ function readableInternalIdentifier(){return 42} console.log(readableInternalIdentifier())",
      {
        ecma: 2022,
        module: true,
        compress: { passes: 2, unsafe: false },
        mangle: { toplevel: true },
        format: { comments: /@license|@preserve|^!/i },
        sourceMap: false,
      },
    )

    expect(result.code).toContain("@license fixture")
    expect(result.code).not.toContain("readableInternalIdentifier")
    expect(result.code).not.toContain("sourceMappingURL")
  })
})