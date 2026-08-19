import { describe, expect, test } from "bun:test"
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { generateBundleCompliance } from "../scripts/bundle-compliance"

async function writePackage(root: string, name: string, version: string, license = "MIT"): Promise<string> {
  const packageRoot = path.join(root, "node_modules", ...name.split("/"))
  await mkdir(packageRoot, { recursive: true })
  await writeFile(path.join(packageRoot, "package.json"), JSON.stringify({
    name,
    version,
    license,
    repository: `https://example.invalid/${name}`,
  }))
  await writeFile(path.join(packageRoot, "LICENSE"), `${name} test license\n`)
  await writeFile(path.join(packageRoot, "index.js"), "export const value = 1\n")
  return packageRoot
}

describe("exact bundle license inventory", () => {
  test("uses metafile inputs plus explicit native runtime packages and copies license evidence", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "droidseal-compliance-"))
    try {
      await writePackage(root, "included", "1.0.0")
      await writePackage(root, "native-only", "2.0.0", "BSD-2-Clause")
      await writePackage(root, "not-bundled", "9.0.0")
      const dist = path.join(root, "dist")
      const metafile = {
        inputs: {
          "src/index.ts": { bytes: 10, imports: [] },
          "node_modules/included/index.js": { bytes: 20, imports: [] },
        },
        outputs: {},
      } satisfies Bun.BuildMetafile

      const result = await generateBundleCompliance({
        projectRoot: root,
        distDirectory: dist,
        metafile,
        bunVersion: "1.3.14",
        runtimePackages: ["native-only"],
        runtimeAssets: ["native.dll"],
      })

      expect(result.packages.map((item) => item.name)).toEqual(["included", "native-only"])
      expect(await readFile(path.join(dist, "third-party", "licenses", "included-1.0.0", "LICENSE"), "utf8"))
        .toContain("included test license")
      const inventory = JSON.parse(await readFile(path.join(dist, "third-party", "bundle-components.json"), "utf8"))
      expect(inventory.runtime.webkitCommit).toBe("5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b")
      expect(inventory.runtime.tinyccCommit).toBe("12882eee073cfe5c7621bcfadf679e1372d4537b")
      expect(inventory.runtime.license).toContain("LGPL-2.1-only")
      expect(inventory.packages).toHaveLength(2)
      expect(JSON.stringify(inventory)).not.toContain("not-bundled")
      expect(result.artifacts.every((artifact) => /^[a-f0-9]{64}$/.test(artifact.sha256))).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  test("fails closed when a bundled package has no license evidence", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "droidseal-compliance-missing-"))
    try {
      const packageRoot = await writePackage(root, "missing-license", "1.0.0")
      await rm(path.join(packageRoot, "LICENSE"))
      const metafile = {
        inputs: { "node_modules/missing-license/index.js": { bytes: 20, imports: [] } },
        outputs: {},
      } satisfies Bun.BuildMetafile
      await expect(generateBundleCompliance({
        projectRoot: root,
        distDirectory: path.join(root, "dist"),
        metafile,
        bunVersion: "1.3.14",
        runtimePackages: [],
        runtimeAssets: [],
      })).rejects.toThrow("no LICENSE/COPYING/NOTICE")
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  test("fails closed when a bundled package has no declared source URL", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "droidseal-compliance-source-"))
    try {
      const packageRoot = await writePackage(root, "missing-source", "1.0.0")
      await writeFile(
        path.join(packageRoot, "package.json"),
        JSON.stringify({ name: "missing-source", version: "1.0.0", license: "MIT" }),
      )
      const metafile = {
        inputs: { "node_modules/missing-source/index.js": { bytes: 20, imports: [] } },
        outputs: {},
      } satisfies Bun.BuildMetafile
      await expect(generateBundleCompliance({
        projectRoot: root,
        distDirectory: path.join(root, "dist"),
        metafile,
        bunVersion: "1.3.14",
        runtimePackages: [],
        runtimeAssets: [],
      })).rejects.toThrow("no declared source URL")
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
})
