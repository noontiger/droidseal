import { createHash } from "node:crypto"
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import path from "node:path"
import solidPlugin from "@opentui/solid/bun-plugin"
import { minify } from "terser"
import { generateBundleCompliance } from "./bundle-compliance"

const projectRoot = path.resolve(import.meta.dir, "..")
const distDirectory = path.join(projectRoot, "dist")
const executableName = "droidseal.exe"
const executablePath = path.join(distDirectory, executableName)
const metadataPath = path.join(distDirectory, "droidseal-build.json")
const temporaryDirectory = await mkdtemp(path.join(projectRoot, ".droidseal-build-"))
const compiledEntryPath = path.join(temporaryDirectory, "droidseal-compiled-entry.js")
const temporaryExecutablePath = path.join(temporaryDirectory, executableName)

function hasTrailingSourceMapDirective(code: string): boolean {
  const tail = code.slice(-8_192)
  return /(?:^|\r?\n)[ \t]*\/\/[#@][ \t]*sourceMappingURL[ \t]*=[^\r\n]+[ \t]*(?=\r?$)/m.test(tail) ||
    /(?:^|\r?\n)[ \t]*\/\*[#@][ \t]*sourceMappingURL[ \t]*=[\s\S]*?\*\/[ \t]*(?:\r?\n)?$/.test(tail)
}

function withRuntimeAssetRoot(code: string): string {
  const prelude = 'process.env.OTUI_ASSET_ROOT||=process.execPath.replace(/[\\\\/][^\\\\/]+$/,"");'
  if (code.startsWith("#!")) {
    const lineEnd = code.indexOf("\n")
    if (lineEnd >= 0) return `${code.slice(0, lineEnd + 1)}${prelude}${code.slice(lineEnd + 1)}`
  }
  return `${prelude}${code}`
}

try {
  if (process.platform !== "win32" || process.arch !== "x64") {
    throw new Error(`The npm binary release currently requires a Windows x64 build host; received ${process.platform}-${process.arch}`)
  }

  const result = await Bun.build({
    entrypoints: [path.join(projectRoot, "src", "index.tsx")],
    target: "bun",
    outdir: temporaryDirectory,
    naming: "droidseal-unminified.js",
    sourcemap: "none",
    minify: false,
    metafile: true,
    external: ["@opentui/core-*"],
    plugins: [solidPlugin],
  })

  if (!result.success) {
    for (const log of result.logs) console.error(log)
    process.exitCode = 1
    throw new Error("Bun build failed")
  }

  const javascript = result.outputs.find((output) => output.kind === "entry-point")
  if (!javascript) throw new Error("Bun build did not return a JavaScript entry-point")
  const bundledSource = await javascript.text()
  const minified = await minify(bundledSource, {
    ecma: 2022,
    module: true,
    compress: {
      passes: 2,
      unsafe: false,
    },
    mangle: {
      toplevel: true,
    },
    format: {
      comments: /@license|@preserve|^!/i,
    },
    sourceMap: false,
  })
  if (!minified.code) throw new Error("Terser returned an empty DroidSeal bundle")
  if (hasTrailingSourceMapDirective(minified.code)) {
    throw new Error("Terser output unexpectedly contains a sourceMappingURL")
  }

  const compiledEntry = `${withRuntimeAssetRoot(minified.code)}\n`
  await writeFile(compiledEntryPath, compiledEntry, "utf8")

  const compilation = Bun.spawnSync({
    cmd: [
      process.execPath,
      "build",
      "--compile",
      "--no-compile-autoload-dotenv",
      "--no-compile-autoload-bunfig",
      "--no-compile-autoload-package-json",
      "--outfile",
      temporaryExecutablePath,
      compiledEntryPath,
    ],
    cwd: projectRoot,
    env: {
      ...process.env,
      NODE_ENV: "production",
    },
    stdout: "pipe",
    stderr: "pipe",
  })
  if (compilation.exitCode !== 0) {
    const stdout = compilation.stdout.toString().trim()
    const stderr = compilation.stderr.toString().trim()
    if (stdout) console.error(stdout)
    if (stderr) console.error(stderr)
    throw new Error(`Bun executable compilation failed with exit code ${compilation.exitCode}`)
  }

  const executable = new Uint8Array(await readFile(temporaryExecutablePath))
  if (executable.byteLength < 1_000_000 || executable[0] !== 0x4d || executable[1] !== 0x5a) {
    throw new Error("Bun compilation did not produce a valid Windows PE executable")
  }

  const assets: Array<{ relativePath: string; bytes: Uint8Array }> = []
  for (const output of result.outputs) {
    if (output === javascript) continue
    const absolute = path.resolve(output.path)
    const relativePath = path.relative(temporaryDirectory, absolute).replaceAll("\\", "/")
    if (!relativePath || relativePath.startsWith("../") || path.isAbsolute(relativePath)) {
      throw new Error(`Bun emitted an asset outside the temporary build directory: ${output.path}`)
    }
    assets.push({
      relativePath,
      bytes: new Uint8Array(await output.arrayBuffer()),
    })
  }
  assets.sort((a, b) => a.relativePath.localeCompare(b.relativePath))

  // Replace dist only after bundling, minification, and native compilation all succeed.
  // The intermediate JavaScript is kept in the temporary directory and never published.
  await rm(distDirectory, { recursive: true, force: true })
  await mkdir(distDirectory, { recursive: true })
  await writeFile(executablePath, executable)
  await chmod(executablePath, 0o755).catch(() => undefined)
  for (const asset of assets) {
    const target = path.join(distDirectory, asset.relativePath)
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, asset.bytes)
  }

  if (!result.metafile) throw new Error("Bun build did not return the required metafile")
  const packageJson = JSON.parse(await readFile(path.join(projectRoot, "package.json"), "utf8")) as {
    packageManager?: string
  }
  const expectedBunVersion = packageJson.packageManager?.match(/^bun@(.+)$/)?.[1]
  if (!expectedBunVersion || Bun.version !== expectedBunVersion) {
    throw new Error(`Bun version mismatch: expected ${expectedBunVersion ?? "bun@<missing>"}, received ${Bun.version}`)
  }
  const compliance = await generateBundleCompliance({
    projectRoot,
    distDirectory,
    metafile: result.metafile,
    bunVersion: Bun.version,
    runtimePackages: ["@opentui/core-win32-x64"],
    runtimeAssets: assets.map((asset) => asset.relativePath),
  })

  const terserPackage = JSON.parse(
    await readFile(path.join(projectRoot, "node_modules", "terser", "package.json"), "utf8"),
  ) as { version?: string }
  const metadata = {
    schemaVersion: 2,
    artifact: {
      path: executableName,
      target: "windows-x64",
      format: "bun-single-file-executable",
      bytes: executable.byteLength,
      sha256: createHash("sha256").update(executable).digest("hex"),
    },
    protection: {
      bundler: "Bun.build",
      compiler: "bun --compile",
      minifier: "terser",
      minifierVersion: terserPackage.version ?? "unknown",
      topLevelMangle: true,
      sourceIncluded: false,
      sourceMap: false,
      sourceBytes: new TextEncoder().encode(bundledSource).byteLength,
      minifiedBytes: new TextEncoder().encode(compiledEntry).byteLength,
    },
    embeddedNative: ["@opentui/core-win32-x64/opentui.dll"],
    assets: assets.map((asset) => ({
      path: asset.relativePath,
      bytes: asset.bytes.byteLength,
      sha256: createHash("sha256").update(asset.bytes).digest("hex"),
    })),
    compliance: {
      generator: "scripts/bundle-compliance.ts",
      bundlePackageCount: compliance.packages.length,
      bunVersion: Bun.version,
      artifacts: compliance.artifacts,
    },
  }
  await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, "utf8")

  console.log(
    `Built dist/${executableName} with Bun compile + Terser ${metadata.protection.minifierVersion} ` +
    `(${metadata.protection.sourceBytes} -> ${metadata.protection.minifiedBytes} intermediate bytes, ` +
    `${metadata.artifact.bytes} executable bytes, ${assets.length} external assets, no source or source map)`,
  )
} finally {
  await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => undefined)
}
