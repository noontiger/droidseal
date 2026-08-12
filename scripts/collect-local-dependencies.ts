#!/usr/bin/env bun
import path from "node:path"
import { access, copyFile, mkdir, readdir, stat, writeFile } from "node:fs/promises"
import { sha256File } from "../src/core/apk-audit.ts"
import type { BundleFileEntry, BundleManifest, BundleToolName } from "../src/core/bundle.ts"
import { discoverToolchain } from "../src/core/toolchain.ts"

const projectRoot = path.resolve(import.meta.dir, "..")
const isWindows = process.platform === "win32"

function parseOut(): string {
  const index = process.argv.indexOf("--out")
  const value = index >= 0 ? process.argv[index + 1] : undefined
  return path.resolve(value ?? path.join(projectRoot, "dependencies"))
}

async function exists(target: string): Promise<boolean> {
  try {
    await access(target)
    return true
  } catch {
    return false
  }
}

function requirePath(value: string | null | undefined, name: string): string {
  if (!value) throw new Error(`未找到 ${name}，无法生成完整依赖目录。`)
  return value
}

function relative(root: string, target: string): string {
  return path.relative(root, target).split(path.sep).join("/")
}

async function copyIfPresent(source: string, destination: string): Promise<boolean> {
  if (!(await exists(source))) return false
  await mkdir(path.dirname(destination), { recursive: true })
  await copyFile(source, destination)
  return true
}

async function copyTree(source: string, destination: string): Promise<void> {
  const info = await stat(source)
  if (info.isFile()) {
    await mkdir(path.dirname(destination), { recursive: true })
    await copyFile(source, destination)
    return
  }
  if (!info.isDirectory()) return

  await mkdir(destination, { recursive: true })
  const entries = await readdir(source)
  await Promise.all(
    entries.map((entry) =>
      copyTree(path.join(source, entry), path.join(destination, entry))
    ),
  )
}

async function main(): Promise<void> {
  const out = parseOut()
  if (await exists(out)) {
    throw new Error(`依赖目录已存在：${out}。为避免覆盖，请先确认并移走旧目录，或用 --out 指定新目录。`)
  }

  console.log(`收集 DroidSeal 本机依赖 → ${out}`)
  const toolchain = await discoverToolchain()
  const keytoolSource = requirePath(toolchain.keytool.path, "keytool")
  const aaptSource = requirePath(toolchain.aapt.path, "aapt")
  const zipalignSource = requirePath(toolchain.zipalign.path, "zipalign")
  const apksignerSource = requirePath(toolchain.apksigner.path, "apksigner")

  const sourceJdk = path.dirname(path.dirname(keytoolSource))
  const javaName = isWindows ? "java.exe" : "java"
  const keytoolName = isWindows ? "keytool.exe" : "keytool"
  const sourceJava = path.join(sourceJdk, "bin", javaName)
  if (!(await exists(sourceJava))) {
    throw new Error(`keytool 所在目录不是完整 JDK：${sourceJdk}`)
  }

  const buildToolsVersion = toolchain.buildToolsVersion ?? path.basename(path.dirname(apksignerSource))
  const sourceBuildTools = path.dirname(apksignerSource)
  const jdkRoot = path.join(out, "jdk")
  const sdkRoot = path.join(out, "android-sdk")
  const buildToolsRoot = path.join(sdkRoot, "build-tools", buildToolsVersion)
  const runtimeRoot = path.join(out, "runtime")
  const appModulesRoot = path.join(out, "node_modules")

  await mkdir(out, { recursive: true })
  console.log(`1/5 复制 JDK：${sourceJdk}`)
  await copyTree(sourceJdk, jdkRoot)

  console.log(`2/5 复制 Android Build Tools ${buildToolsVersion}`)
  await copyTree(sourceBuildTools, buildToolsRoot)

  console.log("3/5 复制 Bun、Node.js、npm 与 npx")
  await mkdir(runtimeRoot, { recursive: true })
  const bunName = isWindows ? "bun.exe" : "bun"
  const nodeName = isWindows ? "node.exe" : "node"
  const bundledBun = path.join(runtimeRoot, bunName)
  const bundledNode = path.join(runtimeRoot, nodeName)
  await copyFile(process.execPath, bundledBun)

  const nodeSource = requirePath(
    Bun.which(isWindows ? "node.exe" : "node") ?? Bun.which("node"),
    "Node.js",
  )
  const npmSource = requirePath(
    Bun.which(isWindows ? "npm.cmd" : "npm") ?? Bun.which("npm"),
    "npm",
  )
  const npxSource = requirePath(
    Bun.which(isWindows ? "npx.cmd" : "npx") ?? Bun.which("npx"),
    "npx",
  )
  await copyFile(nodeSource, bundledNode)

  const commandRoot = path.dirname(npmSource)
  const npmPackage = path.join(commandRoot, "node_modules", "npm")
  if (!(await exists(npmPackage))) {
    throw new Error(`npm 命令存在，但没有找到其运行库：${npmPackage}`)
  }
  await copyTree(npmPackage, path.join(runtimeRoot, "node_modules", "npm"))

  const npmName = isWindows ? "npm.cmd" : "npm"
  const npxName = isWindows ? "npx.cmd" : "npx"
  const bundledNpm = path.join(runtimeRoot, npmName)
  const bundledNpx = path.join(runtimeRoot, npxName)
  await copyFile(npmSource, bundledNpm)
  await copyFile(npxSource, bundledNpx)
  if (isWindows) {
    await copyIfPresent(path.join(commandRoot, "npm"), path.join(runtimeRoot, "npm"))
    await copyIfPresent(path.join(commandRoot, "npx"), path.join(runtimeRoot, "npx"))
  }
  await copyIfPresent(path.join(path.dirname(nodeSource), "LICENSE"), path.join(runtimeRoot, "NODE-LICENSE"))

  console.log("4/5 复制锁定的 JavaScript/TypeScript 依赖")
  const sourceModules = path.join(projectRoot, "node_modules")
  if (!(await exists(sourceModules))) {
    throw new Error("项目 node_modules 不存在；请先运行 bun install --frozen-lockfile。")
  }
  await copyTree(sourceModules, appModulesRoot)

  console.log("5/5 写入路径与 SHA-256 清单")
  const copiedTools: Record<BundleToolName, string> = {
    java: path.join(jdkRoot, "bin", javaName),
    keytool: path.join(jdkRoot, "bin", keytoolName),
    aapt: path.join(buildToolsRoot, path.basename(aaptSource)),
    zipalign: path.join(buildToolsRoot, path.basename(zipalignSource)),
    apksigner: path.join(buildToolsRoot, path.basename(apksignerSource)),
  }
  const runtime = {
    bun: relative(out, bundledBun),
    node: relative(out, bundledNode),
    npm: relative(out, bundledNpm),
    npx: relative(out, bundledNpx),
    nodeModules: relative(out, appModulesRoot),
  }
  const files: BundleFileEntry[] = []
  for (const filePath of [...Object.values(copiedTools), bundledBun, bundledNode, bundledNpm, bundledNpx]) {
    files.push({ relPath: relative(out, filePath), sha256: await sha256File(filePath) })
  }
  const tools = Object.fromEntries(
    Object.entries(copiedTools).map(([name, filePath]) => [name, relative(out, filePath)]),
  ) as Partial<Record<BundleToolName, string>>
  const manifest: BundleManifest = {
    platform: `${process.platform}-${process.arch}`,
    generatedAt: new Date().toISOString(),
    source: "local",
    jdkVersion: path.basename(sourceJdk),
    buildToolsVersion,
    androidSdkRoot: relative(out, sdkRoot),
    tools,
    runtime,
    files,
  }
  await writeFile(path.join(out, "bundle-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`)
  await writeFile(
    path.join(out, "README.txt"),
    [
      "DroidSeal 本机完整依赖目录",
      "",
      "包含：Bun、Node.js、npm/npx、项目锁定依赖、JDK、Android Build Tools。",
      "请从上一级目录运行 droidseal.cmd；该启动器会优先使用这里的工具。",
      "Gradle Wrapper 及其匹配的 Gradle 版本属于待处理 Android 项目，应继续由项目自身提供。",
      "",
    ].join("\n"),
  )
  console.log("完成：依赖已集中到 dependencies，使用 droidseal.cmd 启动。")
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
})
