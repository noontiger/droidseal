#!/usr/bin/env bun
import path from "node:path"
import { mkdir, writeFile } from "node:fs/promises"
import { sha256File } from "../src/core/apk-audit.ts"
import { findFile, installAndroidBuildTools, installManagedJdk } from "../src/core/tool-installer.ts"
import type { BundleManifest, BundleToolName } from "../src/core/bundle.ts"

const isWindows = process.platform === "win32"

function parseOut(): string {
  const index = process.argv.indexOf("--out")
  const value = index >= 0 ? process.argv[index + 1] : undefined
  return path.resolve(value ?? "./droidseal-bundle")
}

function log(message: string): void {
  console.log(message)
}

function executableName(base: string): string {
  if (!isWindows) return base
  return base === "apksigner" ? `${base}.bat` : `${base}.exe`
}

async function requireFile(root: string, base: string): Promise<string> {
  const found = await findFile(root, new Set([executableName(base).toLowerCase()]), 6)
  if (!found) throw new Error(`离线包缺少 ${base}（在 ${root} 未找到）。`)
  return found
}

async function main(): Promise<void> {
  const out = parseOut()
  const platform = `${process.platform}-${process.arch}`
  log(`DroidSeal 离线工具链打包 · 平台 ${platform}`)
  log(`输出目录：${out}`)
  await mkdir(out, { recursive: true })

  log("步骤 1/3：下载并校验 Eclipse Temurin 21")
  const javaHome = await installManagedJdk(log, out)
  const javaPath = path.join(javaHome, "bin", executableName("java"))
  const keytoolPath = path.join(javaHome, "bin", executableName("keytool"))

  log("步骤 2/3：预取 Android Build Tools（sdkmanager）")
  const sdkRoot = path.join(out, "android-sdk")
  const buildToolsVersion = await installAndroidBuildTools({ javaPath, sdkRoot }, log)
  const buildToolsDir = path.join(sdkRoot, "build-tools", buildToolsVersion)

  const [aaptPath, zipalignPath, apksignerPath] = await Promise.all([
    requireFile(buildToolsDir, "aapt"),
    requireFile(buildToolsDir, "zipalign"),
    requireFile(buildToolsDir, "apksigner"),
  ])

  log("步骤 3/3：计算 SHA-256 并写入 bundle-manifest.json")
  const absolute: Record<BundleToolName, string> = {
    java: javaPath,
    keytool: keytoolPath,
    aapt: aaptPath,
    zipalign: zipalignPath,
    apksigner: apksignerPath,
  }

  const tools: Partial<Record<BundleToolName, string>> = {}
  const files: BundleManifest["files"] = []
  for (const [name, filePath] of Object.entries(absolute) as [BundleToolName, string][]) {
    const relPath = path.relative(out, filePath).split(path.sep).join("/")
    tools[name] = relPath
    files.push({ relPath, sha256: await sha256File(filePath) })
  }

  const manifest: BundleManifest = {
    platform,
    generatedAt: new Date().toISOString(),
    temurinVersion: path.basename(javaHome),
    buildToolsVersion,
    androidSdkRoot: path.relative(out, sdkRoot).split(path.sep).join("/"),
    tools,
    files,
  }
  await writeFile(path.join(out, "bundle-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`)

  log("完成。离线使用方法：")
  log(`  1. 复制 ${out} 到目标机 ~/.droidseal/bundle（或设置 DROIDSEAL_BUNDLE_DIR 指向它）`)
  log("  2. 断网运行 `droidseal doctor`，确认各工具 source 为 bundled")
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error))
  process.exit(1)
})
