#!/usr/bin/env node
"use strict"

const { createHash } = require("node:crypto")
const { createReadStream, existsSync, readFileSync } = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")

function fail(message) {
  console.error(`[DroidSeal] ${message}`)
  process.exitCode = 1
}

function sha256(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256")
    const stream = createReadStream(file)
    stream.on("data", (chunk) => hash.update(chunk))
    stream.on("error", reject)
    stream.on("end", () => resolve(hash.digest("hex")))
  })
}

async function main() {
  if (process.platform !== "win32" || process.arch !== "x64") {
    fail(`当前 npm 二进制包仅支持 Windows x64，检测到 ${process.platform}-${process.arch}。`)
    return
  }

  const packageRoot = path.resolve(__dirname, "..")
  const distDirectory = path.join(packageRoot, "dist")
  const executable = path.join(distDirectory, "droidseal.exe")
  const metadataPath = path.join(distDirectory, "droidseal-build.json")

  if (!existsSync(executable) || !existsSync(metadataPath)) {
    fail("安装不完整：缺少 droidseal.exe 或构建元数据，请重新安装 npm 包。")
    return
  }

  let metadata
  try {
    metadata = JSON.parse(readFileSync(metadataPath, "utf8"))
  } catch (error) {
    fail(`无法读取构建元数据：${error instanceof Error ? error.message : String(error)}`)
    return
  }

  if (
    metadata?.schemaVersion !== 2 ||
    metadata?.artifact?.path !== "droidseal.exe" ||
    metadata?.artifact?.target !== "windows-x64" ||
    !/^[a-f0-9]{64}$/.test(metadata?.artifact?.sha256 ?? "")
  ) {
    fail("构建元数据格式无效，拒绝启动未经确认的二进制文件。")
    return
  }

  const actualHash = await sha256(executable)
  if (actualHash !== metadata.artifact.sha256) {
    fail("droidseal.exe 完整性校验失败；文件可能损坏或被修改，请重新安装。")
    return
  }

  const child = spawnSync(executable, process.argv.slice(2), {
    cwd: process.cwd(),
    env: {
      ...process.env,
      OTUI_ASSET_ROOT: process.env.OTUI_ASSET_ROOT || distDirectory,
    },
    stdio: "inherit",
    windowsHide: false,
  })

  if (child.error) {
    fail(`无法启动二进制文件：${child.error.message}`)
    return
  }
  if (typeof child.status === "number") {
    process.exitCode = child.status
    return
  }
  process.exitCode = child.signal === "SIGINT" ? 130 : 1
}

main().catch((error) => {
  fail(error instanceof Error ? error.message : String(error))
})