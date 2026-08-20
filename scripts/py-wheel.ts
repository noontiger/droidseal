// PyPI wheel 构建:先同步 dist(合并态:win + linux)到 droidseal/_bin,再构建 wheel。
// _bin 被 .gitignore 忽略,每次构建必须重新同步,否则 wheel 会缺失平台二进制/原生库,
// 安装后入口报「安装不完整」(实测缺陷)。本脚本保证发布的 wheel 始终完整。
import { access, cp, mkdir, rm } from "node:fs/promises"
import path from "node:path"

const projectRoot = path.resolve(import.meta.dir, "..")
const distDirectory = path.join(projectRoot, "dist")
const binDirectory = path.join(projectRoot, "droidseal", "_bin")
const wheelOut = path.join(projectRoot, "dist-wheel")

const REQUIRED = ["droidseal.exe", "droidseal", "droidseal-build.json", "droidseal-build.linux.json"]
const REQUIRED_LIBS = [
  "@opentui/core-win32-x64/opentui.dll",
  "@opentui/core-linux-x64/libopentui.so",
]

for (const name of [...REQUIRED, ...REQUIRED_LIBS]) {
  await access(path.join(distDirectory, name)).catch(() => {
    throw new Error(`dist 缺少 ${name}——请先完成合并态构建(dist = Windows 构建 + Linux 侧合并)`)
  })
}

await rm(binDirectory, { recursive: true, force: true })
await mkdir(binDirectory, { recursive: true })
await cp(distDirectory, binDirectory, { recursive: true })
console.log(`✓ 已同步 dist → droidseal/_bin(${REQUIRED.length} 关键资产 + ${REQUIRED_LIBS.length} 原生库校验通过)`)

await mkdir(wheelOut, { recursive: true })
const result = Bun.spawnSync(["python", "-m", "pip", "wheel", ".", "--no-deps", "-w", wheelOut], {
  cwd: projectRoot,
})
if (result.exitCode !== 0) {
  throw new Error(`wheel 构建失败:\n${result.stderr.toString()}`)
}
const wheel = (await import("node:fs/promises")).readdir(wheelOut)
for (const file of await wheel) {
  if (file.endsWith(".whl")) console.log(`✓ wheel: ${path.join(wheelOut, file)}`)
}
