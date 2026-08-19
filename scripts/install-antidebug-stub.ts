import { ANTIDEBUG_STUB_FILES, installAntiDebugStub } from "../src/core/antidebug-stub.ts"

function usage(): never {
  console.error("用法：bun scripts/install-antidebug-stub.ts <app-module-dir> [--force]")
  console.error("示例：bun scripts/install-antidebug-stub.ts ../MyApp/app")
  console.error("说明：把自研的 opt-in 反调试 stub（C + CMake + Kotlin）写入目标 app 模块，构建期链接，仅检测不处置。")
  process.exit(2)
}

const args = process.argv.slice(2)
const force = args.includes("--force")
const target = args.find((arg) => !arg.startsWith("--"))
if (!target) usage()

const result = await installAntiDebugStub(target, { force })
console.log(`目标模块：${result.moduleDir}`)
for (const file of result.written) console.log(`  写入 ${file}`)
for (const file of result.skipped) console.log(`  跳过（已存在，用 --force 覆盖）：${file}`)

if (result.written.length === 0) {
  console.log(`没有写入任何文件（共 ${ANTIDEBUG_STUB_FILES.length} 个 stub 文件均已存在）。`)
} else {
  console.log("完成。请阅读 droidseal-antidebug/INTEGRATION.md 完成 Gradle externalNativeBuild 接线。")
}
