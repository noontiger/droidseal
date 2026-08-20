// 双语同步检查门禁:README EN/ZH + 网页 EN/ZH 的结构一致性。
// 用法:
//   bun run sync:check                        # 只检查仓库内 README 对
//   bun run sync:check <gh-pages 工作树目录>   # 加上网页 EN/ZH 对
// 结构漂移(标题数/节 id/元素计数不一致)时以非零退出,防止"更新一处漏另一处"。
import { readFile } from "node:fs/promises"
import path from "node:path"

const projectRoot = path.resolve(import.meta.dir, "..")

async function read(file: string): Promise<string> {
  try {
    return await readFile(file, "utf8")
  } catch {
    throw new Error(`无法读取 ${file}`)
  }
}

function headingCounts(text: string): { h2: number; h3: number } {
  const lines = text.split("\n")
  return {
    h2: lines.filter((l) => l.startsWith("## ") && !l.startsWith("### ")).length,
    h3: lines.filter((l) => l.startsWith("### ")).length,
  }
}

// ① README 对:标题层级结构必须一致(EN 6 节 == ZH 6 节等)
const readmeEn = await read(path.join(projectRoot, "README.md"))
const readmeZh = await read(path.join(projectRoot, "README.zh-CN.md"))
const enH = headingCounts(readmeEn)
const zhH = headingCounts(readmeZh)
const readmeIssues: string[] = []
if (enH.h2 !== zhH.h2) readmeIssues.push(`README ## 标题数不一致:EN ${enH.h2} vs ZH ${zhH.h2}`)
if (enH.h3 !== zhH.h3) readmeIssues.push(`README ### 标题数不一致:EN ${enH.h3} vs ZH ${zhH.h3}`)
if (readmeIssues.length > 0) {
  console.error(readmeIssues.join("\n"))
  console.error("请同步更新 README.md 与 README.zh-CN.md 的章节结构后重跑。")
  process.exit(1)
}

// ② 网页对(可选,需 gh-pages 工作树路径):节 id 与网格元素计数必须一致
const webDir = process.argv[2]
if (webDir) {
  const zh = await read(path.join(webDir, "index.html"))
  const en = await read(path.join(webDir, "index.en.html"))
  const issues: string[] = []
  for (const id of ["pipeline", "modes", "capabilities", "security", "cta"]) {
    if (!zh.includes(`id="${id}"`)) issues.push(`网页 ZH 缺少节 id="${id}"`)
    if (!en.includes(`id="${id}"`)) issues.push(`网页 EN 缺少节 id="${id}"`)
  }
  const count = (text: string, cls: string): number =>
    (text.match(new RegExp(`class="${cls}"`, "g")) ?? []).length
  for (const cls of ["step", "mode", "cap", "sec-item"]) {
    const cz = count(zh, cls)
    const ce = count(en, cls)
    if (cz !== ce) issues.push(`网页元素 .${cls} 数量不一致:ZH ${cz} vs EN ${ce}`)
  }
  if (issues.length > 0) {
    console.error(issues.join("\n"))
    console.error("请同步更新 index.html 与 index.en.html 的布局/内容后重跑。")
    process.exit(1)
  }
  console.log("✓ 网页 EN/ZH 同步检查通过")
}

console.log("✓ README EN/ZH 同步检查通过")
