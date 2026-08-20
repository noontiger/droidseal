// 构建时给 OpenTUI 的滚动条滑块加最小长度补丁。
// node_modules 每次 bun install 会重置,因此必须在构建时重新应用。
// 锚点取自 @opentui/core 的 SliderRenderable.getVirtualThumbSize:
//   const thumbRatio = viewportSize / contentSize;
//   const calculatedSize = Math.floor(virtualTrackSize * thumbRatio);
//   return Math.max(1, Math.min(calculatedSize, virtualTrackSize));
// 把最小 1 提升为 6(虚拟尺寸;实际渲染约为其一半,即约 3 格)。
import { readFile, writeFile } from "node:fs/promises"
import path from "node:path"

const BUNDLE_PATH = path.join(import.meta.dir, "..", "node_modules", "@opentui", "core", "index.bun.js")
const ANCHOR = "Math.max(1, Math.min(calculatedSize, virtualTrackSize))"
const PATCHED = "Math.max(6, Math.min(calculatedSize, virtualTrackSize))"

export async function patchOpenTuiScrollbar(): Promise<boolean> {
  const source = await readFile(BUNDLE_PATH, "utf8")
  if (source.includes(PATCHED)) return false // 已打过补丁,幂等
  if (!source.includes(ANCHOR)) {
    throw new Error(`OpenTUI 滚动条补丁锚点未找到(${ANCHOR})——请检查 @opentui/core 版本是否变化`)
  }
  await writeFile(BUNDLE_PATH, source.replaceAll(ANCHOR, PATCHED))
  return true
}
