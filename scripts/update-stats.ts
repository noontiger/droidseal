// 统计 count-up SVG 生成:拉取实时数据(npm/pypi 下载、GitHub stars/forks)生成暗色科技风 SVG。
// 由 .github/workflows/update-stats.yml 定时/手动/发布时运行,产物提交到 stats/ 供 README 引用。
import { mkdir, writeFile } from "node:fs/promises"
import path from "node:path"

const projectRoot = path.resolve(import.meta.dir, "..")
const outDir = path.join(projectRoot, "stats")

async function getJson(url: string): Promise<Record<string, unknown> & { downloads?: unknown; data?: unknown }> {
  const res = await fetch(url, { headers: { "user-agent": "droidseal-stats" } })
  if (!res.ok) throw new Error(`${url} -> ${res.status}`)
  return res.json()
}

const today = (): string => new Date().toISOString().slice(0, 10)

// 暗色科技风 count-up SVG:图片加载时数字从 0 增到总量(SMIL animate)
function countUpSvg(label: string, value: number, color: string): string {
  const w = 170
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img">
  <rect width="100%" height="100%" fill="#0a2132" rx="3"/>
  <text x="8" y="14" font-family="ui-monospace,Consolas,monospace" font-size="11" fill="#87a9ba">${label}</text>
  <text x="${w - 8}" y="14" text-anchor="end" font-family="ui-monospace,Consolas,monospace" font-size="11" font-weight="600" fill="${color}">
    <tspan id="n">0</tspan>
    <animate attributeName="textContent" values="0;${value}" dur="1.6s" fill="freeze" begin="0.25s" calcMode="linear"/>
  </text>
</svg>
`
}

async function main(): Promise<void> {
  await mkdir(outDir, { recursive: true })
  const results: Array<{ name: string; label: string; value: number; color: string }> = []

  // npm 总下载(range 求和,2015 至今)
  try {
    const range = await getJson(`https://api.npmjs.org/downloads/range/2015-01-01:${today()}/droidseal`)
    const total = ((range.downloads as Array<{ downloads?: number }>) ?? []).reduce(
      (s: number, d) => s + (d.downloads ?? 0),
      0,
    )
    results.push({ name: "npm-total", label: "npm total", value: total, color: "#00a8cc" })
  } catch (error) {
    console.warn("npm 总下载获取失败:", error)
  }
  // npm 月下载
  try {
    const point = await getJson("https://api.npmjs.org/downloads/point/last-month/droidseal")
    results.push({ name: "npm-monthly", label: "npm / month", value: (point.downloads as number) ?? 0, color: "#7aa2ff" })
  } catch (error) {
    console.warn("npm 月下载获取失败:", error)
  }
  // PyPI 总下载(pypistats overall 求和)
  try {
    const overall = await getJson("https://pypistats.org/api/packages/droidseal/overall")
    const total = ((overall.data as Array<{ downloads?: number }>) ?? []).reduce(
      (s: number, d) => s + (d.downloads ?? 0),
      0,
    )
    results.push({ name: "pypi-total", label: "pypi total", value: total, color: "#00a8cc" })
  } catch (error) {
    console.warn("PyPI 总下载获取失败:", error)
  }
  // PyPI 月下载
  try {
    const recent = await getJson("https://pypistats.org/api/packages/droidseal/recent")
    const data = recent.data as { last_month?: number }
    results.push({ name: "pypi-monthly", label: "pypi / month", value: data?.last_month ?? 0, color: "#7aa2ff" })
  } catch (error) {
    console.warn("PyPI 月下载获取失败:", error)
  }
  // GitHub stars / forks
  try {
    const repo = await getJson("https://api.github.com/repos/noontiger/droidseal")
    results.push({ name: "stars", label: "stars", value: (repo.stargazers_count as number) ?? 0, color: "#00a8cc" })
    results.push({ name: "forks", label: "forks", value: (repo.forks_count as number) ?? 0, color: "#7aa2ff" })
  } catch (error) {
    console.warn("GitHub 统计获取失败:", error)
  }

  for (const item of results) {
    await writeFile(path.join(outDir, `${item.name}.svg`), countUpSvg(item.label, item.value, item.color))
    console.log(`✓ stats/${item.name}.svg = ${item.value}`)
  }
}

await main()
