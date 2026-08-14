import { createHash } from "node:crypto"
import { readdir, readFile, stat } from "node:fs/promises"
import path from "node:path"

const root = path.resolve(import.meta.dir, "..")
const requiredFiles = [
  "README.md",
  "LICENSE",
  "TRADEMARKS.md",
  "THIRD_PARTY_NOTICES.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "CODE_OF_CONDUCT.md",
  "GOVERNANCE.md",
  "CHANGELOG.md",
  "droidseal-logo.png",
  "licenses/Bun-1.3.14-LICENSE.md",
  "licenses/Bun-LGPL-RELINKING.md",
  "licenses/LGPL-2.0-only.txt",
  "licenses/TinyCC-12882eee-COPYING",
  "licenses/OpenTUI-MIT.txt",
  "licenses/SolidJS-MIT.txt",
  "licenses/Terser-BSD-2-Clause.txt",
  ".github/CODEOWNERS",
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  ".github/PULL_REQUEST_TEMPLATE.md",
  ".github/workflows/ci.yml",
  ".github/workflows/dco.yml",
] as const
const expectedPackageFiles = [
  "bin/droidseal.cjs",
  "dist",
  "README.md",
  "LICENSE",
  "CHANGELOG.md",
  "SECURITY.md",
  "TRADEMARKS.md",
  "THIRD_PARTY_NOTICES.md",
  "licenses",
] as const
const ignoredDirectories = new Set([
  ".git",
  ".droidseal",
  "dependencies",
  "dist",
  "node_modules",
  "verification-output",
])
const forbiddenExtensions = new Set([".apk", ".aab", ".jks", ".keystore", ".p12", ".pfx", ".pem", ".key"])
const textExtensions = new Set([".ts", ".tsx", ".js", ".cjs", ".json", ".md", ".toml", ".yml", ".yaml", ".txt"])
const findings: string[] = []

async function exists(target: string): Promise<boolean> {
  return Boolean(await stat(target).catch(() => undefined))
}

async function walk(directory: string): Promise<string[]> {
  const files: string[] = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue
    const absolute = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await walk(absolute))
    else files.push(absolute)
  }
  return files
}

for (const required of requiredFiles) {
  if (!(await exists(path.join(root, required)))) findings.push(`缺少开源社区文件：${required}`)
}

const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8")) as {
  name?: string
  description?: string
  license?: string
  bin?: Record<string, string>
  files?: string[]
  repository?: string | { url?: string }
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  overrides?: Record<string, string>
  scripts?: Record<string, string>
  engines?: Record<string, string>
  os?: string[]
  cpu?: string[]
  packageManager?: string
}
const repositoryUrl = typeof packageJson.repository === "string"
  ? packageJson.repository
  : packageJson.repository?.url
if (packageJson.name !== "droidseal") findings.push("package.json name 必须为 droidseal")
if (packageJson.description !== "A simple, local-first Android release security pipeline.") {
  findings.push("package.json description 必须使用统一英文短介绍")
}
if (packageJson.license !== "MIT") findings.push("package.json license 必须与 LICENSE 的 MIT 保持一致")
if (packageJson.bin?.droidseal !== "./bin/droidseal.cjs") findings.push("npm 命令必须指向只负责校验和启动二进制的 bin/droidseal.cjs")
if (JSON.stringify(packageJson.files) !== JSON.stringify(expectedPackageFiles)) {
  findings.push("npm files 必须使用最小二进制发布白名单，禁止包含源码、脚本、路线图和内部文档")
}
if (packageJson.engines?.node !== ">=18") findings.push("npm 启动校验器要求 Node.js >=18")
if (JSON.stringify(packageJson.os) !== JSON.stringify(["win32"]) || JSON.stringify(packageJson.cpu) !== JSON.stringify(["x64"])) {
  findings.push("当前 npm 二进制包必须显式限制为 Windows x64")
}
if (packageJson.dependencies && Object.keys(packageJson.dependencies).length > 0) {
  findings.push("单文件二进制 npm 包不应安装运行时 npm 依赖")
}
if (packageJson.packageManager !== "bun@1.3.14") findings.push("packageManager must stay pinned to bun@1.3.14")

const pinnedLicenseHashes = new Map([
  ["licenses/Bun-1.3.14-LICENSE.md", "2c6160ec8fb853f7e8f97d9b249e756c9b0ac44860a68b6bf4f1b0bcbc5c3741"],
  ["licenses/LGPL-2.0-only.txt", "86dc99d7e5060915ab1dfc1378b7dd351c62088bfa74067e8aa1868c6fdba7d8"],
  ["licenses/TinyCC-12882eee-COPYING", "88f9284c6e8c212181e4c7f9886bb24a960a89ba31e801d12bc4e42b6e8aaab5"],
])
for (const [relative, expectedHash] of pinnedLicenseHashes) {
  const file = path.join(root, relative)
  if (!(await exists(file))) continue
  const actualHash = createHash("sha256").update(await readFile(file)).digest("hex")
  if (actualHash !== expectedHash) findings.push(`Pinned license text hash mismatch: ${relative}`)
}
for (const [name, version] of Object.entries({
  "@opentui/core": "0.4.5",
  "@opentui/solid": "0.4.5",
  "solid-js": "1.9.12",
  "terser": "5.49.0",
})) {
  if (packageJson.devDependencies?.[name] !== version) findings.push(`构建依赖必须精确锁定：${name}@${version}`)
}
if (packageJson.overrides?.["brace-expansion"] !== "2.1.3") findings.push("brace-expansion 安全覆盖必须锁定为 2.1.3")
if (repositoryUrl !== "git+https://github.com/noontiger/droidseal.git") {
  findings.push("package.json repository 必须指向官方 droidseal 仓库")
}
if (!packageJson.scripts?.verify || packageJson.scripts?.prepack !== "bun run verify") {
  findings.push("npm prepack 必须执行完整 verify 发布门禁")
}

const buildScript = await readFile(path.join(root, "scripts", "build.ts"), "utf8")
if (!/from\s+["']terser["']/.test(buildScript) || !/mangle:\s*\{[\s\S]*?toplevel:\s*true/.test(buildScript)) {
  findings.push("构建脚本必须使用 Terser 并启用顶层标识符 mangle")
}
if (!/sourcemap:\s*["']none["']/.test(buildScript) || !/sourceMap:\s*false/.test(buildScript)) {
  findings.push("Bun/Terser 构建必须同时禁用 source map")
}
for (const requiredCompileFlag of [
  '"--compile"',
  '"--no-compile-autoload-dotenv"',
  '"--no-compile-autoload-bunfig"',
  '"--no-compile-autoload-package-json"',
]) {
  if (!buildScript.includes(requiredCompileFlag)) findings.push(`二进制构建缺少参数：${requiredCompileFlag}`)
}

const launcherPath = path.join(root, "bin", "droidseal.cjs")
if (!(await exists(launcherPath))) findings.push("缺少 npm 二进制启动校验器：bin/droidseal.cjs")
else {
  const launcher = await readFile(launcherPath, "utf8")
  for (const marker of ["createHash", "droidseal-build.json", "metadata.artifact.sha256", "spawnSync", "OTUI_ASSET_ROOT"]) {
    if (!launcher.includes(marker)) findings.push(`npm 启动校验器缺少完整性或启动逻辑：${marker}`)
  }
}

const distDirectory = path.join(root, "dist")
const executablePath = path.join(distDirectory, "droidseal.exe")
const buildMetadataPath = path.join(distDirectory, "droidseal-build.json")
if (!(await exists(executablePath))) findings.push("缺少发布二进制：dist/droidseal.exe")
const distFiles = await exists(distDirectory) ? await walk(distDirectory) : []
const distRelativePaths = distFiles
  .map((file) => path.relative(distDirectory, file).replaceAll("\\", "/"))
  .sort()
if (distRelativePaths.some((file) => file.endsWith(".map"))) findings.push("dist 禁止携带任何 source map")
if (distRelativePaths.includes("droidseal.js")) findings.push("dist 禁止携带可直接提取的 DroidSeal JavaScript 主程序")
for (const file of distRelativePaths.filter((entry) => entry.endsWith(".js"))) {
  if (!/^parser\.worker-[a-z0-9]+\.js$/.test(file)) findings.push(`dist 出现未授权 JavaScript：${file}`)
}

let expectedAssetPaths: string[] = []
let expectedCompliancePaths: string[] = []
if (!(await exists(buildMetadataPath))) {
  findings.push("缺少 dist/droidseal-build.json 构建元数据")
} else if (await exists(executablePath)) {
  const executable = await readFile(executablePath)
  const metadata = JSON.parse(await readFile(buildMetadataPath, "utf8")) as {
    schemaVersion?: number
    artifact?: { path?: string; target?: string; format?: string; bytes?: number; sha256?: string }
    protection?: {
      bundler?: string
      compiler?: string
      minifier?: string
      minifierVersion?: string
      topLevelMangle?: boolean
      sourceIncluded?: boolean
      sourceMap?: boolean
      sourceBytes?: number
      minifiedBytes?: number
    }
    embeddedNative?: string[]
    assets?: Array<{ path?: string; bytes?: number; sha256?: string }>
    compliance?: {
      generator?: string
      bundlePackageCount?: number
      bunVersion?: string
      artifacts?: Array<{ path?: string; bytes?: number; sha256?: string }>
    }
  }
  const actualHash = createHash("sha256").update(executable).digest("hex")
  if (executable[0] !== 0x4d || executable[1] !== 0x5a) findings.push("dist/droidseal.exe 不是有效的 Windows PE 文件")
  if (
    metadata.schemaVersion !== 2 ||
    metadata.artifact?.path !== "droidseal.exe" ||
    metadata.artifact?.target !== "windows-x64" ||
    metadata.artifact?.format !== "bun-single-file-executable" ||
    metadata.artifact?.bytes !== executable.byteLength ||
    metadata.artifact?.sha256 !== actualHash
  ) findings.push("二进制大小或 SHA-256 与构建元数据不一致")
  if (
    metadata.protection?.bundler !== "Bun.build" ||
    metadata.protection?.compiler !== "bun --compile" ||
    metadata.protection?.minifier !== "terser" ||
    metadata.protection?.minifierVersion !== "5.49.0" ||
    metadata.protection?.topLevelMangle !== true ||
    metadata.protection?.sourceIncluded !== false ||
    metadata.protection?.sourceMap !== false ||
    typeof metadata.protection?.sourceBytes !== "number" ||
    typeof metadata.protection?.minifiedBytes !== "number" ||
    metadata.protection.sourceBytes <= metadata.protection.minifiedBytes
  ) findings.push("二进制保护元数据与 Terser/Bun 无源码构建策略不一致")
  if (!metadata.embeddedNative?.includes("@opentui/core-win32-x64/opentui.dll")) {
    findings.push("构建元数据未声明嵌入 OpenTUI Windows x64 原生库")
  }
  if (
    metadata.compliance?.generator !== "scripts/bundle-compliance.ts" ||
    metadata.compliance?.bunVersion !== "1.3.14" ||
    typeof metadata.compliance?.bundlePackageCount !== "number" ||
    metadata.compliance.bundlePackageCount < 1
  ) findings.push("Bundle compliance metadata is missing or not pinned to Bun 1.3.14")

  const executableText = executable.toString("latin1")
  for (const identifier of ["effectiveFindingConfidence", "auditSigningMaterials", "DroidSealPipeline"]) {
    if (executableText.includes(identifier)) findings.push(`二进制仍暴露代表性内部标识符：${identifier}`)
  }
  if (!executableText.includes("opentui.dll")) findings.push("二进制未检测到嵌入的 OpenTUI DLL")

  const expectedAssets = metadata.assets ?? []
  expectedAssetPaths = expectedAssets.map((asset) => asset.path).filter((value): value is string => Boolean(value)).sort()
  const complianceArtifacts = metadata.compliance?.artifacts ?? []
  expectedCompliancePaths = complianceArtifacts
    .map((artifact) => artifact.path)
    .filter((value): value is string => Boolean(value))
    .sort()
  const actualAssetPaths = distRelativePaths.filter((relative) => relative !== "droidseal.exe" && relative !== "droidseal-build.json")
  if (JSON.stringify([...expectedAssetPaths, ...expectedCompliancePaths].sort()) !== JSON.stringify(actualAssetPaths)) {
    findings.push("dist 伴随资源与构建元数据清单不一致")
  }
  for (const asset of expectedAssets) {
    if (!asset.path) continue
    const target = path.resolve(distDirectory, asset.path)
    const relative = path.relative(distDirectory, target)
    if (relative.startsWith("..") || path.isAbsolute(relative) || !(await exists(target))) {
      findings.push(`dist 构建资源路径无效：${asset.path}`)
      continue
    }
    const bytes = await readFile(target)
    if (asset.bytes !== bytes.byteLength || asset.sha256 !== createHash("sha256").update(bytes).digest("hex")) {
      findings.push(`dist 构建资源哈希不一致：${asset.path}`)
    }
  }
  for (const artifact of complianceArtifacts) {
    if (!artifact.path) continue
    const target = path.resolve(distDirectory, artifact.path)
    const relative = path.relative(distDirectory, target)
    if (relative.startsWith("..") || path.isAbsolute(relative) || !(await exists(target))) {
      findings.push(`Invalid bundle compliance artifact path: ${artifact.path}`)
      continue
    }
    const bytes = await readFile(target)
    if (artifact.bytes !== bytes.byteLength || artifact.sha256 !== createHash("sha256").update(bytes).digest("hex")) {
      findings.push(`Bundle compliance artifact hash mismatch: ${artifact.path}`)
    }
  }

  const inventoryPath = path.join(distDirectory, "third-party", "bundle-components.json")
  if (!(await exists(inventoryPath))) findings.push("Missing generated exact bundle component inventory")
  else {
    const inventory = JSON.parse(await readFile(inventoryPath, "utf8")) as {
      runtime?: {
        version?: string
        license?: string
        webkitCommit?: string
        tinyccCommit?: string
        relinkingInstructions?: string
      }
      packages?: Array<{ name?: string; version?: string; license?: string; copiedLicenseFiles?: unknown[] }>
    }
    if (
      inventory.runtime?.version !== "1.3.14" ||
      inventory.runtime?.license !== "MIT AND LGPL-2.0-only AND LGPL-2.1-only AND LicenseRef-Bun-Linked-Libraries" ||
      inventory.runtime?.webkitCommit !== "5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b" ||
      inventory.runtime?.tinyccCommit !== "12882eee073cfe5c7621bcfadf679e1372d4537b" ||
      inventory.runtime?.relinkingInstructions !== "licenses/Bun-LGPL-RELINKING.md"
    ) findings.push("Generated bundle inventory has incorrect Bun LGPL component identity")
    if (inventory.packages?.length !== metadata.compliance?.bundlePackageCount) {
      findings.push("Generated bundle package count does not match build metadata")
    }
    for (const item of inventory.packages ?? []) {
      if (!item.name || !item.version || !item.license || !item.copiedLicenseFiles?.length) {
        findings.push("Generated bundle inventory contains a package without complete license evidence")
      }
    }
  }
}

const secretPatterns: Array<{ name: string; pattern: RegExp }> = [
  { name: "私钥正文", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "GitHub token", pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { name: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "Bearer token", pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*\b/i },
  { name: "本机 Windows 用户路径", pattern: /\b[A-Za-z]:\\Users\\(?!User(?:\\|$)|<[^>]+>)[^\\\s"`]+/i },
  { name: "本机 Unix 用户路径", pattern: /\/(?:Users|home)\/(?!user(?:\/|$)|<[^>]+>)[^/\s"`]+/i },
]

for (const file of await walk(root)) {
  const relative = path.relative(root, file).replaceAll("\\", "/")
  const extension = path.extname(file).toLowerCase()
  const base = path.basename(file).toLowerCase()
  if (forbiddenExtensions.has(extension)) findings.push(`禁止提交签名材料或应用产物：${relative}`)
  if (base === ".env" || base.startsWith(".env.")) findings.push(`禁止提交环境密钥文件：${relative}`)
  if (!textExtensions.has(extension) && !["LICENSE", ".gitignore", ".gitattributes", ".editorconfig"].includes(path.basename(file))) {
    continue
  }
  const text = await readFile(file, "utf8").catch(() => "")
  for (const secret of secretPatterns) {
    if (secret.pattern.test(text)) findings.push(`疑似${secret.name}：${relative}`)
  }
}

if (await exists(executablePath) && await exists(buildMetadataPath)) {
  const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm"
  const pack = Bun.spawnSync({
    cmd: [npmCommand, "pack", "--dry-run", "--json", "--ignore-scripts"],
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  })
  if (pack.exitCode !== 0) {
    findings.push(`npm pack --dry-run 执行失败：${pack.stderr.toString().trim() || `exit ${pack.exitCode}`}`)
  } else {
    try {
      const report = JSON.parse(pack.stdout.toString()) as Array<{ files?: Array<{ path?: string }> }>
      const packedPaths = (report[0]?.files ?? [])
        .map((file) => file.path?.replaceAll("\\", "/"))
        .filter((value): value is string => Boolean(value))
        .sort()
      const allowedPaths = new Set([
        "package.json",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "SECURITY.md",
        "TRADEMARKS.md",
        "THIRD_PARTY_NOTICES.md",
        "licenses/Bun-1.3.14-LICENSE.md",
        "licenses/Bun-LGPL-RELINKING.md",
        "licenses/LGPL-2.0-only.txt",
        "licenses/TinyCC-12882eee-COPYING",
        "licenses/OpenTUI-MIT.txt",
        "licenses/SolidJS-MIT.txt",
        "licenses/Terser-BSD-2-Clause.txt",
        "bin/droidseal.cjs",
        "dist/droidseal.exe",
        "dist/droidseal-build.json",
        ...expectedAssetPaths.map((asset) => `dist/${asset}`),
        ...expectedCompliancePaths.map((artifact) => `dist/${artifact}`),
      ])
      for (const packed of packedPaths) {
        if (!allowedPaths.has(packed)) findings.push(`npm tarball 出现白名单外文件：${packed}`)
        if (/^(?:src|scripts|tests|docs)\//.test(packed) || /\.(?:ts|tsx|map)$/.test(packed)) {
          findings.push(`npm tarball 禁止包含源码、测试、构建脚本或 source map：${packed}`)
        }
      }
      for (const required of allowedPaths) {
        if (!packedPaths.includes(required)) findings.push(`npm tarball 缺少必需文件：${required}`)
      }
    } catch (error) {
      findings.push(`无法解析 npm pack --dry-run 输出：${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

if (findings.length > 0) {
  console.error("Open-source binary release check failed:")
  for (const finding of [...new Set(findings)]) console.error(`- ${finding}`)
  process.exit(1)
}

console.log("Open-source binary release check passed")
console.log(`- required community files: ${requiredFiles.length}`)
console.log("- signing files and APK/AAB artifacts: none")
console.log("- known secret patterns and local user paths: none")
console.log("- Terser mangle + Bun Windows x64 executable: passed")
console.log("- executable and external asset SHA-256: passed")
console.log("- npm tarball source/script/source-map exclusion: passed")
console.log("- dependency override policy: passed")
