import { createHash } from "node:crypto"
import { copyFile, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises"
import path from "node:path"

export interface BundledPackage {
  name: string
  version: string
  license: string
  repository?: string
  homepage?: string
  packageRoot: string
  inputs: string[]
  licenseFiles: string[]
}

export interface ComplianceArtifact {
  path: string
  bytes: number
  sha256: string
}

interface GenerateOptions {
  projectRoot: string
  distDirectory: string
  metafile: Bun.BuildMetafile
  bunVersion: string
  runtimePackages: string[]
  runtimeAssets: string[]
}

const licenseFilePattern = /^(?:licen[cs]e|copying|notice)(?:[._-].*)?$/i

function slash(value: string): string {
  return value.replaceAll("\\", "/")
}

function safeSegment(value: string): string {
  return value.replace(/^@/, "").replaceAll("/", "__").replace(/[^A-Za-z0-9._-]/g, "_")
}

function npmPurl(name: string, version: string): string {
  if (name.startsWith("@")) {
    const [scope, packageName] = name.slice(1).split("/")
    return `pkg:npm/%40${scope}/${packageName}@${version}`
  }
  return `pkg:npm/${name}@${version}`
}

function deterministicUuid(value: string): string {
  const hex = createHash("sha256").update(value).digest("hex").slice(0, 32)
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`
}

function repositoryUrl(value: unknown): string | undefined {
  if (typeof value === "string") return value
  if (value && typeof value === "object" && "url" in value && typeof value.url === "string") return value.url
  return undefined
}

function packageRootFromInput(projectRoot: string, input: string): string | undefined {
  const absolute = path.isAbsolute(input) ? path.normalize(input) : path.resolve(projectRoot, input)
  const parts = absolute.split(path.sep)
  const nodeModulesIndex = parts.lastIndexOf("node_modules")
  if (nodeModulesIndex < 0 || nodeModulesIndex + 1 >= parts.length) return undefined
  const packageEnd = parts[nodeModulesIndex + 1]?.startsWith("@") ? nodeModulesIndex + 3 : nodeModulesIndex + 2
  if (packageEnd > parts.length) return undefined
  return parts.slice(0, packageEnd).join(path.sep)
}

async function existingLicenseFiles(packageRoot: string): Promise<string[]> {
  const files: string[] = []
  for (const entry of await readdir(packageRoot, { withFileTypes: true })) {
    if (entry.isFile() && licenseFilePattern.test(entry.name)) files.push(entry.name)
  }
  return files.sort((left, right) => left.localeCompare(right, "en"))
}

async function hashFile(file: string): Promise<string> {
  return createHash("sha256").update(await readFile(file)).digest("hex")
}

// Bundle inputs are the source of truth for runtime license inventory.

async function collectBundledPackages(
  projectRoot: string,
  metafile: Bun.BuildMetafile,
  runtimePackages: string[],
): Promise<BundledPackage[]> {
  const roots = new Map<string, string[]>()
  for (const input of Object.keys(metafile.inputs)) {
    const packageRoot = packageRootFromInput(projectRoot, input)
    if (!packageRoot) continue
    const inputs = roots.get(packageRoot) ?? []
    const absolute = path.isAbsolute(input) ? input : path.resolve(projectRoot, input)
    inputs.push(slash(path.relative(projectRoot, absolute)))
    roots.set(packageRoot, inputs)
  }
  for (const packageName of runtimePackages) {
    const packageRoot = path.join(projectRoot, "node_modules", ...packageName.split("/"))
    const inputs = roots.get(packageRoot) ?? []
    inputs.push(`[native runtime package] ${packageName}`)
    roots.set(packageRoot, inputs)
  }

  const packages: BundledPackage[] = []
  for (const [packageRoot, inputs] of roots) {
    const packageJsonPath = path.join(packageRoot, "package.json")
    const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8")) as {
      name?: string
      version?: string
      license?: string | { type?: string }
      repository?: unknown
      homepage?: string
    }
    const name = packageJson.name?.trim()
    const version = packageJson.version?.trim()
    const license = typeof packageJson.license === "string" ? packageJson.license.trim() : packageJson.license?.type?.trim()
    if (!name || !version) throw new Error(`Bundle package is missing name/version: ${packageJsonPath}`)
    if (!license || /^(?:unknown|unlicensed|none|see license in\b)/i.test(license)) {
      throw new Error(`Bundle package has no verified license field: ${name}@${version}`)
    }
    const licenseFiles = await existingLicenseFiles(packageRoot)
    if (licenseFiles.length === 0) throw new Error(`Bundle package has no LICENSE/COPYING/NOTICE file: ${name}@${version}`)
    const repository = repositoryUrl(packageJson.repository)
    if (!repository && !packageJson.homepage) {
      throw new Error("Bundle package has no declared source URL: " + name + "@" + version)
    }
    packages.push({
      name,
      version,
      license,
      ...(repository ? { repository } : {}),
      ...(packageJson.homepage ? { homepage: packageJson.homepage } : {}),
      packageRoot,
      inputs: [...new Set(inputs)].sort((left, right) => left.localeCompare(right, "en")),
      licenseFiles,
    })
  }
  return packages.sort((left, right) => `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`, "en"))
}

export async function generateBundleCompliance(options: GenerateOptions): Promise<{
  packages: BundledPackage[]
  artifacts: ComplianceArtifact[]
}> {
  const { projectRoot, distDirectory, metafile, bunVersion, runtimePackages, runtimeAssets } = options
  const packages = await collectBundledPackages(projectRoot, metafile, runtimePackages)
  const complianceRoot = path.join(distDirectory, "third-party")
  const licensesRoot = path.join(complianceRoot, "licenses")
  await mkdir(licensesRoot, { recursive: true })

  const copiedLicenses: Array<{ package: string; version: string; license: string; path: string; sha256: string }> = []
  for (const item of packages) {
    const destinationDirectory = path.join(licensesRoot, `${safeSegment(item.name)}-${safeSegment(item.version)}`)
    await mkdir(destinationDirectory, { recursive: true })
    for (const filename of item.licenseFiles) {
      const source = path.join(item.packageRoot, filename)
      const destination = path.join(destinationDirectory, filename)
      await copyFile(source, destination)
      copiedLicenses.push({
        package: item.name,
        version: item.version,
        license: item.license,
        path: slash(path.relative(distDirectory, destination)),
        sha256: await hashFile(destination),
      })
    }
  }

  const webkitCommit = "5488984d20e0dbfe4be2c3ba8fb18eb81a5e0e8b"
  const tinyccCommit = "12882eee073cfe5c7621bcfadf679e1372d4537b"
  const inventory = {
    schemaVersion: 1,
    generatedBy: "DroidSeal Bun metafile compliance generator",
    runtime: {
      name: "Bun",
      version: bunVersion,
      license: "MIT AND LGPL-2.0-only AND LGPL-2.1-only AND LicenseRef-Bun-Linked-Libraries",
      source: `https://github.com/oven-sh/bun/tree/bun-v${bunVersion}`,
      licenseSource: `https://raw.githubusercontent.com/oven-sh/bun/bun-v${bunVersion}/LICENSE.md`,
      webkitCommit,
      webkitSource: `https://github.com/oven-sh/WebKit/tree/${webkitCommit}`,
      tinyccCommit,
      tinyccSource: `https://github.com/oven-sh/tinycc/tree/${tinyccCommit}`,
      relinkingInstructions: "licenses/Bun-LGPL-RELINKING.md",
    },
    runtimeAssets: [...runtimeAssets].sort((left, right) => left.localeCompare(right, "en")),
    packages: packages.map(({ packageRoot: _packageRoot, ...item }) => ({
      ...item,
      copiedLicenseFiles: copiedLicenses.filter((license) => license.package === item.name && license.version === item.version),
    })),
  }
  const inventoryPath = path.join(complianceRoot, "bundle-components.json")
  await writeFile(inventoryPath, JSON.stringify(inventory, null, 2) + "\n", "utf8")

  const rootRef = "pkg:npm/droidseal@0.1.0"
  const bunRef = `pkg:github/oven-sh/bun@bun-v${bunVersion}`
  const componentRefs = packages.map((item) => npmPurl(item.name, item.version))
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${deterministicUuid([bunVersion, ...componentRefs].join("\n"))}`,
    version: 1,
    metadata: {
      component: { type: "application", name: "droidseal", version: "0.1.0", "bom-ref": rootRef },
      tools: { components: [{ type: "application", name: "DroidSeal bundle compliance generator", version: "1" }] },
    },
    components: [
      {
        type: "framework",
        name: "Bun",
        version: bunVersion,
        "bom-ref": bunRef,
        purl: bunRef,
        licenses: [{ expression: "MIT AND LGPL-2.0-only AND LGPL-2.1-only AND LicenseRef-Bun-Linked-Libraries" }],
        externalReferences: [
          { type: "vcs", url: `https://github.com/oven-sh/bun/tree/bun-v${bunVersion}` },
          { type: "other", url: `https://github.com/oven-sh/WebKit/tree/${webkitCommit}`, comment: "Pinned JavaScriptCore/WebKit source" },
          { type: "other", url: `https://github.com/oven-sh/tinycc/tree/${tinyccCommit}`, comment: "Bun-pinned TinyCC source" },
        ],
      },
      ...packages.map((item, index) => ({
        type: "library",
        name: item.name,
        version: item.version,
        "bom-ref": componentRefs[index],
        purl: componentRefs[index],
        licenses: [{ expression: item.license }],
        externalReferences: [item.repository ?? item.homepage]
          .filter((value): value is string => Boolean(value))
          .map((url) => ({ type: "vcs", url })),
      })),
    ],
    dependencies: [{ ref: rootRef, dependsOn: [bunRef, ...componentRefs] }],
  }
  const sbomPath = path.join(complianceRoot, "bundle-sbom.cdx.json")
  await writeFile(sbomPath, JSON.stringify(sbom, null, 2) + "\n", "utf8")

  const tableRows = packages.map((item) => {
    const source = item.repository ?? item.homepage ?? "not declared"
    const notices = copiedLicenses
      .filter((license) => license.package === item.name && license.version === item.version)
      .map((license) => `\`${license.path}\``)
      .join("<br>")
    return `| \`${item.name}\` | ${item.version} | \`${item.license}\` | ${source} | ${notices} |`
  })
  const noticesPath = path.join(complianceRoot, "THIRD_PARTY_NOTICES.generated.md")
  const notices = [
    "# DroidSeal generated bundle notices",
    "",
    "This file is generated from the exact Bun bundler metafile used for this executable.",
    "It lists runtime JavaScript packages plus explicitly embedded native runtime packages.",
    "Build-only tools that do not enter the executable are documented in the repository-level THIRD_PARTY_NOTICES.md.",
    "",
    `## Bun runtime ${bunVersion}`,
    "",
    `- Bun source: https://github.com/oven-sh/bun/tree/bun-v${bunVersion}`,
    `- Bun license source: https://raw.githubusercontent.com/oven-sh/bun/bun-v${bunVersion}/LICENSE.md`,
    `- Pinned WebKit/JavaScriptCore source: https://github.com/oven-sh/WebKit/tree/${webkitCommit}`,
    `- Pinned TinyCC source: https://github.com/oven-sh/tinycc/tree/${tinyccCommit}`,
    "- Included notices: `licenses/Bun-1.3.14-LICENSE.md`, `licenses/LGPL-2.0-only.txt`, `licenses/TinyCC-12882eee-COPYING`",
    "- Relinking and corresponding-source instructions: `licenses/Bun-LGPL-RELINKING.md`",
    "",
    "## Runtime bundle packages",
    "",
    "| Package | Version | Declared license | Source | Included license files |",
    "| --- | --- | --- | --- | --- |",
    ...tableRows,
    "",
  ].join("\n")
  await writeFile(noticesPath, notices, "utf8")

  const artifactFiles: string[] = []
  async function walk(directory: string): Promise<void> {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name)
      if (entry.isDirectory()) await walk(absolute)
      else if (entry.isFile()) artifactFiles.push(absolute)
    }
  }
  await walk(complianceRoot)
  artifactFiles.sort((left, right) => slash(path.relative(distDirectory, left)).localeCompare(slash(path.relative(distDirectory, right)), "en"))
  const artifacts: ComplianceArtifact[] = []
  for (const file of artifactFiles) {
    artifacts.push({
      path: slash(path.relative(distDirectory, file)),
      bytes: (await stat(file)).size,
      sha256: await hashFile(file),
    })
  }
  return { packages, artifacts }
}
