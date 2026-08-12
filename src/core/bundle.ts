import path from "node:path"
import { existsSync } from "node:fs"
import { access, readFile } from "node:fs/promises"
import { homedir } from "node:os"

export type BundleToolName = "java" | "keytool" | "aapt" | "zipalign" | "apksigner"

export interface BundleFileEntry {
  relPath: string
  sha256: string
}

export interface BundleRuntime {
  bun?: string
  node?: string
  npm?: string
  npx?: string
  nodeModules?: string
}

export interface BundleManifest {
  platform: string
  generatedAt: string
  source?: "downloaded" | "local"
  temurinVersion?: string
  jdkVersion?: string
  buildToolsVersion: string
  androidSdkRoot?: string
  tools: Partial<Record<BundleToolName, string>>
  runtime?: BundleRuntime
  files: BundleFileEntry[]
}

async function exists(filePath: string): Promise<boolean> {
  try {
    await access(filePath)
    return true
  } catch {
    return false
  }
}

export function bundleRoot(): string {
  const explicit = process.env.DROIDSEAL_BUNDLE_DIR
  if (explicit) return path.resolve(explicit)

  // Prefer a self-contained dependencies directory next to the source tree or
  // built entrypoint. This keeps portable installs independent from PATH and
  // from the per-user ~/.droidseal directory.
  const candidates = [
    path.resolve(process.cwd(), "dependencies"),
    path.resolve(import.meta.dir, "..", "..", "dependencies"),
    path.resolve(import.meta.dir, "..", "dependencies"),
  ]
  for (const candidate of [...new Set(candidates)]) {
    if (existsSync(path.join(candidate, "bundle-manifest.json"))) return candidate
  }

  return path.join(homedir(), ".droidseal", "bundle")
}

export function manifestPath(root = bundleRoot()): string {
  return path.join(root, "bundle-manifest.json")
}

export async function loadBundleManifest(
  root = bundleRoot(),
): Promise<{ root: string; manifest: BundleManifest } | undefined> {
  const file = manifestPath(root)
  if (!(await exists(file))) return undefined
  try {
    const manifest = JSON.parse(await readFile(file, "utf8")) as BundleManifest
    if (!manifest || typeof manifest !== "object" || !manifest.tools) return undefined
    return { root, manifest }
  } catch {
    return undefined
  }
}

export async function bundledToolPath(
  manifest: BundleManifest,
  root: string,
  name: BundleToolName,
): Promise<string | undefined> {
  const relative = manifest.tools[name]
  if (!relative) return undefined
  const absolute = path.join(root, relative)
  return (await exists(absolute)) ? absolute : undefined
}

export function bundledSdkRoot(manifest: BundleManifest, root: string): string | undefined {
  return manifest.androidSdkRoot ? path.join(root, manifest.androidSdkRoot) : undefined
}
