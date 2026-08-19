import path from "node:path"
import { createHash } from "node:crypto"
import { createReadStream } from "node:fs"
import { copyFile, lstat, mkdir, realpath, writeFile } from "node:fs/promises"
import type { PipelineConfig, RunContext } from "./types.ts"

export type ReleaseEvidenceStatus = "complete" | "partial" | "unresolved" | "not-applicable"

export interface GradleArtifactIdentity {
  sourceApkPath: string
  moduleDirectory: string
  modulePath: string
  variant: string
  mappingDirectory: string
  mappingDirectoryPath: string
}

export interface ReleaseEvidenceFile {
  kind: string
  archivePath: string
  sourceScope: "project" | "run"
  sourcePath: string
  sha256: string
  size: number
}

export interface ReleaseEvidenceMissing {
  kind: string
  fileName: string
  required: boolean
  reason: string
}

export interface ReleaseEvidenceArtifact {
  sourceScope: "output"
  path: string
  sha256: string
  size: number
}

export interface ReleaseEvidenceManifest {
  schemaVersion: 1
  product: "DroidSeal"
  generatedAt: string
  runId: string
  inputKind: PipelineConfig["inputKind"]
  status: ReleaseEvidenceStatus
  artifact: ReleaseEvidenceArtifact | null
  gradle: {
    sourceApkPath: string
    modulePath: string
    variant: string
    mappingDirectory: string
  } | null
  files: ReleaseEvidenceFile[]
  missing: ReleaseEvidenceMissing[]
  notes: string[]
}

export interface ReleaseEvidenceResult {
  directory: string
  manifestPath: string
  status: ReleaseEvidenceStatus
  archivedFiles: string[]
  missing: ReleaseEvidenceMissing[]
  variant?: string
}

interface EvidenceDefinition {
  kind: string
  fileName: string
  required: boolean
}

const R8_EVIDENCE_FILES: readonly EvidenceDefinition[] = [
  { kind: "r8-mapping", fileName: "mapping.txt", required: true },
  { kind: "r8-configuration", fileName: "configuration.txt", required: true },
  { kind: "r8-seeds", fileName: "seeds.txt", required: true },
  { kind: "r8-usage", fileName: "usage.txt", required: true },
  { kind: "r8-missing-rules", fileName: "missing_rules.txt", required: false },
]

function isWithin(root: string, target: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(target))
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function portableRelative(root: string, target: string): string {
  return path.relative(root, target).replaceAll("\\", "/") || "."
}

function variantFromSegments(segments: readonly string[]): string | undefined {
  if (segments.length === 0 || segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return undefined
  }
  return segments
    .map((segment, index) =>
      index === 0 ? segment : segment.slice(0, 1).toUpperCase() + segment.slice(1),
    )
    .join("")
}

export function inferGradleArtifactIdentity(
  projectPath: string,
  sourceApk: string | undefined,
): GradleArtifactIdentity | undefined {
  if (!sourceApk) return undefined
  const projectRoot = path.resolve(projectPath)
  const source = path.resolve(sourceApk)
  if (!isWithin(projectRoot, source) || path.extname(source).toLowerCase() !== ".apk") return undefined

  const relative = portableRelative(projectRoot, source)
  const segments = relative.split("/")
  let buildIndex = -1
  for (let index = 0; index <= segments.length - 5; index += 1) {
    if (
      segments[index]?.toLowerCase() === "build" &&
      segments[index + 1]?.toLowerCase() === "outputs" &&
      segments[index + 2]?.toLowerCase() === "apk"
    ) {
      buildIndex = index
    }
  }
  if (buildIndex < 0) return undefined

  const variantSegments = segments.slice(buildIndex + 3, -1)
  const variant = variantFromSegments(variantSegments)
  if (!variant) return undefined

  const moduleSegments = segments.slice(0, buildIndex)
  const moduleDirectory = path.resolve(projectRoot, ...moduleSegments)
  if (!isWithin(projectRoot, moduleDirectory)) return undefined
  const mappingDirectoryPath = path.join(moduleDirectory, "build", "outputs", "mapping", variant)
  if (!isWithin(projectRoot, mappingDirectoryPath)) return undefined

  return {
    sourceApkPath: relative,
    moduleDirectory,
    modulePath: moduleSegments.join("/") || ".",
    variant,
    mappingDirectory: portableRelative(projectRoot, mappingDirectoryPath),
    mappingDirectoryPath,
  }
}

async function safeRegularFile(root: string, target: string): Promise<boolean> {
  if (!isWithin(root, target)) return false
  try {
    const info = await lstat(target)
    if (!info.isFile()) return false
    // 两侧都先 realpath 规范化再比较,避免 Windows 上短文件名/大小写
    // 等表示差异导致 isWithin 误判(如 CI 的 runneradmin 用户)。
    const [resolvedRoot, resolved] = await Promise.all([realpath(root), realpath(target)])
    return isWithin(resolvedRoot, resolved)
  } catch {
    return false
  }
}

async function digestFile(target: string): Promise<{ sha256: string; size: number }> {
  const info = await lstat(target)
  if (!info.isFile()) throw new Error("not a regular file")
  const hasher = createHash("sha256")
  for await (const chunk of createReadStream(target)) hasher.update(chunk)
  return { sha256: hasher.digest("hex"), size: info.size }
}

async function archiveFile(input: {
  sourceRoot: string
  sourcePath: string
  sourceScope: ReleaseEvidenceFile["sourceScope"]
  sourceDisplayPath: string
  destinationRoot: string
  archivePath: string
  kind: string
}): Promise<ReleaseEvidenceFile | undefined> {
  if (!(await safeRegularFile(input.sourceRoot, input.sourcePath))) return undefined
  const destination = path.resolve(input.destinationRoot, input.archivePath)
  if (!isWithin(input.destinationRoot, destination)) return undefined

  try {
    await mkdir(path.dirname(destination), { recursive: true })
    await copyFile(input.sourcePath, destination)
    const [sourceDigest, archiveDigest] = await Promise.all([
      digestFile(input.sourcePath),
      digestFile(destination),
    ])
    if (
      sourceDigest.sha256 !== archiveDigest.sha256 ||
      sourceDigest.size !== archiveDigest.size
    ) {
      return undefined
    }
    return {
      kind: input.kind,
      archivePath: input.archivePath.replaceAll("\\", "/"),
      sourceScope: input.sourceScope,
      sourcePath: input.sourceDisplayPath.replaceAll("\\", "/"),
      sha256: archiveDigest.sha256,
      size: archiveDigest.size,
    }
  } catch {
    return undefined
  }
}

async function describeFinalArtifact(
  config: PipelineConfig,
  context: RunContext,
): Promise<ReleaseEvidenceArtifact | null> {
  if (!context.finalArtifact) return null
  const outputRoot = path.resolve(config.outputDirectory)
  const artifact = path.resolve(context.finalArtifact)
  if (!(await safeRegularFile(outputRoot, artifact))) return null
  try {
    const digest = await digestFile(artifact)
    return {
      sourceScope: "output",
      path: portableRelative(outputRoot, artifact),
      sha256: digest.sha256,
      size: digest.size,
    }
  } catch {
    return null
  }
}

export async function writeReleaseEvidence(
  config: PipelineConfig,
  context: RunContext,
  generatedAt = new Date().toISOString(),
): Promise<ReleaseEvidenceResult> {
  const evidenceDirectory = path.join(context.reportDirectory, "release-evidence")
  const manifestPath = path.join(evidenceDirectory, "manifest.json")
  await mkdir(evidenceDirectory, { recursive: true })

  const files: ReleaseEvidenceFile[] = []
  const missing: ReleaseEvidenceMissing[] = []
  const notes: string[] = []
  const artifact = await describeFinalArtifact(config, context)

  if (!artifact && config.inputKind === "project") {
    missing.push({
      kind: "final-apk",
      fileName: "*.apk",
      required: true,
      reason: "本次运行没有位于配置输出目录内的普通最终 APK 文件。",
    })
  }

  let identity: GradleArtifactIdentity | undefined
  let status: ReleaseEvidenceStatus

  if (config.inputKind === "apk") {
    status = "not-applicable"
    notes.push("输入是现成 APK；R8 构建输出只存在于源码项目构建目录，因此本项明确标记为不适用。")
  } else {
    identity = inferGradleArtifactIdentity(config.inputPath, context.originalArtifact)
    if (!identity) {
      status = "unresolved"
      notes.push("无法从本次实际选择的 APK 解析 build/outputs/apk/<variant> 布局；为避免混入旧变体，未搜索其他 mapping 目录。")
      for (const definition of R8_EVIDENCE_FILES) {
        missing.push({
          kind: definition.kind,
          fileName: definition.fileName,
          required: definition.required,
          reason: "未解析出本次 APK 的 Gradle 模块与变体，未进行模糊搜索。",
        })
      }
    } else {
      for (const definition of R8_EVIDENCE_FILES) {
        const sourcePath = path.join(identity.mappingDirectoryPath, definition.fileName)
        const archived = await archiveFile({
          sourceRoot: path.resolve(config.inputPath),
          sourcePath,
          sourceScope: "project",
          sourceDisplayPath: portableRelative(path.resolve(config.inputPath), sourcePath),
          destinationRoot: evidenceDirectory,
          archivePath: path.posix.join("r8", definition.fileName),
          kind: definition.kind,
        })
        if (archived) files.push(archived)
        else {
          missing.push({
            kind: definition.kind,
            fileName: definition.fileName,
            required: definition.required,
            reason: definition.required
              ? "所选变体未生成该文件，或文件不是项目根目录内的普通文件。"
              : "可选文件未生成；通常表示本次 R8 没有输出缺失规则建议。",
          })
        }
      }

      const requiredMissing = missing.some((item) => item.required)
      status = requiredMissing || !artifact ? "partial" : "complete"
      notes.push(`仅归档所选变体 ${identity.variant} 的固定白名单文件；未遍历其他历史变体。`)
    }

    const initScript = path.join(context.artifactDirectory, "droidseal-force-r8.init.gradle")
    const archivedInitScript = await archiveFile({
      sourceRoot: path.resolve(context.runDirectory),
      sourcePath: initScript,
      sourceScope: "run",
      sourceDisplayPath: portableRelative(path.resolve(context.runDirectory), initScript),
      destinationRoot: evidenceDirectory,
      archivePath: path.posix.join("build", "droidseal-force-r8.init.gradle"),
      kind: "droidseal-r8-overlay",
    })
    if (archivedInitScript) files.push(archivedInitScript)
  }

  files.sort((left, right) => left.archivePath.localeCompare(right.archivePath))
  missing.sort((left, right) => left.fileName.localeCompare(right.fileName))

  const manifest: ReleaseEvidenceManifest = {
    schemaVersion: 1,
    product: "DroidSeal",
    generatedAt,
    runId: context.runId,
    inputKind: config.inputKind,
    status,
    artifact,
    gradle: identity
      ? {
          sourceApkPath: identity.sourceApkPath,
          modulePath: identity.modulePath,
          variant: identity.variant,
          mappingDirectory: identity.mappingDirectory,
        }
      : null,
    files,
    missing,
    notes,
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8")

  return {
    directory: evidenceDirectory,
    manifestPath,
    status,
    archivedFiles: files.map((file) => file.archivePath),
    missing,
    ...(identity ? { variant: identity.variant } : {}),
  }
}
