import path from "node:path"
import { createHash } from "node:crypto"
import { mkdir, writeFile } from "node:fs/promises"
import type { PipelineConfig, RunContext, SoftwareComponent } from "./types.ts"

export interface SupplyChainArtifactsResult {
  directory: string
  sbomPath: string
  licenseReviewPath: string
  componentCount: number
  unresolvedCount: number
}

interface CycloneDxComponent {
  type: "library" | "file"
  "bom-ref": string
  group?: string
  name: string
  version?: string
  purl?: string
  properties: Array<{ name: string; value: string }>
}

function componentKey(component: SoftwareComponent): string {
  return [
    component.kind,
    component.namespace ?? "",
    component.name,
    component.version ?? "",
    component.resolution,
    component.scope,
  ].join("|")
}

export function normalizeSoftwareComponents(
  components: readonly SoftwareComponent[],
): SoftwareComponent[] {
  const merged = new Map<string, SoftwareComponent>()
  for (const component of components) {
    const key = componentKey(component)
    const current = merged.get(key)
    if (!current) {
      merged.set(key, {
        ...component,
        evidence: [...new Set(component.evidence)].sort(),
        ...(component.architectures ? { architectures: [...new Set(component.architectures)].sort() } : {}),
      })
      continue
    }
    current.evidence = [...new Set([...current.evidence, ...component.evidence])].sort()
    if (component.architectures) {
      current.architectures = [...new Set([...(current.architectures ?? []), ...component.architectures])].sort()
    }
  }
  return [...merged.values()].sort((left, right) => componentKey(left).localeCompare(componentKey(right)))
}

function digestText(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex")
}

function uuidFromDigest(value: string): string {
  const characters = digestText(value).slice(0, 32).split("")
  characters[12] = "5"
  characters[16] = "8"
  const hex = characters.join("")
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join("-")
}

function bomRef(component: SoftwareComponent): string {
  if (component.purl) return component.purl
  return `urn:droidseal:component:${component.kind}:${digestText(componentKey(component)).slice(0, 24)}`
}

function cycloneComponent(component: SoftwareComponent): CycloneDxComponent {
  const properties = [
    { name: "droidseal:component-kind", value: component.kind },
    { name: "droidseal:resolution", value: component.resolution },
    { name: "droidseal:scope", value: component.scope },
    { name: "droidseal:license-concluded", value: "NOASSERTION" },
    { name: "droidseal:evidence", value: JSON.stringify(component.evidence) },
  ]
  if (component.architectures?.length) {
    properties.push({ name: "droidseal:android-abis", value: component.architectures.join(",") })
  }
  return {
    type: component.kind === "native-library" ? "file" : "library",
    "bom-ref": bomRef(component),
    ...(component.namespace ? { group: component.namespace } : {}),
    name: component.name,
    ...(component.version ? { version: component.version } : {}),
    ...(component.purl ? { purl: component.purl } : {}),
    properties,
  }
}

function targetComponent(config: PipelineConfig, context: RunContext): Record<string, unknown> {
  const name =
    context.audit.apkMetadata?.packageName ??
    (path.basename(config.inputPath, path.extname(config.inputPath)) || "android-application")
  const version = context.audit.apkMetadata?.versionName
  return {
    type: "application",
    "bom-ref": `urn:droidseal:target:${digestText(`${name}|${version ?? ""}`).slice(0, 24)}`,
    name,
    ...(version ? { version } : {}),
    properties: [
      { name: "droidseal:input-kind", value: config.inputKind },
      { name: "droidseal:inventory-basis", value: "declared-and-observed-offline-evidence" },
    ],
  }
}

export async function writeSupplyChainArtifacts(
  config: PipelineConfig,
  context: RunContext,
  generatedAt = new Date().toISOString(),
): Promise<SupplyChainArtifactsResult> {
  const directory = path.join(context.reportDirectory, "supply-chain")
  const sbomPath = path.join(directory, "droidseal-sbom.cdx.json")
  const licenseReviewPath = path.join(directory, "license-review.json")
  await mkdir(directory, { recursive: true })

  const normalized = normalizeSoftwareComponents(context.audit.softwareComponents ?? [])
  const cycloneComponents = normalized.map(cycloneComponent)
  const target = targetComponent(config, context)
  const serialSeed = JSON.stringify({
    target,
    components: normalized.map((component) => componentKey(component)),
  })
  const unresolvedCount = normalized.filter((component) => component.resolution !== "declared-exact").length

  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${uuidFromDigest(serialSeed)}`,
    version: 1,
    metadata: {
      timestamp: generatedAt,
      tools: {
        components: [{
          type: "application",
          name: "DroidSeal",
          version: "0.1.0",
        }],
      },
      component: target,
      properties: [
        { name: "droidseal:component-count", value: String(normalized.length) },
        { name: "droidseal:unresolved-or-observed-count", value: String(unresolvedCount) },
        {
          name: "droidseal:precision-policy",
          value: "Versions and Maven purls are emitted only for exact literal declarations.",
        },
      ],
    },
    components: cycloneComponents,
  }

  const licenseReview = {
    schemaVersion: 1,
    product: "DroidSeal",
    generatedAt,
    policy: {
      mode: "offline-no-guess",
      statement:
        "DroidSeal does not infer licenses from package names or online lookups. NOASSERTION requires confirmation from resolved dependency locks, shipped license files, upstream notices, and legal review.",
    },
    summary: {
      componentCount: normalized.length,
      exactDeclaredCount: normalized.length - unresolvedCount,
      unresolvedOrObservedCount: unresolvedCount,
      noAssertionCount: normalized.length,
    },
    components: normalized.map((component) => ({
      bomRef: bomRef(component),
      kind: component.kind,
      ...(component.namespace ? { namespace: component.namespace } : {}),
      name: component.name,
      ...(component.version ? { version: component.version } : {}),
      resolution: component.resolution,
      scope: component.scope,
      licenseConcluded: "NOASSERTION",
      reviewStatus: "required",
      evidence: component.evidence,
      ...(component.architectures ? { architectures: component.architectures } : {}),
    })),
  }

  await Promise.all([
    writeFile(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`, "utf8"),
    writeFile(licenseReviewPath, `${JSON.stringify(licenseReview, null, 2)}\n`, "utf8"),
  ])
  return {
    directory,
    sbomPath,
    licenseReviewPath,
    componentCount: normalized.length,
    unresolvedCount,
  }
}
