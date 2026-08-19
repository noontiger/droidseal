import type { SoftwareComponent, SoftwareComponentScope } from "./types.ts"

export interface GradleComponentSource {
  relativePath: string
  source: string
}

interface MavenCoordinate {
  namespace: string
  name: string
  declaredVersion?: string
}

function exactVersion(declared: string | undefined): string | undefined {
  if (!declared) return undefined
  const value = declared.trim().split("@", 1)[0]!.split(":", 1)[0]!
  if (
    value.length === 0 ||
    /[+$}{\[\]()\s]/.test(value) ||
    /^(?:latest|release|integration)(?:[.-]|$)/i.test(value) ||
    !/^[0-9A-Za-z][0-9A-Za-z._-]*$/.test(value)
  ) {
    return undefined
  }
  return value
}

function purl(namespace: string, name: string, version: string): string {
  return `pkg:maven/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
}

function scopeFromPrefix(prefix: string): SoftwareComponentScope {
  if (/\b(?:classpath|kapt|ksp|annotationProcessor|lintChecks?)\b/i.test(prefix)) return "build"
  if (/\bcompileOnly\b/i.test(prefix)) return "build"
  if (/\b(?:implementation|api|runtimeOnly|compile|provided)\b/i.test(prefix)) return "runtime"
  return "unknown"
}

function parseCoordinate(value: string): MavenCoordinate | undefined {
  const match = /^([a-zA-Z][\w.-]*(?:\.[\w.-]+)+):([\w.-]+)(?::(.+))?$/.exec(value.trim())
  if (!match) return undefined
  return {
    namespace: match[1]!,
    name: match[2]!,
    ...(match[3] ? { declaredVersion: match[3] } : {}),
  }
}

function componentFromCoordinate(
  coordinate: MavenCoordinate,
  scope: SoftwareComponentScope,
  evidence: string,
): SoftwareComponent {
  const version = exactVersion(coordinate.declaredVersion)
  return {
    kind: "maven",
    namespace: coordinate.namespace,
    name: coordinate.name,
    resolution: version ? "declared-exact" : "declared-unresolved",
    scope,
    evidence: [evidence],
    ...(version ? { version, purl: purl(coordinate.namespace, coordinate.name, version) } : {}),
  }
}

function stripTomlComment(line: string): string {
  let quote: "'" | '"' | undefined
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]
    if ((character === "'" || character === '"') && line[index - 1] !== "\\") {
      quote = quote === character ? undefined : quote ?? character
    } else if (character === "#" && quote === undefined) {
      return line.slice(0, index)
    }
  }
  return line
}

function parseVersionCatalog(source: GradleComponentSource): SoftwareComponent[] {
  const components: SoftwareComponent[] = []
  const lines = source.source.split(/\r?\n/)
  let section = ""

  for (let index = 0; index < lines.length; index += 1) {
    const line = stripTomlComment(lines[index] ?? "").trim()
    const sectionMatch = /^\[([^\]]+)]$/.exec(line)
    if (sectionMatch) {
      section = sectionMatch[1]!.trim().toLowerCase()
      continue
    }
    if (section !== "libraries" || line.length === 0) continue

    const assignment = /^([\w.-]+)\s*=\s*(.+)$/.exec(line)
    if (!assignment) continue
    const alias = assignment[1]!
    const value = assignment[2]!
    const evidence = `${source.relativePath}:${index + 1} (${alias})`

    const shorthand = /^["']([^"']+)["']$/.exec(value)?.[1]
    if (shorthand) {
      const coordinate = parseCoordinate(shorthand)
      if (coordinate) components.push(componentFromCoordinate(coordinate, "runtime", evidence))
      continue
    }

    const moduleValue = /\bmodule\s*=\s*["']([^"']+)["']/.exec(value)?.[1]
    const group = /\bgroup\s*=\s*["']([^"']+)["']/.exec(value)?.[1]
    const name = /\bname\s*=\s*["']([^"']+)["']/.exec(value)?.[1]
    const moduleCoordinate = moduleValue ? parseCoordinate(moduleValue) : undefined
    const namespace = moduleCoordinate?.namespace ?? group
    const componentName = moduleCoordinate?.name ?? name
    if (!namespace || !componentName || !namespace.includes(".")) continue

    const hasVersionRef = /\bversion\.ref\s*=/.test(value)
    const declaredVersion = hasVersionRef
      ? undefined
      : /\bversion\s*=\s*["']([^"']+)["']/.exec(value)?.[1]
    components.push(componentFromCoordinate(
      { namespace, name: componentName, ...(declaredVersion ? { declaredVersion } : {}) },
      "runtime",
      evidence,
    ))
  }

  return components
}

function parseGradleScript(source: GradleComponentSource): SoftwareComponent[] {
  const components: SoftwareComponent[] = []
  const lines = source.source.split(/\r?\n/)
  const quotedCoordinate = /(["'])([a-zA-Z][\w.-]*(?:\.[\w.-]+)+:[\w.-]+(?::[^"'\r\n]+)?)\1/g

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? ""
    let match: RegExpExecArray | null
    quotedCoordinate.lastIndex = 0
    while ((match = quotedCoordinate.exec(line)) !== null) {
      const coordinate = parseCoordinate(match[2]!)
      if (!coordinate) continue
      components.push(componentFromCoordinate(
        coordinate,
        scopeFromPrefix(line.slice(0, match.index)),
        `${source.relativePath}:${index + 1}`,
      ))
    }

    const group = /\bgroup\s*=\s*["']([^"']+)["']/.exec(line)?.[1]
    const name = /\bname\s*=\s*["']([^"']+)["']/.exec(line)?.[1]
    if (group?.includes(".") && name) {
      const declaredVersion = /\bversion\s*=\s*["']([^"']+)["']/.exec(line)?.[1]
      components.push(componentFromCoordinate(
        { namespace: group, name, ...(declaredVersion ? { declaredVersion } : {}) },
        scopeFromPrefix(line),
        `${source.relativePath}:${index + 1}`,
      ))
    }
  }
  return components
}

function mergeComponents(components: Iterable<SoftwareComponent>): SoftwareComponent[] {
  const merged = new Map<string, SoftwareComponent>()
  for (const component of components) {
    const key = [
      component.kind,
      component.namespace ?? "",
      component.name,
      component.version ?? "",
      component.resolution,
      component.scope,
    ].join("|")
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
  return [...merged.values()].sort((left, right) =>
    [
      left.kind,
      left.namespace ?? "",
      left.name,
      left.version ?? "",
      left.resolution,
      left.scope,
    ].join("|").localeCompare([
      right.kind,
      right.namespace ?? "",
      right.name,
      right.version ?? "",
      right.resolution,
      right.scope,
    ].join("|")),
  )
}

export function collectGradleSoftwareComponents(
  sources: Iterable<GradleComponentSource>,
): SoftwareComponent[] {
  const components: SoftwareComponent[] = []
  const ordered = [...sources].sort((left, right) => left.relativePath.localeCompare(right.relativePath))
  for (const source of ordered) {
    if (/libs\.versions\.toml$/i.test(source.relativePath)) {
      components.push(...parseVersionCatalog(source))
    } else if (/build\.gradle(?:\.kts)?$/i.test(source.relativePath)) {
      components.push(...parseGradleScript(source))
    }
  }
  return mergeComponents(components)
}
