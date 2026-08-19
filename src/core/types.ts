export type InputKind = "apk" | "project"
export type RunMode = "guided" | "one-click"
export type SigningMode = "existing" | "create" | "skip"
export type BuildMode = "full" | "quick"

export type StepId =
  | "doctor"
  | "prepare"
  | "source-audit"
  | "build"
  | "apk-audit"
  | "protect"
  | "harden"
  | "web-assets"
  | "arsc-obfuscate"
  | "align"
  | "keystore"
  | "sign"
  | "verify"
  | "report"

export type StepStatus = "pending" | "processing" | "success" | "failed" | "skipped"
export type SkipKind =
  | "not-applicable"
  | "user-choice"
  | "configuration"
  | "safety"
  | "missing-input"
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info"
export type FindingConfidence = "confirmed" | "high" | "medium" | "low"

export interface DistinguishedName {
  commonName: string
  organizationalUnit: string
  organization: string
  locality: string
  state: string
  country: string
}

export interface ExistingSigningConfig {
  mode: "existing"
  keystorePath: string
  keyAlias: string
  storePassword: string
  keyPassword: string
}

export interface CreateSigningConfig {
  mode: "create"
  keystorePath: string
  keyAlias: string
  storePassword: string
  keyPassword: string
  validityDays: number
  keyAlgorithm: "RSA" | "EC"
  keySize: number
  distinguishedName: DistinguishedName
  // When true, an existing keystore at keystorePath is deleted before creating
  // the new one (used by the “换新密钥 / 覆盖生成” flow for key renewal).
  overwrite?: boolean
}

export interface SkipSigningConfig {
  mode: "skip"
}

export type SigningConfig = ExistingSigningConfig | CreateSigningConfig | SkipSigningConfig

export interface LocalSafeProtectionConfig {
  mode: "local-safe"
}

export type ProtectionConfig = LocalSafeProtectionConfig

export interface PipelineConfig {
  runMode: RunMode
  inputKind: InputKind
  inputPath: string
  outputDirectory: string
  gradleTask: string
  buildMode?: BuildMode
  explicitBuiltApkPath?: string
  enableAlignment: boolean
  enableWebAssetMinification?: boolean
  enableArscObfuscation?: boolean
  signing: SigningConfig
  protection: ProtectionConfig
}

export interface ToolLocation {
  name: string
  path?: string
  source: "path" | "android-sdk" | "java-home" | "droidseal-managed" | "bundled" | "project" | "missing"
  requiredFor: StepId[]
  detail: string
}

export interface Toolchain {
  java: ToolLocation
  keytool: ToolLocation
  aapt: ToolLocation
  zipalign: ToolLocation
  apksigner: ToolLocation
  gradleWrapper: ToolLocation
  androidSdkRoot?: string
  buildToolsVersion?: string
}

export interface Finding {
  severity: FindingSeverity
  /** Confidence in the evidence, not a claim that exploitation is guaranteed. */
  confidence?: FindingConfidence
  code: string
  title: string
  detail: string
  recommendation: string
  evidence?: string
}

export interface ApkEntrySummary {
  totalEntries: number
  totalCompressedBytes: number
  totalUncompressedBytes: number
  dexFiles: string[]
  nativeLibraries: string[]
  nativeArchitectures: string[]
  legacySignatureFiles: string[]
  hasManifest: boolean
  hasResourcesTable: boolean
}

export interface ApkMetadata {
  packageName?: string
  versionName?: string
  versionCode?: string
  minSdk?: string
  targetSdk?: string
  applicationLabel?: string
  sha256?: string
}

export type SoftwareComponentKind = "maven" | "sdk-family" | "native-library"
export type SoftwareComponentResolution =
  | "declared-exact"
  | "declared-unresolved"
  | "observed"
export type SoftwareComponentScope = "runtime" | "build" | "unknown"

export interface SoftwareComponent {
  kind: SoftwareComponentKind
  name: string
  namespace?: string
  version?: string
  purl?: string
  resolution: SoftwareComponentResolution
  scope: SoftwareComponentScope
  evidence: string[]
  architectures?: string[]
}

export type SignatureExpectationStatus = "literal" | "placeholder" | "unresolved"

export interface SignatureSelfCheckEvidence {
  modulePath: string
  expectedStatus: SignatureExpectationStatus
  /** Normalized lowercase SHA-256 values; kept internal for final-certificate comparison. */
  expectedFingerprints: string[]
  checkMethodNames: string[]
  hasSigningApi: boolean
  hasSha256Digest: boolean
  startupInvoked: boolean
  forcedDisposition: boolean
  locations: {
    configuration: string[]
    signingApi: string[]
    digest: string[]
    startup: string[]
    disposition: string[]
  }
}

export interface SecurityAudit {
  findings: Finding[]
  signatureSelfChecks?: SignatureSelfCheckEvidence[]
  softwareComponents?: SoftwareComponent[]
  apkEntries?: ApkEntrySummary
  apkMetadata?: ApkMetadata
  rawToolOutput?: string
}

export interface CommandResult {
  command: string
  args: string[]
  cwd: string
  exitCode: number
  stdout: string
  stderr: string
  durationMs: number
  timedOut: boolean
}

export interface StepResult {
  id: StepId
  status: Exclude<StepStatus, "pending" | "processing">
  title: string
  summary: string
  skipKind?: SkipKind
  detail: string[]
  startedAt: string
  finishedAt: string
  durationMs: number
  artifactBefore?: string
  artifactAfter?: string
  rollbackMessage?: string
  command?: CommandResult
  findings?: Finding[]
}

export interface StepState {
  id: StepId
  title: string
  description: string
  skippable: boolean
  status: StepStatus
  result?: StepResult
}

export interface RunContext {
  runId: string
  runDirectory: string
  artifactDirectory: string
  reportDirectory: string
  currentArtifact: string | undefined
  originalArtifact: string | undefined
  finalArtifact: string | undefined
  toolchain: Toolchain | undefined
  audit: SecurityAudit
  stepResults: StepResult[]
  signatureVerified?: boolean
}

export type PipelineEvent =
  | { type: "step-started"; step: StepState }
  | { type: "step-progress"; stepId: StepId; message: string }
  | { type: "step-finished"; step: StepState; result: StepResult }

export interface ProcessOptions {
  command: string
  args: string[]
  cwd: string
  env?: Record<string, string>
  redact?: string[]
  timeoutMs?: number
  onLine?: (line: string, stream: "stdout" | "stderr") => void
  stdinInput?: string
  // Marks the command as the Gradle daemon launcher. Gradle forks a long-lived
  // JVM that compiles/lints the whole app and needs far more Metaspace than the
  // conservative default for light JVM tools (apksigner/keytool). When true,
  // process.ts applies the larger GRADLE_* JVM options instead — see process.ts.
  gradle?: boolean
}
