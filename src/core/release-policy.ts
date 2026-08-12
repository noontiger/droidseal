import type {
  Finding,
  FindingConfidence,
  FindingSeverity,
  PipelineConfig,
  RunContext,
  StepId,
} from "./types.ts"

export const RELEASE_POLICY_VERSION = "droidseal-release-policy/1" as const

export type ReleaseDecisionStatus = "pass" | "review" | "block"
export type ReleaseReasonLevel = "block" | "review" | "advisory"

export interface ReleaseDecisionReason {
  code: string
  level: ReleaseReasonLevel
  message: string
  stepId?: StepId
  findingCode?: string
  severity?: FindingSeverity
  confidence?: FindingConfidence
}

export interface ReleaseDecision {
  ruleVersion: typeof RELEASE_POLICY_VERSION
  status: ReleaseDecisionStatus
  reasonCodes: string[]
  blockingReasons: ReleaseDecisionReason[]
  reviewReasons: ReleaseDecisionReason[]
  advisoryReasons: ReleaseDecisionReason[]
}

export type ControlCoverageStatus =
  | "verified"
  | "observed"
  | "not-verified"
  | "external-required"
  | "not-applicable"

export interface ControlCoverageItem {
  id: string
  title: string
  owner: "droidseal" | "app-team" | "server-team"
  status: ControlCoverageStatus
  requiresExternalValidation: boolean
  evidenceCodes: string[]
  detail: string
}

export interface ControlCoverage {
  ruleVersion: typeof RELEASE_POLICY_VERSION
  controls: ControlCoverageItem[]
  counts: Record<ControlCoverageStatus, number>
}

const CONFIDENCE_RANK: Record<FindingConfidence, number> = {
  confirmed: 0,
  high: 1,
  medium: 2,
  low: 3,
}

export function effectiveFindingConfidence(finding: Finding): FindingConfidence {
  if (finding.confidence) return finding.confidence
  return /启发式|可能误报/.test(finding.detail) ? "medium" : "confirmed"
}

function strongestConfidence(findings: readonly Finding[]): FindingConfidence | undefined {
  return findings
    .map(effectiveFindingConfidence)
    .sort((a, b) => CONFIDENCE_RANK[a] - CONFIDENCE_RANK[b])[0]
}

function reasonForFinding(finding: Finding): ReleaseDecisionReason {
  const confidence = effectiveFindingConfidence(finding)
  if (finding.severity === "critical" && (confidence === "confirmed" || confidence === "high")) {
    return {
      code: "CRITICAL_FINDING_CONFIRMED",
      level: "block",
      message: `关键风险 ${finding.code} 具有${confidence === "confirmed" ? "已确认" : "高"}置信度。`,
      findingCode: finding.code,
      severity: finding.severity,
      confidence,
    }
  }
  if (finding.severity === "critical") {
    return {
      code: "CRITICAL_FINDING_REQUIRES_REVIEW",
      level: "review",
      message: `关键风险 ${finding.code} 的证据置信度为 ${confidence}，需人工核验后发布。`,
      findingCode: finding.code,
      severity: finding.severity,
      confidence,
    }
  }
  if (finding.severity === "high" && (confidence === "confirmed" || confidence === "high")) {
    return {
      code: "HIGH_FINDING_REQUIRES_REVIEW",
      level: "review",
      message: `高风险 ${finding.code} 具有${confidence === "confirmed" ? "已确认" : "高"}置信度。`,
      findingCode: finding.code,
      severity: finding.severity,
      confidence,
    }
  }
  return {
    code: finding.code.endsWith("_NOT_OBSERVED")
      ? "EXTERNAL_CONTROL_NOT_OBSERVED"
      : "FINDING_ADVISORY",
    level: "advisory",
    message: `${finding.code} 不触发自动阻断，保留为复核提示。`,
    findingCode: finding.code,
    severity: finding.severity,
    confidence,
  }
}

function compareReasons(a: ReleaseDecisionReason, b: ReleaseDecisionReason): number {
  return a.code.localeCompare(b.code) ||
    (a.stepId ?? "").localeCompare(b.stepId ?? "") ||
    (a.findingCode ?? "").localeCompare(b.findingCode ?? "")
}

export function evaluateReleaseDecision(context: RunContext): ReleaseDecision {
  const reasons: ReleaseDecisionReason[] = []
  for (const step of context.stepResults) {
    if (step.status !== "failed") continue
    reasons.push({
      code: "PIPELINE_STEP_FAILED",
      level: "block",
      message: `步骤 ${step.id} 执行失败：${step.summary}`,
      stepId: step.id,
    })
  }

  if (!context.finalArtifact) {
    reasons.push({
      code: "FINAL_ARTIFACT_MISSING",
      level: "block",
      message: "没有可供发布的最终 APK 产物。",
    })
  } else if (context.signatureVerified === false) {
    reasons.push({
      code: "RELEASE_SIGNATURE_INVALID_OR_MISSING",
      level: "block",
      message: "最终 APK 已确认未签名或签名无效。",
    })
  } else if (context.signatureVerified !== true) {
    reasons.push({
      code: "RELEASE_SIGNATURE_NOT_VERIFIED",
      level: "review",
      message: "最终 APK 的发布签名尚未被 apksigner 验证，不能自动判定为无效。",
    })
  }

  for (const finding of context.audit.findings) reasons.push(reasonForFinding(finding))

  const blockingReasons = reasons.filter((reason) => reason.level === "block").sort(compareReasons)
  const reviewReasons = reasons.filter((reason) => reason.level === "review").sort(compareReasons)
  const advisoryReasons = reasons.filter((reason) => reason.level === "advisory").sort(compareReasons)
  const status: ReleaseDecisionStatus = blockingReasons.length > 0
    ? "block"
    : reviewReasons.length > 0
      ? "review"
      : "pass"
  return {
    ruleVersion: RELEASE_POLICY_VERSION,
    status,
    reasonCodes: [...new Set(reasons.map((reason) => reason.code))].sort(),
    blockingReasons,
    reviewReasons,
    advisoryReasons,
  }
}

function actualEvidence(findings: readonly Finding[], pattern: RegExp): Finding[] {
  return findings.filter((finding) => pattern.test(finding.evidence ?? ""))
}

function externalControl(
  id: string,
  title: string,
  owner: "app-team" | "server-team",
  findings: readonly Finding[],
  evidencePattern?: RegExp,
): ControlCoverageItem {
  const evidence = evidencePattern ? actualEvidence(findings, evidencePattern) : []
  const confidence = strongestConfidence(evidence)
  return {
    id,
    title,
    owner,
    status: evidence.length > 0 ? "observed" : "external-required",
    requiresExternalValidation: true,
    evidenceCodes: [...new Set(evidence.map((finding) => finding.code))].sort(),
    detail: evidence.length > 0
      ? `制品中观察到${confidence ?? "未知"}置信度静态信号；这不能证明服务端闭环或真机策略已完成。`
      : "DroidSeal 无法从通用 APK/源码静态证据验证该控制，需业务侧提供可复核证据。",
  }
}

export function buildControlCoverage(config: PipelineConfig, context: RunContext): ControlCoverage {
  const findings = context.audit.findings
  const verifySucceeded = context.stepResults.some((step) => step.id === "verify" && step.status === "success")
  const sourceAuditSucceeded = context.stepResults.some((step) => step.id === "source-audit" && step.status === "success")
  const buildSucceeded = context.stepResults.some((step) => step.id === "build" && step.status === "success")
  const r8Gap = findings.some((finding) =>
    finding.code === "R8_MINIFICATION_NOT_CONFIRMED" ||
    finding.code === "R8_OBFUSCATION_DISABLED" ||
    finding.code === "R8_SHRINKING_DISABLED" ||
    finding.code === "R8_OPTIMIZATION_DISABLED",
  )
  const signatureSelfCheckCodes = findings
    .filter((finding) => finding.code.startsWith("SIGNATURE_SELF_CHECK_"))
    .map((finding) => finding.code)
    .sort()
  const signatureSelfCheckMismatch = signatureSelfCheckCodes.includes("SIGNATURE_SELF_CHECK_CERT_MISMATCH")
  const signatureSelfCheckMatched = signatureSelfCheckCodes.includes("SIGNATURE_SELF_CHECK_CERT_MATCH")
  const signatureSelfCheckObserved = signatureSelfCheckCodes.includes("SIGNATURE_SELF_CHECK_OBSERVED")
  const controls: ControlCoverageItem[] = [
    {
      id: "droidseal-final-apk-verification",
      title: "最终 APK 结构、签名与哈希验证",
      owner: "droidseal",
      status: verifySucceeded && context.signatureVerified === true ? "verified" : "not-verified",
      requiresExternalValidation: false,
      evidenceCodes: [],
      detail: verifySucceeded && context.signatureVerified === true
        ? "DroidSeal 验证步骤成功且 apksigner 已确认最终签名。"
        : "最终验证或发布签名尚未形成可验证闭环。",
    },
    {
      id: "droidseal-release-r8",
      title: "Release R8/收缩/优化配置",
      owner: "droidseal",
      status: config.inputKind === "apk"
        ? "not-applicable"
        : sourceAuditSucceeded && buildSucceeded && !r8Gap
          ? "verified"
          : "not-verified",
      requiresExternalValidation: false,
      evidenceCodes: findings.filter((finding) => finding.code.startsWith("R8_")).map((finding) => finding.code).sort(),
      detail: config.inputKind === "apk"
        ? "APK 输入无法反向证明源码构建期 R8 配置。"
        : sourceAuditSucceeded && buildSucceeded && !r8Gap
          ? "源码审计与 release 构建均成功，且未发现 R8 禁用或未确认缺口。"
          : "源码审计、构建或 R8 规则证据未达到可验证状态。",
    },
    {
      id: "app-signature-self-check",
      title: "App 启动期自签名校验与最终证书一致性",
      owner: "app-team",
      status: config.inputKind === "apk"
        ? "not-applicable"
        : signatureSelfCheckMismatch
          ? "not-verified"
          : signatureSelfCheckMatched || signatureSelfCheckObserved
            ? "observed"
            : "external-required",
      requiresExternalValidation: true,
      evidenceCodes: signatureSelfCheckCodes,
      detail: config.inputKind === "apk"
        ? "APK 输入无法精确恢复源码启动调用、期望值来源与处置路径。"
        : signatureSelfCheckMismatch
          ? "最终发布证书与源码允许列表已确认不一致，必须停止发布并修正。"
          : signatureSelfCheckMatched
            ? "源码允许列表与本次最终证书匹配；这只证明配置一致，客户端逻辑仍可被补丁或 Hook 绕过。"
            : signatureSelfCheckObserved
              ? "已观察到源码自签名校验闭环，但尚未形成最终证书交叉匹配证据。"
              : "未形成可验证的源码自签名校验证据；是否要求该控制由应用团队按威胁模型决定。",
    },
    externalControl("play-integrity", "Play Integrity 服务端校验", "server-team", findings, /PlayIntegrity|IntegrityManager|integrityToken/i),
    externalControl("key-attestation", "Android Key Attestation 校验", "server-team", findings, /KeyAttestation|attestKey|KeyDescription/i),
    externalControl("challenge-replay", "Challenge/nonce 与防重放", "server-team", findings, /\b(?:nonce|challenge|replay)\b/i),
    externalControl("server-risk-decision", "服务端授权与风险决策", "server-team", findings, /server[-_ ]?risk|riskDecision|serverAuthorization/i),
    externalControl("native-jni-omvll", "JNI/O-MVLL 原生保护", "app-team", findings, /O-MVLL|OMVLL/i),
    externalControl("device-compatibility-matrix", "真机兼容性与回归矩阵", "app-team", findings),
  ]
  const counts: Record<ControlCoverageStatus, number> = {
    verified: 0,
    observed: 0,
    "not-verified": 0,
    "external-required": 0,
    "not-applicable": 0,
  }
  for (const control of controls) counts[control.status] += 1
  return { ruleVersion: RELEASE_POLICY_VERSION, controls, counts }
}
