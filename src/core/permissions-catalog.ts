// Static catalog of Android permissions that matter for security review. Pure data +
// small pure classifiers; consumed by both the APK-side (aapt xmltree) and source-side
// (AndroidManifest.xml) permission audits so the two paths stay in sync.

import type { Finding } from "./types.ts"

export type DangerousGroup =
  | "LOCATION"
  | "CAMERA"
  | "MICROPHONE"
  | "CONTACTS"
  | "SMS"
  | "PHONE"
  | "STORAGE"
  | "CALENDAR"
  | "SENSORS"
  | "ACTIVITY_RECOGNITION"

// Runtime "dangerous" permissions grouped by the permission group the user is prompted for.
export const DANGEROUS_PERMISSIONS: Readonly<Record<DangerousGroup, readonly string[]>> = {
  LOCATION: [
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
  ],
  CAMERA: ["android.permission.CAMERA"],
  MICROPHONE: ["android.permission.RECORD_AUDIO"],
  CONTACTS: [
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
  ],
  SMS: [
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
  ],
  PHONE: [
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
  ],
  STORAGE: [
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
  ],
  CALENDAR: ["android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR"],
  SENSORS: ["android.permission.BODY_SENSORS", "android.permission.BODY_SENSORS_BACKGROUND"],
  ACTIVITY_RECOGNITION: ["android.permission.ACTIVITY_RECOGNITION"],
}

export interface HighRiskPermission {
  permission: string
  severity: "high" | "medium"
  reason: string
}

// Special / high-risk permissions that materially widen the attack surface or trigger
// Play policy review. Not part of the standard runtime groups above.
export const HIGH_RISK_PERMISSIONS: readonly HighRiskPermission[] = [
  { permission: "android.permission.SYSTEM_ALERT_WINDOW", severity: "high", reason: "可在其他应用之上绘制悬浮窗，是覆盖攻击（tapjacking/overlay）与钓鱼的常见前提。" },
  { permission: "android.permission.REQUEST_INSTALL_PACKAGES", severity: "high", reason: "允许应用请求安装其他 APK，是侧载与恶意投放链路的关键能力。" },
  { permission: "android.permission.BIND_ACCESSIBILITY_SERVICE", severity: "high", reason: "无障碍服务可读取屏幕内容并模拟点击，被滥用可完全操控设备。" },
  { permission: "android.permission.MANAGE_EXTERNAL_STORAGE", severity: "high", reason: "授予对全部外部存储的广泛访问，绕过分区存储隔离。" },
  { permission: "android.permission.WRITE_SETTINGS", severity: "medium", reason: "可修改系统设置，影响设备行为。" },
  { permission: "android.permission.QUERY_ALL_PACKAGES", severity: "medium", reason: "枚举设备上所有已安装应用，属 Play 政策敏感权限，需正当理由。" },
  { permission: "android.permission.SCHEDULE_EXACT_ALARM", severity: "medium", reason: "精确闹钟会增加后台唤醒与耗电，Play 对其用途有限制。" },
  { permission: "android.permission.USE_EXACT_ALARM", severity: "medium", reason: "精确闹钟能力，Play 对其用途有限制。" },
  { permission: "android.permission.RECEIVE_BOOT_COMPLETED", severity: "medium", reason: "开机自启常被用于常驻后台，需确认必要性。" },
  { permission: "android.permission.PACKAGE_USAGE_STATS", severity: "medium", reason: "读取应用使用统计，属敏感的用户行为数据。" },
]

const DANGEROUS_LOOKUP: ReadonlyMap<string, DangerousGroup> = (() => {
  const map = new Map<string, DangerousGroup>()
  for (const [group, perms] of Object.entries(DANGEROUS_PERMISSIONS) as [DangerousGroup, readonly string[]][]) {
    for (const perm of perms) map.set(perm, group)
  }
  return map
})()

const HIGH_RISK_LOOKUP: ReadonlyMap<string, HighRiskPermission> =
  new Map(HIGH_RISK_PERMISSIONS.map((entry) => [entry.permission, entry]))

export function dangerousGroupOf(permission: string): DangerousGroup | undefined {
  return DANGEROUS_LOOKUP.get(permission)
}

export function highRiskInfoOf(permission: string): HighRiskPermission | undefined {
  return HIGH_RISK_LOOKUP.get(permission)
}

export interface PermissionClassification {
  all: string[]
  dangerousByGroup: Partial<Record<DangerousGroup, string[]>>
  highRisk: HighRiskPermission[]
}

// Classify a de-duplicated list of requested permission names.
export function classifyPermissions(permissions: Iterable<string>): PermissionClassification {
  const all = [...new Set([...permissions].filter((p) => typeof p === "string" && p.length > 0))].sort()
  const dangerousByGroup: Partial<Record<DangerousGroup, string[]>> = {}
  const highRisk: HighRiskPermission[] = []
  for (const permission of all) {
    const group = dangerousGroupOf(permission)
    if (group) (dangerousByGroup[group] ??= []).push(permission)
    const risk = highRiskInfoOf(permission)
    if (risk) highRisk.push(risk)
  }
  return { all, dangerousByGroup, highRisk }
}

// A custom (app-declared) <permission> whose protectionLevel is weaker than "signature".
export interface CustomPermission {
  name: string
  protectionLevel: string
}

// protectionLevel values that leave a custom permission grantable to arbitrary apps.
function isWeakProtectionLevel(level: string): boolean {
  const base = level.split("|").map((part) => part.trim().toLowerCase())[0] ?? ""
  return base === "normal" || base === "dangerous" || base === ""
}

// Build permission findings shared by the APK and source audits. `codePrefix` is
// "MANIFEST" for the APK side and "SOURCE" for the project side.
export function buildPermissionFindings(
  permissions: Iterable<string>,
  customPermissions: Iterable<CustomPermission>,
  codePrefix: "MANIFEST" | "SOURCE",
): Finding[] {
  const findings: Finding[] = []
  const { all, dangerousByGroup, highRisk } = classifyPermissions(permissions)

  const dangerousGroups = Object.keys(dangerousByGroup) as DangerousGroup[]
  if (dangerousGroups.length > 0) {
    const dangerousList = dangerousGroups
      .map((group) => `${group}(${dangerousByGroup[group]!.length})`)
      .join("、")
    findings.push({
      severity: "info",
      code: `${codePrefix}_DANGEROUS_PERMISSIONS`,
      title: "应用申请了运行时危险权限",
      detail: `按权限组统计：${dangerousList}。危险权限本身不是漏洞，但每一项都扩大隐私暴露面，需与实际功能对应。`,
      recommendation: "核对每项危险权限是否为核心功能所必需，去除冗余权限并遵循最小权限原则。",
      evidence: dangerousGroups.flatMap((group) => dangerousByGroup[group]!).join(", ").slice(0, 300),
    })
  }

  for (const risk of highRisk) {
    findings.push({
      severity: risk.severity,
      code: `${codePrefix}_HIGH_RISK_PERMISSION`,
      title: `申请高风险权限：${risk.permission.split(".").pop()}`,
      detail: `${risk.permission}：${risk.reason}`,
      recommendation: "确认该权限确为必需；若非核心功能请移除，必需时在隐私政策与商店说明中充分披露用途。",
      evidence: risk.permission,
    })
  }

  if (all.includes("android.permission.QUERY_ALL_PACKAGES")) {
    findings.push({
      severity: "medium",
      code: `${codePrefix}_QUERY_ALL_PACKAGES`,
      title: "申请 QUERY_ALL_PACKAGES（可枚举全部已安装应用）",
      detail: "QUERY_ALL_PACKAGES 属 Google Play 政策敏感权限，多数场景应改用 <queries> 定向声明。",
      recommendation: "优先用 <queries> 元素声明具体需要交互的包名/意图；确需全量查询时准备 Play 政策豁免说明。",
      evidence: "android.permission.QUERY_ALL_PACKAGES",
    })
  }

  const weakCustom = [...customPermissions].filter((entry) => isWeakProtectionLevel(entry.protectionLevel))
  if (weakCustom.length > 0) {
    findings.push({
      severity: "medium",
      code: `${codePrefix}_CUSTOM_PERMISSION_WEAK_PROTECTION`,
      title: "自定义权限的 protectionLevel 过弱",
      detail:
        "以下应用自定义权限的 protectionLevel 为 normal/dangerous（或缺省），任意第三方应用均可申请获得，" +
        `无法真正限制受该权限保护的组件：${weakCustom.map((entry) => `${entry.name}(${entry.protectionLevel || "缺省"})`).join("、")}。`,
      recommendation: "将用于保护内部组件的自定义权限 protectionLevel 提升为 signature，使其仅授予同签名应用。",
      evidence: weakCustom.map((entry) => entry.name).join(", ").slice(0, 300),
    })
  }

  return findings
}
