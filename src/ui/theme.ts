import type { FindingSeverity, StepStatus } from "../core/types.ts"

export const theme = {
  background: "#061521",
  panel: "#0a2132",
  panelRaised: "#102d42",
  panelInput: "#0d2a3d",
  panelPassive: "#081c2a",
  border: "#1d4258",
  borderActive: "#39789a",
  text: "#e6f4fa",
  textMuted: "#87a9ba",
  accent: "#34799c",
  accentStrong: "#79c9e7",
  input: "#66c8e8",
  complete: "#ffdf4d",
  purple: "#c6a0f6",
  success: "#63d6aa",
  warning: "#f0bd68",
  error: "#ed8796",
  info: "#8aadf4",
} as const

export function stepColor(status: StepStatus): string {
  const colors: Record<StepStatus, string> = {
    pending: theme.textMuted,
    processing: theme.accent,
    success: theme.complete,
    failed: theme.error,
    skipped: theme.warning,
  }
  return colors[status]
}

export function severityColor(severity: FindingSeverity): string {
  const colors: Record<FindingSeverity, string> = {
    critical: theme.error,
    high: "#f5a97f",
    medium: theme.warning,
    low: theme.info,
    info: theme.textMuted,
  }
  return colors[severity]
}
