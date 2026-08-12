export const INTERACTION_ZOOM_LEVELS = [80, 90, 100, 110, 125, 150] as const
export type InteractionZoom = (typeof INTERACTION_ZOOM_LEVELS)[number]

export interface InteractionZoomMetrics {
  panePadding: number
  messageIndent: number
  messageGap: number
  actionGap: number
}

export function changeInteractionZoom(
  current: InteractionZoom,
  direction: "in" | "out" | "reset",
): InteractionZoom {
  if (direction === "reset") return 100
  const index = INTERACTION_ZOOM_LEVELS.indexOf(current)
  const delta = direction === "in" ? 1 : -1
  const next = Math.max(0, Math.min(INTERACTION_ZOOM_LEVELS.length - 1, index + delta))
  return INTERACTION_ZOOM_LEVELS[next]!
}

export function interactionZoomMetrics(zoom: InteractionZoom): InteractionZoomMetrics {
  if (zoom <= 80) return { panePadding: 1, messageIndent: 1, messageGap: 0, actionGap: 0 }
  if (zoom <= 90) return { panePadding: 1, messageIndent: 1, messageGap: 1, actionGap: 1 }
  if (zoom <= 100) return { panePadding: 2, messageIndent: 2, messageGap: 1, actionGap: 1 }
  if (zoom <= 110) return { panePadding: 2, messageIndent: 3, messageGap: 1, actionGap: 1 }
  if (zoom <= 125) return { panePadding: 3, messageIndent: 3, messageGap: 2, actionGap: 1 }
  return { panePadding: 4, messageIndent: 4, messageGap: 2, actionGap: 2 }
}

export function zoomDirectionFromKey(name: string, sequence: string): "in" | "out" | "reset" | undefined {
  const normalized = name.toLowerCase()
  if (["+", "=", "plus", "add"].includes(normalized) || sequence === "+") return "in"
  if (["-", "_", "minus", "subtract"].includes(normalized) || sequence === "-") return "out"
  if (["0", "zero"].includes(normalized) || sequence === "0") return "reset"
  return undefined
}
