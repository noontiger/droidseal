import { createSignal } from "solid-js"
import { theme } from "./theme.ts"

export function Button(props: {
  label: string
  detail?: string
  shortcut?: string
  tone?: "accent" | "neutral" | "danger" | "input"
  disabled?: boolean
  onPress: () => void
}) {
  const [hovered, setHovered] = createSignal(false)
  const tone = () => props.tone ?? "neutral"
  const background = () => {
    if (props.disabled) return theme.panel
    if (hovered()) {
      if (tone() === "danger") return "#4a2630"
      if (tone() === "input") return "#16465e"
      return "#173b52"
    }
    if (tone() === "accent") return "#103a53"
    if (tone() === "input") return theme.panelInput
    if (tone() === "danger") return "#351d24"
    return theme.panelRaised
  }
  const border = () => {
    if (props.disabled) return theme.border
    if (tone() === "danger") return theme.error
    if (tone() === "input") return theme.input
    if (tone() === "accent") return theme.accent
    return hovered() ? theme.borderActive : theme.border
  }

  const shortcutColor = () => {
    if (props.disabled) return theme.textMuted
    if (tone() === "danger") return theme.error
    if (tone() === "input") return theme.input
    return theme.accentStrong
  }

  return (
    <box
      flexDirection="column"
      border
      borderColor={border()}
      backgroundColor={background()}
      paddingLeft={1}
      paddingRight={1}
      paddingTop={props.detail ? 1 : 0}
      paddingBottom={props.detail ? 1 : 0}
      minWidth={props.detail ? 24 : 12}
      onMouseOver={() => setHovered(true)}
      onMouseOut={() => setHovered(false)}
      onMouseUp={() => {
        if (!props.disabled) props.onPress()
      }}
    >
      <text fg={props.disabled ? theme.textMuted : theme.text} selectable={false}>
        {props.shortcut ? <span style={{ fg: shortcutColor() }}>[{props.shortcut}] </span> : null}
        <b>{props.label}</b>
      </text>
      {props.detail ? (
        <text fg={theme.textMuted} wrapMode="word" selectable={false}>
          {props.detail}
        </text>
      ) : null}
    </box>
  )
}
