export type ThemeMode = 'light' | 'dark'
export type HsvColor = { hue: number; saturation: number; value: number }

export const DEFAULT_COLOR = '#798777'
export const COLOR_STORAGE_KEY = 'fwmigrate-color'

export function normalizeHex(value: unknown): string | null {
  if (typeof value !== 'string') return null
  const hex = value.trim().replace(/^#?/, '#')
  return /^#[\da-f]{6}$/i.test(hex) ? hex.toLowerCase() : null
}

function rgb(hex: string): number[] {
  return [1, 3, 5].map((offset) => parseInt(hex.slice(offset, offset + 2), 16))
}

function toHex(channels: number[]): string {
  return `#${channels.map((channel) => Math.round(channel).toString(16).padStart(2, '0')).join('')}`
}

function mix(color: string, target: string, amount: number): string {
  const destination = rgb(target)
  return toHex(rgb(color).map((channel, index) => channel * (1 - amount) + destination[index] * amount))
}

export function hexToHsv(hex: string): HsvColor {
  const [r, g, b] = rgb(hex).map((channel) => channel / 255)
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  const delta = max - min
  const sector = delta === 0 ? 0 : max === r ? (g - b) / delta : max === g ? (b - r) / delta + 2 : (r - g) / delta + 4
  return { hue: (sector * 60 + 360) % 360, saturation: max === 0 ? 0 : delta / max, value: max }
}

export function hsvToHex({ hue, saturation, value }: HsvColor): string {
  const sector = ((hue % 360 + 360) % 360) / 60
  const chroma = value * saturation
  const x = chroma * (1 - Math.abs(sector % 2 - 1))
  const channels = sector < 1 ? [chroma, x, 0] : sector < 2 ? [x, chroma, 0] : sector < 3 ? [0, chroma, x]
    : sector < 4 ? [0, x, chroma] : sector < 5 ? [x, 0, chroma] : [chroma, 0, x]
  return toHex(channels.map((channel) => (channel + value - chroma) * 255))
}

export function contrastRatio(foreground: string, background: string): number {
  const luminance = (hex: string) => {
    const channels = rgb(hex).map((channel) => {
      const value = channel / 255
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
    })
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722
  }
  const a = luminance(foreground)
  const b = luminance(background)
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

function readable(color: string, backgrounds: string[], mode: ThemeMode, minimum = 4.5): string {
  const target = mode === 'light' ? '#000000' : '#ffffff'
  for (let step = 0; step <= 100; step++) {
    const candidate = mix(color, target, step / 100)
    if (backgrounds.every((background) => contrastRatio(candidate, background) >= minimum)) return candidate
  }
  return target
}

/** Only presentation tokens change; validation and deployment status colors keep their meaning. */
export function buildColorTheme(color: string, mode: ThemeMode): Record<string, string> {
  const seed = normalizeHex(color)
  if (!seed) throw new Error('Expected a six-digit hex color')
  const light = mode === 'light'
  const canvas = mix(seed, light ? '#f8f4ef' : '#1b201d', light ? 0.96 : 0.94)
  const surface = mix(seed, light ? '#fffdf9' : '#272f29', light ? 0.985 : 0.93)
  const input = mix(seed, light ? '#fffcf8' : '#202822', light ? 0.985 : 0.94)
  const muted = mix(seed, surface, light ? 0.90 : 0.88)
  const hover = mix(seed, surface, light ? 0.82 : 0.80)
  const subtle = mix(seed, surface, light ? 0.78 : 0.75)
  const backgrounds = [canvas, surface, input, muted, hover, subtle]
  const onPrimary = light ? '#ffffff' : '#111511'
  const primary = readable(seed, [...backgrounds, onPrimary], mode)
  return {
    '--canvas': canvas,
    '--surface': surface,
    '--surface-muted': muted,
    '--surface-hover': hover,
    '--bg-input': input,
    '--text-heading': readable(mix(seed, light ? '#263028' : '#f5f4ed', 0.90), backgrounds, mode),
    '--text-main': readable(mix(seed, light ? '#3d483e' : '#e1e5db', 0.93), backgrounds, mode),
    '--text-muted': readable(mix(seed, light ? '#596257' : '#c0c5bc', 0.95), backgrounds, mode),
    '--line': light ? mix(seed, surface, 0.65) : readable(mix(seed, surface, 0.70), backgrounds, mode, 3),
    '--line-divider': light ? mix(seed, surface, 0.78) : readable(mix(seed, surface, 0.82), backgrounds, mode, 3),
    '--line-strong': readable(seed, backgrounds, mode, 3),
    '--color-primary': primary,
    '--color-primary-hover': mix(primary, light ? '#000000' : '#ffffff', 0.15),
    '--color-on-primary': onPrimary,
    '--color-primary-subtle': subtle,
    '--color-accent': readable(seed, backgrounds, mode, 3),
  }
}

export const CUSTOM_COLOR_PROPERTIES = Object.keys(buildColorTheme(DEFAULT_COLOR, 'light'))
