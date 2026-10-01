import test from 'node:test'
import assert from 'node:assert/strict'
import { buildColorTheme, contrastRatio, hexToHsv, hsvToHex, normalizeHex } from '../src/styles/themeColor.ts'

test('stored and typed colors accept only six-digit hex values', () => {
  assert.equal(normalizeHex('  #A0B1C2  '), '#a0b1c2')
  assert.equal(normalizeHex('798777'), '#798777')
  for (const value of [null, undefined, {}, 123456, '', '#fff', '#12345678', '#xxxxxx', 'red', 'var(--canvas)', '#123456;']) {
    assert.equal(normalizeHex(value), null)
  }
  assert.throws(() => buildColorTheme('invalid', 'light'), /six-digit hex/)
})

test('wheel coordinates preserve primary colors, neutrals, and arbitrary hex selections', () => {
  for (const hex of ['#000000', '#ffffff', '#888888', '#ff0000', '#00ff00', '#0000ff', '#ffff00', '#00ffff', '#ff00ff', '#798777', '#367fa0', '#123456']) {
    assert.equal(hsvToHex(hexToHsv(hex)), hex)
  }
  assert.equal(hsvToHex({ hue: 360, saturation: 1, value: 1 }), '#ff0000')
  assert.equal(hsvToHex({ hue: 120, saturation: 0, value: 1 }), '#ffffff')
  assert.equal(hsvToHex({ hue: 240, saturation: 1, value: 0 }), '#000000')
})

test('custom themes keep readable text and buttons for bright, dark, and saturated selections', () => {
  for (const r of [0, 64, 128, 192, 255]) for (const g of [0, 64, 128, 192, 255]) for (const b of [0, 64, 128, 192, 255]) {
    const seed = `#${[r, g, b].map(value => value.toString(16).padStart(2, '0')).join('')}`
    for (const mode of ['light', 'dark']) {
      const theme = buildColorTheme(seed, mode)
      for (const fg of ['--text-heading', '--text-main', '--text-muted', '--color-primary']) {
        for (const bg of ['--canvas', '--surface', '--surface-muted', '--surface-hover', '--bg-input', '--color-primary-subtle']) {
          assert.ok(contrastRatio(theme[fg], theme[bg]) >= 4.5, `${seed}/${mode}: ${fg} on ${bg}`)
        }
      }
      for (const bg of ['--color-primary', '--color-primary-hover']) {
        assert.ok(contrastRatio(theme['--color-on-primary'], theme[bg]) >= 4.5, `${seed}/${mode}: button on ${bg}`)
      }
      if (mode === 'dark') for (const fg of ['--line', '--line-divider', '--line-strong']) {
        for (const bg of ['--canvas', '--surface', '--surface-muted', '--surface-hover', '--bg-input', '--color-primary-subtle']) {
          assert.ok(contrastRatio(theme[fg], theme[bg]) >= 3, `${seed}/${mode}: ${fg} on ${bg}`)
        }
      }
      for (const semantic of ['--danger', '--warning', '--success', '--terminal-error', '--terminal-success']) assert.equal(theme[semantic], undefined)
    }
  }
})
