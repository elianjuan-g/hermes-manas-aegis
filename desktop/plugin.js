/**
 * Manas Aegis — Desktop surface.
 *
 * Adds a "Manas Aegis" page to Hermes Desktop (sidebar nav + command palette),
 * embedding the Live Analytical HUD (loopback http://127.0.0.1:<port>) in the
 * SDK's SandboxedFrame — so the dashboard lives inside Desktop, not a browser
 * tab, with the app's guest-content posture (opaque origin, allow-scripts).
 *
 * The HUD port comes from the agent plugin's config (hud_port, default
 * 18777), read live from the gateway via host.request('plugins.manage',
 * { action: 'list' }): each list row carries settings_schema with current
 * values. If the gateway cannot be reached, the page falls back to 18777.
 *
 * Stays inside the plugin SDK surface: static imports only from
 * '@hermes/plugin-sdk' and 'react/jsx-runtime', no eval, no prototype
 * patching, no remote imports, no injected markup.
 */
import { atom, host, PALETTE_AREA, ROUTES_AREA, SIDEBAR_NAV_AREA, SandboxedFrame, useValue } from '@hermes/plugin-sdk'
import { jsx } from 'react/jsx-runtime'

const PLUGIN_NAME = 'hermes-manas-aegis'
const DEFAULT_HUD_PORT = 18777

// The resolved HUD URL; null while the port is still being read from the
// gateway. Shared by every mount of the page.
const hudUrlAtom = atom(null)
let hudPortPromise = null

function hudUrlFor(port) {
  return `http://127.0.0.1:${port}/`
}

async function ensureHudPort() {
  if (hudPortPromise) return hudPortPromise
  hudPortPromise = (async () => {
    try {
      const result = await host.request('plugins.manage', { action: 'list' })
      const plugins = (result && result.plugins) || []
      const row = plugins.find((p) => p && (p.key === PLUGIN_NAME || p.name === PLUGIN_NAME))
      const fields = (row && row.settings_schema) || []
      const field = fields.find((f) => f && f.key === 'hud_port')
      const raw = field && (field.value !== undefined && field.value !== null ? field.value : field.default)
      const port = Number(raw)
      if (Number.isInteger(port) && port > 0 && port < 65536) {
        hudUrlAtom.set(hudUrlFor(port))
        return
      }
    } catch (e) {
      // Gateway unreachable, or an older host without plugins.manage:
      // fall through to the default port below.
    }
    hudUrlAtom.set(hudUrlFor(DEFAULT_HUD_PORT))
  })()
  return hudPortPromise
}

function ManasAegisPage() {
  const hudUrl = useValue(hudUrlAtom)
  if (!hudUrl) {
    // Kick off the one shared resolution; the atom update re-renders.
    void ensureHudPort()
    return jsx('div', {
      style: { display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#8b949e' },
      children: 'Loading Manas Aegis HUD…'
    })
  }
  return jsx('div', {
    style: { display: 'flex', flexDirection: 'column', width: '100%', height: '100%' },
    children: jsx(SandboxedFrame, {
      src: hudUrl,
      title: 'Manas Aegis — Live Analytical HUD',
      style: { flex: '1 1 auto', width: '100%', height: '100%' }
    })
  })
}

export default {
  id: 'hermes-manas-aegis',
  name: 'Manas Aegis',
  description: 'Activity guardrail (alpha) — local event log and STIX export, inside Hermes Desktop.',
  register(ctx) {
    void ensureHudPort()
    ctx.registerMany([
      {
        id: 'page',
        area: ROUTES_AREA,
        data: { path: '/manas-aegis' },
        render: () => jsx(ManasAegisPage, {})
      },
      {
        id: 'nav',
        area: SIDEBAR_NAV_AREA,
        order: 50,
        data: { codicon: 'shield', label: 'Manas Aegis', path: '/manas-aegis' }
      },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'manas-aegis.open',
          label: 'Open Manas Aegis HUD',
          keywords: ['manas', 'aegis', 'guard', 'security', 'hud', 'threat', 'stix'],
          run: () => host.navigate('/manas-aegis')
        }
      }
    ])
  }
}
