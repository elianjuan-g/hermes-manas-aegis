/**
 * Manas Aegis — Desktop surface.
 *
 * Adds a "Manas Aegis" page to Hermes Desktop (sidebar nav + command palette),
 * embedding the Live Analytical HUD (loopback http://127.0.0.1:18777) as a
 * full-page iframe — so the dashboard lives inside Desktop, not a browser tab.
 *
 * Stays inside the plugin SDK surface: static imports only from
 * '@hermes/plugin-sdk' and 'react/jsx-runtime', no eval, no prototype
 * patching, no remote imports, no injected markup.
 */
import { host, PALETTE_AREA, ROUTES_AREA, SIDEBAR_NAV_AREA } from '@hermes/plugin-sdk'
import { jsx } from 'react/jsx-runtime'

const HUD_URL = 'http://127.0.0.1:18777/'

function ManasAegisPage() {
  return jsx('div', {
    style: { display: 'flex', flexDirection: 'column', width: '100%', height: '100%' },
    children: jsx('iframe', {
      src: HUD_URL,
      title: 'Manas Aegis — Live Analytical HUD',
      style: { flex: '1 1 auto', width: '100%', height: '100%', border: '0', display: 'block', background: '#0b0f14' }
    })
  })
}

export default {
  id: 'hermes-manas-aegis',
  name: 'Manas Aegis',
  description: 'Activity guardrail (alpha) — local event log and STIX export, inside Hermes Desktop.',
  register(ctx) {
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
