export interface PresetSection {
  id: 'start-here' | 'sidecar-lanes' | 'surface-memberships' | 'overlays'
  title: string
  description: string
  presetIds: string[]
}

export const PRESET_SECTIONS: PresetSection[] = [
  {
    id: 'start-here',
    title: 'Start Here',
    description: 'Begin with the quiet default, then add broader review only when you need it.',
    presetIds: ['recommended', 'preview', 'threat-review']
  },
  {
    id: 'sidecar-lanes',
    title: 'Sidecar Lanes',
    description: 'Add explicit review dimensions such as supply-chain, governance, or compat.',
    presetIds: ['supply-chain', 'governance', 'compat', 'guidance', 'advisory']
  },
  {
    id: 'surface-memberships',
    title: 'Surface Memberships',
    description: 'Scope review to a specific artifact family when you do not want the broader default.',
    presetIds: ['base', 'skills', 'mcp', 'claude']
  },
  {
    id: 'overlays',
    title: 'Overlays',
    description: 'Change severity posture for rules that are already active.',
    presetIds: ['strict']
  }
]

const PRESET_ORDER = PRESET_SECTIONS.flatMap((section) => section.presetIds)
const PRESET_INDEX = new Map(PRESET_ORDER.map((id, index) => [id, index]))

export function sortPresetIds(ids: string[]): string[] {
  return [...ids].sort((left, right) => {
    const leftIndex = PRESET_INDEX.get(left)
    const rightIndex = PRESET_INDEX.get(right)

    if (leftIndex !== undefined || rightIndex !== undefined) {
      if (leftIndex === undefined) {
        return 1
      }
      if (rightIndex === undefined) {
        return -1
      }
      if (leftIndex !== rightIndex) {
        return leftIndex - rightIndex
      }
    }

    return left.localeCompare(right)
  })
}

export function presetRole(id: string, kind: 'membership' | 'overlay'): string {
  if (kind === 'overlay' || id === 'strict') {
    return 'overlay'
  }
  if (id === 'recommended') {
    return 'quiet default'
  }
  if (['preview', 'threat-review', 'supply-chain', 'governance', 'compat', 'guidance', 'advisory'].includes(id)) {
    return 'sidecar lane'
  }
  if (['base', 'skills', 'mcp', 'claude'].includes(id)) {
    return 'surface preset'
  }
  return 'direct activation'
}

export function presetRoleExplainer(id: string, kind: 'membership' | 'overlay'): string {
  if (kind === 'overlay' || id === 'strict') {
    return 'Changes posture for already-active rules without silently enabling a new rule set.'
  }
  switch (id) {
    case 'recommended':
      return 'Main calm default most teams should start with.'
    case 'preview':
      return 'Broader contextual review beyond the quiet default.'
    case 'threat-review':
      return 'Explicit malicious-behavior and spyware-like review.'
    case 'supply-chain':
      return 'Reproducibility, provenance, and release-chain hardening review.'
    case 'governance':
      return 'Shared authority and workflow policy review.'
    case 'compat':
      return 'Schema, config, and contract correctness review.'
    case 'guidance':
      return 'Advice-oriented maintenance and authoring review.'
    case 'advisory':
      return 'Installed-package advisory review against the offline snapshot.'
    case 'base':
      return 'Narrow stable baseline for teams that want a minimal starting point.'
    case 'skills':
      return 'Focus review on markdown-based instruction and skill surfaces.'
    case 'mcp':
      return 'Focus review on MCP configs, descriptors, and server registries.'
    case 'claude':
      return 'Focus review on shared Claude settings and hook-policy surfaces.'
    default:
      return 'Preset role inside the builtin activation model.'
  }
}
