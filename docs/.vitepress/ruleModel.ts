export interface RuleLaneSection {
  id: string
  title: string
  description: string
}

export const RULE_LANE_SECTIONS: RuleLaneSection[] = [
  {
    id: 'recommended',
    title: 'Recommended',
    description: 'Quiet practical default findings most teams should start with.'
  },
  {
    id: 'preview',
    title: 'Preview',
    description: 'Broader contextual review outside the quiet default.'
  },
  {
    id: 'threat-review',
    title: 'Threat Review',
    description: 'Explicit malicious, secret-bearing, or spyware-like review.'
  },
  {
    id: 'supply-chain',
    title: 'Supply Chain',
    description: 'Reproducibility, provenance, and dependency hardening review.'
  },
  {
    id: 'compat',
    title: 'Compat',
    description: 'Config, schema, and policy contract review.'
  },
  {
    id: 'governance',
    title: 'Governance',
    description: 'Shared authority and workflow policy review.'
  },
  {
    id: 'guidance',
    title: 'Guidance',
    description: 'Advice-oriented guidance and maintainability review.'
  },
  {
    id: 'advisory',
    title: 'Advisory',
    description: 'Installed-package advisory review.'
  }
]

export function sortLaneIds(ids: string[]): string[] {
  const index = new Map(RULE_LANE_SECTIONS.map((section, position) => [section.id, position]))

  return [...ids].sort((left, right) => {
    const leftIndex = index.get(left)
    const rightIndex = index.get(right)

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
