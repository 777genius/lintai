import { computed } from 'vue'
import { useData } from 'vitepress'

import { ruleDisplayCode, ruleShortName } from '../../ruleLabels'
import { data as siteData } from '../../rules.data'
import type { SitePreset, SiteRule } from '../../siteCatalog'

export function useCatalogData() {
  return siteData
}

export function useCurrentRule() {
  const { frontmatter } = useData()

  return computed(() => {
    const ruleId = String(frontmatter.value.ruleId ?? '')
    const rule = siteData.rulesById[ruleId]
    if (!rule) {
      throw new Error(`Unknown ruleId in page frontmatter: ${ruleId}`)
    }
    return rule
  })
}

export function useCurrentPreset() {
  const { frontmatter } = useData()

  return computed(() => {
    const presetId = String(frontmatter.value.presetId ?? '')
    const preset = siteData.presetsById[presetId]
    if (!preset) {
      throw new Error(`Unknown presetId in page frontmatter: ${presetId}`)
    }
    return preset
  })
}

export function relatedRulesFor(rule: SiteRule): SiteRule[] {
  const explicit = new Set(rule.relatedRuleIds)

  const scored = siteData.catalog.rules
    .filter((candidate) => candidate.ruleId !== rule.ruleId)
    .map((candidate) => ({
      rule: candidate,
      score: relatedRuleScore(rule, candidate, explicit),
      sameSurface: candidate.surface === rule.surface,
      explicit: explicit.has(candidate.ruleId)
    }))
    .filter((entry) => entry.score > 0)

  const preferred = scored.filter((entry) => entry.explicit || entry.sameSurface)
  const candidates = preferred.length ? preferred : scored

  return candidates.sort(sortRelatedEntries).slice(0, 6).map((entry) => entry.rule)
}

export function presetsForRule(rule: SiteRule): SitePreset[] {
  return rule.defaultPresets
    .map((presetId) => siteData.presetsById[presetId])
    .filter(Boolean)
}

export function rulesForPreset(preset: SitePreset): SiteRule[] {
  return preset.ruleIds
    .map((ruleId) => siteData.rulesById[ruleId])
    .filter(Boolean)
}

export { ruleDisplayCode, ruleShortName }

function relatedRuleScore(rule: SiteRule, candidate: SiteRule, explicit: Set<string>): number {
  if (explicit.has(candidate.ruleId)) {
    return 100
  }

  let score = 0
  if (candidate.providerId === rule.providerId) {
    score += 10
  }
  if (candidate.surface === rule.surface) {
    score += 20
  }
  if (candidate.scope === rule.scope) {
    score += 5
  }
  if (candidate.tier === rule.tier) {
    score += 3
  }

  const sharedPresetCount = candidate.defaultPresets.filter((preset) =>
    rule.defaultPresets.includes(preset)
  ).length
  score += sharedPresetCount * 8

  return score
}

function sortRelatedEntries(
  left: { rule: SiteRule; score: number },
  right: { rule: SiteRule; score: number }
): number {
  if (left.score !== right.score) {
    return right.score - left.score
  }
  return left.rule.ruleId.localeCompare(right.rule.ruleId)
}
