import type { SiteRule } from './siteCatalog'

export function ruleDisplayCode(rule: Pick<SiteRule, 'displayCode' | 'slug'>): string {
  return rule.displayCode ?? rule.slug.toUpperCase()
}

export function ruleShortName(rule: Pick<SiteRule, 'docTitle' | 'summary'>): string {
  return (rule.docTitle || rule.summary).trim()
}

export function ruleSidebarText(
  rule: Pick<SiteRule, 'displayCode' | 'slug' | 'docTitle' | 'summary'>
): string {
  return `${ruleDisplayCode(rule)} · ${ruleShortName(rule)}`
}
