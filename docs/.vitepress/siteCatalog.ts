import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { PRESET_SECTIONS } from './presetModel'
import { RULE_LANE_SECTIONS } from './ruleModel'
import { ruleDisplayCode, ruleShortName, ruleSidebarText } from './ruleLabels'

export interface SiteProvider {
  id: string
  slug: string
  title: string
}

export interface SitePreset {
  id: string
  kind: 'membership' | 'overlay'
  title: string
  description: string
  extends: string[]
  ruleIds: string[]
  canonicalPath: string
}

export interface SiteRuleLifecyclePreview {
  kind: 'preview'
  blocker: string
  promotionRequirements: string
}

export interface SiteRuleLifecycleStable {
  kind: 'stable'
  rationale: string
  maliciousCaseIds: string[]
  benignCaseIds: string[]
  requiresStructuredEvidence: boolean
  remediationReviewed: boolean
  deterministicSignalBasis: string
}

export type SiteRuleLifecycle = SiteRuleLifecyclePreview | SiteRuleLifecycleStable

export interface SiteRule {
  ruleId: string
  providerId: string
  providerSlug: string
  displayCode?: string
  docTitle: string
  slug: string
  canonicalPath: string
  summary: string
  publicLane: string
  category: string
  scope: string
  surface: string
  tier: string
  defaultSeverity: string
  defaultConfidence: string
  detectionClass: string
  remediationSupport: string
  defaultPresets: string[]
  lifecycleState: string
  lifecycle: SiteRuleLifecycle
  canonicalNote: string
  relatedRuleIds: string[]
}

export interface SiteCatalog {
  version: number
  providers: SiteProvider[]
  presets: SitePreset[]
  rules: SiteRule[]
}

export interface SiteCatalogData {
  catalog: SiteCatalog
  providersById: Record<string, SiteProvider>
  presetsById: Record<string, SitePreset>
  rulesById: Record<string, SiteRule>
  rulesByLane: Array<{ lane: string; title: string; description: string; rules: SiteRule[] }>
  rulesByProvider: Array<{ provider: SiteProvider; rules: SiteRule[] }>
}

export interface SidebarItem {
  text: string
  link?: string
  collapsed?: boolean
  items?: SidebarItem[]
}

const docsRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const catalogPath = path.resolve(docsRoot, '.generated/catalog.json')
let cachedCatalogMtimeMs: number | null = null
let cachedCatalogData: SiteCatalogData | null = null

export function loadSiteCatalogData(): SiteCatalogData {
  const stat = fs.statSync(catalogPath)
  if (cachedCatalogData && cachedCatalogMtimeMs === stat.mtimeMs) {
    validateDocsCoverage(cachedCatalogData.catalog)
    return cachedCatalogData
  }

  const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8')) as SiteCatalog
  validateCatalog(catalog)

  const providersById = indexBy(catalog.providers, (provider) => provider.id)
  const presetsById = indexBy(catalog.presets, (preset) => preset.id)
  const rulesById = indexBy(catalog.rules, (rule) => rule.ruleId)

  const rulesByProvider = catalog.providers.map((provider) => ({
    provider,
    rules: catalog.rules
      .filter((rule) => rule.providerId === provider.id)
      .sort((left, right) => sortRules(left, right))
  }))
  const rulesByLane = RULE_LANE_SECTIONS.map((section) => ({
    lane: section.id,
    title: section.title,
    description: section.description,
    rules: catalog.rules
      .filter((rule) => rule.publicLane === section.id)
      .sort((left, right) => sortRules(left, right))
  })).filter((group) => group.rules.length > 0)

  validateCatalogRelations(catalog, { providersById, presetsById, rulesById })
  validateDocsCoverage(catalog)

  cachedCatalogMtimeMs = stat.mtimeMs
  cachedCatalogData = {
    catalog,
    providersById,
    presetsById,
    rulesById,
    rulesByLane,
    rulesByProvider
  }

  return cachedCatalogData
}

export function metadataForPage(
  frontmatter: Record<string, unknown>
): { title: string; description: string; canonicalPath: string } | null {
  const data = loadSiteCatalogData()
  const lintaiPage = String(frontmatter.lintaiPage ?? '')

  if (lintaiPage === 'rule') {
    const ruleId = String(frontmatter.ruleId ?? '')
    const rule = data.rulesById[ruleId]
    if (!rule) {
      return null
    }
    return {
      title: `${ruleDisplayCode(rule)}: ${ruleShortName(rule)}`,
      description: rule.summary,
      canonicalPath: rule.canonicalPath
    }
  }

  if (lintaiPage === 'preset') {
    const presetId = String(frontmatter.presetId ?? '')
    const preset = data.presetsById[presetId]
    if (!preset) {
      return null
    }
    return {
      title: preset.title,
      description: preset.description,
      canonicalPath: preset.canonicalPath
    }
  }

  return null
}

export function buildSidebar(data: SiteCatalogData): SidebarItem[] {
  const ruleItems = data.rulesByLane.map(({ title, rules }) => ({
    text: title,
    collapsed: true,
    items: rules.map((rule) => ({
      text: ruleSidebarText(rule),
      link: rule.canonicalPath
    }))
  }))

  const presetItems = PRESET_SECTIONS.map((section) => ({
    text: section.title,
    collapsed: false,
    items: section.presetIds
      .map((id) => data.presetsById[id])
      .filter(Boolean)
      .map((preset) => ({
        text: preset.title,
        link: preset.canonicalPath
      }))
  })).filter((section) => section.items.length > 0)

  return [
    {
      text: 'Overview',
      items: [
        { text: 'Project Index', link: '/' },
        { text: 'Security Rules Snapshot', link: '/SECURITY_RULES' }
      ]
    },
    {
      text: 'Rules',
      items: [{ text: 'All Rules', link: '/rules/' }, ...ruleItems]
    },
    {
      text: 'Presets',
      items: [{ text: 'All Presets', link: '/presets/' }, ...presetItems]
    },
    {
      text: 'Reference',
      items: [
        { text: 'Top AI Linter Rules', link: '/TOP_AI_LINTER_RULES' },
        { text: 'Architecture Decisions', link: '/ARCHITECTURE_DECISIONS' }
      ]
    }
  ]
}

function validateCatalog(catalog: SiteCatalog) {
  const ruleIds = new Set<string>()
  const rulePaths = new Set<string>()
  const presetIds = new Set<string>()
  const presetPaths = new Set<string>()

  for (const rule of catalog.rules) {
    if (ruleIds.has(rule.ruleId)) {
      throw new Error(`duplicate ruleId in catalog: ${rule.ruleId}`)
    }
    if (rulePaths.has(rule.canonicalPath)) {
      throw new Error(`duplicate rule canonicalPath in catalog: ${rule.canonicalPath}`)
    }
    ruleIds.add(rule.ruleId)
    rulePaths.add(rule.canonicalPath)
  }

  for (const preset of catalog.presets) {
    if (presetIds.has(preset.id)) {
      throw new Error(`duplicate preset id in catalog: ${preset.id}`)
    }
    if (presetPaths.has(preset.canonicalPath)) {
      throw new Error(`duplicate preset canonicalPath in catalog: ${preset.canonicalPath}`)
    }
    presetIds.add(preset.id)
    presetPaths.add(preset.canonicalPath)
  }
}

function validateCatalogRelations(
  catalog: SiteCatalog,
  indexes: {
    providersById: Record<string, SiteProvider>
    presetsById: Record<string, SitePreset>
    rulesById: Record<string, SiteRule>
  }
) {
  for (const rule of catalog.rules) {
    if (!indexes.providersById[rule.providerId]) {
      throw new Error(`rule ${rule.ruleId} references unknown provider ${rule.providerId}`)
    }
    if (rule.providerSlug !== indexes.providersById[rule.providerId].slug) {
      throw new Error(`rule ${rule.ruleId} has providerSlug mismatch`)
    }
    for (const presetId of rule.defaultPresets) {
      if (!indexes.presetsById[presetId]) {
        throw new Error(`rule ${rule.ruleId} references unknown preset ${presetId}`)
      }
    }
    for (const relatedRuleId of rule.relatedRuleIds) {
      if (!indexes.rulesById[relatedRuleId]) {
        throw new Error(`rule ${rule.ruleId} references unknown related rule ${relatedRuleId}`)
      }
    }
  }

  for (const preset of catalog.presets) {
    for (const parentId of preset.extends) {
      if (!indexes.presetsById[parentId]) {
        throw new Error(`preset ${preset.id} extends unknown preset ${parentId}`)
      }
    }
    for (const ruleId of preset.ruleIds) {
      if (!indexes.rulesById[ruleId]) {
        throw new Error(`preset ${preset.id} references unknown rule ${ruleId}`)
      }
    }
  }
}

function validateDocsCoverage(catalog: SiteCatalog) {
  validateRulePages(catalog.rules)
  validatePresetPages(catalog.presets)
}

function validateRulePages(rules: SiteRule[]) {
  const rulesRoot = path.resolve(docsRoot, 'rules')
  const actualPages = listMarkdownFiles(rulesRoot)
    .filter((file) => !file.endsWith('/index.md'))
    .map((file) => file.replaceAll(path.sep, '/'))

  const expected = new Map(
    rules.map((rule) => [
      path.resolve(docsRoot, `${rule.canonicalPath.slice(1)}.md`).replaceAll(path.sep, '/'),
      rule
    ])
  )

  for (const pagePath of actualPages) {
    const rule = expected.get(pagePath)
    if (!rule) {
      throw new Error(`orphan rule page: ${relativeToDocs(pagePath)}`)
    }
    const frontmatter = readFrontmatter(pagePath)
    assertField(frontmatter.layout, 'doc', `rule page ${relativeToDocs(pagePath)} must set layout: doc`)
    assertField(
      frontmatter.lintaiPage,
      'rule',
      `rule page ${relativeToDocs(pagePath)} must set lintaiPage: rule`
    )
    assertField(
      frontmatter.ruleId,
      rule.ruleId,
      `rule page ${relativeToDocs(pagePath)} must set ruleId: ${rule.ruleId}`
    )
    assertOptionalField(
      frontmatter.title,
      rule.displayCode ?? rule.slug,
      `rule page ${relativeToDocs(pagePath)} has stale title`
    )
    assertOptionalField(
      frontmatter.description,
      rule.summary,
      `rule page ${relativeToDocs(pagePath)} has stale description`
    )
    expected.delete(pagePath)
  }

  if (expected.size > 0) {
    const missing = [...expected.values()].map((rule) => `${rule.ruleId} -> ${rule.canonicalPath}.md`)
    throw new Error(`missing rule pages:\n${missing.join('\n')}`)
  }
}

function validatePresetPages(presets: SitePreset[]) {
  const presetsRoot = path.resolve(docsRoot, 'presets')
  const actualPages = listMarkdownFiles(presetsRoot)
    .filter((file) => !file.endsWith('/index.md'))
    .map((file) => file.replaceAll(path.sep, '/'))

  const expected = new Map(
    presets.map((preset) => [
      path.resolve(docsRoot, `${preset.canonicalPath.slice(1)}.md`).replaceAll(path.sep, '/'),
      preset
    ])
  )

  for (const pagePath of actualPages) {
    const preset = expected.get(pagePath)
    if (!preset) {
      throw new Error(`orphan preset page: ${relativeToDocs(pagePath)}`)
    }
    const frontmatter = readFrontmatter(pagePath)
    assertField(
      frontmatter.layout,
      'doc',
      `preset page ${relativeToDocs(pagePath)} must set layout: doc`
    )
    assertField(
      frontmatter.lintaiPage,
      'preset',
      `preset page ${relativeToDocs(pagePath)} must set lintaiPage: preset`
    )
    assertField(
      frontmatter.presetId,
      preset.id,
      `preset page ${relativeToDocs(pagePath)} must set presetId: ${preset.id}`
    )
    assertOptionalField(
      frontmatter.title,
      preset.title,
      `preset page ${relativeToDocs(pagePath)} has stale title`
    )
    assertOptionalField(
      frontmatter.description,
      preset.description,
      `preset page ${relativeToDocs(pagePath)} has stale description`
    )
    expected.delete(pagePath)
  }

  if (expected.size > 0) {
    const missing = [...expected.values()].map((preset) => `${preset.id} -> ${preset.canonicalPath}.md`)
    throw new Error(`missing preset pages:\n${missing.join('\n')}`)
  }
}

function listMarkdownFiles(root: string): string[] {
  if (!fs.existsSync(root)) {
    return []
  }

  const files: string[] = []
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const fullPath = path.resolve(root, entry.name)
    if (entry.isDirectory()) {
      files.push(...listMarkdownFiles(fullPath))
      continue
    }
    if (entry.isFile() && entry.name.endsWith('.md')) {
      files.push(fullPath)
    }
  }
  return files.sort()
}

function readFrontmatter(filePath: string): Record<string, string> {
  const text = fs.readFileSync(filePath, 'utf8')
  const match = text.match(/^---\n([\s\S]*?)\n---\n/)
  if (!match) {
    throw new Error(`missing frontmatter in ${relativeToDocs(filePath)}`)
  }

  const fields: Record<string, string> = {}
  for (const line of match[1].split('\n')) {
    const pair = line.match(/^([A-Za-z][A-Za-z0-9_-]*):\s*(.+)\s*$/)
    if (!pair) {
      continue
    }
    fields[pair[1]] = pair[2].replace(/^['"]|['"]$/g, '')
  }
  return fields
}

function relativeToDocs(filePath: string): string {
  return path.relative(docsRoot, filePath).replaceAll(path.sep, '/')
}

function assertField(actual: string | undefined, expected: string, message: string) {
  if (actual !== expected) {
    throw new Error(`${message} (got ${actual ?? 'undefined'})`)
  }
}

function assertOptionalField(actual: string | undefined, expected: string, message: string) {
  if (actual !== undefined && actual !== expected) {
    throw new Error(`${message} (got ${actual})`)
  }
}

function indexBy<T>(items: T[], getKey: (item: T) => string): Record<string, T> {
  return Object.fromEntries(items.map((item) => [getKey(item), item]))
}

function sortRules(left: SiteRule, right: SiteRule): number {
  const leftKey = left.displayCode ?? left.slug
  const rightKey = right.displayCode ?? right.slug

  if (leftKey !== rightKey) {
    return leftKey.localeCompare(rightKey)
  }
  return left.slug.localeCompare(right.slug)
}
