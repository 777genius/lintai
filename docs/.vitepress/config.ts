import { defineConfig } from 'vitepress'

import { buildSidebar, loadSiteCatalogData, metadataForPage } from './siteCatalog'

const siteData = loadSiteCatalogData()
const docsBase = process.env.LINTAI_DOCS_BASE ?? '/lintai/docs/'
const siteUrl = process.env.LINTAI_SITE_URL ?? 'https://777genius.github.io/lintai'

export default defineConfig({
  base: docsBase,
  title: 'lintai docs',
  description: 'Generated and narrative documentation for lintai rules and presets.',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: [
    /V0_1_RELEASE_CHARTER$/,
    /PUBLIC_COMPATIBILITY_POLICY$/,
    /ARCH_GAPS$/,
    /MEMORY$/,
    /CATALOG$/,
    /(?:^|\/)index$/,
    /(?:^|\/)README$/,
    /research\//,
    /validation\//
  ],
  rewrites: {
    'INDEX.md': 'index.md'
  },
  srcExclude: ['.generated/**', 'VITEPRESS_AUTOGEN_RESEARCH_2026-03-29.md'],
  transformPageData(pageData) {
    const metadata = metadataForPage(pageData.frontmatter)
    if (!metadata) {
      return
    }

    return {
      title: metadata.title,
      description: metadata.description,
      frontmatter: {
        ...pageData.frontmatter,
        head: [
          ...(Array.isArray(pageData.frontmatter.head) ? pageData.frontmatter.head : []),
          ['meta', { name: 'lintai:canonical-path', content: metadata.canonicalPath }],
          ['meta', { property: 'og:title', content: metadata.title }],
          ['meta', { property: 'og:description', content: metadata.description }]
        ]
      }
    }
  },
  themeConfig: {
    nav: [
      { text: 'Home', link: siteUrl },
      { text: 'Rules', link: '/rules/' },
      { text: 'Presets', link: '/presets/' }
    ],
    sidebar: buildSidebar(siteData),
    search: {
      provider: 'local'
    }
  }
})
