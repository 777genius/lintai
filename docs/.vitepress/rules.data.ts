import { defineLoader } from 'vitepress'

import { loadSiteCatalogData, type SiteCatalogData } from './siteCatalog'

declare const data: SiteCatalogData
export { data }

export default defineLoader({
  watch: ['../.generated/catalog.json', '../rules/**/*.md', '../presets/**/*.md'],
  async load() {
    return loadSiteCatalogData()
  }
})
