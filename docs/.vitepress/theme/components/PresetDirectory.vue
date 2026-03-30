<script setup lang="ts">
import { computed } from 'vue'
import { withBase } from 'vitepress'

import { useCatalogData } from '../support/catalog'

const siteData = useCatalogData()
const order = ['base', 'preview', 'compat', 'skills', 'mcp', 'claude', 'strict']

const presets = computed(() =>
  order.map((id) => siteData.presetsById[id]).filter(Boolean)
)
</script>

<template>
  <div class="lintai-link-grid">
    <article
      v-for="preset in presets"
      :key="preset.id"
      class="lintai-link-tile lintai-link-panel"
    >
      <a
        class="lintai-link-overlay"
        :href="withBase(preset.canonicalPath)"
        :aria-label="preset.title"
      />
      <span class="lintai-link-title">{{ preset.title }}</span>
      <span class="lintai-link-summary">{{ preset.description }}</span>
      <span class="lintai-link-chips">
        <span class="lintai-badge" :class="{ overlay: preset.kind === 'overlay' }">
          {{ preset.kind }}
        </span>
        <span class="lintai-badge lintai-badge-count">{{ preset.ruleIds.length }} rules</span>
      </span>
    </article>
  </div>
</template>
