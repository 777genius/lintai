<script setup lang="ts">
import { computed } from 'vue'
import { withBase } from 'vitepress'

import { PRESET_SECTIONS, presetRole } from '../../presetModel'
import { useCatalogData } from '../support/catalog'

const siteData = useCatalogData()
const presetSections = computed(() =>
  PRESET_SECTIONS.map((section) => ({
    ...section,
    presets: section.presetIds.map((id) => siteData.presetsById[id]).filter(Boolean)
  })).filter((section) => section.presets.length > 0)
)
</script>

<template>
  <div class="lintai-directory">
    <section
      v-for="section in presetSections"
      :key="section.id"
      class="lintai-card"
    >
      <div class="lintai-section-header">
        <div>
          <p class="lintai-kicker">Preset Group</p>
          <h2>{{ section.title }}</h2>
        </div>
      </div>
      <p class="lintai-note">{{ section.description }}</p>
      <div class="lintai-link-grid">
        <article
          v-for="preset in section.presets"
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
              {{ presetRole(preset.id, preset.kind) }}
            </span>
            <span v-if="preset.kind !== 'overlay'" class="lintai-badge lintai-badge-subtle">
              direct activation
            </span>
            <span class="lintai-badge lintai-badge-count">{{ preset.ruleIds.length }} rules</span>
          </span>
        </article>
      </div>
    </section>
  </div>
</template>
