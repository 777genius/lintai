<script setup lang="ts">
import { withBase } from 'vitepress'

import { presetRole } from '../support/catalog'
import type { SitePreset, SiteRule } from '../../siteCatalog'

defineProps<{
  rule: SiteRule
  presets: SitePreset[]
}>()
</script>

<template>
  <section class="lintai-card">
    <div class="lintai-card-header">
      <p class="lintai-kicker">Activation Model</p>
      <h2>Preset Activation</h2>
    </div>
    <p class="lintai-note">
      These presets explain where this rule appears in the product experience.
    </p>
    <div class="lintai-link-grid lintai-link-grid-tight">
      <article
        v-for="preset in presets"
        :key="preset.id"
        class="lintai-link-tile lintai-link-tile-compact lintai-link-panel"
        :class="{ overlay: preset.kind === 'overlay' }"
        >
        <a class="lintai-link-overlay" :href="withBase(preset.canonicalPath)" :aria-label="preset.title" />
        <span class="lintai-link-title">{{ preset.title }}</span>
        <span class="lintai-link-meta">{{ presetRole(preset.id, preset.kind) }}</span>
      </article>
    </div>
  </section>
</template>
