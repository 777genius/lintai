<script setup lang="ts">
import { withBase } from 'vitepress'

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
      <h2>Preset Membership</h2>
    </div>
    <p class="lintai-note">
      This rule is part of the builtin activation graph through these preset memberships.
    </p>
    <div class="lintai-link-grid lintai-link-grid-tight">
      <article
        v-for="preset in presets"
        :key="preset.id"
        class="lintai-link-tile lintai-link-tile-compact lintai-link-panel"
        :class="{ overlay: preset.kind === 'overlay' }"
      >
        <a class="lintai-link-overlay" :href="withBase(preset.canonicalPath)" :aria-label="preset.id" />
        <span class="lintai-link-title">{{ preset.id }}</span>
        <span class="lintai-link-meta">{{ preset.kind }}</span>
      </article>
    </div>
  </section>
</template>
