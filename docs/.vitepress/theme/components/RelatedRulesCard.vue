<script setup lang="ts">
import { withBase } from 'vitepress'

import { ruleDisplayCode, ruleShortName } from '../support/catalog'
import type { SiteRule } from '../../siteCatalog'

defineProps<{
  rules: SiteRule[]
}>()
</script>

<template>
  <section v-if="rules.length" class="lintai-card">
    <div class="lintai-card-header">
      <p class="lintai-kicker">Nearby Signals</p>
      <h2>Related Rules</h2>
    </div>
    <div class="lintai-link-grid">
      <article
        v-for="rule in rules"
        :key="rule.ruleId"
        class="lintai-link-tile lintai-link-panel"
      >
        <a
          class="lintai-link-overlay"
          :href="withBase(rule.canonicalPath)"
          :aria-label="`${ruleDisplayCode(rule)}: ${ruleShortName(rule)}`"
        />
        <span class="lintai-link-code">{{ ruleDisplayCode(rule) }}</span>
        <span class="lintai-link-title">{{ ruleShortName(rule) }}</span>
        <span class="lintai-link-summary">{{ rule.summary }}</span>
        <span class="lintai-link-chips">
          <span class="lintai-badge" :data-kind="'lane'">{{ rule.publicLane }}</span>
          <span class="lintai-badge" :data-kind="'category'">{{ rule.category }}</span>
          <span class="lintai-badge" :data-kind="'surface'">{{ rule.surface }}</span>
        </span>
      </article>
    </div>
  </section>
</template>
