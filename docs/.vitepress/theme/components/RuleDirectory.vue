<script setup lang="ts">
import { computed } from 'vue'
import { withBase } from 'vitepress'

import { RULE_LANE_SECTIONS, ruleDisplayCode, ruleShortName, useCatalogData } from '../support/catalog'

const siteData = useCatalogData()
const laneGroups = computed(() =>
  RULE_LANE_SECTIONS.map((section) => ({
    ...section,
    rules: siteData.catalog.rules
      .filter((rule) => rule.publicLane === section.id)
      .sort((left, right) => ruleDisplayCode(left).localeCompare(ruleDisplayCode(right)))
  })).filter((section) => section.rules.length > 0)
)

function providerTitle(providerId: string): string {
  return siteData.providersById[providerId]?.title ?? providerId
}
</script>

<template>
  <div class="lintai-directory">
    <section
      v-for="group in laneGroups"
      :key="group.id"
      class="lintai-card lintai-provider-card"
    >
      <div class="lintai-section-header">
        <div>
          <p class="lintai-kicker">Public Lane</p>
          <h2>{{ group.title }}</h2>
        </div>
        <span class="lintai-badge lintai-badge-count">{{ group.rules.length }} rules</span>
      </div>
      <p class="lintai-note">{{ group.description }}</p>
      <div class="lintai-link-grid">
        <article
          v-for="rule in group.rules"
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
            <span class="lintai-badge" :data-kind="'category'">{{ rule.category }}</span>
            <span class="lintai-badge" :data-kind="'surface'">{{ rule.surface }}</span>
            <span class="lintai-badge lintai-badge-subtle">{{ providerTitle(rule.providerId) }}</span>
          </span>
        </article>
      </div>
    </section>
  </div>
</template>
