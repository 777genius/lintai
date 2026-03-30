<script setup lang="ts">
import { withBase } from 'vitepress'

import { ruleDisplayCode, ruleShortName, useCatalogData } from '../support/catalog'

const siteData = useCatalogData()
</script>

<template>
  <div class="lintai-directory">
    <section v-for="group in siteData.rulesByProvider" :key="group.provider.id" class="lintai-card lintai-provider-card">
      <div class="lintai-section-header">
        <div>
          <p class="lintai-kicker">Provider</p>
          <h2>{{ group.provider.title }}</h2>
        </div>
        <span class="lintai-badge lintai-badge-count">{{ group.rules.length }} rules</span>
      </div>
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
            <span class="lintai-badge" :data-kind="'tier'" :data-value="rule.tier">{{ rule.tier }}</span>
            <span class="lintai-badge" :data-kind="'surface'">{{ rule.surface }}</span>
          </span>
        </article>
      </div>
    </section>
  </div>
</template>
