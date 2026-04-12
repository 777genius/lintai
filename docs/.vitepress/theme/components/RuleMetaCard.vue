<script setup lang="ts">
import { categoryExplainer, laneExplainer, ruleDisplayCode, ruleShortName } from '../support/catalog'
import type { SiteRule } from '../../siteCatalog'

defineProps<{
  rule: SiteRule
}>()
</script>

<template>
  <section class="lintai-card lintai-hero-card lintai-rule-hero">
    <div class="lintai-card-header">
      <p class="lintai-kicker">Rule Reference</p>
      <div class="lintai-badges">
        <span class="lintai-badge lintai-badge-subtle">{{ ruleDisplayCode(rule) }}</span>
        <span class="lintai-badge lintai-badge-subtle">{{ rule.providerId }}</span>
        <span class="lintai-badge" :data-kind="'lane'">{{ rule.publicLane }}</span>
        <span class="lintai-badge" :data-kind="'category'">{{ rule.category }}</span>
        <span class="lintai-badge" :data-kind="'tier'" :data-value="rule.tier">{{ rule.tier }}</span>
        <span class="lintai-badge" :data-kind="'surface'">{{ rule.surface }}</span>
        <span class="lintai-badge" :data-kind="'severity'" :data-value="rule.defaultSeverity">
          {{ rule.defaultSeverity }}
        </span>
      </div>
    </div>

    <h1 class="lintai-hero-title">{{ ruleShortName(rule) }}</h1>
    <p class="lintai-hero-summary">{{ rule.summary }}</p>

    <dl class="lintai-kv lintai-stat-grid">
      <div class="lintai-stat-card">
        <dt>Public lane</dt>
        <dd>{{ rule.publicLane }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Category</dt>
        <dd>{{ rule.category }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Provider</dt>
        <dd>{{ rule.providerId }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Scope</dt>
        <dd>{{ rule.scope }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Surface</dt>
        <dd>{{ rule.surface }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Tier</dt>
        <dd>{{ rule.tier }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Severity</dt>
        <dd>{{ rule.defaultSeverity }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Confidence</dt>
        <dd>{{ rule.defaultConfidence }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Detection</dt>
        <dd>{{ rule.detectionClass }}</dd>
      </div>
      <div class="lintai-stat-card">
        <dt>Remediation</dt>
        <dd>{{ rule.remediationSupport }}</dd>
      </div>
    </dl>

    <div class="lintai-info-stack">
      <div class="lintai-info-block">
        <span class="lintai-info-label">How to read this lane</span>
        <p>{{ laneExplainer(rule.publicLane) }}</p>
      </div>
      <div class="lintai-info-block">
        <span class="lintai-info-label">How to read this category</span>
        <p>{{ categoryExplainer(rule.category) }}</p>
      </div>
    </div>
  </section>
</template>
