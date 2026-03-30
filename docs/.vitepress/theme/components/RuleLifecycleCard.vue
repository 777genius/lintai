<script setup lang="ts">
import { computed } from 'vue'

import type { SiteRule } from '../../siteCatalog'

const props = defineProps<{
  rule: SiteRule
}>()

const lifecycleTitle = computed(() =>
  props.rule.lifecycle.kind === 'stable' ? 'Stable Lifecycle Contract' : 'Preview Lifecycle Contract'
)
</script>

<template>
  <section class="lintai-card">
    <div class="lintai-card-header">
      <p class="lintai-kicker">Lifecycle</p>
      <h2>{{ lifecycleTitle }}</h2>
    </div>

    <div class="lintai-info-stack">
      <div class="lintai-info-block">
        <span class="lintai-info-label">State</span>
        <p>{{ rule.lifecycleState }}</p>
      </div>

      <template v-if="rule.lifecycle.kind === 'preview'">
        <div class="lintai-info-block">
          <span class="lintai-info-label">Promotion blocker</span>
          <p>{{ rule.lifecycle.blocker }}</p>
        </div>
        <div class="lintai-info-block">
          <span class="lintai-info-label">Promotion requirements</span>
          <p>{{ rule.lifecycle.promotionRequirements }}</p>
        </div>
      </template>

      <template v-else>
        <div class="lintai-info-block">
          <span class="lintai-info-label">Graduation rationale</span>
          <p>{{ rule.lifecycle.rationale }}</p>
        </div>
        <div class="lintai-info-block">
          <span class="lintai-info-label">Deterministic signal basis</span>
          <p>{{ rule.lifecycle.deterministicSignalBasis }}</p>
        </div>
        <div class="lintai-info-block">
          <span class="lintai-info-label">Malicious corpus</span>
          <div class="lintai-badges">
            <span v-for="caseId in rule.lifecycle.maliciousCaseIds" :key="caseId" class="lintai-badge lintai-badge-subtle">
              {{ caseId }}
            </span>
          </div>
        </div>
        <div class="lintai-info-block">
          <span class="lintai-info-label">Benign corpus</span>
          <div class="lintai-badges">
            <span v-for="caseId in rule.lifecycle.benignCaseIds" :key="caseId" class="lintai-badge lintai-badge-subtle">
              {{ caseId }}
            </span>
          </div>
        </div>
        <div class="lintai-inline-facts">
          <span class="lintai-badge lintai-badge-subtle">
            structured evidence {{ rule.lifecycle.requiresStructuredEvidence ? 'required' : 'optional' }}
          </span>
          <span class="lintai-badge lintai-badge-subtle">
            remediation {{ rule.lifecycle.remediationReviewed ? 'reviewed' : 'not reviewed' }}
          </span>
        </div>
      </template>

      <div class="lintai-info-block">
        <span class="lintai-info-label">Canonical note</span>
        <p>{{ rule.canonicalNote }}</p>
      </div>
    </div>
  </section>
</template>
