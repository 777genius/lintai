<script setup lang="ts">
import { computed } from 'vue'

import PresetRuleTable from '../components/PresetRuleTable.vue'
import { rulesForPreset, useCurrentPreset } from '../support/catalog'

const preset = useCurrentPreset()
const rules = computed(() => rulesForPreset(preset.value))
const activationLabel = computed(() =>
  preset.value.kind === 'overlay'
    ? 'Overlay preset: changes posture for already-active rules.'
    : 'Membership preset: directly activates this rule set.'
)
</script>

<template>
  <div class="lintai-preset-shell">
    <section class="lintai-card lintai-hero-card">
      <div class="lintai-card-header">
        <p class="lintai-kicker">Preset Reference</p>
        <div class="lintai-meta-row">
          <span class="lintai-badge" :class="{ overlay: preset.kind === 'overlay' }">
            {{ preset.kind }}
          </span>
          <span v-if="preset.extends.length" class="lintai-badge lintai-badge-subtle">
            extends {{ preset.extends.join(', ') }}
          </span>
          <span class="lintai-badge lintai-badge-count">{{ rules.length }} direct rules</span>
        </div>
      </div>
      <h1 class="lintai-hero-title">{{ preset.title }}</h1>
      <p class="lintai-hero-summary">{{ preset.description }}</p>
      <p class="lintai-hero-note">{{ activationLabel }}</p>
    </section>
    <PresetRuleTable :rules="rules" />
    <div class="lintai-doc-divider" />
  </div>
</template>
