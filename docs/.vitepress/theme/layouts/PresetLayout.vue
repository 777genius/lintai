<script setup lang="ts">
import { computed } from 'vue'

import PresetRuleTable from '../components/PresetRuleTable.vue'
import { presetRole, presetRoleExplainer, rulesForPreset, useCurrentPreset } from '../support/catalog'

const preset = useCurrentPreset()
const rules = computed(() => rulesForPreset(preset.value))
const roleLabel = computed(() => presetRole(preset.value.id, preset.value.kind))
const roleExplainer = computed(() => presetRoleExplainer(preset.value.id, preset.value.kind))
const activationLabel = computed(() =>
  preset.value.kind === 'overlay'
    ? 'No direct rules are enabled until another preset activates them.'
    : 'Explicitly turns on this rule set.'
)
</script>

<template>
  <div class="lintai-preset-shell">
    <section class="lintai-card lintai-hero-card">
      <div class="lintai-card-header">
        <p class="lintai-kicker">Preset Reference</p>
        <div class="lintai-meta-row">
          <span class="lintai-badge lintai-badge-subtle">
            {{ roleLabel }}
          </span>
          <span
            v-if="preset.kind !== 'overlay'"
            class="lintai-badge"
            :class="{ overlay: preset.kind === 'overlay' }"
          >
            {{ preset.kind === 'overlay' ? 'overlay' : 'direct activation' }}
          </span>
          <span v-if="preset.extends.length" class="lintai-badge lintai-badge-subtle">
            extends {{ preset.extends.join(', ') }}
          </span>
          <span class="lintai-badge lintai-badge-count">{{ rules.length }} direct rules</span>
        </div>
      </div>
      <h1 class="lintai-hero-title">{{ preset.title }}</h1>
      <p class="lintai-hero-summary">{{ preset.description }}</p>
      <p class="lintai-hero-note">{{ roleExplainer }}</p>
      <p class="lintai-hero-note">{{ activationLabel }}</p>
    </section>
    <PresetRuleTable :rules="rules" />
    <div class="lintai-doc-divider" />
  </div>
</template>
