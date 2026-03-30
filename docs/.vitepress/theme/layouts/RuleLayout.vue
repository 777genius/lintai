<script setup lang="ts">
import RelatedRulesCard from '../components/RelatedRulesCard.vue'
import RuleActivationCard from '../components/RuleActivationCard.vue'
import RuleLifecycleCard from '../components/RuleLifecycleCard.vue'
import RuleMetaCard from '../components/RuleMetaCard.vue'
import { presetsForRule, relatedRulesFor, useCurrentRule } from '../support/catalog'

const rule = useCurrentRule()
</script>

<template>
  <div class="lintai-rule-shell">
    <RuleMetaCard :rule="rule" />
    <div class="lintai-split-grid">
      <RuleActivationCard :rule="rule" :presets="presetsForRule(rule)" />
      <RuleLifecycleCard :rule="rule" />
    </div>
    <RelatedRulesCard :rules="relatedRulesFor(rule)" />
    <div class="lintai-doc-divider" />
  </div>
</template>
