<script setup lang="ts">
import { computed } from 'vue'
import { useData } from 'vitepress'
import DefaultTheme from 'vitepress/theme'

import PresetLayout from './layouts/PresetLayout.vue'
import RuleLayout from './layouts/RuleLayout.vue'

const { frontmatter } = useData()
const lintaiPage = computed(() => String(frontmatter.value.lintaiPage ?? ''))
</script>

<template>
  <DefaultTheme.Layout>
    <template #doc-before>
      <RuleLayout v-if="lintaiPage === 'rule'" />
      <PresetLayout v-else-if="lintaiPage === 'preset'" />
    </template>
  </DefaultTheme.Layout>
</template>
