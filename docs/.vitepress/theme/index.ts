import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'

import Layout from './Layout.vue'
import PresetDirectory from './components/PresetDirectory.vue'
import PresetRuleTable from './components/PresetRuleTable.vue'
import RelatedRulesCard from './components/RelatedRulesCard.vue'
import RuleActivationCard from './components/RuleActivationCard.vue'
import RuleDirectory from './components/RuleDirectory.vue'
import RuleLifecycleCard from './components/RuleLifecycleCard.vue'
import RuleMetaCard from './components/RuleMetaCard.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    DefaultTheme.enhanceApp?.({ app })
    app.component('RuleMetaCard', RuleMetaCard)
    app.component('RuleLifecycleCard', RuleLifecycleCard)
    app.component('RuleActivationCard', RuleActivationCard)
    app.component('RelatedRulesCard', RelatedRulesCard)
    app.component('PresetRuleTable', PresetRuleTable)
    app.component('RuleDirectory', RuleDirectory)
    app.component('PresetDirectory', PresetDirectory)
  }
} satisfies Theme
