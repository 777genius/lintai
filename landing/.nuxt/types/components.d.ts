
import type { DefineComponent, SlotsType } from 'vue'
type IslandComponent<T> = DefineComponent<{}, {refresh: () => Promise<void>}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, SlotsType<{ fallback: { error: unknown } }>> & T

type HydrationStrategies = {
  hydrateOnVisible?: IntersectionObserverInit | true
  hydrateOnIdle?: number | true
  hydrateOnInteraction?: keyof HTMLElementEventMap | Array<keyof HTMLElementEventMap> | true
  hydrateOnMediaQuery?: string
  hydrateAfter?: number
  hydrateWhen?: boolean
  hydrateNever?: true
}
type LazyComponent<T> = DefineComponent<HydrationStrategies, {}, {}, {}, {}, {}, {}, { hydrated: () => void }> & T

interface _GlobalComponents {
  PageBackground: typeof import("../../components/PageBackground.vue")['default']
  SectionDivider: typeof import("../../components/SectionDivider.vue")['default']
  AppLogo: typeof import("../../components/common/AppLogo.vue")['default']
  ThemeToggle: typeof import("../../components/common/ThemeToggle.vue")['default']
  AppFooter: typeof import("../../components/layout/AppFooter.vue")['default']
  AppHeader: typeof import("../../components/layout/AppHeader.vue")['default']
  LanguageSwitcher: typeof import("../../components/layout/LanguageSwitcher.vue")['default']
  ComparisonSection: typeof import("../../components/sections/ComparisonSection.vue")['default']
  DownloadSection: typeof import("../../components/sections/DownloadSection.vue")['default']
  FAQSection: typeof import("../../components/sections/FAQSection.vue")['default']
  FeaturedRulesSection: typeof import("../../components/sections/FeaturedRulesSection.vue")['default']
  FeaturesSection: typeof import("../../components/sections/FeaturesSection.vue")['default']
  HeroSection: typeof import("../../components/sections/HeroSection.vue")['default']
  FeatureCard: typeof import("../../components/ui/FeatureCard.vue")['default']
  HeroDemo: typeof import("../../components/ui/HeroDemo.vue")['default']
  NuxtWelcome: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/welcome.vue")['default']
  NuxtLayout: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-layout")['default']
  NuxtErrorBoundary: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-error-boundary.vue")['default']
  ClientOnly: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/client-only")['default']
  DevOnly: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/dev-only")['default']
  ServerPlaceholder: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/server-placeholder")['default']
  NuxtLink: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-link")['default']
  NuxtLoadingIndicator: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-loading-indicator")['default']
  NuxtTime: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-time.vue")['default']
  NuxtRouteAnnouncer: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-route-announcer")['default']
  NuxtImg: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtImg']
  NuxtPicture: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtPicture']
  NuxtLinkLocale: typeof import("../../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/NuxtLinkLocale")['default']
  SwitchLocalePathLink: typeof import("../../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/SwitchLocalePathLink")['default']
  Icon: typeof import("../../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/Icon.vue")['default']
  IconCSS: typeof import("../../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/IconCSS.vue")['default']
  NuxtPage: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/pages/runtime/page")['default']
  NoScript: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['NoScript']
  Link: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Link']
  Base: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Base']
  Title: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Title']
  Meta: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Meta']
  Style: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Style']
  Head: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Head']
  Html: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Html']
  Body: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Body']
  NuxtIsland: typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-island")['default']
  LazyPageBackground: LazyComponent<typeof import("../../components/PageBackground.vue")['default']>
  LazySectionDivider: LazyComponent<typeof import("../../components/SectionDivider.vue")['default']>
  LazyAppLogo: LazyComponent<typeof import("../../components/common/AppLogo.vue")['default']>
  LazyThemeToggle: LazyComponent<typeof import("../../components/common/ThemeToggle.vue")['default']>
  LazyAppFooter: LazyComponent<typeof import("../../components/layout/AppFooter.vue")['default']>
  LazyAppHeader: LazyComponent<typeof import("../../components/layout/AppHeader.vue")['default']>
  LazyLanguageSwitcher: LazyComponent<typeof import("../../components/layout/LanguageSwitcher.vue")['default']>
  LazyComparisonSection: LazyComponent<typeof import("../../components/sections/ComparisonSection.vue")['default']>
  LazyDownloadSection: LazyComponent<typeof import("../../components/sections/DownloadSection.vue")['default']>
  LazyFAQSection: LazyComponent<typeof import("../../components/sections/FAQSection.vue")['default']>
  LazyFeaturedRulesSection: LazyComponent<typeof import("../../components/sections/FeaturedRulesSection.vue")['default']>
  LazyFeaturesSection: LazyComponent<typeof import("../../components/sections/FeaturesSection.vue")['default']>
  LazyHeroSection: LazyComponent<typeof import("../../components/sections/HeroSection.vue")['default']>
  LazyFeatureCard: LazyComponent<typeof import("../../components/ui/FeatureCard.vue")['default']>
  LazyHeroDemo: LazyComponent<typeof import("../../components/ui/HeroDemo.vue")['default']>
  LazyNuxtWelcome: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/welcome.vue")['default']>
  LazyNuxtLayout: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-layout")['default']>
  LazyNuxtErrorBoundary: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-error-boundary.vue")['default']>
  LazyClientOnly: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/client-only")['default']>
  LazyDevOnly: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/dev-only")['default']>
  LazyServerPlaceholder: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/server-placeholder")['default']>
  LazyNuxtLink: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-link")['default']>
  LazyNuxtLoadingIndicator: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-loading-indicator")['default']>
  LazyNuxtTime: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-time.vue")['default']>
  LazyNuxtRouteAnnouncer: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-route-announcer")['default']>
  LazyNuxtImg: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtImg']>
  LazyNuxtPicture: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtPicture']>
  LazyNuxtLinkLocale: LazyComponent<typeof import("../../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/NuxtLinkLocale")['default']>
  LazySwitchLocalePathLink: LazyComponent<typeof import("../../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/SwitchLocalePathLink")['default']>
  LazyIcon: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/Icon.vue")['default']>
  LazyIconCSS: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/IconCSS.vue")['default']>
  LazyNuxtPage: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/pages/runtime/page")['default']>
  LazyNoScript: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['NoScript']>
  LazyLink: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Link']>
  LazyBase: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Base']>
  LazyTitle: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Title']>
  LazyMeta: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Meta']>
  LazyStyle: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Style']>
  LazyHead: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Head']>
  LazyHtml: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Html']>
  LazyBody: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Body']>
  LazyNuxtIsland: LazyComponent<typeof import("../../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-island")['default']>
}

declare module 'vue' {
  export interface GlobalComponents extends _GlobalComponents { }
}

export {}
