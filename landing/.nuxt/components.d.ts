
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


export const PageBackground: typeof import("../components/PageBackground.vue")['default']
export const SectionDivider: typeof import("../components/SectionDivider.vue")['default']
export const AppLogo: typeof import("../components/common/AppLogo.vue")['default']
export const ThemeToggle: typeof import("../components/common/ThemeToggle.vue")['default']
export const AppFooter: typeof import("../components/layout/AppFooter.vue")['default']
export const AppHeader: typeof import("../components/layout/AppHeader.vue")['default']
export const LanguageSwitcher: typeof import("../components/layout/LanguageSwitcher.vue")['default']
export const ComparisonSection: typeof import("../components/sections/ComparisonSection.vue")['default']
export const DownloadSection: typeof import("../components/sections/DownloadSection.vue")['default']
export const FAQSection: typeof import("../components/sections/FAQSection.vue")['default']
export const FeaturedRulesSection: typeof import("../components/sections/FeaturedRulesSection.vue")['default']
export const FeaturesSection: typeof import("../components/sections/FeaturesSection.vue")['default']
export const HeroSection: typeof import("../components/sections/HeroSection.vue")['default']
export const FeatureCard: typeof import("../components/ui/FeatureCard.vue")['default']
export const HeroDemo: typeof import("../components/ui/HeroDemo.vue")['default']
export const NuxtWelcome: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/welcome.vue")['default']
export const NuxtLayout: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-layout")['default']
export const NuxtErrorBoundary: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-error-boundary.vue")['default']
export const ClientOnly: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/client-only")['default']
export const DevOnly: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/dev-only")['default']
export const ServerPlaceholder: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/server-placeholder")['default']
export const NuxtLink: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-link")['default']
export const NuxtLoadingIndicator: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-loading-indicator")['default']
export const NuxtTime: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-time.vue")['default']
export const NuxtRouteAnnouncer: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-route-announcer")['default']
export const NuxtImg: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtImg']
export const NuxtPicture: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtPicture']
export const NuxtLinkLocale: typeof import("../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/NuxtLinkLocale")['default']
export const SwitchLocalePathLink: typeof import("../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/SwitchLocalePathLink")['default']
export const Icon: typeof import("../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/Icon.vue")['default']
export const IconCSS: typeof import("../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/IconCSS.vue")['default']
export const NuxtPage: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/pages/runtime/page")['default']
export const NoScript: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['NoScript']
export const Link: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Link']
export const Base: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Base']
export const Title: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Title']
export const Meta: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Meta']
export const Style: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Style']
export const Head: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Head']
export const Html: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Html']
export const Body: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Body']
export const NuxtIsland: typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-island")['default']
export const LazyPageBackground: LazyComponent<typeof import("../components/PageBackground.vue")['default']>
export const LazySectionDivider: LazyComponent<typeof import("../components/SectionDivider.vue")['default']>
export const LazyAppLogo: LazyComponent<typeof import("../components/common/AppLogo.vue")['default']>
export const LazyThemeToggle: LazyComponent<typeof import("../components/common/ThemeToggle.vue")['default']>
export const LazyAppFooter: LazyComponent<typeof import("../components/layout/AppFooter.vue")['default']>
export const LazyAppHeader: LazyComponent<typeof import("../components/layout/AppHeader.vue")['default']>
export const LazyLanguageSwitcher: LazyComponent<typeof import("../components/layout/LanguageSwitcher.vue")['default']>
export const LazyComparisonSection: LazyComponent<typeof import("../components/sections/ComparisonSection.vue")['default']>
export const LazyDownloadSection: LazyComponent<typeof import("../components/sections/DownloadSection.vue")['default']>
export const LazyFAQSection: LazyComponent<typeof import("../components/sections/FAQSection.vue")['default']>
export const LazyFeaturedRulesSection: LazyComponent<typeof import("../components/sections/FeaturedRulesSection.vue")['default']>
export const LazyFeaturesSection: LazyComponent<typeof import("../components/sections/FeaturesSection.vue")['default']>
export const LazyHeroSection: LazyComponent<typeof import("../components/sections/HeroSection.vue")['default']>
export const LazyFeatureCard: LazyComponent<typeof import("../components/ui/FeatureCard.vue")['default']>
export const LazyHeroDemo: LazyComponent<typeof import("../components/ui/HeroDemo.vue")['default']>
export const LazyNuxtWelcome: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/welcome.vue")['default']>
export const LazyNuxtLayout: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-layout")['default']>
export const LazyNuxtErrorBoundary: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-error-boundary.vue")['default']>
export const LazyClientOnly: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/client-only")['default']>
export const LazyDevOnly: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/dev-only")['default']>
export const LazyServerPlaceholder: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/server-placeholder")['default']>
export const LazyNuxtLink: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-link")['default']>
export const LazyNuxtLoadingIndicator: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-loading-indicator")['default']>
export const LazyNuxtTime: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-time.vue")['default']>
export const LazyNuxtRouteAnnouncer: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-route-announcer")['default']>
export const LazyNuxtImg: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtImg']>
export const LazyNuxtPicture: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-stubs")['NuxtPicture']>
export const LazyNuxtLinkLocale: LazyComponent<typeof import("../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/NuxtLinkLocale")['default']>
export const LazySwitchLocalePathLink: LazyComponent<typeof import("../node_modules/.pnpm/@nuxtjs+i18n@9.5.6_eslint@9.39.4_rollup@4.60.1_vue@3.5.31/node_modules/@nuxtjs/i18n/dist/runtime/components/SwitchLocalePathLink")['default']>
export const LazyIcon: LazyComponent<typeof import("../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/Icon.vue")['default']>
export const LazyIconCSS: LazyComponent<typeof import("../node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/IconCSS.vue")['default']>
export const LazyNuxtPage: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/pages/runtime/page")['default']>
export const LazyNoScript: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['NoScript']>
export const LazyLink: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Link']>
export const LazyBase: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Base']>
export const LazyTitle: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Title']>
export const LazyMeta: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Meta']>
export const LazyStyle: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Style']>
export const LazyHead: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Head']>
export const LazyHtml: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Html']>
export const LazyBody: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/head/runtime/components")['Body']>
export const LazyNuxtIsland: LazyComponent<typeof import("../node_modules/.pnpm/nuxt@3.21.2_@emnapi+core@1.9.2_@emnapi+runtime@1.9.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_r_xotflepmc45our5vt3zofsrpmm/node_modules/nuxt/dist/app/components/nuxt-island")['default']>

export const componentNames: string[]
