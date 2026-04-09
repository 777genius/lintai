import vuetify from 'vite-plugin-vuetify';
import { generateI18nRoutes, supportedLocales } from './data/i18n';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
declare const process: any;

const siteUrl = process.env.NUXT_PUBLIC_SITE_URL || 'https://777genius.github.io/lintai';
const githubRepo = process.env.NUXT_PUBLIC_GITHUB_REPO || '777genius/lintai';
const githubReleasesUrl = `https://github.com/${githubRepo}/releases`;
const docsUrl = process.env.NUXT_PUBLIC_DOCS_URL || 'https://777genius.github.io/lintai/docs/';
const quickstartUrl = process.env.NUXT_PUBLIC_QUICKSTART_URL || docsUrl;
const baseURL = process.env.NUXT_APP_BASE_URL || '/';

export default defineNuxtConfig({
  compatibilityDate: '2026-01-19',
  ssr: true,
  experimental: {
    // Work around the current Nuxt dev-time #app-manifest regression.
    appManifest: false,
  },
  app: {
    baseURL,
    head: {
      link: [
        { rel: 'icon', href: `${baseURL}favicon.ico`, sizes: 'any' },
        { rel: 'icon', type: 'image/png', sizes: '32x32', href: `${baseURL}favicon-32.png` },
        { rel: 'icon', type: 'image/svg+xml', href: `${baseURL}icon.svg` },
        { rel: 'preconnect', href: 'https://fonts.googleapis.com' },
        { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' },
        {
          rel: 'preload',
          href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap',
          as: 'style',
        },
        {
          rel: 'stylesheet',
          href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap',
        },
      ],
    },
  },
  modules: ['@pinia/nuxt', '@nuxtjs/i18n', '@vueuse/nuxt', 'nuxt-icon', '@nuxt/eslint'],
  css: ['~/assets/styles/main.scss'],
  components: [
    {
      path: '~/components',
      pathPrefix: false,
    },
  ],
  build: {
    transpile: ['vuetify'],
  },
  vite: {
    plugins: [vuetify({ autoImport: true })],
  },
  nitro: {
    compressPublicAssets: true,
    prerender: {
      routes: [...generateI18nRoutes(), '/sitemap.xml', '/robots.txt'],
    },
  },
  routeRules: {
    '/_nuxt/**': {
      headers: { 'Cache-Control': 'public, max-age=31536000, immutable' },
    },
  },
  i18n: {
    restructureDir: false,
    locales: supportedLocales,
    defaultLocale: 'en',
    strategy: 'prefix_except_default',
    lazy: true,
    langDir: 'locales',
    bundle: {
      optimizeTranslationDirective: false,
    },
    experimental: {
      generatedLocaleFilePathFormat: 'off',
    },
    detectBrowserLanguage: {
      useCookie: true,
      cookieKey: 'i18n_redirected',
      redirectOn: 'root',
      alwaysRedirect: false,
      fallbackLocale: 'en',
    },
  },
  // @ts-expect-error - field provided by nuxt modules
  site: {
    url: siteUrl,
    name: 'lintai',
  },
  runtimeConfig: {
    public: {
      siteUrl,
      githubRepo,
      githubReleasesUrl,
      docsUrl,
      quickstartUrl,
    },
  },
});
