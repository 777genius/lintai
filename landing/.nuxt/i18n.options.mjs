
// @ts-nocheck


export const localeCodes =  [
  "en",
  "ru"
]

export const localeLoaders = {
  en: [
    {
      key: "locale_en_46json_5a97b9b6",
      load: () => import("#nuxt-i18n/5a97b9b6" /* webpackChunkName: "locale_en_46json_5a97b9b6" */),
      cache: true
    }
  ],
  ru: [
    {
      key: "locale_ru_46json_ece7a24e",
      load: () => import("#nuxt-i18n/ece7a24e" /* webpackChunkName: "locale_ru_46json_ece7a24e" */),
      cache: true
    }
  ]
}

export const vueI18nConfigs = []

export const nuxtI18nOptions = {
  restructureDir: false,
  experimental: {
    localeDetector: "",
    switchLocalePathLinkSSR: false,
    autoImportTranslationFunctions: false,
    typedPages: true,
    typedOptionsAndMessages: false,
    generatedLocaleFilePathFormat: "off",
    alternateLinkCanonicalQueries: false,
    hmr: true
  },
  bundle: {
    compositionOnly: true,
    runtimeOnly: false,
    fullInstall: true,
    dropMessageCompiler: false,
    optimizeTranslationDirective: false
  },
  compilation: {
    strictMessage: true,
    escapeHtml: false
  },
  customBlocks: {
    defaultSFCLang: "json",
    globalSFCScope: false
  },
  locales: [
    {
      code: "en",
      iso: "en-US",
      name: "English",
      flag: "🇺🇸"
    },
    {
      code: "ru",
      iso: "ru-RU",
      name: "Русский",
      flag: "🇷🇺"
    }
  ],
  defaultLocale: "en",
  defaultDirection: "ltr",
  routesNameSeparator: "___",
  trailingSlash: false,
  defaultLocaleRouteNameSuffix: "default",
  strategy: "prefix_except_default",
  lazy: true,
  langDir: "locales",
  rootRedirect: undefined,
  detectBrowserLanguage: {
    alwaysRedirect: false,
    cookieCrossOrigin: false,
    cookieDomain: null,
    cookieKey: "i18n_redirected",
    cookieSecure: false,
    fallbackLocale: "en",
    redirectOn: "root",
    useCookie: true
  },
  differentDomains: false,
  baseUrl: "",
  customRoutes: "page",
  pages: {},
  skipSettingLocaleOnNavigate: false,
  types: "composition",
  debug: false,
  parallelPlugin: false,
  multiDomainLocales: false,
  i18nModules: []
}

export const normalizedLocales = [
  {
    code: "en",
    iso: "en-US",
    name: "English",
    flag: "🇺🇸"
  },
  {
    code: "ru",
    iso: "ru-RU",
    name: "Русский",
    flag: "🇷🇺"
  }
]

export const NUXT_I18N_MODULE_ID = "@nuxtjs/i18n"
export const parallelPlugin = false
export const isSSG = true
export const hasPages = true

export const DEFAULT_COOKIE_KEY = "i18n_redirected"
export const DEFAULT_DYNAMIC_PARAMS_KEY = "nuxtI18nInternal"
export const SWITCH_LOCALE_PATH_LINK_IDENTIFIER = "nuxt-i18n-slp"
/** client **/

/** client-end **/