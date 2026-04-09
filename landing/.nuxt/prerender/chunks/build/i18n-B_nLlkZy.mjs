import { computed } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { e as useRuntimeConfig } from './server.mjs';

const useDocsLinks = () => {
  const config = useRuntimeConfig();
  const docsUrl = computed(
    () => config.public.docsUrl || "https://777genius.github.io/lintai/docs/"
  );
  const quickstartUrl = computed(() => config.public.quickstartUrl || docsUrl.value);
  const supportBoundaryUrl = computed(
    () => "https://777genius.github.io/lintai/docs/POSITIONING_AND_SCOPE.html"
  );
  const betaReleaseUrl = computed(
    () => "https://777genius.github.io/lintai/docs/PUBLIC_BETA_RELEASE.html"
  );
  return { docsUrl, quickstartUrl, supportBoundaryUrl, betaReleaseUrl };
};
const supportedLocales = [
  { code: "en", iso: "en-US", name: "English", flag: "\u{1F1FA}\u{1F1F8}", file: "en.json" },
  { code: "ru", iso: "ru-RU", name: "\u0420\u0443\u0441\u0441\u043A\u0438\u0439", flag: "\u{1F1F7}\u{1F1FA}", file: "ru.json" }
];
const defaultLocale = "en";

export { defaultLocale as d, supportedLocales as s, useDocsLinks as u };
//# sourceMappingURL=i18n-B_nLlkZy.mjs.map
