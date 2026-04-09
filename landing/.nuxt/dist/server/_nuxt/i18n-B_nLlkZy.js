import { computed } from "vue";
import { e as useRuntimeConfig } from "../server.mjs";
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
  { code: "en", iso: "en-US", name: "English", flag: "🇺🇸", file: "en.json" },
  { code: "ru", iso: "ru-RU", name: "Русский", flag: "🇷🇺", file: "ru.json" }
];
const defaultLocale = "en";
export {
  defaultLocale as d,
  supportedLocales as s,
  useDocsLinks as u
};
//# sourceMappingURL=i18n-B_nLlkZy.js.map
