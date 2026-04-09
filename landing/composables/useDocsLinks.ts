import { computed } from 'vue';

export const useDocsLinks = () => {
  const config = useRuntimeConfig();

  const docsUrl = computed(
    () => config.public.docsUrl || 'https://777genius.github.io/lintai/docs/',
  );
  const quickstartUrl = computed(() => config.public.quickstartUrl || docsUrl.value);
  const supportBoundaryUrl = computed(
    () => 'https://777genius.github.io/lintai/docs/POSITIONING_AND_SCOPE.html',
  );
  const betaReleaseUrl = computed(
    () => 'https://777genius.github.io/lintai/docs/PUBLIC_BETA_RELEASE.html',
  );

  return { docsUrl, quickstartUrl, supportBoundaryUrl, betaReleaseUrl };
};
