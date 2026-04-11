<script setup lang="ts">
usePageSeo('meta.homeTitle', 'meta.homeDescription');
useTrackSections();
const { containerRef } = useParallaxSections();
</script>

<template>
  <div ref="containerRef" class="page">
    <PageBackground />
    <HeroSection />
    <SectionDivider />
    <LazyFeaturesSection />
    <SectionDivider :flip="true" />
    <LazyFeaturedRulesSection />
    <SectionDivider />
    <LazyComparisonSection />
    <SectionDivider :flip="true" />
    <LazyDownloadSection />
    <SectionDivider />
    <LazyFAQSection />
  </div>
</template>
