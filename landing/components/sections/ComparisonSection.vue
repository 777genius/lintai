<script setup lang="ts">
import {
  mdiCheckDecagramOutline,
  mdiFileSearchOutline,
  mdiLanConnect,
  mdiPlayCircleOutline,
  mdiRadar,
  mdiShieldCheckOutline,
} from '@mdi/js';

const { content } = useLandingContent();
const { t } = useI18n();

const highlightIds = ['offline', 'signal', 'boundary', 'scope'] as const;

const comparisonVisuals = {
  offline: { icon: mdiPlayCircleOutline, accent: '#00f0ff' },
  signal: { icon: mdiFileSearchOutline, accent: '#ff00ff' },
  scope: { icon: mdiRadar, accent: '#39ff14' },
  ci: { icon: mdiLanConnect, accent: '#7dd3fc' },
  boundary: { icon: mdiShieldCheckOutline, accent: '#ffd166' },
  installed: { icon: mdiCheckDecagramOutline, accent: '#c084fc' },
} as const;

const highlightRows = computed(() =>
  highlightIds
    .map((id) => content.value.comparisonRows.find((row) => row.id === id))
    .filter((row): row is NonNullable<typeof row> => row !== null && row !== undefined)
    .map((row) => ({
      ...row,
      icon: comparisonVisuals[row.id as keyof typeof comparisonVisuals]?.icon ?? mdiShieldCheckOutline,
      accent:
        comparisonVisuals[row.id as keyof typeof comparisonVisuals]?.accent ?? '#00f0ff',
    })),
);

const secondaryRows = computed(() =>
  content.value.comparisonRows
    .filter((row) => !highlightIds.includes(row.id as (typeof highlightIds)[number]))
    .map((row) => ({
      ...row,
      icon: comparisonVisuals[row.id as keyof typeof comparisonVisuals]?.icon ?? mdiShieldCheckOutline,
      accent:
        comparisonVisuals[row.id as keyof typeof comparisonVisuals]?.accent ?? '#00f0ff',
    })),
);
</script>

<template>
  <section id="comparison" class="comparison-section section anchor-offset">
    <v-container>
      <div class="comparison-section__header">
        <h2 class="comparison-section__title">
          {{ t('comparison.sectionTitle') }}
        </h2>
        <p class="comparison-section__subtitle">
          {{ t('comparison.sectionSubtitle') }}
        </p>
      </div>

      <div class="comparison-section__grid">
        <article
          v-for="row in highlightRows"
          :key="row.id"
          class="comparison-card"
          :style="{ '--accent': row.accent }"
        >
          <div class="comparison-card__top">
            <div class="comparison-card__icon-wrap">
              <div class="comparison-card__icon-bg" />
              <v-icon :icon="row.icon" size="22" class="comparison-card__icon" />
            </div>
            <h3 class="comparison-card__title">{{ row.feature }}</h3>
          </div>

          <p class="comparison-card__body">{{ row.lintai.note }}</p>

          <div class="comparison-card__contrast">
            <div class="comparison-card__contrast-label">
              {{ t('comparison.withoutDedicatedCheck') }}
            </div>
            <p class="comparison-card__contrast-copy">{{ row.manualReview.note }}</p>
          </div>
        </article>
      </div>

      <div v-if="secondaryRows.length" class="comparison-section__secondary">
        <div class="comparison-section__secondary-label">
          {{ t('comparison.alsoUseful') }}
        </div>

        <div class="comparison-section__secondary-grid">
          <article
            v-for="row in secondaryRows"
            :key="row.id"
            class="comparison-secondary-card"
            :style="{ '--accent': row.accent }"
          >
            <div class="comparison-secondary-card__head">
              <v-icon :icon="row.icon" size="18" class="comparison-secondary-card__icon" />
              <h3 class="comparison-secondary-card__title">{{ row.feature }}</h3>
            </div>
            <p class="comparison-secondary-card__body">{{ row.lintai.note }}</p>
          </article>
        </div>
      </div>
    </v-container>
  </section>
</template>

<style scoped>
.comparison-section {
  position: relative;
}

.comparison-section__header {
  text-align: center;
  max-width: 760px;
  margin: 0 auto 48px;
}

.comparison-section__title {
  font-size: 2.4rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.15;
  margin-bottom: 16px;
  background: linear-gradient(135deg, #e0e6ff 0%, #39ff14 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.comparison-section__subtitle {
  font-size: 1.08rem;
  color: #8892b0;
  line-height: 1.65;
  margin: 0;
}

.comparison-section__grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 22px;
}

.comparison-card {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-height: 100%;
  padding: 22px;
  border-radius: 22px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: linear-gradient(180deg, rgba(11, 15, 25, 0.94), rgba(8, 11, 18, 0.86));
  box-shadow:
    0 18px 60px rgba(0, 0, 0, 0.22),
    inset 0 1px 0 rgba(255, 255, 255, 0.04);
}

.comparison-card__top {
  display: flex;
  align-items: center;
  gap: 12px;
}

.comparison-card__icon-wrap {
  position: relative;
  width: 42px;
  height: 42px;
  min-width: 42px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.comparison-card__icon-bg {
  position: absolute;
  inset: 0;
  border-radius: 12px;
  background: var(--accent);
  opacity: 0.16;
}

.comparison-card__icon {
  position: relative;
  color: var(--accent) !important;
}

.comparison-card__title {
  margin: 0;
  font-size: 1.08rem;
  line-height: 1.35;
  color: #e2e8f0;
}

.comparison-card__body {
  margin: 0;
  color: #c5d0e9;
  line-height: 1.65;
  font-size: 0.96rem;
}

.comparison-card__contrast {
  margin-top: auto;
  padding-top: 12px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}

.comparison-card__contrast-label {
  font-size: 0.68rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent);
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 6px;
}

.comparison-card__contrast-copy {
  margin: 0;
  color: #94a3c4;
  line-height: 1.55;
  font-size: 0.86rem;
}

.comparison-section__secondary {
  margin-top: 20px;
  padding: 18px 20px 0;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
}

.comparison-section__secondary-label {
  margin-bottom: 14px;
  font-size: 0.76rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: #8fa1c8;
  font-family: 'JetBrains Mono', monospace;
}

.comparison-section__secondary-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

.comparison-secondary-card {
  padding: 16px 18px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.06);
}

.comparison-secondary-card__head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

.comparison-secondary-card__icon {
  color: var(--accent) !important;
}

.comparison-secondary-card__title {
  margin: 0;
  font-size: 0.96rem;
  color: #dbe5ff;
  line-height: 1.4;
}

.comparison-secondary-card__body {
  margin: 0;
  color: #9fb0d3;
  line-height: 1.55;
  font-size: 0.88rem;
}

.v-theme--light .comparison-section__title {
  background: linear-gradient(135deg, #0f172a 0%, #15803d 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.v-theme--light .comparison-section__subtitle {
  color: #475569;
}

.v-theme--light .comparison-card {
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.95), rgba(248, 250, 252, 0.94));
  border-color: rgba(15, 23, 42, 0.08);
  box-shadow:
    0 18px 50px rgba(15, 23, 42, 0.08),
    inset 0 1px 0 rgba(255, 255, 255, 0.9);
}

.v-theme--light .comparison-card__title {
  color: #0f172a;
}

.v-theme--light .comparison-card__body {
  color: #475569;
}

.v-theme--light .comparison-card__contrast {
  border-top-color: rgba(15, 23, 42, 0.08);
}

.v-theme--light .comparison-card__contrast-copy {
  color: #64748b;
}

.v-theme--light .comparison-section__secondary {
  border-top-color: rgba(15, 23, 42, 0.08);
}

.v-theme--light .comparison-secondary-card {
  background: rgba(255, 255, 255, 0.82);
  border-color: rgba(15, 23, 42, 0.08);
}

.v-theme--light .comparison-secondary-card__title {
  color: #0f172a;
}

.v-theme--light .comparison-secondary-card__body {
  color: #64748b;
}

@media (max-width: 960px) {
  .comparison-section__title {
    font-size: 1.9rem;
  }

  .comparison-section__grid,
  .comparison-section__secondary-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .comparison-section__title {
    font-size: 1.65rem;
  }

  .comparison-section__header {
    margin-bottom: 36px;
  }

  .comparison-card,
  .comparison-secondary-card {
    padding: 18px;
  }

  .comparison-section__secondary {
    padding-inline: 0;
  }
}
</style>
