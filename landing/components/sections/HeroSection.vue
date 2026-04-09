<script setup lang="ts">
import { mdiOpenSourceInitiative, mdiRobotOutline, mdiViewDashboardOutline } from '@mdi/js';

const { content } = useLandingContent();
const { t, locale } = useI18n();
const config = useRuntimeConfig();
const githubUrl = `https://github.com/${config.public.githubRepo}`;
const { docsUrl } = useDocsLinks();
const { data: releaseData } = useReleaseDownloads();

const releaseVersion = computed(() => releaseData.value?.version || null);
const releaseDate = computed(() => {
  const raw = releaseData.value?.pubDate;
  if (!raw) return null;
  return formatReleaseDate(raw, locale.value);
});
</script>

<template>
  <section id="hero" class="hero-section section anchor-offset">
    <v-container class="hero-section__container">
      <div class="hero-section__grid">
        <div class="hero-section__content">
          <h1 class="hero-section__title">
            <span class="hero-section__logo">L</span>
            {{ content.hero.title }}
          </h1>

          <p class="hero-section__subtitle">
            {{ content.hero.subtitle }}
          </p>

          <div class="hero-section__actions">
            <v-btn
              variant="flat"
              size="large"
              :href="githubUrl"
              target="_blank"
              rel="noopener noreferrer"
              class="hero-section__btn-primary"
            >
              {{ t('hero.primaryCta') }}
            </v-btn>
            <v-btn
              variant="outlined"
              size="large"
              href="#featured-rules"
              class="hero-section__btn-secondary"
            >
              {{ t('hero.secondaryCta') }}
            </v-btn>
            <v-btn variant="tonal" size="large" :href="docsUrl" class="hero-section__btn-tertiary">
              {{ t('hero.docsCta') }}
            </v-btn>
          </div>

          <div class="hero-section__meta-row">
            <div v-if="releaseVersion" class="hero-section__release-badge">
              {{ t('hero.latestRelease') }} · v{{ releaseVersion
              }}<template v-if="releaseDate"> · {{ releaseDate }}</template>
            </div>
          </div>

          <div class="hero-section__trust">
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiRobotOutline" />
              <span>{{ t('hero.trust.oneRepo') }}</span>
            </div>
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiViewDashboardOutline" />
              <span>{{ t('hero.trust.validated') }}</span>
            </div>
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiOpenSourceInitiative" />
              <span>{{ t('hero.trust.openSource') }}</span>
            </div>
          </div>

          <div class="hero-section__fact-grid">
            <div class="hero-section__fact-card">
              <span class="hero-section__fact-label">{{ t('hero.factFocusLabel') }}</span>
              <p class="hero-section__fact-copy">{{ t('hero.factFocusBody') }}</p>
            </div>
            <div class="hero-section__fact-card">
              <span class="hero-section__fact-label">{{ t('hero.factOutputsLabel') }}</span>
              <p class="hero-section__fact-copy">{{ t('hero.factOutputsBody') }}</p>
            </div>
          </div>
        </div>

        <div class="hero-section__demo-col">
          <div class="hero-section__preview">
            <div class="hero-section__preview-glow" />
            <LazyHeroDemo />
          </div>
        </div>
      </div>
    </v-container>
  </section>
</template>

<style scoped>
.hero-section {
  position: relative;
  min-height: min(760px, calc(100svh - 64px));
  display: flex;
  align-items: flex-start;
  padding-top: 20px;
  padding-bottom: 40px;
}

.hero-section__container {
  position: relative;
  z-index: 1;
}

.hero-section__grid {
  display: grid;
  grid-template-columns: minmax(0, 0.95fr) minmax(460px, 600px);
  gap: clamp(20px, 2.4vw, 40px);
  align-items: center;
}

.hero-section__content {
  position: relative;
  z-index: 2;
  max-width: 620px;
}

.hero-section__title {
  font-size: clamp(3rem, 5vw, 4.7rem);
  font-weight: 800;
  letter-spacing: -0.04em;
  line-height: 1.1;
  margin-bottom: 20px;
  background: linear-gradient(135deg, #e0e6ff 0%, #00f0ff 50%, #ff00ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  display: flex;
  align-items: center;
  gap: 16px;
  white-space: nowrap;
}

.hero-section__logo {
  width: 56px;
  height: 56px;
  border-radius: 14px;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #00f0ff, #ff00ff 55%, #39ff14);
  color: #0a0a0f;
  font-size: 1.85rem;
  line-height: 1;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 800;
  box-shadow: 0 10px 30px rgba(0, 240, 255, 0.2);
  -webkit-text-fill-color: initial;
}

.hero-section__subtitle {
  font-size: 1.08rem;
  line-height: 1.75;
  color: #a8b4d1;
  max-width: 58ch;
  margin-bottom: 28px;
}

.hero-section__actions {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  margin-bottom: 18px;
}

.hero-section__meta-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 14px;
  margin-bottom: 22px;
}

.hero-section__release-badge {
  font-size: 0.78rem;
  font-weight: 500;
  color: #8892b0;
  font-family: 'JetBrains Mono', monospace;
}

.hero-section__btn-primary {
  background: linear-gradient(135deg, #00f0ff, #ff00ff) !important;
  color: #0a0a0f !important;
  font-weight: 700 !important;
  letter-spacing: 0.02em !important;
  box-shadow: 0 4px 20px rgba(0, 240, 255, 0.3) !important;
  transition: all 0.3s ease !important;
}

.hero-section__btn-primary:hover {
  box-shadow: 0 6px 30px rgba(0, 240, 255, 0.5) !important;
  transform: translateY(-1px) !important;
}

.hero-section__btn-secondary {
  border-color: rgba(0, 240, 255, 0.3) !important;
  color: #00f0ff !important;
  font-weight: 600 !important;
  transition: all 0.3s ease !important;
}

.hero-section__btn-secondary:hover {
  border-color: rgba(0, 240, 255, 0.5) !important;
  background: rgba(0, 240, 255, 0.06) !important;
}

.hero-section__btn-tertiary {
  background: rgba(255, 255, 255, 0.04) !important;
  color: #d9e2ff !important;
  font-weight: 600 !important;
  border: 1px solid rgba(217, 226, 255, 0.12) !important;
  transition: all 0.3s ease !important;
}

.hero-section__btn-tertiary:hover {
  background: rgba(255, 255, 255, 0.08) !important;
  border-color: rgba(217, 226, 255, 0.24) !important;
  transform: translateY(-1px) !important;
}

.hero-section__trust {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 24px;
}

.hero-section__trust-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 12px;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.03);
  font-size: 0.82rem;
  font-weight: 500;
  color: #9aa7c7;
}

.hero-section__trust-icon {
  color: #00f0ff;
  opacity: 0.8;
}

.hero-section__fact-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.hero-section__fact-card {
  border-radius: 20px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.04), rgba(255, 255, 255, 0.02)),
    rgba(8, 11, 18, 0.72);
  padding: 18px;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.hero-section__fact-label {
  display: block;
  margin-bottom: 10px;
  color: #8fa1c8;
  font-size: 0.72rem;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  font-family: 'JetBrains Mono', monospace;
}

.hero-section__fact-copy {
  margin: 0;
  color: #d7e3ff;
  line-height: 1.6;
  font-size: 0.96rem;
}

.hero-section__demo-col {
  position: relative;
}

.hero-section__preview {
  position: relative;
  width: 100%;
  max-width: 600px;
  margin-left: auto;
}

.hero-section__preview-glow {
  position: absolute;
  inset: -24px -18px -32px;
  background:
    radial-gradient(circle at 20% 30%, rgba(0, 240, 255, 0.16), transparent 36%),
    radial-gradient(circle at 80% 18%, rgba(255, 0, 255, 0.14), transparent 34%),
    radial-gradient(circle at 60% 88%, rgba(57, 255, 20, 0.1), transparent 30%);
  filter: blur(36px);
  pointer-events: none;
}

.hero-demo-fallback {
  aspect-ratio: 16 / 10;
  border-radius: 18px;
  background: rgba(10, 10, 15, 0.75);
  border: 1px solid rgba(0, 240, 255, 0.12);
}

@keyframes heroFadeIn {
  from {
    opacity: 0;
    transform: translateY(16px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

@keyframes heroSlideUp {
  from {
    opacity: 0;
    transform: translateY(28px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.v-theme--light .hero-section__title {
  background: linear-gradient(135deg, #1e293b 0%, #0891b2 55%, #7c3aed 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.v-theme--light .hero-section__subtitle,
.v-theme--light .hero-section__trust-item,
.v-theme--light .hero-section__release-badge {
  color: #64748b;
}

@media (max-width: 960px) {
  .hero-section {
    min-height: auto;
    padding-top: 12px;
    padding-bottom: 28px;
  }

  .hero-section__grid {
    grid-template-columns: 1fr;
    gap: 28px;
  }

  .hero-section__title {
    font-size: 2.4rem;
    white-space: normal;
  }

  .hero-section__subtitle {
    font-size: 1.05rem;
    margin-bottom: 28px;
  }

  .hero-section__fact-grid {
    grid-template-columns: 1fr;
  }

  .hero-section__preview {
    max-width: none;
    margin-left: 0;
  }
}

@media (max-width: 600px) {
  .hero-section {
    padding-top: 8px;
    padding-bottom: 20px;
  }

  .hero-section__title {
    font-size: 2rem;
    gap: 12px;
  }

  .hero-section__logo {
    width: 48px;
    height: 48px;
    font-size: 1.2rem;
  }

  .hero-section__actions :deep(.v-btn) {
    width: 100%;
  }
}
</style>
