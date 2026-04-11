<script setup lang="ts">
import { mdiArrowTopRight, mdiCodeBracesBox, mdiLockOutline, mdiShieldCheckOutline } from '@mdi/js';

const { content } = useLandingContent();
const { t, locale } = useI18n();
const config = useRuntimeConfig();
const githubUrl = `https://github.com/${config.public.githubRepo}`;
const { data: releaseData, quickRunCommand } = useReleaseDownloads();
const compactTitle = computed(() => locale.value === 'ru');
const copiedQuickRun = ref(false);

let quickRunTimer: ReturnType<typeof setTimeout> | null = null;

onBeforeUnmount(() => {
  if (quickRunTimer) {
    clearTimeout(quickRunTimer);
  }
});

const releaseVersion = computed(() => releaseData.value?.version || null);
const releaseDate = computed(() => {
  const raw = releaseData.value?.pubDate;
  if (!raw) return null;
  return formatReleaseDate(raw, locale.value);
});

const fallbackCopy = async (text: string) => {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.setAttribute('readonly', '');
  textarea.style.position = 'absolute';
  textarea.style.left = '-9999px';
  document.body.appendChild(textarea);
  textarea.select();
  document.execCommand('copy');
  document.body.removeChild(textarea);
};

const copyQuickRun = async () => {
  if (!import.meta.client || !quickRunCommand) {
    return;
  }

  const text = quickRunCommand.trim();

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      await fallbackCopy(text);
    }
  } catch {
    await fallbackCopy(text);
  }

  copiedQuickRun.value = true;

  if (quickRunTimer) {
    clearTimeout(quickRunTimer);
  }

  quickRunTimer = setTimeout(() => {
    copiedQuickRun.value = false;
  }, 1800);
};
</script>

<template>
  <section id="hero" class="hero-section section anchor-offset">
    <v-container class="hero-section__container">
      <div class="hero-section__grid">
        <div class="hero-section__content">
          <h1 class="hero-section__title" :class="{ 'hero-section__title--compact': compactTitle }">
            {{ content.hero.title }}
          </h1>

          <p class="hero-section__subtitle">
            <span>{{ content.hero.subtitle }}</span>
            <template v-if="content.hero.sourceLabel && content.hero.sourceHref">
              {{ ' ' }}
              <a
                :href="content.hero.sourceHref"
                target="_blank"
                rel="noopener noreferrer"
                class="hero-section__source-link"
              >
                {{ content.hero.sourceLabel }}
              </a>
            </template>
          </p>

          <p class="hero-section__support-line">
            {{ content.hero.supportLine }}
          </p>

          <div v-if="quickRunCommand" class="hero-section__quick-run">
            <div class="hero-section__quick-run-head">
              <span class="hero-section__quick-run-label">{{ t('hero.quickRunLabel') }}</span>
              <button type="button" class="hero-section__quick-run-copy" @click="copyQuickRun">
                {{ copiedQuickRun ? t('download.copied') : t('download.copy') }}
              </button>
            </div>
            <pre class="hero-section__quick-run-command"><code>{{ quickRunCommand }}</code></pre>
          </div>

          <div class="hero-section__actions">
            <div class="hero-section__cta-row">
              <v-btn variant="flat" size="large" href="#download" class="hero-section__btn-primary">
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
            </div>

            <a
              :href="githubUrl"
              target="_blank"
              rel="noopener noreferrer"
              class="hero-section__subaction"
            >
              <span>{{ t('hero.docsCta') }}</span>
              <v-icon size="16" :icon="mdiArrowTopRight" />
            </a>
          </div>

          <div class="hero-section__meta-row">
            <div v-if="releaseVersion" class="hero-section__release-badge">
              {{ t('hero.latestRelease') }} · v{{ releaseVersion
              }}<template v-if="releaseDate"> · {{ releaseDate }}</template>
            </div>
          </div>

          <div class="hero-section__trust">
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiLockOutline" />
              <span>{{ t('hero.trust.oneRepo') }}</span>
            </div>
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiShieldCheckOutline" />
              <span>{{ t('hero.trust.validated') }}</span>
            </div>
            <div class="hero-section__trust-item">
              <v-icon size="16" class="hero-section__trust-icon" :icon="mdiCodeBracesBox" />
              <span>{{ t('hero.trust.openSource') }}</span>
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
  min-height: auto;
  display: flex;
  align-items: flex-start;
  padding-top: 20px;
  padding-bottom: 28px;
}

.hero-section__container {
  position: relative;
  z-index: 1;
}

.hero-section__grid {
  display: grid;
  grid-template-columns: 1fr;
  gap: clamp(20px, 2.2vw, 30px);
  align-items: start;
}

.hero-section__content {
  position: relative;
  z-index: 2;
  max-width: 980px;
  min-height: auto;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  padding-top: clamp(12px, 2vh, 24px);
}

.hero-section__title {
  font-size: clamp(2.8rem, 4vw, 3.8rem);
  font-weight: 800;
  letter-spacing: -0.04em;
  line-height: 1.03;
  margin-bottom: 20px;
  background: linear-gradient(135deg, #e0e6ff 0%, #00f0ff 50%, #ff00ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  max-width: none;
  text-wrap: balance;
}

.hero-section__title--compact {
  letter-spacing: -0.05em;
  font-size: clamp(2.55rem, 3.35vw, 3.35rem);
}

.hero-section__subtitle {
  font-size: 1.08rem;
  line-height: 1.75;
  color: #a8b4d1;
  max-width: 58ch;
  margin-bottom: 14px;
}

.hero-section__source-link {
  color: #8ae8ff;
  text-decoration: underline;
  text-underline-offset: 0.18em;
  transition: color 0.2s ease;
}

.hero-section__source-link:hover {
  color: #c5f4ff;
}

.hero-section__support-line {
  margin: 0 0 28px;
  color: #d3ddf9;
  font-size: 0.96rem;
  line-height: 1.65;
  max-width: 62ch;
}

.hero-section__quick-run {
  width: min(100%, 720px);
  margin: 0 0 26px;
  padding: 14px 16px 16px;
  border-radius: 18px;
  border: 1px solid rgba(0, 240, 255, 0.12);
  background:
    linear-gradient(180deg, rgba(0, 240, 255, 0.05), rgba(255, 255, 255, 0.02)),
    rgba(9, 13, 22, 0.86);
  backdrop-filter: blur(12px);
}

.hero-section__quick-run-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}

.hero-section__quick-run-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #8fa1c8;
}

.hero-section__quick-run-copy {
  appearance: none;
  border: 1px solid rgba(0, 240, 255, 0.2);
  background: rgba(0, 240, 255, 0.06);
  color: #8ae8ff;
  border-radius: 999px;
  padding: 6px 12px;
  font-size: 0.74rem;
  font-weight: 700;
  cursor: pointer;
  transition:
    border-color 0.2s ease,
    background-color 0.2s ease,
    color 0.2s ease;
}

.hero-section__quick-run-copy:hover {
  border-color: rgba(0, 240, 255, 0.34);
  background: rgba(0, 240, 255, 0.12);
  color: #d6fbff;
}

.hero-section__quick-run-command {
  margin: 0;
  padding: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.84rem;
  line-height: 1.7;
  color: #f8fafc;
}

.hero-section__actions {
  display: grid;
  gap: 12px;
  justify-items: start;
  margin-bottom: 20px;
}

.hero-section__cta-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  align-items: center;
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
  min-width: 230px;
  min-height: 48px;
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
  min-width: 220px;
  min-height: 48px;
  transition: all 0.3s ease !important;
}

.hero-section__btn-secondary:hover {
  border-color: rgba(0, 240, 255, 0.5) !important;
  background: rgba(0, 240, 255, 0.06) !important;
}

.hero-section__subaction {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 0 4px;
  color: #d3ddf9;
  text-decoration: none;
  font-size: 0.92rem;
  font-weight: 600;
  transition:
    color 0.2s ease,
    transform 0.2s ease;
}

.hero-section__subaction:hover {
  color: #ffffff;
  transform: translateX(2px);
}

.hero-section__trust {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 0;
  margin-bottom: 0;
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

.hero-section__demo-col {
  position: relative;
}

.hero-section__preview {
  position: relative;
  width: 100%;
  max-width: 1120px;
  margin-left: 0;
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

.v-theme--light .hero-section__support-line {
  color: #334155;
}

.v-theme--light .hero-section__quick-run {
  border-color: rgba(14, 165, 233, 0.14);
  background:
    linear-gradient(180deg, rgba(14, 165, 233, 0.08), rgba(255, 255, 255, 0.8)),
    rgba(255, 255, 255, 0.85);
}

.v-theme--light .hero-section__quick-run-label {
  color: #64748b;
}

.v-theme--light .hero-section__quick-run-copy {
  border-color: rgba(2, 132, 199, 0.18);
  background: rgba(2, 132, 199, 0.06);
  color: #075985;
}

.v-theme--light .hero-section__quick-run-copy:hover {
  border-color: rgba(2, 132, 199, 0.28);
  background: rgba(2, 132, 199, 0.1);
  color: #0f172a;
}

.v-theme--light .hero-section__quick-run-command {
  color: #0f172a;
}

.v-theme--light .hero-section__source-link {
  color: #005a8f;
}

.v-theme--light .hero-section__source-link:hover {
  color: #003f66;
}

.v-theme--light .hero-section__subtitle,
.v-theme--light .hero-section__trust-item,
.v-theme--light .hero-section__release-badge,
.v-theme--light .hero-section__subaction {
  color: #64748b;
}

@media (min-width: 1261px) {
  .hero-section__title--compact {
    font-size: clamp(1.88rem, 2.2vw, 2.42rem);
  }
}

@media (max-width: 960px) {
  .hero-section {
    min-height: auto;
    padding-top: 12px;
    padding-bottom: 28px;
  }

  .hero-section__grid {
    gap: 28px;
  }

  .hero-section__title {
    font-size: 2.4rem;
    max-width: 100%;
    white-space: normal;
  }

  .hero-section__content {
    min-height: auto;
    padding-top: 0;
  }

  .hero-section__subtitle {
    font-size: 1.05rem;
    margin-bottom: 14px;
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
  }

  .hero-section__cta-row {
    width: 100%;
    flex-direction: column;
  }

  .hero-section__cta-row :deep(.v-btn) {
    width: 100%;
  }

  .hero-section__actions {
    width: 100%;
  }

  .hero-section__trust {
    gap: 8px;
  }

  .hero-section__trust-item {
    padding: 8px 10px;
    font-size: 0.74rem;
  }
}
</style>
