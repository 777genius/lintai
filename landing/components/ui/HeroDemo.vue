<script setup lang="ts">
import { computed } from 'vue';

const { t } = useI18n();

const focusAreas = computed(() => [
  {
    id: 'run',
    pill: t('hero.demo.focus.run.pill'),
    title: t('hero.demo.focus.run.title'),
    body: t('hero.demo.focus.run.body'),
  },
  {
    id: 'access',
    pill: t('hero.demo.focus.access.pill'),
    title: t('hero.demo.focus.access.title'),
    body: t('hero.demo.focus.access.body'),
  },
  {
    id: 'inherit',
    pill: t('hero.demo.focus.inherit.pill'),
    title: t('hero.demo.focus.inherit.title'),
    body: t('hero.demo.focus.inherit.body'),
  },
]);

const surfaces = computed(() => [
  'SKILL.md',
  'mcp.json',
  '.claude/settings.json',
  '.cursor/rules/*.mdc',
]);
</script>

<template>
  <div class="hero-demo" role="img" :aria-label="t('hero.preview')">
    <div class="hero-demo__glow" />

    <div class="hero-demo__header">
      <div class="hero-demo__eyebrow-row">
        <span class="hero-demo__eyebrow">{{ t('hero.demo.scanLabel') }}</span>
        <span class="hero-demo__status">{{ t('hero.demo.offline') }}</span>
      </div>
      <h3 class="hero-demo__title">{{ t('hero.demo.title') }}</h3>
      <p class="hero-demo__subtitle">{{ t('hero.demo.subtitle') }}</p>
      <code class="hero-demo__command">$ lintai scan .</code>
    </div>

    <div class="hero-demo__body">
      <div class="hero-demo__focus-grid">
        <article v-for="area in focusAreas" :key="area.id" class="hero-demo__focus-card">
          <span class="hero-demo__focus-pill">{{ area.pill }}</span>
          <div class="hero-demo__focus-title">{{ area.title }}</div>
          <p class="hero-demo__focus-body">{{ area.body }}</p>
        </article>
      </div>

      <div class="hero-demo__example-card">
        <div class="hero-demo__example-label">{{ t('hero.demo.exampleLabel') }}</div>
        <code class="hero-demo__example-file">{{ t('hero.demo.exampleFile') }}</code>
        <h4 class="hero-demo__example-title">{{ t('hero.demo.exampleTitle') }}</h4>
        <p class="hero-demo__example-body">{{ t('hero.demo.exampleBody') }}</p>
      </div>
    </div>

    <div class="hero-demo__footer">
      <span class="hero-demo__footer-label">{{ t('hero.demo.summaryLabel') }}</span>
      <div class="hero-demo__surfaces">
        <span v-for="surface in surfaces" :key="surface" class="hero-demo__surface-pill">
          {{ surface }}
        </span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hero-demo {
  position: relative;
  border-radius: 24px;
  background:
    linear-gradient(180deg, rgba(9, 13, 22, 0.96), rgba(6, 10, 18, 0.94)),
    radial-gradient(circle at top left, rgba(0, 240, 255, 0.08), transparent 44%);
  border: 1px solid rgba(0, 240, 255, 0.12);
  box-shadow:
    0 22px 72px rgba(0, 0, 0, 0.3),
    0 0 80px rgba(0, 240, 255, 0.05);
  overflow: hidden;
}

.hero-demo__glow {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(circle at 10% 12%, rgba(0, 240, 255, 0.08), transparent 20%),
    radial-gradient(circle at 84% 18%, rgba(255, 0, 255, 0.08), transparent 24%),
    linear-gradient(180deg, transparent, rgba(57, 255, 20, 0.03));
  pointer-events: none;
}

.hero-demo__header,
.hero-demo__body,
.hero-demo__footer {
  position: relative;
  z-index: 1;
}

.hero-demo__header {
  padding: 18px 18px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.hero-demo__eyebrow-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 12px;
}

.hero-demo__eyebrow,
.hero-demo__status,
.hero-demo__footer-label,
.hero-demo__example-label {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #8fa1c8;
}

.hero-demo__status {
  color: #b5f7ff;
}

.hero-demo__title {
  margin: 14px 0 8px;
  color: #eef2ff;
  font-size: 1.1rem;
  line-height: 1.25;
}

.hero-demo__subtitle {
  margin: 0;
  color: #b9c4e3;
  font-size: 0.86rem;
  line-height: 1.55;
}

.hero-demo__command,
.hero-demo__example-file {
  display: block;
  margin-top: 12px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.88rem;
  line-height: 1.4;
  color: #f8fafc;
  overflow-wrap: anywhere;
}

.hero-demo__body {
  display: grid;
  gap: 12px;
  padding: 16px 18px;
}

.hero-demo__focus-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.hero-demo__focus-card,
.hero-demo__example-card {
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.025);
  padding: 14px;
}

.hero-demo__focus-pill,
.hero-demo__surface-pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 6px 10px;
  font-size: 0.72rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
  color: #b9c4e3;
}

.hero-demo__focus-title,
.hero-demo__example-title {
  margin-top: 10px;
  color: #eef2ff;
  font-size: 0.96rem;
  line-height: 1.35;
  font-weight: 700;
}

.hero-demo__focus-body,
.hero-demo__example-body {
  margin: 6px 0 0;
  color: #b9c4e3;
  font-size: 0.8rem;
  line-height: 1.5;
}

.hero-demo__example-card {
  border-color: rgba(0, 240, 255, 0.14);
  background:
    linear-gradient(180deg, rgba(0, 240, 255, 0.06), rgba(255, 255, 255, 0.03)),
    rgba(255, 255, 255, 0.02);
}

.hero-demo__example-file {
  margin-top: 10px;
  color: #b5f7ff;
  font-size: 0.8rem;
}

.hero-demo__footer {
  padding: 0 18px 18px;
}

.hero-demo__surfaces {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.v-theme--light .hero-demo {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 247, 251, 0.94)),
    radial-gradient(circle at top left, rgba(8, 145, 178, 0.08), transparent 42%);
  border-color: rgba(8, 145, 178, 0.14);
}

.v-theme--light .hero-demo__title,
.v-theme--light .hero-demo__command,
.v-theme--light .hero-demo__focus-title,
.v-theme--light .hero-demo__example-title,
.v-theme--light .hero-demo__example-file {
  color: #0f172a;
}

.v-theme--light .hero-demo__subtitle,
.v-theme--light .hero-demo__focus-body,
.v-theme--light .hero-demo__example-body,
.v-theme--light .hero-demo__focus-pill,
.v-theme--light .hero-demo__surface-pill {
  color: #475569;
}

@media (max-width: 700px) {
  .hero-demo__header,
  .hero-demo__body,
  .hero-demo__footer {
    padding-inline: 14px;
  }

  .hero-demo__eyebrow-row {
    grid-template-columns: 1fr;
    align-items: flex-start;
  }

  .hero-demo__title {
    font-size: 1rem;
  }

  .hero-demo__command {
    font-size: 0.82rem;
  }
}

@media (max-width: 960px) {
  .hero-demo__focus-grid {
    grid-template-columns: 1fr;
  }
}
</style>
