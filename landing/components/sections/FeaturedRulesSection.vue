<script setup lang="ts">
const { content } = useLandingContent();
const { t } = useI18n();
</script>

<template>
  <section id="featured-rules" class="featured-rules section anchor-offset">
    <v-container>
      <div class="featured-rules__header">
        <h2 class="featured-rules__title">{{ t('featuredRules.sectionTitle') }}</h2>
        <p class="featured-rules__subtitle">{{ t('featuredRules.sectionSubtitle') }}</p>
      </div>

      <v-row>
        <v-col v-for="rule in content.featuredRules" :key="rule.id" cols="12" md="6">
          <article class="featured-rules__card">
            <div class="featured-rules__eyebrow">{{ rule.eyebrow }}</div>
            <div class="featured-rules__code">{{ rule.code }}</div>
            <h3 class="featured-rules__card-title">{{ rule.title }}</h3>
            <p class="featured-rules__body">{{ rule.description }}</p>

            <div class="featured-rules__panel">
              <div class="featured-rules__panel-label">{{ t('featuredRules.whyItMatters') }}</div>
              <p class="featured-rules__panel-copy">{{ rule.whyItMatters }}</p>
            </div>

            <div class="featured-rules__footer">
              <span class="featured-rules__signal">
                <span class="featured-rules__signal-label">{{
                  t('featuredRules.evidenceLabel')
                }}</span>
                <span>{{ rule.evidence }}</span>
              </span>
              <a
                :href="rule.href"
                class="featured-rules__link"
                target="_blank"
                rel="noopener noreferrer"
              >
                {{ t('featuredRules.openRule') }}
              </a>
            </div>
          </article>
        </v-col>
      </v-row>
    </v-container>
  </section>
</template>

<style scoped>
.featured-rules {
  position: relative;
}

.featured-rules__header {
  text-align: center;
  max-width: 760px;
  margin: 0 auto 56px;
}

.featured-rules__title {
  font-size: 2.4rem;
  font-weight: 800;
  letter-spacing: -0.03em;
  line-height: 1.15;
  margin-bottom: 16px;
  background: linear-gradient(135deg, #e0e6ff 0%, #00f0ff 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.featured-rules__subtitle {
  font-size: 1.08rem;
  color: #8892b0;
  line-height: 1.65;
  margin: 0;
}

.featured-rules__card {
  height: 100%;
  border-radius: 24px;
  border: 1px solid rgba(0, 240, 255, 0.12);
  background: linear-gradient(180deg, rgba(11, 15, 25, 0.95), rgba(8, 11, 18, 0.86));
  box-shadow:
    0 18px 60px rgba(0, 0, 0, 0.22),
    inset 0 1px 0 rgba(255, 255, 255, 0.04);
  padding: 24px;
  display: grid;
  gap: 14px;
}

.featured-rules__eyebrow,
.featured-rules__signal-label {
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-family: 'JetBrains Mono', monospace;
  color: #8fa1c8;
}

.featured-rules__code {
  font-size: 1.2rem;
  font-weight: 800;
  color: #00f0ff;
  font-family: 'JetBrains Mono', monospace;
}

.featured-rules__card-title {
  margin: 0;
  font-size: 1.1rem;
  line-height: 1.4;
  color: #e2e8f0;
}

.featured-rules__body,
.featured-rules__panel-copy {
  margin: 0;
  line-height: 1.65;
  color: #b9c4e3;
}

.featured-rules__panel {
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.03);
  padding: 16px;
}

.featured-rules__panel-label {
  margin-bottom: 8px;
  font-size: 0.78rem;
  font-weight: 700;
  color: #dbeafe;
}

.featured-rules__footer {
  margin-top: auto;
  display: flex;
  justify-content: space-between;
  align-items: flex-end;
  gap: 16px;
}

.featured-rules__signal {
  display: grid;
  gap: 6px;
  color: #95a3c4;
  font-size: 0.86rem;
}

.featured-rules__link {
  color: #00f0ff;
  text-decoration: none;
  font-weight: 700;
}

.featured-rules__link:hover {
  text-decoration: underline;
}

.v-theme--light .featured-rules__title {
  background: linear-gradient(135deg, #1e293b 0%, #0891b2 100%);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
}

.v-theme--light .featured-rules__subtitle {
  color: #475569;
}

@media (max-width: 960px) {
  .featured-rules__title {
    font-size: 1.9rem;
  }
}
</style>
