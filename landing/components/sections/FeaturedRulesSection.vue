<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { mdiChevronLeft, mdiChevronRight } from '@mdi/js';

const { content } = useLandingContent();
const { t } = useI18n();
const { width } = useWindowSize();

const sectionRef = ref<HTMLElement | null>(null);
const activePage = ref(0);
const visible = ref(false);

const visibleCards = computed(() => {
  if (width.value >= 1200) return 3;
  if (width.value >= 960) return 2;
  return 1;
});

const pages = computed(() => {
  const size = visibleCards.value;
  const rules = content.value.featuredRules;
  return Array.from({ length: Math.ceil(rules.length / size) }, (_, index) =>
    rules.slice(index * size, index * size + size),
  );
});

const totalPages = computed(() => pages.value.length);

let observer: IntersectionObserver | null = null;
let autoAdvanceId: ReturnType<typeof setInterval> | null = null;

const normalizePage = (index: number) => {
  const count = totalPages.value;
  if (!count) return 0;
  return (index + count) % count;
};

const goToPage = (index: number) => {
  activePage.value = normalizePage(index);
};

const nextPage = () => {
  goToPage(activePage.value + 1);
};

const prevPage = () => {
  goToPage(activePage.value - 1);
};

const startAutoAdvance = () => {
  if (autoAdvanceId || totalPages.value < 2) return;
  autoAdvanceId = setInterval(() => {
    nextPage();
  }, 4800);
};

const stopAutoAdvance = () => {
  if (!autoAdvanceId) return;
  clearInterval(autoAdvanceId);
  autoAdvanceId = null;
};

watch(visible, (value) => {
  if (value) startAutoAdvance();
  else stopAutoAdvance();
});

watch([totalPages, visibleCards], () => {
  activePage.value = Math.min(activePage.value, Math.max(totalPages.value - 1, 0));
});

onMounted(() => {
  observer = new IntersectionObserver(
    ([entry]) => {
      visible.value = entry.isIntersecting;
    },
    { threshold: 0.2 },
  );

  if (sectionRef.value) observer.observe(sectionRef.value);
});

onUnmounted(() => {
  observer?.disconnect();
  stopAutoAdvance();
});
</script>

<template>
  <section id="featured-rules" ref="sectionRef" class="featured-rules section anchor-offset">
    <v-container>
      <div class="featured-rules__header">
        <h2 class="featured-rules__title">{{ t('featuredRules.sectionTitle') }}</h2>
        <p class="featured-rules__subtitle">{{ t('featuredRules.sectionSubtitle') }}</p>
      </div>

      <div
        class="featured-rules__carousel"
        @mouseenter="stopAutoAdvance"
        @mouseleave="visible && startAutoAdvance()"
      >
        <button
          type="button"
          class="featured-rules__nav featured-rules__nav--prev"
          :aria-label="t('common.previous')"
          @click="prevPage"
        >
          <v-icon :icon="mdiChevronLeft" size="28" />
        </button>

        <div class="featured-rules__viewport">
          <Transition name="featured-rules-page" mode="out-in">
            <div
              :key="`${activePage}-${visibleCards}`"
              class="featured-rules__grid"
              :style="{ '--cards-per-page': visibleCards }"
            >
              <article
                v-for="rule in pages[activePage]"
                :key="rule.id"
                class="featured-rules__card"
              >
                <div class="featured-rules__meta">
                  <div class="featured-rules__eyebrow">{{ rule.eyebrow }}</div>
                  <span class="featured-rules__lifecycle">{{ rule.lifecycle }}</span>
                </div>
                <div class="featured-rules__code">{{ rule.code }}</div>
                <div class="featured-rules__surface">{{ rule.surface }}</div>
                <h3 class="featured-rules__card-title">{{ rule.title }}</h3>
                <p class="featured-rules__body">{{ rule.description }}</p>

                <div class="featured-rules__panel">
                  <div class="featured-rules__panel-label">
                    {{ t('featuredRules.whyItMatters') }}
                  </div>
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
            </div>
          </Transition>
        </div>

        <button
          type="button"
          class="featured-rules__nav featured-rules__nav--next"
          :aria-label="t('common.next')"
          @click="nextPage"
        >
          <v-icon :icon="mdiChevronRight" size="28" />
        </button>
      </div>

      <div class="featured-rules__pagination" role="tablist" aria-label="Featured rules slides">
        <button
          v-for="(_, index) in pages"
          :key="index"
          type="button"
          class="featured-rules__dot"
          :class="{ 'featured-rules__dot--active': index === activePage }"
          :aria-label="`Featured rules page ${index + 1}`"
          :aria-selected="index === activePage"
          role="tab"
          @click="goToPage(index)"
        />
      </div>
    </v-container>
  </section>
</template>

<style scoped>
.featured-rules {
  position: relative;
}

.featured-rules :deep(.v-container) {
  max-width: 1440px !important;
}

.featured-rules__header {
  text-align: center;
  max-width: 760px;
  margin: 0 auto 56px;
}

.featured-rules__carousel {
  position: relative;
  max-width: 1400px;
  margin: 0 auto;
}

.featured-rules__viewport {
  padding: 0 40px 12px;
  overflow: hidden;
}

.featured-rules__grid {
  display: grid;
  grid-template-columns: repeat(var(--cards-per-page), minmax(0, 1fr));
  gap: 28px;
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
  min-height: 100%;
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

.featured-rules__meta {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.featured-rules__nav {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  z-index: 2;
  width: 48px;
  height: 48px;
  border-radius: 999px;
  border: 1px solid rgba(0, 240, 255, 0.14);
  background: rgba(10, 10, 15, 0.8);
  color: #e0e6ff;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition:
    transform 0.2s ease,
    border-color 0.2s ease,
    background 0.2s ease;
}

.featured-rules__nav:hover {
  transform: translateY(-50%) scale(1.04);
  border-color: rgba(0, 240, 255, 0.28);
}

.featured-rules__nav--prev {
  left: -6px;
}

.featured-rules__nav--next {
  right: -6px;
}

.featured-rules__eyebrow,
.featured-rules__signal-label {
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  font-family: 'JetBrains Mono', monospace;
  color: #8fa1c8;
}

.featured-rules__lifecycle {
  border-radius: 999px;
  padding: 6px 10px;
  background: rgba(0, 240, 255, 0.08);
  border: 1px solid rgba(0, 240, 255, 0.14);
  color: #c7f9ff;
  font-size: 0.7rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  font-family: 'JetBrains Mono', monospace;
}

.featured-rules__code {
  font-size: 1.2rem;
  font-weight: 800;
  color: #00f0ff;
  font-family: 'JetBrains Mono', monospace;
}

.featured-rules__surface {
  color: #7dd3fc;
  font-size: 0.8rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
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

.featured-rules__pagination {
  margin-top: 18px;
  display: flex;
  justify-content: center;
  gap: 10px;
}

.featured-rules__dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  border: none;
  cursor: pointer;
  background: rgba(0, 240, 255, 0.3);
  transition:
    width 0.2s ease,
    background 0.2s ease;
}

.featured-rules__dot--active {
  width: 28px;
  background: #00f0ff;
}

.featured-rules-page-enter-active,
.featured-rules-page-leave-active {
  transition:
    opacity 0.24s ease,
    transform 0.24s ease;
}

.featured-rules-page-enter-from,
.featured-rules-page-leave-to {
  opacity: 0;
  transform: translateX(18px);
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

.v-theme--light .featured-rules__nav {
  background: rgba(255, 255, 255, 0.94);
  color: #0f172a;
  border-color: rgba(8, 145, 178, 0.14);
}

@media (max-width: 960px) {
  .featured-rules__title {
    font-size: 1.9rem;
  }

  .featured-rules__grid {
    grid-template-columns: repeat(var(--cards-per-page), minmax(0, 1fr));
  }

  .featured-rules__viewport {
    padding-inline: 12px;
  }

  .featured-rules__nav {
    display: none;
  }
}

@media (max-width: 700px) {
  .featured-rules__grid {
    grid-template-columns: 1fr;
  }
}
</style>
