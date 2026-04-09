<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { mdiChevronLeft, mdiChevronRight } from '@mdi/js';

const { content } = useLandingContent();
const { t } = useI18n();

const sectionRef = ref<HTMLElement | null>(null);
const trackRef = ref<HTMLElement | null>(null);
const activeIndex = ref(0);
const visible = ref(false);

const totalSlides = computed(() => content.value.featuredRules.length);

let observer: IntersectionObserver | null = null;
let autoAdvanceId: ReturnType<typeof setInterval> | null = null;

const normalizeIndex = (index: number) => {
  const count = totalSlides.value;
  if (!count) return 0;
  return (index + count) % count;
};

const scrollToIndex = (index: number, behavior: ScrollBehavior = 'smooth') => {
  const track = trackRef.value;
  if (!track) return;

  const nextIndex = normalizeIndex(index);
  const slide = track.children.item(nextIndex);
  if (!(slide instanceof HTMLElement)) return;

  activeIndex.value = nextIndex;
  track.scrollTo({
    left: slide.offsetLeft,
    behavior,
  });
};

const syncActiveFromScroll = () => {
  const track = trackRef.value;
  if (!track) return;

  const children = Array.from(track.children) as HTMLElement[];
  if (!children.length) return;

  const currentLeft = track.scrollLeft;
  let bestIndex = 0;
  let bestDistance = Number.POSITIVE_INFINITY;

  children.forEach((slide, index) => {
    const distance = Math.abs(slide.offsetLeft - currentLeft);
    if (distance < bestDistance) {
      bestDistance = distance;
      bestIndex = index;
    }
  });

  activeIndex.value = bestIndex;
};

const nextSlide = () => {
  scrollToIndex(activeIndex.value + 1);
};

const prevSlide = () => {
  scrollToIndex(activeIndex.value - 1);
};

const startAutoAdvance = () => {
  if (autoAdvanceId || totalSlides.value < 2) return;
  autoAdvanceId = setInterval(() => {
    nextSlide();
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

watch(totalSlides, () => {
  activeIndex.value = 0;
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
          @click="prevSlide"
        >
          <v-icon :icon="mdiChevronLeft" size="28" />
        </button>

        <div ref="trackRef" class="featured-rules__track" @scroll.passive="syncActiveFromScroll">
          <article
            v-for="rule in content.featuredRules"
            :key="rule.id"
            class="featured-rules__slide featured-rules__card"
          >
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
        </div>

        <button
          type="button"
          class="featured-rules__nav featured-rules__nav--next"
          :aria-label="t('common.next')"
          @click="nextSlide"
        >
          <v-icon :icon="mdiChevronRight" size="28" />
        </button>
      </div>

      <div class="featured-rules__pagination" role="tablist" aria-label="Featured rules slides">
        <button
          v-for="(rule, index) in content.featuredRules"
          :key="rule.id"
          type="button"
          class="featured-rules__dot"
          :class="{ 'featured-rules__dot--active': index === activeIndex }"
          :aria-label="`${rule.code} - ${rule.title}`"
          :aria-selected="index === activeIndex"
          role="tab"
          @click="scrollToIndex(index)"
        />
      </div>
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

.featured-rules__carousel {
  position: relative;
}

.featured-rules__track {
  display: flex;
  gap: 24px;
  overflow-x: auto;
  scroll-snap-type: x mandatory;
  scrollbar-width: none;
  padding: 0 48px 12px;
}

.featured-rules__track::-webkit-scrollbar {
  display: none;
}

.featured-rules__slide {
  flex: 0 0 min(420px, calc(50% - 12px));
  scroll-snap-align: start;
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
  left: 0;
}

.featured-rules__nav--next {
  right: 0;
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

  .featured-rules__track {
    padding-inline: 0;
  }

  .featured-rules__slide {
    flex-basis: min(380px, 88vw);
  }

  .featured-rules__nav {
    display: none;
  }
}
</style>
