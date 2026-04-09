<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';

const { t } = useI18n();

const steps = computed(() => [
  {
    id: 'index',
    number: '01',
    title: t('hero.demo.steps.index.title'),
    body: t('hero.demo.steps.index.body'),
  },
  {
    id: 'scan',
    number: '02',
    title: t('hero.demo.steps.scan.title'),
    body: t('hero.demo.steps.scan.body'),
  },
  {
    id: 'ship',
    number: '03',
    title: t('hero.demo.steps.ship.title'),
    body: t('hero.demo.steps.ship.body'),
  },
]);

const scenarios = computed(() => [
  {
    id: 'skills',
    surface: 'SKILL.md',
    family: t('hero.demo.scenarios.skills.family'),
    ruleCode: 'SEC352',
    ruleTitle: t('hero.demo.scenarios.skills.title'),
    summary: t('hero.demo.scenarios.skills.summary'),
    evidence: 'allowed-tools: Bash, Read',
    related: ['SEC355', 'SEC393'],
    accent: '#00f0ff',
  },
  {
    id: 'claude-hooks',
    surface: '.claude/settings.json',
    family: t('hero.demo.scenarios.claudeHooks.family'),
    ruleCode: 'SEC340',
    ruleTitle: t('hero.demo.scenarios.claudeHooks.title'),
    summary: t('hero.demo.scenarios.claudeHooks.summary'),
    evidence: 'command: "npx claude-flow@alpha hooks pre-command"',
    related: ['SEC381', 'SEC341'],
    accent: '#ff00ff',
  },
  {
    id: 'mcp',
    surface: 'mcp.json',
    family: t('hero.demo.scenarios.mcp.family'),
    ruleCode: 'SEC329',
    ruleTitle: t('hero.demo.scenarios.mcp.title'),
    summary: t('hero.demo.scenarios.mcp.summary'),
    evidence: '"command": "npx"',
    related: ['SEC396', 'SEC397'],
    accent: '#39ff14',
  },
  {
    id: 'claude-perms',
    surface: '.claude/settings.json',
    family: t('hero.demo.scenarios.claudePerms.family'),
    ruleCode: 'SEC362',
    ruleTitle: t('hero.demo.scenarios.claudePerms.title'),
    summary: t('hero.demo.scenarios.claudePerms.summary'),
    evidence: 'permissions.allow = ["Bash(*)", "Write(*)"]',
    related: ['SEC369', 'SEC373'],
    accent: '#ffd700',
  },
  {
    id: 'cursor',
    surface: '.cursor/rules/review.mdc',
    family: t('hero.demo.scenarios.cursor.family'),
    ruleCode: 'SEC379',
    ruleTitle: t('hero.demo.scenarios.cursor.title'),
    summary: t('hero.demo.scenarios.cursor.summary'),
    evidence: 'alwaysApply: true + globs',
    related: ['SEC378', 'SEC380'],
    accent: '#7c3aed',
  },
  {
    id: 'copilot',
    surface: '.github/instructions/review.instructions.md',
    family: t('hero.demo.scenarios.copilot.family'),
    ruleCode: 'SEC377',
    ruleTitle: t('hero.demo.scenarios.copilot.title'),
    summary: t('hero.demo.scenarios.copilot.summary'),
    evidence: 'applyTo: "[unclosed"',
    related: ['SEC354', 'SEC370'],
    accent: '#fb7185',
  },
]);

const containerRef = ref<HTMLElement | null>(null);
const activeIndex = ref(0);
const visible = ref(false);
const activeScenario = computed(() => scenarios.value[activeIndex.value] ?? scenarios.value[0]);
const surfacesPreview = computed(() => scenarios.value.slice(0, 3));
const progressWidth = computed(
  () => `${((activeIndex.value + 1) / Math.max(scenarios.value.length, 1)) * 100}%`,
);

let observer: IntersectionObserver | null = null;
let intervalId: ReturnType<typeof setInterval> | null = null;

const start = () => {
  if (intervalId || scenarios.value.length < 2) return;
  intervalId = setInterval(() => {
    activeIndex.value = (activeIndex.value + 1) % scenarios.value.length;
  }, 3200);
};

const stop = () => {
  if (!intervalId) return;
  clearInterval(intervalId);
  intervalId = null;
};

watch(visible, (value) => {
  if (value) start();
  else stop();
});

onMounted(() => {
  observer = new IntersectionObserver(
    ([entry]) => {
      visible.value = entry.isIntersecting;
    },
    { threshold: 0.2 },
  );

  if (containerRef.value) observer.observe(containerRef.value);
});

onUnmounted(() => {
  observer?.disconnect();
  stop();
});
</script>

<template>
  <div ref="containerRef" class="hero-demo" role="img" :aria-label="t('hero.preview')">
    <div class="hero-demo__glow" />

    <div class="hero-demo__header">
      <div class="hero-demo__eyebrow-row">
        <span class="hero-demo__eyebrow">{{ t('hero.demo.scanLabel') }}</span>
        <span class="hero-demo__status">{{ t('hero.demo.offline') }}</span>
      </div>
      <code class="hero-demo__command">$ lintai scan . --format sarif</code>
      <div class="hero-demo__chips">
        <span class="hero-demo__chip">{{ t('hero.demo.repoLocalOnly') }}</span>
        <span class="hero-demo__chip">{{ t('hero.demo.stableFirst') }}</span>
        <span class="hero-demo__chip">{{ t('hero.demo.machineReadable') }}</span>
      </div>
    </div>

    <div class="hero-demo__body">
      <div class="hero-demo__steps">
        <div v-for="step in steps" :key="step.id" class="hero-demo__step-card">
          <span class="hero-demo__step-number">{{ step.number }}</span>
          <div class="hero-demo__step-copy">
            <div class="hero-demo__step-title">{{ step.title }}</div>
            <p class="hero-demo__step-body">{{ step.body }}</p>
          </div>
        </div>
      </div>

      <Transition name="hero-demo-fade" mode="out-in">
        <div
          :key="activeScenario.id"
          class="hero-demo__signal-card"
          :style="{ '--accent': activeScenario.accent }"
        >
          <div class="hero-demo__signal-head">
            <div>
              <div class="hero-demo__signal-label">{{ t('hero.demo.currentSignal') }}</div>
              <div class="hero-demo__signal-surface">{{ activeScenario.surface }}</div>
            </div>
            <span class="hero-demo__rule-chip">{{ activeScenario.ruleCode }}</span>
          </div>

          <div class="hero-demo__signal-family">{{ activeScenario.family }}</div>
          <h3 class="hero-demo__signal-title">{{ activeScenario.ruleTitle }}</h3>
          <p class="hero-demo__signal-summary">{{ activeScenario.summary }}</p>

          <div class="hero-demo__surface-pills">
            <span
              v-for="surface in surfacesPreview"
              :key="surface.id"
              class="hero-demo__surface-pill"
              :class="{ 'hero-demo__surface-pill--active': surface.id === activeScenario.id }"
            >
              {{ surface.surface }}
            </span>
          </div>
        </div>
      </Transition>
    </div>

    <div class="hero-demo__footer">
      <span class="hero-demo__footer-label">{{ t('hero.demo.summaryLabel') }}</span>
      <div class="hero-demo__progress">
        <span class="hero-demo__progress-bar" :style="{ width: progressWidth }" />
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
  min-width: 0;
}

.hero-demo__header {
  padding: 16px 16px 12px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.hero-demo__eyebrow-row,
.hero-demo__footer,
.hero-demo__signal-head,
.hero-demo__evidence-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 12px;
}

.hero-demo__eyebrow,
.hero-demo__status,
.hero-demo__footer-label,
.hero-demo__signal-label,
.hero-demo__evidence-label,
.hero-demo__step-number {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.7rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: #8fa1c8;
}

.hero-demo__status {
  color: #b5f7ff;
}

.hero-demo__command {
  display: block;
  margin-top: 8px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
  line-height: 1.4;
  color: #f8fafc;
}

.hero-demo__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.hero-demo__chip,
.hero-demo__surface-pill,
.hero-demo__rule-chip {
  border-radius: 999px;
  padding: 7px 10px;
  font-size: 0.72rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
}

.hero-demo__chip,
.hero-demo__surface-pill {
  color: #b9c4e3;
}

.hero-demo__body {
  display: grid;
  gap: 12px;
  padding: 14px 16px;
}

.hero-demo__steps {
  display: grid;
  gap: 8px;
}

.hero-demo__step-card {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 12px;
  align-items: center;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.05);
  background: rgba(255, 255, 255, 0.018);
  padding: 11px 12px;
}

.hero-demo__step-number {
  min-width: 30px;
  color: #b5f7ff;
}

.hero-demo__step-title {
  color: #eff6ff;
  font-size: 0.88rem;
  font-weight: 700;
  margin-bottom: 2px;
}

.hero-demo__step-body,
.hero-demo__signal-summary {
  margin: 0;
  color: #b9c4e3;
  line-height: 1.45;
  font-size: 0.8rem;
}

.hero-demo__signal-card {
  border-radius: 16px;
  border: 1px solid color-mix(in srgb, var(--accent) 26%, rgba(255, 255, 255, 0.08));
  background:
    linear-gradient(
      180deg,
      color-mix(in srgb, var(--accent) 7%, rgba(255, 255, 255, 0.03)),
      rgba(255, 255, 255, 0.02)
    ),
    rgba(255, 255, 255, 0.02);
  padding: 14px;
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--accent) 10%, transparent);
}

.hero-demo__signal-surface,
.hero-demo__detail-code {
  font-family: 'JetBrains Mono', monospace;
}

.hero-demo__signal-surface {
  margin-top: 4px;
  color: #eef6ff;
  font-size: 0.88rem;
  line-height: 1.35;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.hero-demo__signal-family {
  margin-top: 8px;
  color: color-mix(in srgb, var(--accent) 76%, #ffffff 24%);
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  font-family: 'JetBrains Mono', monospace;
}

.hero-demo__signal-title {
  margin: 8px 0 6px;
  color: #eef2ff;
  font-size: 0.98rem;
  line-height: 1.32;
  overflow-wrap: anywhere;
  word-break: break-word;
}

.hero-demo__rule-chip {
  color: #0a0a0f;
  background: linear-gradient(135deg, #00f0ff, #39ff14);
  border-color: transparent;
  font-weight: 800;
  flex-shrink: 0;
}

.hero-demo__surface-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
  min-width: 0;
}

.hero-demo__surface-pill--active {
  border-color: color-mix(in srgb, var(--accent) 32%, rgba(255, 255, 255, 0.08));
  color: #f2fbff;
  background: color-mix(in srgb, var(--accent) 14%, rgba(255, 255, 255, 0.04));
}

.hero-demo__footer {
  padding: 0 16px 16px;
  gap: 16px;
}

.hero-demo__progress {
  flex: 1;
  height: 7px;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.07);
  overflow: hidden;
}

.hero-demo__progress-bar {
  display: block;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, #00f0ff, #ff00ff 52%, #39ff14);
  transition: width 0.28s ease;
}

.hero-demo-fade-enter-active,
.hero-demo-fade-leave-active {
  transition:
    opacity 0.24s ease,
    transform 0.24s ease;
}

.hero-demo-fade-enter-from,
.hero-demo-fade-leave-to {
  opacity: 0;
  transform: translateY(8px);
}

.v-theme--light .hero-demo {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 247, 251, 0.94)),
    radial-gradient(circle at top left, rgba(8, 145, 178, 0.08), transparent 42%);
  border-color: rgba(8, 145, 178, 0.14);
}

.v-theme--light .hero-demo__command,
.v-theme--light .hero-demo__signal-surface,
.v-theme--light .hero-demo__signal-title,
.v-theme--light .hero-demo__step-title {
  color: #0f172a;
}

.v-theme--light .hero-demo__step-body,
.v-theme--light .hero-demo__signal-summary,
.v-theme--light .hero-demo__chip,
.v-theme--light .hero-demo__surface-pill {
  color: #475569;
}

@media (max-width: 700px) {
  .hero-demo__header,
  .hero-demo__body,
  .hero-demo__footer {
    padding-inline: 14px;
  }

  .hero-demo__command {
    font-size: 0.82rem;
  }

  .hero-demo__signal-head,
  .hero-demo__evidence-row,
  .hero-demo__footer {
    grid-template-columns: 1fr;
    align-items: flex-start;
  }
}
</style>
