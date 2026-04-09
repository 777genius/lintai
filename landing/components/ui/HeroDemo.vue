<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';

const { t } = useI18n();

const scenarios = computed(() => [
  {
    id: 'skills',
    surface: 'SKILL.md',
    family: t('hero.demo.scenarios.skills.family'),
    ruleCode: 'SEC352',
    ruleTitle: t('hero.demo.scenarios.skills.title'),
    summary: t('hero.demo.scenarios.skills.summary'),
    evidence: 'allowed-tools: Bash, Read',
    remediation: t('hero.demo.scenarios.skills.remediation'),
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
    remediation: t('hero.demo.scenarios.claudeHooks.remediation'),
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
    remediation: t('hero.demo.scenarios.mcp.remediation'),
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
    remediation: t('hero.demo.scenarios.claudePerms.remediation'),
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
    evidence: 'inclusion: always',
    remediation: t('hero.demo.scenarios.cursor.remediation'),
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
    remediation: t('hero.demo.scenarios.copilot.remediation'),
    related: ['SEC354', 'SEC370'],
    accent: '#fb7185',
  },
]);

const containerRef = ref<HTMLElement | null>(null);
const activeIndex = ref(0);
const visible = ref(false);
const activeScenario = computed(() => scenarios.value[activeIndex.value] ?? scenarios.value[0]);
const progressWidth = computed(
  () => `${((activeIndex.value + 1) / Math.max(scenarios.value.length, 1)) * 100}%`,
);

let observer: IntersectionObserver | null = null;
let intervalId: ReturnType<typeof setInterval> | null = null;

const start = () => {
  if (intervalId) return;
  intervalId = setInterval(() => {
    activeIndex.value = (activeIndex.value + 1) % scenarios.value.length;
  }, 2400);
};

const stop = () => {
  if (!intervalId) return;
  clearInterval(intervalId);
  intervalId = null;
};

const selectScenario = (index: number) => {
  activeIndex.value = index;
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
    { threshold: 0.15 },
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
        <span class="hero-demo__chip">{{ t('hero.demo.previewDeeper') }}</span>
        <span class="hero-demo__chip">{{ t('hero.demo.machineReadable') }}</span>
      </div>
    </div>

    <div class="hero-demo__grid">
      <div class="hero-demo__surface-panel">
        <div class="hero-demo__panel-head">
          <span>{{ t('hero.demo.surfaceMap') }}</span>
          <span>{{ scenarios.length }}</span>
        </div>

        <div class="hero-demo__surface-list">
          <div
            v-for="(scenario, index) in scenarios"
            :key="scenario.id"
            class="hero-demo__surface-row"
            :class="{ 'hero-demo__surface-row--active': index === activeIndex }"
            :style="{ '--accent': scenario.accent }"
            @mouseenter="selectScenario(index)"
          >
            <div class="hero-demo__surface-topline">
              <span class="hero-demo__surface-file">{{ scenario.surface }}</span>
              <span class="hero-demo__surface-code">{{ scenario.ruleCode }}</span>
            </div>
            <p class="hero-demo__surface-family">{{ scenario.family }}</p>
            <div class="hero-demo__surface-related">
              <span
                v-for="related in scenario.related"
                :key="related"
                class="hero-demo__related-chip"
              >
                {{ related }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div class="hero-demo__signal-panel">
        <div class="hero-demo__panel-head">
          <span>{{ t('hero.demo.signalBoard') }}</span>
          <span>{{ t('hero.demo.outputsLabel') }}</span>
        </div>

        <Transition name="hero-demo-fade" mode="out-in">
          <div
            :key="activeScenario.id"
            class="hero-demo__signal-view"
            :style="{ '--accent': activeScenario.accent }"
          >
            <div class="hero-demo__signal-topline">
              <span class="hero-demo__rule-chip">{{ activeScenario.ruleCode }}</span>
              <span class="hero-demo__family-chip">{{ activeScenario.family }}</span>
            </div>

            <h3 class="hero-demo__signal-title">{{ activeScenario.ruleTitle }}</h3>
            <p class="hero-demo__signal-summary">{{ activeScenario.summary }}</p>

            <div class="hero-demo__detail-grid">
              <div class="hero-demo__detail-card">
                <span class="hero-demo__detail-label">{{ t('hero.demo.evidenceLabel') }}</span>
                <code class="hero-demo__detail-code">{{ activeScenario.evidence }}</code>
              </div>

              <div class="hero-demo__detail-card">
                <span class="hero-demo__detail-label">{{ t('hero.demo.remediationLabel') }}</span>
                <p class="hero-demo__detail-copy">{{ activeScenario.remediation }}</p>
              </div>
            </div>

            <div class="hero-demo__outputs">
              <span class="hero-demo__detail-label">{{ t('hero.demo.outputsLabel') }}</span>
              <div class="hero-demo__output-list">
                <span class="hero-demo__output">{{ t('hero.demo.structuredEvidence') }}</span>
                <span class="hero-demo__output">SARIF</span>
                <span class="hero-demo__output">JSON</span>
                <span class="hero-demo__output">{{ t('hero.demo.stableFirst') }}</span>
              </div>
            </div>
          </div>
        </Transition>
      </div>
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
  border-radius: 22px;
  background:
    linear-gradient(180deg, rgba(9, 13, 22, 0.96), rgba(6, 10, 18, 0.92)),
    radial-gradient(circle at top left, rgba(0, 240, 255, 0.08), transparent 42%);
  border: 1px solid rgba(0, 240, 255, 0.12);
  box-shadow:
    0 24px 80px rgba(0, 0, 0, 0.34),
    0 0 80px rgba(0, 240, 255, 0.05);
  overflow: hidden;
}

.hero-demo__glow {
  position: absolute;
  inset: 0;
  background:
    radial-gradient(circle at 12% 14%, rgba(0, 240, 255, 0.08), transparent 22%),
    radial-gradient(circle at 82% 20%, rgba(255, 0, 255, 0.08), transparent 24%),
    linear-gradient(180deg, transparent, rgba(57, 255, 20, 0.03));
  pointer-events: none;
}

.hero-demo__header,
.hero-demo__grid,
.hero-demo__footer {
  position: relative;
  z-index: 1;
}

.hero-demo__header {
  padding: 18px 18px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}

.hero-demo__eyebrow-row,
.hero-demo__panel-head,
.hero-demo__signal-topline,
.hero-demo__surface-topline,
.hero-demo__footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.hero-demo__eyebrow,
.hero-demo__status,
.hero-demo__panel-head,
.hero-demo__detail-label,
.hero-demo__footer-label {
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
  margin-top: 10px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.9rem;
  line-height: 1.4;
  color: #f8fafc;
}

.hero-demo__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 12px;
}

.hero-demo__chip,
.hero-demo__output,
.hero-demo__related-chip,
.hero-demo__rule-chip,
.hero-demo__family-chip {
  border-radius: 999px;
  padding: 7px 10px;
  font-size: 0.72rem;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.04);
}

.hero-demo__chip,
.hero-demo__output,
.hero-demo__family-chip,
.hero-demo__related-chip {
  color: #b9c4e3;
}

.hero-demo__grid {
  display: grid;
  grid-template-columns: 0.95fr 1.15fr;
  gap: 16px;
  padding: 16px 18px 18px;
}

.hero-demo__surface-panel,
.hero-demo__signal-panel {
  border-radius: 18px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.03);
  padding: 14px;
}

.hero-demo__surface-list {
  display: grid;
  gap: 10px;
  margin-top: 14px;
}

.hero-demo__surface-row {
  border-radius: 14px;
  padding: 12px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.025);
  transition:
    transform 0.22s ease,
    border-color 0.22s ease,
    box-shadow 0.22s ease,
    background 0.22s ease;
}

.hero-demo__surface-row--active {
  transform: translateX(4px);
  border-color: color-mix(in srgb, var(--accent) 42%, rgba(255, 255, 255, 0.08));
  background: color-mix(in srgb, var(--accent) 9%, rgba(255, 255, 255, 0.03));
  box-shadow: 0 16px 36px color-mix(in srgb, var(--accent) 10%, transparent);
}

.hero-demo__surface-file,
.hero-demo__surface-code,
.hero-demo__detail-code {
  font-family: 'JetBrains Mono', monospace;
}

.hero-demo__surface-file {
  color: #f8fafc;
  font-size: 0.82rem;
}

.hero-demo__surface-code,
.hero-demo__rule-chip {
  color: #0a0a0f;
  background: linear-gradient(135deg, #00f0ff, #39ff14);
  border-color: transparent;
  font-weight: 800;
}

.hero-demo__surface-family {
  margin: 8px 0 0;
  color: #97a6cb;
  font-size: 0.78rem;
  line-height: 1.45;
}

.hero-demo__surface-related {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
  margin-top: 10px;
}

.hero-demo__signal-panel {
  overflow: hidden;
}

.hero-demo__signal-view {
  margin-top: 14px;
}

.hero-demo__signal-title {
  margin: 16px 0 10px;
  color: #eef2ff;
  font-size: 1.2rem;
  line-height: 1.3;
}

.hero-demo__signal-summary,
.hero-demo__detail-copy {
  margin: 0;
  color: #b9c4e3;
  line-height: 1.7;
  font-size: 0.94rem;
}

.hero-demo__family-chip {
  color: color-mix(in srgb, var(--accent) 78%, #ffffff 22%);
  border-color: color-mix(in srgb, var(--accent) 30%, rgba(255, 255, 255, 0.08));
  background: color-mix(in srgb, var(--accent) 10%, rgba(255, 255, 255, 0.03));
}

.hero-demo__detail-grid {
  display: grid;
  gap: 12px;
  margin-top: 16px;
}

.hero-demo__detail-card {
  border-radius: 16px;
  padding: 14px;
  border: 1px solid rgba(255, 255, 255, 0.06);
  background: rgba(255, 255, 255, 0.03);
}

.hero-demo__detail-code {
  display: block;
  margin-top: 8px;
  color: color-mix(in srgb, var(--accent) 80%, #ffffff 20%);
  font-size: 0.76rem;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
}

.hero-demo__outputs {
  margin-top: 16px;
}

.hero-demo__output-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 10px;
}

.hero-demo__output {
  color: #0a0a0f;
  background: linear-gradient(135deg, #00f0ff, #39ff14);
  border-color: transparent;
}

.hero-demo__footer {
  padding: 0 18px 18px;
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
  transform: translateY(12px);
}

.v-theme--light .hero-demo {
  background:
    linear-gradient(180deg, rgba(255, 255, 255, 0.96), rgba(244, 247, 251, 0.94)),
    radial-gradient(circle at top left, rgba(8, 145, 178, 0.08), transparent 42%);
  border-color: rgba(8, 145, 178, 0.14);
}

.v-theme--light .hero-demo__command,
.v-theme--light .hero-demo__surface-file,
.v-theme--light .hero-demo__signal-title {
  color: #0f172a;
}

.v-theme--light .hero-demo__signal-summary,
.v-theme--light .hero-demo__detail-copy,
.v-theme--light .hero-demo__surface-family,
.v-theme--light .hero-demo__chip,
.v-theme--light .hero-demo__family-chip,
.v-theme--light .hero-demo__related-chip {
  color: #475569;
}

@media (max-width: 960px) {
  .hero-demo__grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 700px) {
  .hero-demo__header,
  .hero-demo__grid,
  .hero-demo__footer {
    padding-inline: 14px;
  }

  .hero-demo__command {
    font-size: 0.8rem;
  }

  .hero-demo__footer {
    gap: 10px;
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
