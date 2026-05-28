<script setup lang="ts">
import {
  mdiAlertOctagonOutline,
  mdiBomb,
  mdiBugOutline,
  mdiCloudAlertOutline,
  mdiConsoleNetworkOutline,
  mdiLockOpenVariantOutline,
  mdiShieldCheckOutline,
  mdiSkullCrossbonesOutline,
  mdiVirusOutline,
} from '@mdi/js';

const threats = [
  {
    id: 'bug',
    icon: mdiBugOutline,
    startY: '18%',
    hitY: '49%',
    exitY: '10%',
    delayMs: -200,
    durationMs: 4200,
  },
  {
    id: 'virus',
    icon: mdiVirusOutline,
    startY: '36%',
    hitY: '50%',
    exitY: '24%',
    delayMs: -1100,
    durationMs: 4700,
  },
  {
    id: 'lock',
    icon: mdiLockOpenVariantOutline,
    startY: '57%',
    hitY: '51%',
    exitY: '68%',
    delayMs: -2000,
    durationMs: 4400,
  },
  {
    id: 'cloud',
    icon: mdiCloudAlertOutline,
    startY: '72%',
    hitY: '52%',
    exitY: '84%',
    delayMs: -3000,
    durationMs: 5000,
  },
  {
    id: 'alert',
    icon: mdiAlertOctagonOutline,
    startY: '24%',
    hitY: '49%',
    exitY: '18%',
    delayMs: -3800,
    durationMs: 5200,
  },
  {
    id: 'console',
    icon: mdiConsoleNetworkOutline,
    startY: '47%',
    hitY: '51%',
    exitY: '36%',
    delayMs: -4500,
    durationMs: 5600,
  },
  {
    id: 'skull',
    icon: mdiSkullCrossbonesOutline,
    startY: '63%',
    hitY: '52%',
    exitY: '78%',
    delayMs: -5200,
    durationMs: 5100,
  },
  {
    id: 'bomb',
    icon: mdiBomb,
    startY: '10%',
    hitY: '48%',
    exitY: '6%',
    delayMs: -6000,
    durationMs: 5800,
  },
];
</script>

<template>
  <div class="hero-shield-animation" aria-hidden="true">
    <div class="hero-shield-animation__field" />
    <div class="hero-shield-animation__shield-wrap">
      <div class="hero-shield-animation__shield-halo" />
      <v-icon class="hero-shield-animation__shield" :icon="mdiShieldCheckOutline" />
    </div>

    <span
      v-for="threat in threats"
      :key="threat.id"
      class="hero-shield-animation__threat"
      :class="`hero-shield-animation__threat--${threat.id}`"
      :style="{
        '--start-y': threat.startY,
        '--hit-y': threat.hitY,
        '--exit-y': threat.exitY,
        '--delay': `${threat.delayMs}ms`,
        '--duration': `${threat.durationMs}ms`,
      }"
    >
      <span class="hero-shield-animation__threat-impact" />
      <v-icon :icon="threat.icon" />
    </span>
  </div>
</template>

<style scoped>
@property --shield-bug-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-bug-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-virus-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-virus-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-lock-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-lock-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-cloud-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-cloud-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-alert-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-alert-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-console-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-console-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-skull-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-skull-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

@property --shield-bomb-x {
  syntax: '<length>';
  inherits: false;
  initial-value: 0px;
}

@property --shield-bomb-r {
  syntax: '<angle>';
  inherits: false;
  initial-value: 0deg;
}

.hero-shield-animation {
  position: relative;
  width: min(100%, 560px);
  aspect-ratio: 1.12;
  overflow: hidden;
  isolation: isolate;
}

.hero-shield-animation__field {
  position: absolute;
  inset: 9% 2% 8% 3%;
  border-radius: 50%;
  border: 1px solid rgba(0, 240, 255, 0.12);
  background:
    linear-gradient(90deg, rgba(0, 240, 255, 0.05), rgba(255, 0, 255, 0.035)),
    repeating-linear-gradient(
      0deg,
      rgba(255, 255, 255, 0.035) 0,
      rgba(255, 255, 255, 0.035) 1px,
      transparent 1px,
      transparent 28px
    );
  mask-image: radial-gradient(circle, #000 48%, transparent 72%);
}

.hero-shield-animation__shield-wrap {
  position: absolute;
  left: 16%;
  top: 50%;
  width: clamp(150px, 13vw, 230px);
  aspect-ratio: 1;
  display: grid;
  place-items: center;
  transform: translate(
      calc(
        var(--shield-bug-x) + var(--shield-virus-x) + var(--shield-lock-x) + var(--shield-cloud-x) +
          var(--shield-alert-x) + var(--shield-console-x) + var(--shield-skull-x) +
          var(--shield-bomb-x)
      ),
      -50%
    )
    rotate(
      calc(
        var(--shield-bug-r) + var(--shield-virus-r) + var(--shield-lock-r) + var(--shield-cloud-r) +
          var(--shield-alert-r) + var(--shield-console-r) + var(--shield-skull-r) +
          var(--shield-bomb-r)
      )
    );
  animation:
    shieldBugImpact 4200ms -200ms infinite,
    shieldVirusImpact 4700ms -1100ms infinite,
    shieldLockImpact 4400ms -2000ms infinite,
    shieldCloudImpact 5000ms -3000ms infinite,
    shieldAlertImpact 5200ms -3800ms infinite,
    shieldConsoleImpact 5600ms -4500ms infinite,
    shieldSkullImpact 5100ms -5200ms infinite,
    shieldBombImpact 5800ms -6000ms infinite;
  animation-timing-function: cubic-bezier(0.5, 0, 0.25, 1);
}

.hero-shield-animation__shield-halo {
  position: absolute;
  inset: 9%;
  border-radius: 50%;
  border: 1px solid rgba(0, 240, 255, 0.25);
  box-shadow:
    0 0 34px rgba(0, 240, 255, 0.18),
    inset 0 0 28px rgba(0, 240, 255, 0.1);
  animation: haloPulse 3.8s infinite;
}

.hero-shield-animation__shield {
  position: relative;
  z-index: 2;
  width: 72%;
  height: 72%;
  color: #4df3ff;
  filter: drop-shadow(0 0 18px rgba(0, 240, 255, 0.55)) drop-shadow(0 14px 30px rgba(0, 0, 0, 0.5));
}

.hero-shield-animation__threat {
  position: absolute;
  left: 108%;
  top: var(--start-y);
  z-index: 3;
  width: 44px;
  height: 44px;
  display: grid;
  place-items: center;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(11, 17, 29, 0.86);
  color: #ff6bcb;
  box-shadow:
    0 12px 26px rgba(0, 0, 0, 0.28),
    0 0 20px rgba(255, 0, 255, 0.1);
  animation: threatBounce var(--duration, 4.8s) infinite cubic-bezier(0.5, 0, 0.25, 1);
  animation-delay: var(--delay, 0s);
  transform: translate(-50%, -50%);
}

.hero-shield-animation__threat .v-icon {
  width: 24px;
  height: 24px;
}

.hero-shield-animation__threat-impact {
  position: absolute;
  inset: 50%;
  z-index: -1;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  border: 1px solid rgba(138, 232, 255, 0.9);
  opacity: 0;
  transform: translate(-50%, -50%) scale(0.4);
  animation: threatImpact var(--duration, 4.8s) infinite;
  animation-delay: var(--delay, 0s);
}

.hero-shield-animation__threat--bug {
  color: #39ff14;
}

.hero-shield-animation__threat--virus {
  color: #ff4d7d;
}

.hero-shield-animation__threat--lock {
  color: #f6d365;
}

.hero-shield-animation__threat--cloud {
  color: #8ae8ff;
}

.hero-shield-animation__threat--alert {
  color: #ff8f5a;
}

.hero-shield-animation__threat--console {
  color: #9aa7ff;
}

.hero-shield-animation__threat--skull {
  color: #f8fafc;
}

.hero-shield-animation__threat--bomb {
  color: #ff5cf7;
}

@keyframes threatBounce {
  0% {
    opacity: 0;
    left: 108%;
    top: var(--start-y);
    transform: translate(-50%, -50%) rotate(0deg) scale(0.78);
  }
  12% {
    opacity: 1;
  }
  44% {
    opacity: 1;
    left: 58%;
    top: var(--hit-y);
    transform: translate(-50%, -50%) rotate(-18deg) scale(1);
  }
  48%,
  54% {
    opacity: 1;
    left: 39%;
    top: var(--hit-y);
    transform: translate(-50%, -50%) rotate(-78deg) scale(0.9);
  }
  66% {
    opacity: 1;
    left: 62%;
    top: var(--exit-y);
    transform: translate(-50%, -50%) rotate(-165deg) scale(0.82);
  }
  100% {
    opacity: 0;
    left: 112%;
    top: var(--exit-y);
    transform: translate(-50%, -50%) rotate(-245deg) scale(0.64);
  }
}

@keyframes threatImpact {
  0%,
  42%,
  100% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(0.4);
  }
  48% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(0.9);
  }
  58% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(2.4);
  }
}

@keyframes shieldBugImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-bug-x: 0px;
    --shield-bug-r: 0deg;
  }
  48% {
    --shield-bug-x: -7px;
    --shield-bug-r: -3deg;
  }
  52% {
    --shield-bug-x: 4px;
    --shield-bug-r: 2deg;
  }
}

@keyframes shieldVirusImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-virus-x: 0px;
    --shield-virus-r: 0deg;
  }
  48% {
    --shield-virus-x: -7px;
    --shield-virus-r: -3deg;
  }
  52% {
    --shield-virus-x: 4px;
    --shield-virus-r: 2deg;
  }
}

@keyframes shieldLockImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-lock-x: 0px;
    --shield-lock-r: 0deg;
  }
  48% {
    --shield-lock-x: -7px;
    --shield-lock-r: -3deg;
  }
  52% {
    --shield-lock-x: 4px;
    --shield-lock-r: 2deg;
  }
}

@keyframes shieldCloudImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-cloud-x: 0px;
    --shield-cloud-r: 0deg;
  }
  48% {
    --shield-cloud-x: -7px;
    --shield-cloud-r: -3deg;
  }
  52% {
    --shield-cloud-x: 4px;
    --shield-cloud-r: 2deg;
  }
}

@keyframes shieldAlertImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-alert-x: 0px;
    --shield-alert-r: 0deg;
  }
  48% {
    --shield-alert-x: -7px;
    --shield-alert-r: -3deg;
  }
  52% {
    --shield-alert-x: 4px;
    --shield-alert-r: 2deg;
  }
}

@keyframes shieldConsoleImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-console-x: 0px;
    --shield-console-r: 0deg;
  }
  48% {
    --shield-console-x: -7px;
    --shield-console-r: -3deg;
  }
  52% {
    --shield-console-x: 4px;
    --shield-console-r: 2deg;
  }
}

@keyframes shieldSkullImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-skull-x: 0px;
    --shield-skull-r: 0deg;
  }
  48% {
    --shield-skull-x: -7px;
    --shield-skull-r: -3deg;
  }
  52% {
    --shield-skull-x: 4px;
    --shield-skull-r: 2deg;
  }
}

@keyframes shieldBombImpact {
  0%,
  44%,
  56%,
  100% {
    --shield-bomb-x: 0px;
    --shield-bomb-r: 0deg;
  }
  48% {
    --shield-bomb-x: -7px;
    --shield-bomb-r: -3deg;
  }
  52% {
    --shield-bomb-x: 4px;
    --shield-bomb-r: 2deg;
  }
}

@keyframes haloPulse {
  0%,
  100% {
    opacity: 0.72;
    transform: scale(1);
  }
  30%,
  61% {
    opacity: 1;
    transform: scale(1.08);
  }
}

.v-theme--light .hero-shield-animation__field {
  border-color: rgba(2, 132, 199, 0.14);
  background:
    linear-gradient(90deg, rgba(14, 165, 233, 0.07), rgba(124, 58, 237, 0.04)),
    repeating-linear-gradient(
      0deg,
      rgba(15, 23, 42, 0.05) 0,
      rgba(15, 23, 42, 0.05) 1px,
      transparent 1px,
      transparent 28px
    );
}

.v-theme--light .hero-shield-animation__threat {
  border-color: rgba(15, 23, 42, 0.1);
  background: rgba(255, 255, 255, 0.88);
  box-shadow: 0 12px 24px rgba(15, 23, 42, 0.12);
}
</style>
