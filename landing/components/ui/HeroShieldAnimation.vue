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
  { id: 'bug', icon: mdiBugOutline },
  { id: 'virus', icon: mdiVirusOutline },
  { id: 'lock', icon: mdiLockOpenVariantOutline },
  { id: 'cloud', icon: mdiCloudAlertOutline },
  { id: 'alert', icon: mdiAlertOctagonOutline },
  { id: 'console', icon: mdiConsoleNetworkOutline },
  { id: 'skull', icon: mdiSkullCrossbonesOutline },
  { id: 'bomb', icon: mdiBomb },
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
    >
      <span class="hero-shield-animation__threat-impact" />
      <v-icon :icon="threat.icon" />
    </span>
  </div>
</template>

<style scoped>
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
  transform: translateY(-50%);
  display: grid;
  place-items: center;
  animation: shieldShake 3.8s infinite;
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
  --start-y: 18%;
  --hit-y: 49%;
  --exit-y: 10%;
  --delay: -0.2s;
  --duration: 4.2s;
  color: #39ff14;
}

.hero-shield-animation__threat--virus {
  --start-y: 36%;
  --hit-y: 50%;
  --exit-y: 24%;
  --delay: -1.1s;
  --duration: 4.7s;
  color: #ff4d7d;
}

.hero-shield-animation__threat--lock {
  --start-y: 57%;
  --hit-y: 51%;
  --exit-y: 68%;
  --delay: -2s;
  --duration: 4.4s;
  color: #f6d365;
}

.hero-shield-animation__threat--cloud {
  --start-y: 72%;
  --hit-y: 52%;
  --exit-y: 84%;
  --delay: -3s;
  --duration: 5s;
  color: #8ae8ff;
}

.hero-shield-animation__threat--alert {
  --start-y: 24%;
  --hit-y: 49%;
  --exit-y: 18%;
  --delay: -3.8s;
  --duration: 5.2s;
  color: #ff8f5a;
}

.hero-shield-animation__threat--console {
  --start-y: 47%;
  --hit-y: 51%;
  --exit-y: 36%;
  --delay: -4.5s;
  --duration: 5.6s;
  color: #9aa7ff;
}

.hero-shield-animation__threat--skull {
  --start-y: 63%;
  --hit-y: 52%;
  --exit-y: 78%;
  --delay: -5.2s;
  --duration: 5.1s;
  color: #f8fafc;
}

.hero-shield-animation__threat--bomb {
  --start-y: 10%;
  --hit-y: 48%;
  --exit-y: 6%;
  --delay: -6s;
  --duration: 5.8s;
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

@keyframes shieldShake {
  0%,
  26%,
  100% {
    transform: translateY(-50%) rotate(0deg);
  }
  29% {
    transform: translate(-6px, -50%) rotate(-3deg);
  }
  32% {
    transform: translate(3px, -50%) rotate(2deg);
  }
  35% {
    transform: translateY(-50%) rotate(0deg);
  }
  57% {
    transform: translateY(-50%) rotate(0deg);
  }
  60% {
    transform: translate(-5px, -50%) rotate(-2deg);
  }
  63% {
    transform: translate(2px, -50%) rotate(1deg);
  }
  66% {
    transform: translateY(-50%) rotate(0deg);
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
