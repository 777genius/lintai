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
      <v-icon :icon="threat.icon" />
    </span>

    <span
      v-for="index in 5"
      :key="index"
      class="hero-shield-animation__impact"
      :class="`hero-shield-animation__impact--${index}`"
    />
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
  right: -16%;
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
  animation: threatBounce 4.8s infinite cubic-bezier(0.5, 0, 0.25, 1);
}

.hero-shield-animation__threat .v-icon {
  width: 24px;
  height: 24px;
}

.hero-shield-animation__threat--bug {
  top: 18%;
  color: #39ff14;
  animation-delay: -0.2s;
  animation-duration: 4.2s;
}

.hero-shield-animation__threat--virus {
  top: 36%;
  color: #ff4d7d;
  animation-delay: -1.1s;
  animation-duration: 4.7s;
}

.hero-shield-animation__threat--lock {
  top: 57%;
  color: #f6d365;
  animation-delay: -2s;
  animation-duration: 4.4s;
}

.hero-shield-animation__threat--cloud {
  top: 72%;
  color: #8ae8ff;
  animation-delay: -3s;
  animation-duration: 5s;
}

.hero-shield-animation__threat--alert {
  top: 24%;
  color: #ff8f5a;
  animation-delay: -3.8s;
  animation-duration: 5.2s;
}

.hero-shield-animation__threat--console {
  top: 47%;
  color: #9aa7ff;
  animation-delay: -4.5s;
  animation-duration: 5.6s;
}

.hero-shield-animation__threat--skull {
  top: 63%;
  color: #f8fafc;
  animation-delay: -5.2s;
  animation-duration: 5.1s;
}

.hero-shield-animation__threat--bomb {
  top: 10%;
  color: #ff5cf7;
  animation-delay: -6s;
  animation-duration: 5.8s;
}

.hero-shield-animation__impact {
  position: absolute;
  left: 31%;
  top: 50%;
  z-index: 1;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  border: 1px solid rgba(138, 232, 255, 0.9);
  opacity: 0;
  transform: translate(-50%, -50%);
  animation: impactRing 3.8s infinite;
}

.hero-shield-animation__impact--1 {
  top: 24%;
  animation-delay: 0.1s;
}

.hero-shield-animation__impact--2 {
  top: 39%;
  animation-delay: 0.85s;
}

.hero-shield-animation__impact--3 {
  top: 58%;
  animation-delay: 1.55s;
}

.hero-shield-animation__impact--4 {
  top: 73%;
  animation-delay: 2.35s;
}

.hero-shield-animation__impact--5 {
  top: 31%;
  animation-delay: 3.1s;
}

@keyframes threatBounce {
  0% {
    opacity: 0;
    transform: translate3d(0, 0, 0) rotate(0deg) scale(0.78);
  }
  12% {
    opacity: 1;
  }
  44% {
    opacity: 1;
    transform: translate3d(-72%, 8px, 0) rotate(-18deg) scale(1);
  }
  52% {
    opacity: 1;
    transform: translate3d(-365%, 0, 0) rotate(-78deg) scale(0.9);
  }
  66% {
    opacity: 1;
    transform: translate3d(-210%, -26px, 0) rotate(-165deg) scale(0.82);
  }
  100% {
    opacity: 0;
    transform: translate3d(16%, -56px, 0) rotate(-245deg) scale(0.64);
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

@keyframes impactRing {
  0%,
  23%,
  100% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(0.4);
  }
  27% {
    opacity: 1;
    transform: translate(-50%, -50%) scale(0.85);
  }
  36% {
    opacity: 0;
    transform: translate(-50%, -50%) scale(2.4);
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
