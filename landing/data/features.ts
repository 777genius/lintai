import {
  mdiCodeBracesBox,
  mdiFileSearchOutline,
  mdiLockOutline,
  mdiRadar,
  mdiShieldCheckOutline,
  mdiTextBoxSearchOutline,
} from '@mdi/js';

export const features = [
  { id: 'offlineFirst', icon: mdiLockOutline, accent: '#00f0ff' },
  { id: 'deterministic', icon: mdiShieldCheckOutline, accent: '#ff00ff' },
  { id: 'repoSurfaces', icon: mdiFileSearchOutline, accent: '#39ff14' },
  { id: 'ciReady', icon: mdiCodeBracesBox, accent: '#ffd700' },
  { id: 'honestBoundary', icon: mdiTextBoxSearchOutline, accent: '#00f0ff' },
  { id: 'installedAudit', icon: mdiRadar, accent: '#ff00ff' },
] as const;
