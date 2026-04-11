import {
  mdiCodeBracesBox,
  mdiLockOutline,
  mdiRadar,
} from '@mdi/js';

export const features = [
  { id: 'sharedShell', icon: mdiLockOutline, accent: '#00f0ff' },
  { id: 'mcpLauncher', icon: mdiCodeBracesBox, accent: '#ff00ff' },
  { id: 'hookBoundary', icon: mdiRadar, accent: '#39ff14' },
] as const;
