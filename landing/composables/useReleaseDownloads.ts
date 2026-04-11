import latestRelease from '~/data/release-latest.json';
import {
  buildArchiveCommand,
  buildPowerShellInstallerCommand,
  buildShellQuickRunCommand,
  buildShellInstallerCommand,
  getReleasePageUrl,
  getReleaseAssetUrl,
  getTaggedReleaseUrl,
  normalizeDownloadsResponse,
} from '~/utils/releaseDownloads';
import type { DownloadArch, DownloadsApiResponse, DownloadOs } from '~/utils/releaseDownloads';

type ResolveResult = { url: string; version: string | null } | null;

const staticReleaseData = normalizeDownloadsResponse(
  latestRelease as Partial<DownloadsApiResponse>,
);

export const useReleaseDownloads = () => {
  const config = useRuntimeConfig();
  const githubRepo = config.public.githubRepo || '777genius/lintai';
  const previewReleaseTag = import.meta.dev ? 'v0.1.0' : null;
  const data = ref<DownloadsApiResponse>(staticReleaseData);
  const pending = ref(false);
  const error = ref<Error | null>(null);
  const releasePageUrl = config.public.githubReleasesUrl || getReleasePageUrl(githubRepo);
  const fallbackUrl = getTaggedReleaseUrl(githubRepo, data.value.tag);
  const shellInstallerUrl =
    data.value.variants.installers.shell.url ||
    getReleaseAssetUrl(githubRepo, previewReleaseTag, 'lintai-installer.sh');
  const powerShellInstallerUrl =
    data.value.variants.installers.powershell.url ||
    getReleaseAssetUrl(githubRepo, previewReleaseTag, 'lintai-installer.ps1');
  const shellInstallCommand = buildShellInstallerCommand(shellInstallerUrl);
  const quickRunCommand = buildShellQuickRunCommand(shellInstallerUrl);
  const powerShellInstallCommand = buildPowerShellInstallerCommand(powerShellInstallerUrl);
  const archiveCommand = buildArchiveCommand(githubRepo, data.value.tag);

  const resolve = (os: DownloadOs, arch: DownloadArch | 'unknown'): ResolveResult => {
    const api = data.value;
    if (!api.ok) {
      return null;
    }

    if (os === 'windows') {
      const variant = api.variants.windows.x64;
      return variant.url ? { url: variant.url, version: variant.version || api.version } : null;
    }

    if (os === 'linux') {
      const variant = api.variants.linux.x64.url
        ? api.variants.linux.x64
        : api.variants.linux.muslX64;
      return variant.url ? { url: variant.url, version: variant.version || api.version } : null;
    }

    if (os === 'macos') {
      if (arch === 'x64') {
        return null;
      }

      const byArch = api.variants.macos.arm64;
      if (byArch.url) {
        return { url: byArch.url, version: byArch.version || api.version };
      }

      return null;
    }

    return null;
  };

  const resolveUrlOrFallback = (os: DownloadOs, arch: DownloadArch | 'unknown'): string =>
    resolve(os, arch)?.url || fallbackUrl;

  return {
    data,
    pending,
    error,
    releasePageUrl,
    fallbackUrl,
    shellInstallerUrl,
    powerShellInstallerUrl,
    shellInstallCommand,
    quickRunCommand,
    powerShellInstallCommand,
    archiveCommand,
    resolve,
    resolveUrlOrFallback,
  };
};
