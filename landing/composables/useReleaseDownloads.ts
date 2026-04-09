import { emptyDownloadsResponse } from '~/utils/releaseDownloads';
import type { DownloadArch, DownloadsApiResponse, DownloadOs } from '~/utils/releaseDownloads';

type ResolveResult = { url: string; version: string | null } | null;

const CACHE_KEY = 'lintai_release_meta';
const CACHE_TTL = 10 * 60 * 1000;

function isClient(): boolean {
  return typeof window !== 'undefined';
}

function readCache(): DownloadsApiResponse | null {
  if (!isClient()) {
    return null;
  }

  try {
    const raw = window.sessionStorage.getItem(CACHE_KEY);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as { ts: number; data: DownloadsApiResponse };
    if (Date.now() - parsed.ts > CACHE_TTL) {
      return null;
    }

    return parsed.data;
  } catch {
    return null;
  }
}

function writeCache(data: DownloadsApiResponse): void {
  if (!isClient()) {
    return;
  }

  try {
    window.sessionStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), data }));
  } catch {
    // Ignore unavailable session storage.
  }
}

export const useReleaseDownloads = () => {
  const config = useRuntimeConfig();
  const githubRepo = config.public.githubRepo || '777genius/lintai';
  const fallbackUrl =
    config.public.githubReleasesUrl || `https://github.com/${githubRepo}/releases`;

  const { data, pending, error } = useAsyncData<DownloadsApiResponse>(
    'lintai-releases',
    async () => {
      const cached = readCache();
      if (cached) {
        return cached;
      }

      try {
        const parsed = await $fetch<DownloadsApiResponse>('/api/releases/latest');
        writeCache(parsed);
        return parsed;
      } catch {
        return emptyDownloadsResponse();
      }
    },
    {
      server: true,
      lazy: false,
      default: () => emptyDownloadsResponse(),
    },
  );

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

  return { data, pending, error, fallbackUrl, resolve, resolveUrlOrFallback };
};
