export type DownloadOs = 'macos' | 'windows' | 'linux';
export type DownloadArch = 'arm64' | 'x64' | 'unknown';

export type ReleaseAsset = {
  name: string;
  browser_download_url: string;
};

export type GitHubRelease = {
  tag_name: string;
  published_at: string;
  assets: ReleaseAsset[];
};

export type Variant = {
  url: string | null;
  platformKey: string | null;
  version: string | null;
};

export type DownloadsApiResponse = {
  ok: boolean;
  source: 'github-releases';
  fetchedAt: string;
  tag: string | null;
  version: string | null;
  pubDate: string | null;
  variants: {
    installers: { shell: Variant; powershell: Variant };
    macos: { arm64: Variant };
    windows: { x64: Variant };
    linux: { x64: Variant; muslX64: Variant };
  };
};

const emptyVariant: Variant = { url: null, platformKey: null, version: null };

function normalizeVariant(value: Partial<Variant> | null | undefined): Variant {
  return {
    url: value?.url || null,
    platformKey: value?.platformKey || null,
    version: value?.version || null,
  };
}

function findAsset(assets: ReleaseAsset[], pattern: RegExp): ReleaseAsset | null {
  return assets.find((asset) => pattern.test(asset.name)) || null;
}

function toVariant(asset: ReleaseAsset | null, version: string | null): Variant {
  if (!asset) {
    return { ...emptyVariant };
  }

  return {
    url: asset.browser_download_url,
    platformKey: asset.name,
    version,
  };
}

export function parseGitHubRelease(release: GitHubRelease): DownloadsApiResponse {
  const tag = release.tag_name?.trim() || null;
  const version = tag?.replace(/^v/, '') || null;
  const assets = release.assets || [];

  return {
    ok: true,
    source: 'github-releases',
    fetchedAt: new Date().toISOString(),
    tag,
    version,
    pubDate: release.published_at || null,
    variants: {
      installers: {
        shell: toVariant(findAsset(assets, /^lintai-installer\.sh$/i), version),
        powershell: toVariant(findAsset(assets, /^lintai-installer\.ps1$/i), version),
      },
      macos: {
        arm64: toVariant(findAsset(assets, /aarch64-apple-darwin\.tar\.gz$/i), version),
      },
      windows: {
        x64: toVariant(findAsset(assets, /x86_64-pc-windows-msvc\.zip$/i), version),
      },
      linux: {
        x64: toVariant(findAsset(assets, /x86_64-unknown-linux-gnu\.tar\.gz$/i), version),
        muslX64: toVariant(findAsset(assets, /x86_64-unknown-linux-musl\.tar\.gz$/i), version),
      },
    },
  };
}

export function emptyDownloadsResponse(): DownloadsApiResponse {
  return {
    ok: false,
    source: 'github-releases',
    fetchedAt: new Date().toISOString(),
    tag: null,
    version: null,
    pubDate: null,
    variants: {
      installers: {
        shell: { ...emptyVariant },
        powershell: { ...emptyVariant },
      },
      macos: {
        arm64: { ...emptyVariant },
      },
      windows: {
        x64: { ...emptyVariant },
      },
      linux: {
        x64: { ...emptyVariant },
        muslX64: { ...emptyVariant },
      },
    },
  };
}

export function normalizeDownloadsResponse(
  value: Partial<DownloadsApiResponse> | null | undefined,
): DownloadsApiResponse {
  const empty = emptyDownloadsResponse();

  return {
    ok: value?.ok === true,
    source: empty.source,
    fetchedAt: value?.fetchedAt || empty.fetchedAt,
    tag: value?.tag || null,
    version: value?.version || null,
    pubDate: value?.pubDate || null,
    variants: {
      installers: {
        shell: normalizeVariant(value?.variants?.installers?.shell),
        powershell: normalizeVariant(value?.variants?.installers?.powershell),
      },
      macos: {
        arm64: normalizeVariant(value?.variants?.macos?.arm64),
      },
      windows: {
        x64: normalizeVariant(value?.variants?.windows?.x64),
      },
      linux: {
        x64: normalizeVariant(value?.variants?.linux?.x64),
        muslX64: normalizeVariant(value?.variants?.linux?.muslX64),
      },
    },
  };
}

export function getReleasePageUrl(githubRepo: string): string {
  return `https://github.com/${githubRepo}/releases`;
}

export function getTaggedReleaseUrl(githubRepo: string, tag: string | null): string {
  return tag
    ? `https://github.com/${githubRepo}/releases/tag/${tag}`
    : getReleasePageUrl(githubRepo);
}

export function getReleaseAssetUrl(
  githubRepo: string,
  tag: string | null,
  assetName: string,
): string | null {
  if (!tag) {
    return null;
  }

  return `https://github.com/${githubRepo}/releases/download/${tag}/${assetName}`;
}

export function buildShellInstallerCommand(url: string | null): string | null {
  if (!url) {
    return null;
  }

  return `curl -fsSLO ${url}\nsh ./lintai-installer.sh`;
}

export function buildShellQuickRunCommand(url: string | null): string | null {
  const installCommand = buildShellInstallerCommand(url);
  if (!installCommand) {
    return null;
  }

  return `${installCommand}\nlintai scan .`;
}

export function buildPowerShellInstallerCommand(url: string | null): string | null {
  if (!url) {
    return null;
  }

  return `Invoke-WebRequest -Uri ${url} -OutFile .\\lintai-installer.ps1\npowershell -ExecutionPolicy Bypass -File .\\lintai-installer.ps1`;
}

export function buildArchiveCommand(githubRepo: string, tag: string | null): string | null {
  if (!tag) {
    return null;
  }

  return [
    `TAG=${tag}`,
    `curl -fsSLO https://github.com/${githubRepo}/releases/download/$TAG/lintai-$TAG-x86_64-unknown-linux-gnu.tar.gz`,
    `curl -fsSLO https://github.com/${githubRepo}/releases/download/$TAG/SHA256SUMS`,
  ].join('\n');
}
