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
  const version = release.tag_name?.replace(/^v/, '') || null;
  const assets = release.assets || [];

  return {
    ok: true,
    source: 'github-releases',
    fetchedAt: new Date().toISOString(),
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
