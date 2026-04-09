import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const landingRoot = path.resolve(scriptDir, "..");
const dataOutputPath = path.join(landingRoot, "data", "release-latest.json");
const publicOutputPath = path.join(landingRoot, "public", "releases", "latest.json");
const emptyFetchedAt = "1970-01-01T00:00:00.000Z";

const emptyVariant = { url: null, platformKey: null, version: null };

function emptyManifest() {
  return {
    ok: false,
    source: "github-releases",
    fetchedAt: emptyFetchedAt,
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

function findAsset(assets, pattern) {
  return assets.find((asset) => pattern.test(asset.name)) || null;
}

function toVariant(asset, version) {
  if (!asset) {
    return { ...emptyVariant };
  }

  return {
    url: asset.browser_download_url,
    platformKey: asset.name,
    version,
  };
}

function parseRelease(release) {
  const tag = typeof release?.tag_name === "string" && release.tag_name.trim()
    ? release.tag_name.trim()
    : null;
  const version = tag ? tag.replace(/^v/, "") : null;
  const assets = Array.isArray(release?.assets) ? release.assets : [];

  return {
    ok: true,
    source: "github-releases",
    fetchedAt: new Date().toISOString(),
    tag,
    version,
    pubDate: release?.published_at || null,
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

async function fetchJson(url, token) {
  const response = await fetch(url, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "lintai-release-manifest/1.0",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub API ${response.status} for ${url}`);
  }

  return response.json();
}

async function resolveLatestRelease(repo, tag, token) {
  if (tag) {
    return fetchJson(`https://api.github.com/repos/${repo}/releases/tags/${tag}`, token);
  }

  const releases = await fetchJson(`https://api.github.com/repos/${repo}/releases?per_page=20`, token);
  return releases.find((release) => !release.draft) || null;
}

async function writeManifestFile(filePath, manifest) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(manifest, null, 2)}\n`);
}

const githubRepo =
  process.env.LINTAI_GITHUB_REPO ||
  process.env.NUXT_PUBLIC_GITHUB_REPO ||
  process.env.GITHUB_REPOSITORY ||
  "777genius/lintai";
const githubToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || null;
const releaseTag = process.env.LINTAI_RELEASE_TAG?.trim() || null;
const requireReleaseManifest = process.env.LINTAI_REQUIRE_RELEASE_MANIFEST === "true";

let manifest = emptyManifest();

try {
  const release = await resolveLatestRelease(githubRepo, releaseTag, githubToken);
  if (release) {
    manifest = parseRelease(release);
  }
} catch (error) {
  if (requireReleaseManifest) {
    throw error;
  }

  console.warn(
    `[lintai] release manifest refresh skipped: ${
      error instanceof Error ? error.message : String(error)
    }`,
  );
}

if (requireReleaseManifest && !manifest.ok) {
  throw new Error(
    releaseTag
      ? `required release manifest for tag ${releaseTag} was not found`
      : `required release manifest for ${githubRepo} was not found`,
  );
}

await Promise.all([
  writeManifestFile(dataOutputPath, manifest),
  writeManifestFile(publicOutputPath, manifest),
]);

console.log(
  `[lintai] wrote release manifest for ${githubRepo}: ${manifest.tag || "no published release detected"}`,
);
