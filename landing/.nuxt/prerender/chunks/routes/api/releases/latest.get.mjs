import { defineEventHandler, setHeader } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs';
import { u as useRuntimeConfig } from '../../../nitro/nitro.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/destr@2.0.5/node_modules/destr/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ofetch@1.5.1/node_modules/ofetch/dist/node.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/node-mock-http@1.0.4/node_modules/node-mock-http/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/fs.mjs';
import 'node:crypto';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/fs-lite.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/lru-cache.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ohash@2.0.11/node_modules/ohash/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/scule@1.3.0/node_modules/scule/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unctx@2.5.0/node_modules/unctx/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/radix3@1.1.2/node_modules/radix3/dist/index.mjs';
import 'node:fs';
import 'node:url';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/pathe@2.0.3/node_modules/pathe/dist/index.mjs';

const emptyVariant = { url: null, platformKey: null, version: null };
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
    version
  };
}
function parseGitHubRelease(release) {
  var _a;
  const version = ((_a = release.tag_name) == null ? void 0 : _a.replace(/^v/, "")) || null;
  const assets = release.assets || [];
  return {
    ok: true,
    source: "github-releases",
    fetchedAt: (/* @__PURE__ */ new Date()).toISOString(),
    version,
    pubDate: release.published_at || null,
    variants: {
      installers: {
        shell: toVariant(findAsset(assets, /^lintai-installer\.sh$/i), version),
        powershell: toVariant(findAsset(assets, /^lintai-installer\.ps1$/i), version)
      },
      macos: {
        arm64: toVariant(findAsset(assets, /aarch64-apple-darwin\.tar\.gz$/i), version)
      },
      windows: {
        x64: toVariant(findAsset(assets, /x86_64-pc-windows-msvc\.zip$/i), version)
      },
      linux: {
        x64: toVariant(findAsset(assets, /x86_64-unknown-linux-gnu\.tar\.gz$/i), version),
        muslX64: toVariant(findAsset(assets, /x86_64-unknown-linux-musl\.tar\.gz$/i), version)
      }
    }
  };
}
function emptyDownloadsResponse() {
  return {
    ok: false,
    source: "github-releases",
    fetchedAt: (/* @__PURE__ */ new Date()).toISOString(),
    version: null,
    pubDate: null,
    variants: {
      installers: {
        shell: { ...emptyVariant },
        powershell: { ...emptyVariant }
      },
      macos: {
        arm64: { ...emptyVariant }
      },
      windows: {
        x64: { ...emptyVariant }
      },
      linux: {
        x64: { ...emptyVariant },
        muslX64: { ...emptyVariant }
      }
    }
  };
}

const RELEASE_CACHE_TTL = 10 * 60 * 1e3;
let cachedRelease = null;
let cachedAt = 0;
const latest_get = defineEventHandler(async (event) => {
  var _a;
  const config = useRuntimeConfig(event);
  const githubRepo = config.public.githubRepo || "777genius/lintai";
  const token = (_a = config.github) == null ? void 0 : _a.token;
  setHeader(event, "cache-control", "public, max-age=600, stale-while-revalidate=86400");
  if (cachedRelease && Date.now() - cachedAt < RELEASE_CACHE_TTL) {
    return cachedRelease;
  }
  try {
    const release = await $fetch(
      `https://api.github.com/repos/${githubRepo}/releases/latest`,
      {
        headers: {
          Accept: "application/vnd.github+json",
          ...token ? { Authorization: `Bearer ${token}` } : {}
        }
      }
    );
    const parsed = parseGitHubRelease(release);
    cachedRelease = parsed;
    cachedAt = Date.now();
    return parsed;
  } catch {
    const fallback = emptyDownloadsResponse();
    cachedRelease = fallback;
    cachedAt = Date.now();
    return fallback;
  }
});

export { latest_get as default };
//# sourceMappingURL=latest.get.mjs.map
