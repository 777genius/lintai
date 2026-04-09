import { defineEventHandler, setHeader } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs';
import { u as useRuntimeConfig } from '../nitro/nitro.mjs';
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

const supportedLocales = [
  { code: "en", iso: "en-US", name: "English", flag: "\u{1F1FA}\u{1F1F8}", file: "en.json" },
  { code: "ru", iso: "ru-RU", name: "\u0420\u0443\u0441\u0441\u043A\u0438\u0439", flag: "\u{1F1F7}\u{1F1FA}", file: "ru.json" }
];
const defaultLocale = "en";
const sitemapPages = ["/", "/download"];
const buildI18nRoutes = (source) => {
  const routes = [];
  for (const page of source) {
    routes.push(page);
    for (const locale of supportedLocales) {
      if (locale.code === defaultLocale) continue;
      routes.push(page === "/" ? `/${locale.code}` : `/${locale.code}${page}`);
    }
  }
  return routes;
};
const generateSitemapRoutes = () => buildI18nRoutes(sitemapPages);

const escapeXml = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");
const buildDate = (/* @__PURE__ */ new Date()).toISOString().split("T")[0];
const sitemap_xml = defineEventHandler((event) => {
  const config = useRuntimeConfig();
  const siteUrl = config.public.siteUrl || "https://777genius.github.io/lintai";
  setHeader(event, "content-type", "application/xml; charset=utf-8");
  const routes = generateSitemapRoutes();
  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${routes.map(
    (path) => `  <url>
    <loc>${escapeXml(`${siteUrl}${path}`)}</loc>
    <lastmod>${buildDate}</lastmod>
  </url>`
  ).join("\n")}
</urlset>
`;
  return body;
});

export { sitemap_xml as default };
//# sourceMappingURL=sitemap.xml.mjs.map
