import { defineComponent, computed, mergeProps, useSSRContext } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { ssrRenderAttrs } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/server-renderer/index.mjs';
import { u as useAppConfig, r as resolveIconName } from './index-7WrDIlZh.mjs';
import { _ as _export_sfc } from './server.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ofetch@1.5.1/node_modules/ofetch/dist/node.mjs';
import '../_/renderer.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-bundle-renderer@2.2.0/node_modules/vue-bundle-renderer/dist/runtime.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs';
import '../nitro/nitro.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/destr@2.0.5/node_modules/destr/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/node-mock-http@1.0.4/node_modules/node-mock-http/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/fs.mjs';
import 'node:crypto';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/fs-lite.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unstorage@1.17.5_db0@0.3.4_ioredis@5.10.1/node_modules/unstorage/drivers/lru-cache.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ohash@2.0.11/node_modules/ohash/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/scule@1.3.0/node_modules/scule/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unctx@2.5.0/node_modules/unctx/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/radix3@1.1.2/node_modules/radix3/dist/index.mjs';
import 'node:fs';
import 'node:url';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/pathe@2.0.3/node_modules/pathe/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/server.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/devalue@5.6.4/node_modules/devalue/index.js';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/plugins.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/utils.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/pinia@3.0.4_typescript@6.0.2_vue@3.5.31/node_modules/pinia/dist/pinia.prod.cjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-router@4.6.4_vue@3.5.31/node_modules/vue-router/vue-router.node.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/cookie-es@2.0.1/node_modules/cookie-es/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-devtools-stub@0.1.0/node_modules/vue-devtools-stub/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@mdi+js@7.4.47/node_modules/@mdi/js/commonjs/mdi.js';

const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "IconCSS",
  __ssrInlineRender: true,
  props: {
    name: {
      type: String,
      required: true
    },
    size: {
      type: String,
      default: ""
    }
  },
  setup(__props) {
    const appConfig = useAppConfig();
    const props = __props;
    const iconName = computed(() => {
      var _a, _b;
      if ((_b = (_a = appConfig.nuxtIcon) == null ? void 0 : _a.aliases) == null ? void 0 : _b[props.name]) {
        return appConfig.nuxtIcon.aliases[props.name];
      }
      return props.name;
    });
    const resolvedIcon = computed(() => resolveIconName(iconName.value));
    const iconUrl = computed(() => {
      var _a, _b;
      const customUrl = (_b = (_a = appConfig.nuxtIcon) == null ? void 0 : _a.iconifyApiOptions) == null ? void 0 : _b.url;
      if (customUrl) {
        try {
          new URL(customUrl);
        } catch (e) {
          console.warn("Nuxt IconCSS: Invalid custom Iconify API URL");
          return;
        }
      }
      const baseUrl = customUrl || "https://api.iconify.design";
      return `url('${baseUrl}/${resolvedIcon.value.prefix}/${resolvedIcon.value.name}.svg')`;
    });
    const sSize = computed(() => {
      var _a, _b, _c;
      if (!props.size && typeof ((_a = appConfig.nuxtIcon) == null ? void 0 : _a.size) === "boolean" && !((_b = appConfig.nuxtIcon) == null ? void 0 : _b.size)) {
        return void 0;
      }
      const size = props.size || ((_c = appConfig.nuxtIcon) == null ? void 0 : _c.size) || "1em";
      if (String(Number(size)) === size) {
        return `${size}px`;
      }
      return size;
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _cssVars = { style: {
        ":--v77378481": iconUrl.value
      } };
      _push(`<span${ssrRenderAttrs(mergeProps({
        style: { width: sSize.value, height: sSize.value }
      }, _attrs, _cssVars))} data-v-f4f280f3></span>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("node_modules/.pnpm/nuxt-icon@0.6.10_vite@7.3.1_vue@3.5.31/node_modules/nuxt-icon/dist/runtime/IconCSS.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const IconCSS = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-f4f280f3"]]);

export { IconCSS as default };
//# sourceMappingURL=IconCSS-DpZ5SiEn.mjs.map
