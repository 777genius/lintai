import __nuxt_component_0 from "./DownloadSection-BF4_R9cX.js";
import { defineComponent, mergeProps, withCtx, unref, createVNode, toDisplayString, useSSRContext } from "vue";
import { ssrRenderComponent, ssrInterpolate } from "vue/server-renderer";
import { u as useLandingContent, b as usePageSeo } from "./usePageSeo-Ba4JSXZC.js";
import { V as VContainer } from "../server.mjs";
import "./i18n-B_nLlkZy.js";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@unhead+vue@2.1.12_vue@3.5.31/node_modules/@unhead/vue/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ofetch@1.5.1/node_modules/ofetch/dist/node.mjs";
import "#internal/nuxt/paths";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unctx@2.5.0/node_modules/unctx/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs";
import "pinia";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs";
import "vue-router";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/cookie-es@2.0.1/node_modules/cookie-es/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/destr@2.0.5/node_modules/destr/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ohash@2.0.11/node_modules/ohash/dist/index.mjs";
import "@vue/devtools-api";
import "@mdi/js";
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "download",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    usePageSeo("meta.downloadTitle", "meta.downloadDescription");
    return (_ctx, _push, _parent, _attrs) => {
      const _component_DownloadSection = __nuxt_component_0;
      _push(ssrRenderComponent(VContainer, mergeProps({ class: "section" }, _attrs), {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<h1 class="text-h4 section-title"${_scopeId}>${ssrInterpolate(unref(content).download.title)}</h1><p class="text-body-2 mb-6"${_scopeId}>${ssrInterpolate(unref(content).download.note)}</p>`);
            _push2(ssrRenderComponent(_component_DownloadSection, null, null, _parent2, _scopeId));
          } else {
            return [
              createVNode("h1", { class: "text-h4 section-title" }, toDisplayString(unref(content).download.title), 1),
              createVNode("p", { class: "text-body-2 mb-6" }, toDisplayString(unref(content).download.note), 1),
              createVNode(_component_DownloadSection)
            ];
          }
        }),
        _: 1
      }, _parent));
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/download.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
export {
  _sfc_main as default
};
//# sourceMappingURL=download-BPC7ENgR.js.map
