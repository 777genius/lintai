import { defineComponent, computed, mergeProps, useSSRContext } from "vue";
import { ssrRenderAttrs } from "vue/server-renderer";
import { u as useAppConfig, r as resolveIconName } from "./index-7WrDIlZh.js";
import { _ as _export_sfc } from "../server.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ofetch@1.5.1/node_modules/ofetch/dist/node.mjs";
import "#internal/nuxt/paths";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unctx@2.5.0/node_modules/unctx/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs";
import "pinia";
import "vue-router";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/cookie-es@2.0.1/node_modules/cookie-es/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/destr@2.0.5/node_modules/destr/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ohash@2.0.11/node_modules/ohash/dist/index.mjs";
import "@vue/devtools-api";
import "@mdi/js";
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
      if (appConfig.nuxtIcon?.aliases?.[props.name]) {
        return appConfig.nuxtIcon.aliases[props.name];
      }
      return props.name;
    });
    const resolvedIcon = computed(() => resolveIconName(iconName.value));
    const iconUrl = computed(() => {
      const customUrl = appConfig.nuxtIcon?.iconifyApiOptions?.url;
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
      if (!props.size && typeof appConfig.nuxtIcon?.size === "boolean" && !appConfig.nuxtIcon?.size) {
        return void 0;
      }
      const size = props.size || appConfig.nuxtIcon?.size || "1em";
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
export {
  IconCSS as default
};
//# sourceMappingURL=IconCSS-DpZ5SiEn.js.map
