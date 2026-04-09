import { defineComponent, computed, mergeProps, withCtx, unref, createVNode, openBlock, createBlock, Fragment, renderList, toDisplayString, useSSRContext } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate, ssrRenderList, ssrRenderStyle } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/server-renderer/index.mjs';
import { _ as _export_sfc, u as useI18n, V as VContainer, d as VIcon } from './server.mjs';
import { mdiLockOutline, mdiShieldCheckOutline, mdiFileSearchOutline, mdiCodeBracesBox, mdiTextBoxSearchOutline, mdiRadar } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@mdi+js@7.4.47/node_modules/@mdi/js/commonjs/mdi.js';
import { a as useLandingContent } from './usePageSeo-Ba4JSXZC.mjs';
import { V as VRow, a as VCol } from './index-DlBCAopn.mjs';
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
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs';
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
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs';
import './i18n-B_nLlkZy.mjs';

const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "FeatureCard",
  __ssrInlineRender: true,
  props: {
    title: {},
    description: {},
    icon: {},
    accent: {}
  },
  setup(__props) {
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<div${ssrRenderAttrs(mergeProps({
        class: "feature-card",
        style: { "--accent": __props.accent || "#6366f1" }
      }, _attrs))} data-v-47f733f3><div class="feature-card__header" data-v-47f733f3><div class="feature-card__icon-wrap" data-v-47f733f3><div class="feature-card__icon-bg" data-v-47f733f3></div>`);
      _push(ssrRenderComponent(VIcon, {
        icon: __props.icon,
        size: "22",
        class: "feature-card__icon"
      }, null, _parent));
      _push(`</div><h3 class="feature-card__title" data-v-47f733f3>${ssrInterpolate(__props.title)}</h3></div><p class="feature-card__desc" data-v-47f733f3>${ssrInterpolate(__props.description)}</p><div class="feature-card__shine" data-v-47f733f3></div></div>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/ui/FeatureCard.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const __nuxt_component_0 = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["__scopeId", "data-v-47f733f3"]]);
const features = [
  { id: "offlineFirst", icon: mdiLockOutline, accent: "#00f0ff" },
  { id: "deterministic", icon: mdiShieldCheckOutline, accent: "#ff00ff" },
  { id: "repoSurfaces", icon: mdiFileSearchOutline, accent: "#39ff14" },
  { id: "ciReady", icon: mdiCodeBracesBox, accent: "#ffd700" },
  { id: "honestBoundary", icon: mdiTextBoxSearchOutline, accent: "#00f0ff" },
  { id: "installedAudit", icon: mdiRadar, accent: "#ff00ff" }
];
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "FeaturesSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t } = useI18n();
    const items = computed(
      () => features.map((feature) => {
        const contentItem = content.value.features.find((item) => item.id === feature.id);
        if (!contentItem) return null;
        return { ...contentItem, icon: feature.icon, accent: feature.accent };
      }).filter((item) => item !== null)
    );
    return (_ctx, _push, _parent, _attrs) => {
      const _component_FeatureCard = __nuxt_component_0;
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "features",
        class: "features-section section anchor-offset"
      }, _attrs))} data-v-266db552>`);
      _push(ssrRenderComponent(VContainer, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<div class="features-section__header" data-v-266db552${_scopeId}><h2 class="features-section__title" data-v-266db552${_scopeId}>${ssrInterpolate(unref(t)("features.sectionTitle"))}</h2><p class="features-section__subtitle" data-v-266db552${_scopeId}>${ssrInterpolate(unref(t)("features.sectionSubtitle"))}</p></div>`);
            _push2(ssrRenderComponent(VRow, { justify: "center" }, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(`<!--[-->`);
                  ssrRenderList(unref(items), (item, index) => {
                    _push3(ssrRenderComponent(VCol, {
                      key: item.id,
                      cols: "12",
                      sm: "6",
                      lg: "4"
                    }, {
                      default: withCtx((_3, _push4, _parent4, _scopeId3) => {
                        if (_push4) {
                          _push4(`<div class="features-section__card-wrap" style="${ssrRenderStyle({ "--delay": `${index * 0.06}s` })}" data-v-266db552${_scopeId3}>`);
                          _push4(ssrRenderComponent(_component_FeatureCard, {
                            title: item.title,
                            description: item.description,
                            icon: item.icon,
                            accent: item.accent
                          }, null, _parent4, _scopeId3));
                          _push4(`</div>`);
                        } else {
                          return [
                            createVNode("div", {
                              class: "features-section__card-wrap",
                              style: { "--delay": `${index * 0.06}s` }
                            }, [
                              createVNode(_component_FeatureCard, {
                                title: item.title,
                                description: item.description,
                                icon: item.icon,
                                accent: item.accent
                              }, null, 8, ["title", "description", "icon", "accent"])
                            ], 4)
                          ];
                        }
                      }),
                      _: 2
                    }, _parent3, _scopeId2));
                  });
                  _push3(`<!--]-->`);
                } else {
                  return [
                    (openBlock(true), createBlock(Fragment, null, renderList(unref(items), (item, index) => {
                      return openBlock(), createBlock(VCol, {
                        key: item.id,
                        cols: "12",
                        sm: "6",
                        lg: "4"
                      }, {
                        default: withCtx(() => [
                          createVNode("div", {
                            class: "features-section__card-wrap",
                            style: { "--delay": `${index * 0.06}s` }
                          }, [
                            createVNode(_component_FeatureCard, {
                              title: item.title,
                              description: item.description,
                              icon: item.icon,
                              accent: item.accent
                            }, null, 8, ["title", "description", "icon", "accent"])
                          ], 4)
                        ]),
                        _: 2
                      }, 1024);
                    }), 128))
                  ];
                }
              }),
              _: 1
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode("div", { class: "features-section__header" }, [
                createVNode("h2", { class: "features-section__title" }, toDisplayString(unref(t)("features.sectionTitle")), 1),
                createVNode("p", { class: "features-section__subtitle" }, toDisplayString(unref(t)("features.sectionSubtitle")), 1)
              ]),
              createVNode(VRow, { justify: "center" }, {
                default: withCtx(() => [
                  (openBlock(true), createBlock(Fragment, null, renderList(unref(items), (item, index) => {
                    return openBlock(), createBlock(VCol, {
                      key: item.id,
                      cols: "12",
                      sm: "6",
                      lg: "4"
                    }, {
                      default: withCtx(() => [
                        createVNode("div", {
                          class: "features-section__card-wrap",
                          style: { "--delay": `${index * 0.06}s` }
                        }, [
                          createVNode(_component_FeatureCard, {
                            title: item.title,
                            description: item.description,
                            icon: item.icon,
                            accent: item.accent
                          }, null, 8, ["title", "description", "icon", "accent"])
                        ], 4)
                      ]),
                      _: 2
                    }, 1024);
                  }), 128))
                ]),
                _: 1
              })
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</section>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/FeaturesSection.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const FeaturesSection = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-266db552"]]);

export { FeaturesSection as default };
//# sourceMappingURL=FeaturesSection-BgaSYBq_.mjs.map
