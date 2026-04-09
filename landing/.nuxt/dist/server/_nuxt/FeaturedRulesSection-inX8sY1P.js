import { defineComponent, mergeProps, withCtx, unref, createVNode, toDisplayString, openBlock, createBlock, Fragment, renderList, useSSRContext } from "vue";
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate, ssrRenderList, ssrRenderAttr } from "vue/server-renderer";
import { u as useLandingContent } from "./usePageSeo-Ba4JSXZC.js";
import { u as useI18n, V as VContainer, _ as _export_sfc } from "../server.mjs";
import { V as VRow, a as VCol } from "./index-DlBCAopn.js";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs";
import "./i18n-B_nLlkZy.js";
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
  __name: "FeaturedRulesSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t } = useI18n();
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "featured-rules",
        class: "featured-rules section anchor-offset"
      }, _attrs))} data-v-18fbef70>`);
      _push(ssrRenderComponent(VContainer, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<div class="featured-rules__header" data-v-18fbef70${_scopeId}><h2 class="featured-rules__title" data-v-18fbef70${_scopeId}>${ssrInterpolate(unref(t)("featuredRules.sectionTitle"))}</h2><p class="featured-rules__subtitle" data-v-18fbef70${_scopeId}>${ssrInterpolate(unref(t)("featuredRules.sectionSubtitle"))}</p></div>`);
            _push2(ssrRenderComponent(VRow, null, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(`<!--[-->`);
                  ssrRenderList(unref(content).featuredRules, (rule) => {
                    _push3(ssrRenderComponent(VCol, {
                      key: rule.id,
                      cols: "12",
                      md: "6"
                    }, {
                      default: withCtx((_3, _push4, _parent4, _scopeId3) => {
                        if (_push4) {
                          _push4(`<article class="featured-rules__card" data-v-18fbef70${_scopeId3}><div class="featured-rules__eyebrow" data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.eyebrow)}</div><div class="featured-rules__code" data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.code)}</div><h3 class="featured-rules__card-title" data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.title)}</h3><p class="featured-rules__body" data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.description)}</p><div class="featured-rules__panel" data-v-18fbef70${_scopeId3}><div class="featured-rules__panel-label" data-v-18fbef70${_scopeId3}>${ssrInterpolate(unref(t)("featuredRules.whyItMatters"))}</div><p class="featured-rules__panel-copy" data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.whyItMatters)}</p></div><div class="featured-rules__footer" data-v-18fbef70${_scopeId3}><span class="featured-rules__signal" data-v-18fbef70${_scopeId3}><span class="featured-rules__signal-label" data-v-18fbef70${_scopeId3}>${ssrInterpolate(unref(t)("featuredRules.evidenceLabel"))}</span><span data-v-18fbef70${_scopeId3}>${ssrInterpolate(rule.evidence)}</span></span><a${ssrRenderAttr("href", rule.href)} class="featured-rules__link" target="_blank" rel="noopener noreferrer" data-v-18fbef70${_scopeId3}>${ssrInterpolate(unref(t)("featuredRules.openRule"))}</a></div></article>`);
                        } else {
                          return [
                            createVNode("article", { class: "featured-rules__card" }, [
                              createVNode("div", { class: "featured-rules__eyebrow" }, toDisplayString(rule.eyebrow), 1),
                              createVNode("div", { class: "featured-rules__code" }, toDisplayString(rule.code), 1),
                              createVNode("h3", { class: "featured-rules__card-title" }, toDisplayString(rule.title), 1),
                              createVNode("p", { class: "featured-rules__body" }, toDisplayString(rule.description), 1),
                              createVNode("div", { class: "featured-rules__panel" }, [
                                createVNode("div", { class: "featured-rules__panel-label" }, toDisplayString(unref(t)("featuredRules.whyItMatters")), 1),
                                createVNode("p", { class: "featured-rules__panel-copy" }, toDisplayString(rule.whyItMatters), 1)
                              ]),
                              createVNode("div", { class: "featured-rules__footer" }, [
                                createVNode("span", { class: "featured-rules__signal" }, [
                                  createVNode("span", { class: "featured-rules__signal-label" }, toDisplayString(unref(t)("featuredRules.evidenceLabel")), 1),
                                  createVNode("span", null, toDisplayString(rule.evidence), 1)
                                ]),
                                createVNode("a", {
                                  href: rule.href,
                                  class: "featured-rules__link",
                                  target: "_blank",
                                  rel: "noopener noreferrer"
                                }, toDisplayString(unref(t)("featuredRules.openRule")), 9, ["href"])
                              ])
                            ])
                          ];
                        }
                      }),
                      _: 2
                    }, _parent3, _scopeId2));
                  });
                  _push3(`<!--]-->`);
                } else {
                  return [
                    (openBlock(true), createBlock(Fragment, null, renderList(unref(content).featuredRules, (rule) => {
                      return openBlock(), createBlock(VCol, {
                        key: rule.id,
                        cols: "12",
                        md: "6"
                      }, {
                        default: withCtx(() => [
                          createVNode("article", { class: "featured-rules__card" }, [
                            createVNode("div", { class: "featured-rules__eyebrow" }, toDisplayString(rule.eyebrow), 1),
                            createVNode("div", { class: "featured-rules__code" }, toDisplayString(rule.code), 1),
                            createVNode("h3", { class: "featured-rules__card-title" }, toDisplayString(rule.title), 1),
                            createVNode("p", { class: "featured-rules__body" }, toDisplayString(rule.description), 1),
                            createVNode("div", { class: "featured-rules__panel" }, [
                              createVNode("div", { class: "featured-rules__panel-label" }, toDisplayString(unref(t)("featuredRules.whyItMatters")), 1),
                              createVNode("p", { class: "featured-rules__panel-copy" }, toDisplayString(rule.whyItMatters), 1)
                            ]),
                            createVNode("div", { class: "featured-rules__footer" }, [
                              createVNode("span", { class: "featured-rules__signal" }, [
                                createVNode("span", { class: "featured-rules__signal-label" }, toDisplayString(unref(t)("featuredRules.evidenceLabel")), 1),
                                createVNode("span", null, toDisplayString(rule.evidence), 1)
                              ]),
                              createVNode("a", {
                                href: rule.href,
                                class: "featured-rules__link",
                                target: "_blank",
                                rel: "noopener noreferrer"
                              }, toDisplayString(unref(t)("featuredRules.openRule")), 9, ["href"])
                            ])
                          ])
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
              createVNode("div", { class: "featured-rules__header" }, [
                createVNode("h2", { class: "featured-rules__title" }, toDisplayString(unref(t)("featuredRules.sectionTitle")), 1),
                createVNode("p", { class: "featured-rules__subtitle" }, toDisplayString(unref(t)("featuredRules.sectionSubtitle")), 1)
              ]),
              createVNode(VRow, null, {
                default: withCtx(() => [
                  (openBlock(true), createBlock(Fragment, null, renderList(unref(content).featuredRules, (rule) => {
                    return openBlock(), createBlock(VCol, {
                      key: rule.id,
                      cols: "12",
                      md: "6"
                    }, {
                      default: withCtx(() => [
                        createVNode("article", { class: "featured-rules__card" }, [
                          createVNode("div", { class: "featured-rules__eyebrow" }, toDisplayString(rule.eyebrow), 1),
                          createVNode("div", { class: "featured-rules__code" }, toDisplayString(rule.code), 1),
                          createVNode("h3", { class: "featured-rules__card-title" }, toDisplayString(rule.title), 1),
                          createVNode("p", { class: "featured-rules__body" }, toDisplayString(rule.description), 1),
                          createVNode("div", { class: "featured-rules__panel" }, [
                            createVNode("div", { class: "featured-rules__panel-label" }, toDisplayString(unref(t)("featuredRules.whyItMatters")), 1),
                            createVNode("p", { class: "featured-rules__panel-copy" }, toDisplayString(rule.whyItMatters), 1)
                          ]),
                          createVNode("div", { class: "featured-rules__footer" }, [
                            createVNode("span", { class: "featured-rules__signal" }, [
                              createVNode("span", { class: "featured-rules__signal-label" }, toDisplayString(unref(t)("featuredRules.evidenceLabel")), 1),
                              createVNode("span", null, toDisplayString(rule.evidence), 1)
                            ]),
                            createVNode("a", {
                              href: rule.href,
                              class: "featured-rules__link",
                              target: "_blank",
                              rel: "noopener noreferrer"
                            }, toDisplayString(unref(t)("featuredRules.openRule")), 9, ["href"])
                          ])
                        ])
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
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/FeaturedRulesSection.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const FeaturedRulesSection = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-18fbef70"]]);
export {
  FeaturedRulesSection as default
};
//# sourceMappingURL=FeaturedRulesSection-inX8sY1P.js.map
