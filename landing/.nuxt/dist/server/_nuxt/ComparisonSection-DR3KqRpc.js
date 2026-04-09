import { defineComponent, mergeProps, withCtx, unref, createVNode, toDisplayString, openBlock, createBlock, Fragment, renderList, useSSRContext } from "vue";
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate, ssrRenderList, ssrRenderClass } from "vue/server-renderer";
import { u as useLandingContent } from "./usePageSeo-Ba4JSXZC.js";
import { u as useI18n, V as VContainer, _ as _export_sfc } from "../server.mjs";
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
  __name: "ComparisonSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t } = useI18n();
    const columns = [
      { key: "lintai", labelKey: "comparison.columns.lintai", highlight: true },
      { key: "manualReview", labelKey: "comparison.columns.manualReview" },
      { key: "scripts", labelKey: "comparison.columns.scripts" },
      { key: "cloudScanners", labelKey: "comparison.columns.cloudScanners" }
    ];
    function getStatusIcon(status) {
      switch (status) {
        case "yes":
          return "✓";
        case "partial":
          return "◐";
        default:
          return "✕";
      }
    }
    function getCellClass(status) {
      switch (status) {
        case "yes":
          return "comparison-row__cell--yes";
        case "partial":
          return "comparison-row__cell--partial";
        default:
          return "comparison-row__cell--no";
      }
    }
    function getCell(row, key) {
      return row[key];
    }
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "comparison",
        class: "comparison-section section anchor-offset"
      }, _attrs))} data-v-46d824a9>`);
      _push(ssrRenderComponent(VContainer, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<div class="comparison-section__header" data-v-46d824a9${_scopeId}><h2 class="comparison-section__title" data-v-46d824a9${_scopeId}>${ssrInterpolate(unref(t)("comparison.sectionTitle"))}</h2><p class="comparison-section__subtitle" data-v-46d824a9${_scopeId}>${ssrInterpolate(unref(t)("comparison.sectionSubtitle"))}</p></div><div class="comparison-grid" data-v-46d824a9${_scopeId}><div class="comparison-grid__header" data-v-46d824a9${_scopeId}><div class="comparison-grid__feature-head" data-v-46d824a9${_scopeId}>${ssrInterpolate(unref(t)("comparison.feature"))}</div><!--[-->`);
            ssrRenderList(columns, (column) => {
              _push2(`<div class="${ssrRenderClass([{ "comparison-grid__column-head--highlight": column.highlight }, "comparison-grid__column-head"])}" data-v-46d824a9${_scopeId}>${ssrInterpolate(unref(t)(column.labelKey))}</div>`);
            });
            _push2(`<!--]--></div><!--[-->`);
            ssrRenderList(unref(content).comparisonRows, (row) => {
              _push2(`<article class="comparison-row" data-v-46d824a9${_scopeId}><div class="comparison-row__feature" data-v-46d824a9${_scopeId}>${ssrInterpolate(row.feature)}</div><div class="comparison-row__cells" data-v-46d824a9${_scopeId}><!--[-->`);
              ssrRenderList(columns, (column) => {
                _push2(`<div class="${ssrRenderClass([[
                  getCellClass(getCell(row, column.key).status),
                  { "comparison-row__cell--highlight": column.highlight }
                ], "comparison-row__cell"])}" data-v-46d824a9${_scopeId}><span class="comparison-row__icon" data-v-46d824a9${_scopeId}>${ssrInterpolate(getStatusIcon(getCell(row, column.key).status))}</span><span class="comparison-row__note" data-v-46d824a9${_scopeId}>${ssrInterpolate(getCell(row, column.key).note)}</span></div>`);
              });
              _push2(`<!--]--></div></article>`);
            });
            _push2(`<!--]--></div>`);
          } else {
            return [
              createVNode("div", { class: "comparison-section__header" }, [
                createVNode("h2", { class: "comparison-section__title" }, toDisplayString(unref(t)("comparison.sectionTitle")), 1),
                createVNode("p", { class: "comparison-section__subtitle" }, toDisplayString(unref(t)("comparison.sectionSubtitle")), 1)
              ]),
              createVNode("div", { class: "comparison-grid" }, [
                createVNode("div", { class: "comparison-grid__header" }, [
                  createVNode("div", { class: "comparison-grid__feature-head" }, toDisplayString(unref(t)("comparison.feature")), 1),
                  (openBlock(), createBlock(Fragment, null, renderList(columns, (column) => {
                    return createVNode("div", {
                      key: column.key,
                      class: ["comparison-grid__column-head", { "comparison-grid__column-head--highlight": column.highlight }]
                    }, toDisplayString(unref(t)(column.labelKey)), 3);
                  }), 64))
                ]),
                (openBlock(true), createBlock(Fragment, null, renderList(unref(content).comparisonRows, (row) => {
                  return openBlock(), createBlock("article", {
                    key: row.id,
                    class: "comparison-row"
                  }, [
                    createVNode("div", { class: "comparison-row__feature" }, toDisplayString(row.feature), 1),
                    createVNode("div", { class: "comparison-row__cells" }, [
                      (openBlock(), createBlock(Fragment, null, renderList(columns, (column) => {
                        return createVNode("div", {
                          key: column.key,
                          class: ["comparison-row__cell", [
                            getCellClass(getCell(row, column.key).status),
                            { "comparison-row__cell--highlight": column.highlight }
                          ]]
                        }, [
                          createVNode("span", { class: "comparison-row__icon" }, toDisplayString(getStatusIcon(getCell(row, column.key).status)), 1),
                          createVNode("span", { class: "comparison-row__note" }, toDisplayString(getCell(row, column.key).note), 1)
                        ], 2);
                      }), 64))
                    ])
                  ]);
                }), 128))
              ])
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
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/ComparisonSection.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const ComparisonSection = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-46d824a9"]]);
export {
  ComparisonSection as default
};
//# sourceMappingURL=ComparisonSection-DR3KqRpc.js.map
