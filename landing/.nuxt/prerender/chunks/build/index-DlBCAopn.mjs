import { defineComponent, mergeProps, ref, defineAsyncComponent, computed, withCtx, unref, createTextVNode, toDisplayString, createVNode, openBlock, createBlock, Fragment, createCommentVNode, h, capitalize, useSSRContext } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/server-renderer/index.mjs';
import { _ as _export_sfc, u as useI18n, V as VContainer, c as VBtn, d as VIcon, e as useRuntimeConfig, g as genericComponent, p as propsFactory, m as makeTagProps, a as makeComponentProps, b as breakpoints } from './server.mjs';
import { mdiRobotOutline, mdiViewDashboardOutline, mdiOpenSourceInitiative } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@mdi+js@7.4.47/node_modules/@mdi/js/commonjs/mdi.js';
import { u as usePageSeo, a as useLandingContent, b as useReleaseDownloads, f as formatReleaseDate } from './usePageSeo-Ba4JSXZC.mjs';
import { u as useDocsLinks } from './i18n-B_nLlkZy.mjs';
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

const breakpointProps = (() => {
  return breakpoints.reduce((props, val) => {
    props[val] = {
      type: [Boolean, String, Number],
      default: false
    };
    return props;
  }, {});
})();
const offsetProps = (() => {
  return breakpoints.reduce((props, val) => {
    const offsetKey = "offset" + capitalize(val);
    props[offsetKey] = {
      type: [String, Number],
      default: null
    };
    return props;
  }, {});
})();
const orderProps = (() => {
  return breakpoints.reduce((props, val) => {
    const orderKey = "order" + capitalize(val);
    props[orderKey] = {
      type: [String, Number],
      default: null
    };
    return props;
  }, {});
})();
const propMap$1 = {
  col: Object.keys(breakpointProps),
  offset: Object.keys(offsetProps),
  order: Object.keys(orderProps)
};
function breakpointClass$1(type, prop, val) {
  let className = type;
  if (val == null || val === false) {
    return void 0;
  }
  if (prop) {
    const breakpoint = prop.replace(type, "");
    className += `-${breakpoint}`;
  }
  if (type === "col") {
    className = "v-" + className;
  }
  if (type === "col" && (val === "" || val === true)) {
    return className.toLowerCase();
  }
  className += `-${val}`;
  return className.toLowerCase();
}
const ALIGN_SELF_VALUES = ["auto", "start", "end", "center", "baseline", "stretch"];
const makeVColProps = propsFactory({
  cols: {
    type: [Boolean, String, Number],
    default: false
  },
  ...breakpointProps,
  offset: {
    type: [String, Number],
    default: null
  },
  ...offsetProps,
  order: {
    type: [String, Number],
    default: null
  },
  ...orderProps,
  alignSelf: {
    type: String,
    default: null,
    validator: (str) => ALIGN_SELF_VALUES.includes(str)
  },
  ...makeComponentProps(),
  ...makeTagProps()
}, "VCol");
const VCol = genericComponent()({
  name: "VCol",
  props: makeVColProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const classes = computed(() => {
      const classList = [];
      let type;
      for (type in propMap$1) {
        propMap$1[type].forEach((prop) => {
          const value = props[prop];
          const className = breakpointClass$1(type, prop, value);
          if (className) classList.push(className);
        });
      }
      const hasColClasses = classList.some((className) => className.startsWith("v-col-"));
      classList.push({
        // Default to .v-col if no other col-{bp}-* classes generated nor `cols` specified.
        "v-col": !hasColClasses || !props.cols,
        [`v-col-${props.cols}`]: props.cols,
        [`offset-${props.offset}`]: props.offset,
        [`order-${props.order}`]: props.order,
        [`align-self-${props.alignSelf}`]: props.alignSelf
      });
      return classList;
    });
    return () => {
      var _a;
      return h(props.tag, {
        class: [classes.value, props.class],
        style: props.style
      }, (_a = slots.default) == null ? void 0 : _a.call(slots));
    };
  }
});
const ALIGNMENT = ["start", "end", "center"];
const SPACE = ["space-between", "space-around", "space-evenly"];
function makeRowProps(prefix, def) {
  return breakpoints.reduce((props, val) => {
    const prefixKey = prefix + capitalize(val);
    props[prefixKey] = def();
    return props;
  }, {});
}
const ALIGN_VALUES = [...ALIGNMENT, "baseline", "stretch"];
const alignValidator = (str) => ALIGN_VALUES.includes(str);
const alignProps = makeRowProps("align", () => ({
  type: String,
  default: null,
  validator: alignValidator
}));
const JUSTIFY_VALUES = [...ALIGNMENT, ...SPACE];
const justifyValidator = (str) => JUSTIFY_VALUES.includes(str);
const justifyProps = makeRowProps("justify", () => ({
  type: String,
  default: null,
  validator: justifyValidator
}));
const ALIGN_CONTENT_VALUES = [...ALIGNMENT, ...SPACE, "stretch"];
const alignContentValidator = (str) => ALIGN_CONTENT_VALUES.includes(str);
const alignContentProps = makeRowProps("alignContent", () => ({
  type: String,
  default: null,
  validator: alignContentValidator
}));
const propMap = {
  align: Object.keys(alignProps),
  justify: Object.keys(justifyProps),
  alignContent: Object.keys(alignContentProps)
};
const classMap = {
  align: "align",
  justify: "justify",
  alignContent: "align-content"
};
function breakpointClass(type, prop, val) {
  let className = classMap[type];
  if (val == null) {
    return void 0;
  }
  if (prop) {
    const breakpoint = prop.replace(type, "");
    className += `-${breakpoint}`;
  }
  className += `-${val}`;
  return className.toLowerCase();
}
const makeVRowProps = propsFactory({
  dense: Boolean,
  noGutters: Boolean,
  align: {
    type: String,
    default: null,
    validator: alignValidator
  },
  ...alignProps,
  justify: {
    type: String,
    default: null,
    validator: justifyValidator
  },
  ...justifyProps,
  alignContent: {
    type: String,
    default: null,
    validator: alignContentValidator
  },
  ...alignContentProps,
  ...makeComponentProps(),
  ...makeTagProps()
}, "VRow");
const VRow = genericComponent()({
  name: "VRow",
  props: makeVRowProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const classes = computed(() => {
      const classList = [];
      let type;
      for (type in propMap) {
        propMap[type].forEach((prop) => {
          const value = props[prop];
          const className = breakpointClass(type, prop, value);
          if (className) classList.push(className);
        });
      }
      classList.push({
        "v-row--no-gutters": props.noGutters,
        "v-row--dense": props.dense,
        [`align-${props.align}`]: props.align,
        [`justify-${props.justify}`]: props.justify,
        [`align-content-${props.alignContent}`]: props.alignContent
      });
      return classList;
    });
    return () => {
      var _a;
      return h(props.tag, {
        class: ["v-row", classes.value, props.class],
        style: props.style
      }, (_a = slots.default) == null ? void 0 : _a.call(slots));
    };
  }
});
const _sfc_main$3 = {};
function _sfc_ssrRender(_ctx, _push, _parent, _attrs) {
  _push(`<div${ssrRenderAttrs(mergeProps({
    class: "page-bg",
    "aria-hidden": "true"
  }, _attrs))} data-v-d2de2625><div class="page-bg__grid" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--1" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--2" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--3" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--4" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--5" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--6" data-v-d2de2625></div><div class="page-bg__orb page-bg__orb--7" data-v-d2de2625></div><div class="page-bg__scanline" data-v-d2de2625></div></div>`);
}
const _sfc_setup$3 = _sfc_main$3.setup;
_sfc_main$3.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/PageBackground.vue");
  return _sfc_setup$3 ? _sfc_setup$3(props, ctx) : void 0;
};
const __nuxt_component_0 = /* @__PURE__ */ _export_sfc(_sfc_main$3, [["ssrRender", _sfc_ssrRender], ["__scopeId", "data-v-d2de2625"]]);
const __nuxt_component_0_lazy = defineAsyncComponent(() => import('./HeroDemo-BrNhyOSY.mjs').then((c) => c.default || c));
const _sfc_main$2 = /* @__PURE__ */ defineComponent({
  __name: "HeroSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t, locale } = useI18n();
    const config = useRuntimeConfig();
    const githubUrl = `https://github.com/${config.public.githubRepo}`;
    const { docsUrl } = useDocsLinks();
    const { data: releaseData } = useReleaseDownloads();
    const releaseVersion = computed(() => {
      var _a;
      return ((_a = releaseData.value) == null ? void 0 : _a.version) || null;
    });
    const releaseDate = computed(() => {
      var _a;
      const raw = (_a = releaseData.value) == null ? void 0 : _a.pubDate;
      if (!raw) return null;
      return formatReleaseDate(raw, locale.value);
    });
    return (_ctx, _push, _parent, _attrs) => {
      const _component_LazyHeroDemo = __nuxt_component_0_lazy;
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "hero",
        class: "hero-section section anchor-offset"
      }, _attrs))} data-v-773c8334>`);
      _push(ssrRenderComponent(VContainer, { class: "hero-section__container" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(VRow, {
              align: "start",
              justify: "space-between"
            }, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(ssrRenderComponent(VCol, {
                    cols: "12",
                    md: "6",
                    class: "hero-section__content"
                  }, {
                    default: withCtx((_3, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`<h1 class="hero-section__title" data-v-773c8334${_scopeId3}><span class="hero-section__logo" data-v-773c8334${_scopeId3}>L</span> ${ssrInterpolate(unref(content).hero.title)}</h1><p class="hero-section__subtitle" data-v-773c8334${_scopeId3}>${ssrInterpolate(unref(content).hero.subtitle)}</p><div class="hero-section__actions" data-v-773c8334${_scopeId3}>`);
                        _push4(ssrRenderComponent(VBtn, {
                          variant: "flat",
                          size: "large",
                          href: githubUrl,
                          target: "_blank",
                          rel: "noopener noreferrer",
                          class: "hero-section__btn-primary"
                        }, {
                          default: withCtx((_4, _push5, _parent5, _scopeId4) => {
                            if (_push5) {
                              _push5(`${ssrInterpolate(unref(t)("hero.primaryCta"))}`);
                            } else {
                              return [
                                createTextVNode(toDisplayString(unref(t)("hero.primaryCta")), 1)
                              ];
                            }
                          }),
                          _: 1
                        }, _parent4, _scopeId3));
                        _push4(ssrRenderComponent(VBtn, {
                          variant: "outlined",
                          size: "large",
                          href: "#featured-rules",
                          class: "hero-section__btn-secondary"
                        }, {
                          default: withCtx((_4, _push5, _parent5, _scopeId4) => {
                            if (_push5) {
                              _push5(`${ssrInterpolate(unref(t)("hero.secondaryCta"))}`);
                            } else {
                              return [
                                createTextVNode(toDisplayString(unref(t)("hero.secondaryCta")), 1)
                              ];
                            }
                          }),
                          _: 1
                        }, _parent4, _scopeId3));
                        _push4(ssrRenderComponent(VBtn, {
                          variant: "tonal",
                          size: "large",
                          href: unref(docsUrl),
                          class: "hero-section__btn-tertiary"
                        }, {
                          default: withCtx((_4, _push5, _parent5, _scopeId4) => {
                            if (_push5) {
                              _push5(`${ssrInterpolate(unref(t)("hero.docsCta"))}`);
                            } else {
                              return [
                                createTextVNode(toDisplayString(unref(t)("hero.docsCta")), 1)
                              ];
                            }
                          }),
                          _: 1
                        }, _parent4, _scopeId3));
                        _push4(`</div><div class="hero-section__meta-row" data-v-773c8334${_scopeId3}>`);
                        if (unref(releaseVersion)) {
                          _push4(`<div class="hero-section__release-badge" data-v-773c8334${_scopeId3}>${ssrInterpolate(unref(t)("hero.latestRelease"))} \xB7 v${ssrInterpolate(unref(releaseVersion))}`);
                          if (unref(releaseDate)) {
                            _push4(`<!--[--> \xB7 ${ssrInterpolate(unref(releaseDate))}<!--]-->`);
                          } else {
                            _push4(`<!---->`);
                          }
                          _push4(`</div>`);
                        } else {
                          _push4(`<!---->`);
                        }
                        _push4(`</div><div class="hero-section__trust" data-v-773c8334${_scopeId3}><div class="hero-section__trust-item" data-v-773c8334${_scopeId3}>`);
                        _push4(ssrRenderComponent(VIcon, {
                          size: "16",
                          class: "hero-section__trust-icon",
                          icon: unref(mdiRobotOutline)
                        }, null, _parent4, _scopeId3));
                        _push4(`<span data-v-773c8334${_scopeId3}>${ssrInterpolate(unref(t)("hero.trust.oneRepo"))}</span></div><div class="hero-section__trust-divider" data-v-773c8334${_scopeId3}></div><div class="hero-section__trust-item" data-v-773c8334${_scopeId3}>`);
                        _push4(ssrRenderComponent(VIcon, {
                          size: "16",
                          class: "hero-section__trust-icon",
                          icon: unref(mdiViewDashboardOutline)
                        }, null, _parent4, _scopeId3));
                        _push4(`<span data-v-773c8334${_scopeId3}>${ssrInterpolate(unref(t)("hero.trust.validated"))}</span></div><div class="hero-section__trust-divider" data-v-773c8334${_scopeId3}></div><div class="hero-section__trust-item" data-v-773c8334${_scopeId3}>`);
                        _push4(ssrRenderComponent(VIcon, {
                          size: "16",
                          class: "hero-section__trust-icon",
                          icon: unref(mdiOpenSourceInitiative)
                        }, null, _parent4, _scopeId3));
                        _push4(`<span data-v-773c8334${_scopeId3}>${ssrInterpolate(unref(t)("hero.trust.openSource"))}</span></div></div>`);
                      } else {
                        return [
                          createVNode("h1", { class: "hero-section__title" }, [
                            createVNode("span", { class: "hero-section__logo" }, "L"),
                            createTextVNode(" " + toDisplayString(unref(content).hero.title), 1)
                          ]),
                          createVNode("p", { class: "hero-section__subtitle" }, toDisplayString(unref(content).hero.subtitle), 1),
                          createVNode("div", { class: "hero-section__actions" }, [
                            createVNode(VBtn, {
                              variant: "flat",
                              size: "large",
                              href: githubUrl,
                              target: "_blank",
                              rel: "noopener noreferrer",
                              class: "hero-section__btn-primary"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(unref(t)("hero.primaryCta")), 1)
                              ]),
                              _: 1
                            }),
                            createVNode(VBtn, {
                              variant: "outlined",
                              size: "large",
                              href: "#featured-rules",
                              class: "hero-section__btn-secondary"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(unref(t)("hero.secondaryCta")), 1)
                              ]),
                              _: 1
                            }),
                            createVNode(VBtn, {
                              variant: "tonal",
                              size: "large",
                              href: unref(docsUrl),
                              class: "hero-section__btn-tertiary"
                            }, {
                              default: withCtx(() => [
                                createTextVNode(toDisplayString(unref(t)("hero.docsCta")), 1)
                              ]),
                              _: 1
                            }, 8, ["href"])
                          ]),
                          createVNode("div", { class: "hero-section__meta-row" }, [
                            unref(releaseVersion) ? (openBlock(), createBlock("div", {
                              key: 0,
                              class: "hero-section__release-badge"
                            }, [
                              createTextVNode(toDisplayString(unref(t)("hero.latestRelease")) + " \xB7 v" + toDisplayString(unref(releaseVersion)), 1),
                              unref(releaseDate) ? (openBlock(), createBlock(Fragment, { key: 0 }, [
                                createTextVNode(" \xB7 " + toDisplayString(unref(releaseDate)), 1)
                              ], 64)) : createCommentVNode("", true)
                            ])) : createCommentVNode("", true)
                          ]),
                          createVNode("div", { class: "hero-section__trust" }, [
                            createVNode("div", { class: "hero-section__trust-item" }, [
                              createVNode(VIcon, {
                                size: "16",
                                class: "hero-section__trust-icon",
                                icon: unref(mdiRobotOutline)
                              }, null, 8, ["icon"]),
                              createVNode("span", null, toDisplayString(unref(t)("hero.trust.oneRepo")), 1)
                            ]),
                            createVNode("div", { class: "hero-section__trust-divider" }),
                            createVNode("div", { class: "hero-section__trust-item" }, [
                              createVNode(VIcon, {
                                size: "16",
                                class: "hero-section__trust-icon",
                                icon: unref(mdiViewDashboardOutline)
                              }, null, 8, ["icon"]),
                              createVNode("span", null, toDisplayString(unref(t)("hero.trust.validated")), 1)
                            ]),
                            createVNode("div", { class: "hero-section__trust-divider" }),
                            createVNode("div", { class: "hero-section__trust-item" }, [
                              createVNode(VIcon, {
                                size: "16",
                                class: "hero-section__trust-icon",
                                icon: unref(mdiOpenSourceInitiative)
                              }, null, 8, ["icon"]),
                              createVNode("span", null, toDisplayString(unref(t)("hero.trust.openSource")), 1)
                            ])
                          ])
                        ];
                      }
                    }),
                    _: 1
                  }, _parent3, _scopeId2));
                  _push3(ssrRenderComponent(VCol, {
                    cols: "12",
                    md: "5",
                    class: "hero-section__demo-col"
                  }, {
                    default: withCtx((_3, _push4, _parent4, _scopeId3) => {
                      if (_push4) {
                        _push4(`<div class="hero-section__preview" data-v-773c8334${_scopeId3}><div class="hero-section__preview-glow" data-v-773c8334${_scopeId3}></div>`);
                        _push4(ssrRenderComponent(_component_LazyHeroDemo, null, null, _parent4, _scopeId3));
                        _push4(`</div>`);
                      } else {
                        return [
                          createVNode("div", { class: "hero-section__preview" }, [
                            createVNode("div", { class: "hero-section__preview-glow" }),
                            createVNode(_component_LazyHeroDemo)
                          ])
                        ];
                      }
                    }),
                    _: 1
                  }, _parent3, _scopeId2));
                } else {
                  return [
                    createVNode(VCol, {
                      cols: "12",
                      md: "6",
                      class: "hero-section__content"
                    }, {
                      default: withCtx(() => [
                        createVNode("h1", { class: "hero-section__title" }, [
                          createVNode("span", { class: "hero-section__logo" }, "L"),
                          createTextVNode(" " + toDisplayString(unref(content).hero.title), 1)
                        ]),
                        createVNode("p", { class: "hero-section__subtitle" }, toDisplayString(unref(content).hero.subtitle), 1),
                        createVNode("div", { class: "hero-section__actions" }, [
                          createVNode(VBtn, {
                            variant: "flat",
                            size: "large",
                            href: githubUrl,
                            target: "_blank",
                            rel: "noopener noreferrer",
                            class: "hero-section__btn-primary"
                          }, {
                            default: withCtx(() => [
                              createTextVNode(toDisplayString(unref(t)("hero.primaryCta")), 1)
                            ]),
                            _: 1
                          }),
                          createVNode(VBtn, {
                            variant: "outlined",
                            size: "large",
                            href: "#featured-rules",
                            class: "hero-section__btn-secondary"
                          }, {
                            default: withCtx(() => [
                              createTextVNode(toDisplayString(unref(t)("hero.secondaryCta")), 1)
                            ]),
                            _: 1
                          }),
                          createVNode(VBtn, {
                            variant: "tonal",
                            size: "large",
                            href: unref(docsUrl),
                            class: "hero-section__btn-tertiary"
                          }, {
                            default: withCtx(() => [
                              createTextVNode(toDisplayString(unref(t)("hero.docsCta")), 1)
                            ]),
                            _: 1
                          }, 8, ["href"])
                        ]),
                        createVNode("div", { class: "hero-section__meta-row" }, [
                          unref(releaseVersion) ? (openBlock(), createBlock("div", {
                            key: 0,
                            class: "hero-section__release-badge"
                          }, [
                            createTextVNode(toDisplayString(unref(t)("hero.latestRelease")) + " \xB7 v" + toDisplayString(unref(releaseVersion)), 1),
                            unref(releaseDate) ? (openBlock(), createBlock(Fragment, { key: 0 }, [
                              createTextVNode(" \xB7 " + toDisplayString(unref(releaseDate)), 1)
                            ], 64)) : createCommentVNode("", true)
                          ])) : createCommentVNode("", true)
                        ]),
                        createVNode("div", { class: "hero-section__trust" }, [
                          createVNode("div", { class: "hero-section__trust-item" }, [
                            createVNode(VIcon, {
                              size: "16",
                              class: "hero-section__trust-icon",
                              icon: unref(mdiRobotOutline)
                            }, null, 8, ["icon"]),
                            createVNode("span", null, toDisplayString(unref(t)("hero.trust.oneRepo")), 1)
                          ]),
                          createVNode("div", { class: "hero-section__trust-divider" }),
                          createVNode("div", { class: "hero-section__trust-item" }, [
                            createVNode(VIcon, {
                              size: "16",
                              class: "hero-section__trust-icon",
                              icon: unref(mdiViewDashboardOutline)
                            }, null, 8, ["icon"]),
                            createVNode("span", null, toDisplayString(unref(t)("hero.trust.validated")), 1)
                          ]),
                          createVNode("div", { class: "hero-section__trust-divider" }),
                          createVNode("div", { class: "hero-section__trust-item" }, [
                            createVNode(VIcon, {
                              size: "16",
                              class: "hero-section__trust-icon",
                              icon: unref(mdiOpenSourceInitiative)
                            }, null, 8, ["icon"]),
                            createVNode("span", null, toDisplayString(unref(t)("hero.trust.openSource")), 1)
                          ])
                        ])
                      ]),
                      _: 1
                    }),
                    createVNode(VCol, {
                      cols: "12",
                      md: "5",
                      class: "hero-section__demo-col"
                    }, {
                      default: withCtx(() => [
                        createVNode("div", { class: "hero-section__preview" }, [
                          createVNode("div", { class: "hero-section__preview-glow" }),
                          createVNode(_component_LazyHeroDemo)
                        ])
                      ]),
                      _: 1
                    })
                  ];
                }
              }),
              _: 1
            }, _parent2, _scopeId));
          } else {
            return [
              createVNode(VRow, {
                align: "start",
                justify: "space-between"
              }, {
                default: withCtx(() => [
                  createVNode(VCol, {
                    cols: "12",
                    md: "6",
                    class: "hero-section__content"
                  }, {
                    default: withCtx(() => [
                      createVNode("h1", { class: "hero-section__title" }, [
                        createVNode("span", { class: "hero-section__logo" }, "L"),
                        createTextVNode(" " + toDisplayString(unref(content).hero.title), 1)
                      ]),
                      createVNode("p", { class: "hero-section__subtitle" }, toDisplayString(unref(content).hero.subtitle), 1),
                      createVNode("div", { class: "hero-section__actions" }, [
                        createVNode(VBtn, {
                          variant: "flat",
                          size: "large",
                          href: githubUrl,
                          target: "_blank",
                          rel: "noopener noreferrer",
                          class: "hero-section__btn-primary"
                        }, {
                          default: withCtx(() => [
                            createTextVNode(toDisplayString(unref(t)("hero.primaryCta")), 1)
                          ]),
                          _: 1
                        }),
                        createVNode(VBtn, {
                          variant: "outlined",
                          size: "large",
                          href: "#featured-rules",
                          class: "hero-section__btn-secondary"
                        }, {
                          default: withCtx(() => [
                            createTextVNode(toDisplayString(unref(t)("hero.secondaryCta")), 1)
                          ]),
                          _: 1
                        }),
                        createVNode(VBtn, {
                          variant: "tonal",
                          size: "large",
                          href: unref(docsUrl),
                          class: "hero-section__btn-tertiary"
                        }, {
                          default: withCtx(() => [
                            createTextVNode(toDisplayString(unref(t)("hero.docsCta")), 1)
                          ]),
                          _: 1
                        }, 8, ["href"])
                      ]),
                      createVNode("div", { class: "hero-section__meta-row" }, [
                        unref(releaseVersion) ? (openBlock(), createBlock("div", {
                          key: 0,
                          class: "hero-section__release-badge"
                        }, [
                          createTextVNode(toDisplayString(unref(t)("hero.latestRelease")) + " \xB7 v" + toDisplayString(unref(releaseVersion)), 1),
                          unref(releaseDate) ? (openBlock(), createBlock(Fragment, { key: 0 }, [
                            createTextVNode(" \xB7 " + toDisplayString(unref(releaseDate)), 1)
                          ], 64)) : createCommentVNode("", true)
                        ])) : createCommentVNode("", true)
                      ]),
                      createVNode("div", { class: "hero-section__trust" }, [
                        createVNode("div", { class: "hero-section__trust-item" }, [
                          createVNode(VIcon, {
                            size: "16",
                            class: "hero-section__trust-icon",
                            icon: unref(mdiRobotOutline)
                          }, null, 8, ["icon"]),
                          createVNode("span", null, toDisplayString(unref(t)("hero.trust.oneRepo")), 1)
                        ]),
                        createVNode("div", { class: "hero-section__trust-divider" }),
                        createVNode("div", { class: "hero-section__trust-item" }, [
                          createVNode(VIcon, {
                            size: "16",
                            class: "hero-section__trust-icon",
                            icon: unref(mdiViewDashboardOutline)
                          }, null, 8, ["icon"]),
                          createVNode("span", null, toDisplayString(unref(t)("hero.trust.validated")), 1)
                        ]),
                        createVNode("div", { class: "hero-section__trust-divider" }),
                        createVNode("div", { class: "hero-section__trust-item" }, [
                          createVNode(VIcon, {
                            size: "16",
                            class: "hero-section__trust-icon",
                            icon: unref(mdiOpenSourceInitiative)
                          }, null, 8, ["icon"]),
                          createVNode("span", null, toDisplayString(unref(t)("hero.trust.openSource")), 1)
                        ])
                      ])
                    ]),
                    _: 1
                  }),
                  createVNode(VCol, {
                    cols: "12",
                    md: "5",
                    class: "hero-section__demo-col"
                  }, {
                    default: withCtx(() => [
                      createVNode("div", { class: "hero-section__preview" }, [
                        createVNode("div", { class: "hero-section__preview-glow" }),
                        createVNode(_component_LazyHeroDemo)
                      ])
                    ]),
                    _: 1
                  })
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
const _sfc_setup$2 = _sfc_main$2.setup;
_sfc_main$2.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/HeroSection.vue");
  return _sfc_setup$2 ? _sfc_setup$2(props, ctx) : void 0;
};
const __nuxt_component_1 = /* @__PURE__ */ _export_sfc(_sfc_main$2, [["__scopeId", "data-v-773c8334"]]);
const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "SectionDivider",
  __ssrInlineRender: true,
  props: {
    flip: { type: Boolean, default: false }
  },
  setup(__props) {
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<div${ssrRenderAttrs(mergeProps({
        class: ["section-wave", { "section-wave--flip": __props.flip }],
        "aria-hidden": "true"
      }, _attrs))} data-v-9d9a35e1><svg class="section-wave__svg section-wave__svg--1" viewBox="0 0 2880 100" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" data-v-9d9a35e1><path class="section-wave__path" d="M0,100 L0,60 C360,10 1080,90 1440,60 C1800,10 2520,90 2880,60 L2880,100 Z" data-v-9d9a35e1></path></svg><svg class="section-wave__svg section-wave__svg--2" viewBox="0 0 2880 100" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg" data-v-9d9a35e1><path class="section-wave__path section-wave__path--2" d="M0,100 L0,50 C480,85 960,15 1440,50 C1920,85 2400,15 2880,50 L2880,100 Z" data-v-9d9a35e1></path></svg></div>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/SectionDivider.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const __nuxt_component_2 = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["__scopeId", "data-v-9d9a35e1"]]);
const useParallaxSections = (speed = 0.1) => {
  const containerRef = ref(null);
  return { containerRef };
};
const __nuxt_component_3_lazy = defineAsyncComponent(() => import('./FeaturesSection-BgaSYBq_.mjs').then((c) => c.default || c));
const __nuxt_component_4_lazy = defineAsyncComponent(() => import('./FeaturedRulesSection-inX8sY1P.mjs').then((c) => c.default || c));
const __nuxt_component_5_lazy = defineAsyncComponent(() => import('./DownloadSection-BF4_R9cX.mjs').then((c) => c.default || c));
const __nuxt_component_6_lazy = defineAsyncComponent(() => import('./ComparisonSection-DR3KqRpc.mjs').then((c) => c.default || c));
const __nuxt_component_7_lazy = defineAsyncComponent(() => import('./FAQSection-6dfuvw15.mjs').then((c) => c.default || c));
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "index",
  __ssrInlineRender: true,
  setup(__props) {
    usePageSeo("meta.homeTitle", "meta.homeDescription");
    const { containerRef } = useParallaxSections();
    return (_ctx, _push, _parent, _attrs) => {
      const _component_PageBackground = __nuxt_component_0;
      const _component_HeroSection = __nuxt_component_1;
      const _component_SectionDivider = __nuxt_component_2;
      const _component_LazyFeaturesSection = __nuxt_component_3_lazy;
      const _component_LazyFeaturedRulesSection = __nuxt_component_4_lazy;
      const _component_LazyDownloadSection = __nuxt_component_5_lazy;
      const _component_LazyComparisonSection = __nuxt_component_6_lazy;
      const _component_LazyFAQSection = __nuxt_component_7_lazy;
      _push(`<div${ssrRenderAttrs(mergeProps({
        ref_key: "containerRef",
        ref: containerRef,
        class: "page"
      }, _attrs))}>`);
      _push(ssrRenderComponent(_component_PageBackground, null, null, _parent));
      _push(ssrRenderComponent(_component_HeroSection, null, null, _parent));
      _push(ssrRenderComponent(_component_SectionDivider, null, null, _parent));
      _push(ssrRenderComponent(_component_LazyFeaturesSection, null, null, _parent));
      _push(ssrRenderComponent(_component_SectionDivider, { flip: true }, null, _parent));
      _push(ssrRenderComponent(_component_LazyFeaturedRulesSection, null, null, _parent));
      _push(ssrRenderComponent(_component_SectionDivider, null, null, _parent));
      _push(ssrRenderComponent(_component_LazyDownloadSection, null, null, _parent));
      _push(ssrRenderComponent(_component_SectionDivider, { flip: true }, null, _parent));
      _push(ssrRenderComponent(_component_LazyComparisonSection, null, null, _parent));
      _push(ssrRenderComponent(_component_SectionDivider, null, null, _parent));
      _push(ssrRenderComponent(_component_LazyFAQSection, null, null, _parent));
      _push(`</div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("pages/index.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const index = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  default: _sfc_main
}, Symbol.toStringTag, { value: "Module" }));

export { VRow as V, VCol as a, index as i };
//# sourceMappingURL=index-DlBCAopn.mjs.map
