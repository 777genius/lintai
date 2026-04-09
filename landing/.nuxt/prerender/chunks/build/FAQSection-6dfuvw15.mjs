import { defineComponent, ref, watch, computed, mergeProps, withCtx, unref, createVNode, toDisplayString, openBlock, createBlock, Fragment, renderList, toRef, normalizeStyle, normalizeClass, provide, createElementVNode, inject, withDirectives, vShow, useSSRContext } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate, ssrRenderList, ssrRenderAttr } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/server-renderer/index.mjs';
import { mdiCodeTags, mdiRocketLaunchOutline, mdiShieldLockOutline, mdiAccountGroupOutline, mdiSourceBranch, mdiPackageVariantClosed, mdiHelpCircleOutline, mdiFrequentlyAskedQuestions, mdiArrowTopRight } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@mdi+js@7.4.47/node_modules/@mdi/js/commonjs/mdi.js';
import { a as useLandingContent } from './usePageSeo-Ba4JSXZC.mjs';
import { _ as _export_sfc, u as useI18n, V as VContainer, d as VIcon, g as genericComponent, ak as useGroup, L as provideTheme, a1 as provideDefaults, C as useRender, ap as useGroupItem, G as useBackgroundColor, ao as useElevation, H as useRounded, Q as VDefaultsProvider, a2 as Ripple, B as useDimension, p as propsFactory, m as makeTagProps, a as makeComponentProps, U as makeThemeProps, ag as pick, ah as makeGroupProps, K as makeRoundedProps, as as makeGroupItemProps, at as makeElevationProps, S as IconValue, D as makeDimensionProps } from './server.mjs';
import { a as useAnalytics, u as useLazy, b as VExpandTransition, m as makeLazyProps } from './lazy-CNBWeTG7.mjs';
import { u as useDocsLinks } from './i18n-B_nLlkZy.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs';
import '../_/renderer.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-bundle-renderer@2.2.0/node_modules/vue-bundle-renderer/dist/runtime.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/h3@1.15.11/node_modules/h3/dist/index.mjs';
import '../nitro/nitro.mjs';
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
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/server.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/devalue@5.6.4/node_modules/devalue/index.js';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/plugins.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/unhead@2.1.12/node_modules/unhead/dist/utils.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/pinia@3.0.4_typescript@6.0.2_vue@3.5.31/node_modules/pinia/dist/pinia.prod.cjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-router@4.6.4_vue@3.5.31/node_modules/vue-router/vue-router.node.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/cookie-es@2.0.1/node_modules/cookie-es/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-devtools-stub@0.1.0/node_modules/vue-devtools-stub/dist/index.mjs';

const VExpansionPanelSymbol = /* @__PURE__ */ Symbol.for("vuetify:v-expansion-panel");
const makeVExpansionPanelTextProps = propsFactory({
  ...makeComponentProps(),
  ...makeLazyProps()
}, "VExpansionPanelText");
const VExpansionPanelText = genericComponent()({
  name: "VExpansionPanelText",
  props: makeVExpansionPanelTextProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const expansionPanel = inject(VExpansionPanelSymbol);
    if (!expansionPanel) throw new Error("[Vuetify] v-expansion-panel-text needs to be placed inside v-expansion-panel");
    const {
      hasContent,
      onAfterLeave
    } = useLazy(props, expansionPanel.isSelected);
    useRender(() => createVNode(VExpandTransition, {
      "onAfterLeave": onAfterLeave
    }, {
      default: () => {
        var _a;
        return [withDirectives(createElementVNode("div", {
          "class": normalizeClass(["v-expansion-panel-text", props.class]),
          "style": normalizeStyle(props.style)
        }, [slots.default && hasContent.value && createElementVNode("div", {
          "class": "v-expansion-panel-text__wrapper"
        }, [(_a = slots.default) == null ? void 0 : _a.call(slots)])]), [[vShow, expansionPanel.isSelected.value]])];
      }
    }));
    return {};
  }
});
const makeVExpansionPanelTitleProps = propsFactory({
  color: String,
  expandIcon: {
    type: IconValue,
    default: "$expand"
  },
  collapseIcon: {
    type: IconValue,
    default: "$collapse"
  },
  hideActions: Boolean,
  focusable: Boolean,
  static: Boolean,
  ripple: {
    type: [Boolean, Object],
    default: false
  },
  readonly: Boolean,
  ...makeComponentProps(),
  ...makeDimensionProps()
}, "VExpansionPanelTitle");
const VExpansionPanelTitle = genericComponent()({
  name: "VExpansionPanelTitle",
  directives: {
    vRipple: Ripple
  },
  props: makeVExpansionPanelTitleProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const expansionPanel = inject(VExpansionPanelSymbol);
    if (!expansionPanel) throw new Error("[Vuetify] v-expansion-panel-title needs to be placed inside v-expansion-panel");
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.color);
    const {
      dimensionStyles
    } = useDimension(props);
    const slotProps = computed(() => ({
      collapseIcon: props.collapseIcon,
      disabled: expansionPanel.disabled.value,
      expanded: expansionPanel.isSelected.value,
      expandIcon: props.expandIcon,
      readonly: props.readonly
    }));
    const icon = toRef(() => expansionPanel.isSelected.value ? props.collapseIcon : props.expandIcon);
    useRender(() => {
      var _a;
      return withDirectives(createElementVNode("button", {
        "class": normalizeClass(["v-expansion-panel-title", {
          "v-expansion-panel-title--active": expansionPanel.isSelected.value,
          "v-expansion-panel-title--focusable": props.focusable,
          "v-expansion-panel-title--static": props.static
        }, backgroundColorClasses.value, props.class]),
        "style": normalizeStyle([backgroundColorStyles.value, dimensionStyles.value, props.style]),
        "type": "button",
        "tabindex": expansionPanel.disabled.value ? -1 : void 0,
        "disabled": expansionPanel.disabled.value,
        "aria-expanded": expansionPanel.isSelected.value,
        "onClick": !props.readonly ? expansionPanel.toggle : void 0
      }, [createElementVNode("span", {
        "class": "v-expansion-panel-title__overlay"
      }, null), (_a = slots.default) == null ? void 0 : _a.call(slots, slotProps.value), !props.hideActions && createVNode(VDefaultsProvider, {
        "defaults": {
          VIcon: {
            icon: icon.value
          }
        }
      }, {
        default: () => {
          var _a2, _b;
          return [createElementVNode("span", {
            "class": "v-expansion-panel-title__icon"
          }, [(_b = (_a2 = slots.actions) == null ? void 0 : _a2.call(slots, slotProps.value)) != null ? _b : createVNode(VIcon, null, null)])];
        }
      })]), [[Ripple, props.ripple]]);
    });
    return {};
  }
});
const makeVExpansionPanelProps = propsFactory({
  title: String,
  text: String,
  bgColor: String,
  ...makeElevationProps(),
  ...makeGroupItemProps(),
  ...makeRoundedProps(),
  ...makeTagProps(),
  ...makeVExpansionPanelTitleProps(),
  ...makeVExpansionPanelTextProps()
}, "VExpansionPanel");
const VExpansionPanel = genericComponent()({
  name: "VExpansionPanel",
  props: makeVExpansionPanelProps(),
  emits: {
    "group:selected": (val) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const groupItem = useGroupItem(props, VExpansionPanelSymbol);
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.bgColor);
    const {
      elevationClasses
    } = useElevation(props);
    const {
      roundedClasses
    } = useRounded(props);
    const isDisabled = toRef(() => (groupItem == null ? void 0 : groupItem.disabled.value) || props.disabled);
    const selectedIndices = computed(() => groupItem.group.items.value.reduce((arr, item, index) => {
      if (groupItem.group.selected.value.includes(item.id)) arr.push(index);
      return arr;
    }, []));
    const isBeforeSelected = computed(() => {
      const index = groupItem.group.items.value.findIndex((item) => item.id === groupItem.id);
      return !groupItem.isSelected.value && selectedIndices.value.some((selectedIndex) => selectedIndex - index === 1);
    });
    const isAfterSelected = computed(() => {
      const index = groupItem.group.items.value.findIndex((item) => item.id === groupItem.id);
      return !groupItem.isSelected.value && selectedIndices.value.some((selectedIndex) => selectedIndex - index === -1);
    });
    provide(VExpansionPanelSymbol, groupItem);
    useRender(() => {
      const hasText = !!(slots.text || props.text);
      const hasTitle = !!(slots.title || props.title);
      const expansionPanelTitleProps = VExpansionPanelTitle.filterProps(props);
      const expansionPanelTextProps = VExpansionPanelText.filterProps(props);
      return createVNode(props.tag, {
        "class": normalizeClass(["v-expansion-panel", {
          "v-expansion-panel--active": groupItem.isSelected.value,
          "v-expansion-panel--before-active": isBeforeSelected.value,
          "v-expansion-panel--after-active": isAfterSelected.value,
          "v-expansion-panel--disabled": isDisabled.value
        }, roundedClasses.value, backgroundColorClasses.value, props.class]),
        "style": normalizeStyle([backgroundColorStyles.value, props.style])
      }, {
        default: () => [createElementVNode("div", {
          "class": normalizeClass(["v-expansion-panel__shadow", ...elevationClasses.value])
        }, null), createVNode(VDefaultsProvider, {
          "defaults": {
            VExpansionPanelTitle: {
              ...expansionPanelTitleProps
            },
            VExpansionPanelText: {
              ...expansionPanelTextProps
            }
          }
        }, {
          default: () => {
            var _a;
            return [hasTitle && createVNode(VExpansionPanelTitle, {
              "key": "title"
            }, {
              default: () => [slots.title ? slots.title() : props.title]
            }), hasText && createVNode(VExpansionPanelText, {
              "key": "text"
            }, {
              default: () => [slots.text ? slots.text() : props.text]
            }), (_a = slots.default) == null ? void 0 : _a.call(slots)];
          }
        })]
      });
    });
    return {
      groupItem
    };
  }
});
const allowedVariants = ["default", "accordion", "inset", "popout"];
const makeVExpansionPanelsProps = propsFactory({
  flat: Boolean,
  ...makeGroupProps(),
  ...pick(makeVExpansionPanelProps(), ["bgColor", "collapseIcon", "color", "eager", "elevation", "expandIcon", "focusable", "hideActions", "readonly", "ripple", "rounded", "tile", "static"]),
  ...makeThemeProps(),
  ...makeComponentProps(),
  ...makeTagProps(),
  variant: {
    type: String,
    default: "default",
    validator: (v) => allowedVariants.includes(v)
  }
}, "VExpansionPanels");
const VExpansionPanels = genericComponent()({
  name: "VExpansionPanels",
  props: makeVExpansionPanelsProps(),
  emits: {
    "update:modelValue": (val) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      next,
      prev
    } = useGroup(props, VExpansionPanelSymbol);
    const {
      themeClasses
    } = provideTheme(props);
    const variantClass = toRef(() => props.variant && `v-expansion-panels--variant-${props.variant}`);
    provideDefaults({
      VExpansionPanel: {
        bgColor: toRef(() => props.bgColor),
        collapseIcon: toRef(() => props.collapseIcon),
        color: toRef(() => props.color),
        eager: toRef(() => props.eager),
        elevation: toRef(() => props.elevation),
        expandIcon: toRef(() => props.expandIcon),
        focusable: toRef(() => props.focusable),
        hideActions: toRef(() => props.hideActions),
        readonly: toRef(() => props.readonly),
        ripple: toRef(() => props.ripple),
        rounded: toRef(() => props.rounded),
        static: toRef(() => props.static)
      }
    });
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-expansion-panels", {
        "v-expansion-panels--flat": props.flat,
        "v-expansion-panels--tile": props.tile
      }, themeClasses.value, variantClass.value, props.class]),
      "style": normalizeStyle(props.style)
    }, {
      default: () => {
        var _a;
        return [(_a = slots.default) == null ? void 0 : _a.call(slots, {
          prev,
          next
        })];
      }
    }));
    return {
      next,
      prev
    };
  }
});
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "FAQSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t } = useI18n();
    const { trackFaqExpand } = useAnalytics();
    const openPanels = ref([]);
    watch(openPanels, (newVal, oldVal) => {
      var _a, _b;
      const prev = new Set(oldVal != null ? oldVal : []);
      const opened = (newVal != null ? newVal : []).filter((i) => !prev.has(i));
      for (const idx of opened) {
        const faq = (_b = (_a = content.value) == null ? void 0 : _a.faq) == null ? void 0 : _b[idx];
        if (faq) trackFaqExpand(faq.id, faq.question);
      }
    });
    const faqIconById = {
      whatIsIt: mdiPackageVariantClosed,
      whatDoesItScan: mdiSourceBranch,
      offlineFirst: mdiAccountGroupOutline,
      stablePreview: mdiShieldLockOutline,
      fastestStart: mdiRocketLaunchOutline,
      cloudVsLintai: mdiCodeTags
    };
    const { docsUrl, supportBoundaryUrl, betaReleaseUrl } = useDocsLinks();
    const faqLabelById = computed(() => ({
      whatIsIt: t("faq.labels.whatIsIt"),
      whatDoesItScan: t("faq.labels.whatDoesItScan"),
      offlineFirst: t("faq.labels.offlineFirst"),
      stablePreview: t("faq.labels.stablePreview"),
      fastestStart: t("faq.labels.fastestStart"),
      cloudVsLintai: t("faq.labels.cloudVsLintai")
    }));
    const faqQuickLinks = computed(() => {
      return [
        {
          title: t("faq.quickLinks.docsTitle"),
          body: t("faq.quickLinks.docsBody"),
          href: docsUrl.value
        },
        {
          title: t("faq.quickLinks.rulesTitle"),
          body: t("faq.quickLinks.rulesBody"),
          href: supportBoundaryUrl.value
        },
        {
          title: t("faq.quickLinks.betaTitle"),
          body: t("faq.quickLinks.betaBody"),
          href: betaReleaseUrl.value
        }
      ];
    });
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "faq",
        class: "faq-section section anchor-offset"
      }, _attrs))} data-v-edec58e0>`);
      _push(ssrRenderComponent(VContainer, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<div class="faq-section__header" data-v-edec58e0${_scopeId}><h2 class="faq-section__title" data-v-edec58e0${_scopeId}>${ssrInterpolate(unref(t)("faq.sectionTitle"))}</h2><p class="faq-section__subtitle" data-v-edec58e0${_scopeId}>${ssrInterpolate(unref(t)("faq.subtitle"))}</p></div><div class="faq-section__content" data-v-edec58e0${_scopeId}><div class="faq-section__list" data-v-edec58e0${_scopeId}>`);
            _push2(ssrRenderComponent(VExpansionPanels, {
              modelValue: openPanels.value,
              "onUpdate:modelValue": ($event) => openPanels.value = $event,
              multiple: "",
              variant: "accordion",
              class: "faq-section__panels"
            }, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(`<!--[-->`);
                  ssrRenderList(unref(content).faq, (item, index) => {
                    _push3(ssrRenderComponent(VExpansionPanel, {
                      key: item.id,
                      class: "faq-section__panel",
                      style: { "--delay": `${index * 0.08}s` },
                      elevation: "0"
                    }, {
                      default: withCtx((_3, _push4, _parent4, _scopeId3) => {
                        if (_push4) {
                          _push4(ssrRenderComponent(VExpansionPanelTitle, { class: "faq-section__panel-title" }, {
                            default: withCtx((_4, _push5, _parent5, _scopeId4) => {
                              if (_push5) {
                                _push5(`<div class="faq-section__panel-header" data-v-edec58e0${_scopeId4}><div class="faq-section__panel-icon-wrap" data-v-edec58e0${_scopeId4}>`);
                                _push5(ssrRenderComponent(VIcon, {
                                  size: "22",
                                  class: "faq-section__panel-icon",
                                  icon: faqIconById[item.id] || unref(mdiHelpCircleOutline)
                                }, null, _parent5, _scopeId4));
                                _push5(`</div><div class="faq-section__panel-copy" data-v-edec58e0${_scopeId4}><span class="faq-section__panel-label" data-v-edec58e0${_scopeId4}>${ssrInterpolate(faqLabelById.value[item.id] || unref(t)("faq.labels.default"))}</span><span class="faq-section__panel-question" data-v-edec58e0${_scopeId4}>${ssrInterpolate(item.question)}</span></div></div>`);
                              } else {
                                return [
                                  createVNode("div", { class: "faq-section__panel-header" }, [
                                    createVNode("div", { class: "faq-section__panel-icon-wrap" }, [
                                      createVNode(VIcon, {
                                        size: "22",
                                        class: "faq-section__panel-icon",
                                        icon: faqIconById[item.id] || unref(mdiHelpCircleOutline)
                                      }, null, 8, ["icon"])
                                    ]),
                                    createVNode("div", { class: "faq-section__panel-copy" }, [
                                      createVNode("span", { class: "faq-section__panel-label" }, toDisplayString(faqLabelById.value[item.id] || unref(t)("faq.labels.default")), 1),
                                      createVNode("span", { class: "faq-section__panel-question" }, toDisplayString(item.question), 1)
                                    ])
                                  ])
                                ];
                              }
                            }),
                            _: 2
                          }, _parent4, _scopeId3));
                          _push4(ssrRenderComponent(VExpansionPanelText, { class: "faq-section__panel-text" }, {
                            default: withCtx((_4, _push5, _parent5, _scopeId4) => {
                              var _a;
                              if (_push5) {
                                _push5(`<div class="faq-section__answer" data-v-edec58e0${_scopeId4}>${(_a = item.answer) != null ? _a : ""}</div>`);
                              } else {
                                return [
                                  createVNode("div", {
                                    class: "faq-section__answer",
                                    innerHTML: item.answer
                                  }, null, 8, ["innerHTML"])
                                ];
                              }
                            }),
                            _: 2
                          }, _parent4, _scopeId3));
                        } else {
                          return [
                            createVNode(VExpansionPanelTitle, { class: "faq-section__panel-title" }, {
                              default: withCtx(() => [
                                createVNode("div", { class: "faq-section__panel-header" }, [
                                  createVNode("div", { class: "faq-section__panel-icon-wrap" }, [
                                    createVNode(VIcon, {
                                      size: "22",
                                      class: "faq-section__panel-icon",
                                      icon: faqIconById[item.id] || unref(mdiHelpCircleOutline)
                                    }, null, 8, ["icon"])
                                  ]),
                                  createVNode("div", { class: "faq-section__panel-copy" }, [
                                    createVNode("span", { class: "faq-section__panel-label" }, toDisplayString(faqLabelById.value[item.id] || unref(t)("faq.labels.default")), 1),
                                    createVNode("span", { class: "faq-section__panel-question" }, toDisplayString(item.question), 1)
                                  ])
                                ])
                              ]),
                              _: 2
                            }, 1024),
                            createVNode(VExpansionPanelText, { class: "faq-section__panel-text" }, {
                              default: withCtx(() => [
                                createVNode("div", {
                                  class: "faq-section__answer",
                                  innerHTML: item.answer
                                }, null, 8, ["innerHTML"])
                              ]),
                              _: 2
                            }, 1024)
                          ];
                        }
                      }),
                      _: 2
                    }, _parent3, _scopeId2));
                  });
                  _push3(`<!--]-->`);
                } else {
                  return [
                    (openBlock(true), createBlock(Fragment, null, renderList(unref(content).faq, (item, index) => {
                      return openBlock(), createBlock(VExpansionPanel, {
                        key: item.id,
                        class: "faq-section__panel",
                        style: { "--delay": `${index * 0.08}s` },
                        elevation: "0"
                      }, {
                        default: withCtx(() => [
                          createVNode(VExpansionPanelTitle, { class: "faq-section__panel-title" }, {
                            default: withCtx(() => [
                              createVNode("div", { class: "faq-section__panel-header" }, [
                                createVNode("div", { class: "faq-section__panel-icon-wrap" }, [
                                  createVNode(VIcon, {
                                    size: "22",
                                    class: "faq-section__panel-icon",
                                    icon: faqIconById[item.id] || unref(mdiHelpCircleOutline)
                                  }, null, 8, ["icon"])
                                ]),
                                createVNode("div", { class: "faq-section__panel-copy" }, [
                                  createVNode("span", { class: "faq-section__panel-label" }, toDisplayString(faqLabelById.value[item.id] || unref(t)("faq.labels.default")), 1),
                                  createVNode("span", { class: "faq-section__panel-question" }, toDisplayString(item.question), 1)
                                ])
                              ])
                            ]),
                            _: 2
                          }, 1024),
                          createVNode(VExpansionPanelText, { class: "faq-section__panel-text" }, {
                            default: withCtx(() => [
                              createVNode("div", {
                                class: "faq-section__answer",
                                innerHTML: item.answer
                              }, null, 8, ["innerHTML"])
                            ]),
                            _: 2
                          }, 1024)
                        ]),
                        _: 2
                      }, 1032, ["style"]);
                    }), 128))
                  ];
                }
              }),
              _: 1
            }, _parent2, _scopeId));
            _push2(`</div><div class="faq-section__decoration" data-v-edec58e0${_scopeId}><div class="faq-section__guide-card" data-v-edec58e0${_scopeId}><div class="faq-section__guide-badge" data-v-edec58e0${_scopeId}>`);
            _push2(ssrRenderComponent(VIcon, {
              size: "18",
              class: "faq-section__guide-badge-icon",
              icon: unref(mdiFrequentlyAskedQuestions)
            }, null, _parent2, _scopeId));
            _push2(`<span data-v-edec58e0${_scopeId}>${ssrInterpolate(unref(t)("faq.quickLinks.badge"))}</span></div><h3 class="faq-section__guide-title" data-v-edec58e0${_scopeId}>${ssrInterpolate(unref(t)("faq.quickLinks.title"))}</h3><p class="faq-section__guide-text" data-v-edec58e0${_scopeId}>${ssrInterpolate(unref(t)("faq.quickLinks.subtitle"))}</p><!--[-->`);
            ssrRenderList(faqQuickLinks.value, (link) => {
              _push2(`<a${ssrRenderAttr("href", link.href)} class="faq-section__guide-link" data-v-edec58e0${_scopeId}><div class="faq-section__guide-link-copy" data-v-edec58e0${_scopeId}><span class="faq-section__guide-link-title" data-v-edec58e0${_scopeId}>${ssrInterpolate(link.title)}</span><span class="faq-section__guide-link-body" data-v-edec58e0${_scopeId}>${ssrInterpolate(link.body)}</span></div>`);
              _push2(ssrRenderComponent(VIcon, {
                size: "18",
                class: "faq-section__guide-link-icon",
                icon: unref(mdiArrowTopRight)
              }, null, _parent2, _scopeId));
              _push2(`</a>`);
            });
            _push2(`<!--]--></div></div></div>`);
          } else {
            return [
              createVNode("div", { class: "faq-section__header" }, [
                createVNode("h2", { class: "faq-section__title" }, toDisplayString(unref(t)("faq.sectionTitle")), 1),
                createVNode("p", { class: "faq-section__subtitle" }, toDisplayString(unref(t)("faq.subtitle")), 1)
              ]),
              createVNode("div", { class: "faq-section__content" }, [
                createVNode("div", { class: "faq-section__list" }, [
                  createVNode(VExpansionPanels, {
                    modelValue: openPanels.value,
                    "onUpdate:modelValue": ($event) => openPanels.value = $event,
                    multiple: "",
                    variant: "accordion",
                    class: "faq-section__panels"
                  }, {
                    default: withCtx(() => [
                      (openBlock(true), createBlock(Fragment, null, renderList(unref(content).faq, (item, index) => {
                        return openBlock(), createBlock(VExpansionPanel, {
                          key: item.id,
                          class: "faq-section__panel",
                          style: { "--delay": `${index * 0.08}s` },
                          elevation: "0"
                        }, {
                          default: withCtx(() => [
                            createVNode(VExpansionPanelTitle, { class: "faq-section__panel-title" }, {
                              default: withCtx(() => [
                                createVNode("div", { class: "faq-section__panel-header" }, [
                                  createVNode("div", { class: "faq-section__panel-icon-wrap" }, [
                                    createVNode(VIcon, {
                                      size: "22",
                                      class: "faq-section__panel-icon",
                                      icon: faqIconById[item.id] || unref(mdiHelpCircleOutline)
                                    }, null, 8, ["icon"])
                                  ]),
                                  createVNode("div", { class: "faq-section__panel-copy" }, [
                                    createVNode("span", { class: "faq-section__panel-label" }, toDisplayString(faqLabelById.value[item.id] || unref(t)("faq.labels.default")), 1),
                                    createVNode("span", { class: "faq-section__panel-question" }, toDisplayString(item.question), 1)
                                  ])
                                ])
                              ]),
                              _: 2
                            }, 1024),
                            createVNode(VExpansionPanelText, { class: "faq-section__panel-text" }, {
                              default: withCtx(() => [
                                createVNode("div", {
                                  class: "faq-section__answer",
                                  innerHTML: item.answer
                                }, null, 8, ["innerHTML"])
                              ]),
                              _: 2
                            }, 1024)
                          ]),
                          _: 2
                        }, 1032, ["style"]);
                      }), 128))
                    ]),
                    _: 1
                  }, 8, ["modelValue", "onUpdate:modelValue"])
                ]),
                createVNode("div", { class: "faq-section__decoration" }, [
                  createVNode("div", { class: "faq-section__guide-card" }, [
                    createVNode("div", { class: "faq-section__guide-badge" }, [
                      createVNode(VIcon, {
                        size: "18",
                        class: "faq-section__guide-badge-icon",
                        icon: unref(mdiFrequentlyAskedQuestions)
                      }, null, 8, ["icon"]),
                      createVNode("span", null, toDisplayString(unref(t)("faq.quickLinks.badge")), 1)
                    ]),
                    createVNode("h3", { class: "faq-section__guide-title" }, toDisplayString(unref(t)("faq.quickLinks.title")), 1),
                    createVNode("p", { class: "faq-section__guide-text" }, toDisplayString(unref(t)("faq.quickLinks.subtitle")), 1),
                    (openBlock(true), createBlock(Fragment, null, renderList(faqQuickLinks.value, (link) => {
                      return openBlock(), createBlock("a", {
                        key: link.href,
                        href: link.href,
                        class: "faq-section__guide-link"
                      }, [
                        createVNode("div", { class: "faq-section__guide-link-copy" }, [
                          createVNode("span", { class: "faq-section__guide-link-title" }, toDisplayString(link.title), 1),
                          createVNode("span", { class: "faq-section__guide-link-body" }, toDisplayString(link.body), 1)
                        ]),
                        createVNode(VIcon, {
                          size: "18",
                          class: "faq-section__guide-link-icon",
                          icon: unref(mdiArrowTopRight)
                        }, null, 8, ["icon"])
                      ], 8, ["href"]);
                    }), 128))
                  ])
                ])
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
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/FAQSection.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const FAQSection = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-edec58e0"]]);

export { FAQSection as default };
//# sourceMappingURL=FAQSection-6dfuvw15.mjs.map
