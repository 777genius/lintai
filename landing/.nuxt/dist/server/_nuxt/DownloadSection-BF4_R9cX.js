import { defineComponent, ref, computed, watchEffect, mergeProps, withCtx, unref, createVNode, toDisplayString, openBlock, createBlock, createTextVNode, Fragment, createCommentVNode, renderList, useSSRContext } from "vue";
import { ssrRenderAttrs, ssrRenderComponent, ssrInterpolate, ssrRenderAttr, ssrRenderList, ssrRenderClass, ssrRenderStyle } from "vue/server-renderer";
import { u as useLandingContent, a as useReleaseDownloads, f as formatReleaseDate } from "./usePageSeo-Ba4JSXZC.js";
import { u as useI18n, V as VContainer, _ as _export_sfc } from "../server.mjs";
import { u as useDocsLinks } from "./i18n-B_nLlkZy.js";
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
  __name: "DownloadSection",
  __ssrInlineRender: true,
  setup(__props) {
    const { content } = useLandingContent();
    const { t, locale } = useI18n();
    const { data: releaseData, fallbackUrl } = useReleaseDownloads();
    const { quickstartUrl, supportBoundaryUrl } = useDocsLinks();
    const copiedCommandId = ref(null);
    const selectedInstallId = ref(null);
    const releaseVersion = computed(() => releaseData.value?.version || null);
    const releaseDate = computed(() => {
      if (!releaseData.value?.pubDate) {
        return "";
      }
      return formatReleaseDate(releaseData.value.pubDate, locale.value);
    });
    const supportAccent = ["#39ff14", "#00f0ff", "#ffb703", "#f472b6", "#94a3b8"];
    const installChannels = computed(
      () => content.value.installChannels.map(
        (channel) => channel.id === "docs" ? { ...channel, href: quickstartUrl.value } : channel
      )
    );
    const quickstartInstallChannels = computed(
      () => installChannels.value.filter(
        (channel) => channel.command && !["docs", "releases"].includes(channel.id)
      )
    );
    watchEffect(() => {
      if (selectedInstallId.value && quickstartInstallChannels.value.some((channel) => channel.id === selectedInstallId.value)) {
        return;
      }
      selectedInstallId.value = quickstartInstallChannels.value.find((channel) => channel.recommended)?.id || quickstartInstallChannels.value[0]?.id || null;
    });
    const selectedInstallChannel = computed(
      () => quickstartInstallChannels.value.find((channel) => channel.id === selectedInstallId.value) || quickstartInstallChannels.value[0] || null
    );
    const quickstartSteps = computed(
      () => content.value.quickstartSteps.map((step) => {
        if (step.id !== "install" || !selectedInstallChannel.value?.command) {
          return step;
        }
        return {
          ...step,
          command: `${selectedInstallChannel.value.command}
lintai version`,
          note: selectedInstallChannel.value.note
        };
      })
    );
    const copyCommand = async (commandId, command) => {
      {
        return;
      }
    };
    const copyLabel = (commandId) => copiedCommandId.value === commandId ? t("download.copied") : t("download.copy");
    const commandActions = /* @__PURE__ */ new Set(["scan", "version", "explain-config", "open", "download"]);
    const classifyToken = (token, tokenIndex) => {
      if (["|", "&&", "||"].includes(token)) {
        return "operator";
      }
      if (token.startsWith("https://") || token.startsWith("http://")) {
        return "url";
      }
      if (token.startsWith("--") || token.startsWith("-") && token.length > 1) {
        return "flag";
      }
      if (tokenIndex === 0) {
        return "command";
      }
      if (tokenIndex === 1 && commandActions.has(token)) {
        return "action";
      }
      if (token === "." || token.startsWith("./") || token.startsWith("/") || token.startsWith("~/") || token.includes("/") || token.endsWith(".sh") || token.endsWith(".yaml") || token.endsWith(".json") || token.endsWith(".txt")) {
        return "path";
      }
      return "plain";
    };
    const renderHighlightedCommand = (command) => command.split("\n").map((line) => {
      const tokens = line.match(/\S+|\s+/g) || [];
      let tokenIndex = 0;
      return tokens.map((part) => {
        if (/^\s+$/.test(part)) {
          return { text: part, className: "plain" };
        }
        const tokenClass = classifyToken(part, tokenIndex);
        tokenIndex += 1;
        return { text: part, className: tokenClass };
      });
    });
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<section${ssrRenderAttrs(mergeProps({
        id: "download",
        class: "download-section section anchor-offset"
      }, _attrs))} data-v-232bd77c>`);
      _push(ssrRenderComponent(VContainer, null, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<div class="download-section__header" data-v-232bd77c${_scopeId}><h2 class="download-section__title" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(content).download.title)}</h2><p class="download-section__subtitle" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(content).download.note)}</p>`);
            if (unref(releaseVersion)) {
              _push2(`<p class="download-section__release-info" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.latestRelease"))} · <a${ssrRenderAttr("href", unref(fallbackUrl))} target="_blank" rel="noopener noreferrer" data-v-232bd77c${_scopeId}>v${ssrInterpolate(unref(releaseVersion))}</a>`);
              if (unref(releaseDate)) {
                _push2(`<!--[--> · ${ssrInterpolate(unref(releaseDate))}<!--]-->`);
              } else {
                _push2(`<!---->`);
              }
              _push2(`</p>`);
            } else {
              _push2(`<!---->`);
            }
            _push2(`</div><div class="download-section__overview" data-v-232bd77c${_scopeId}><article class="download-section__overview-card download-section__overview-card--quickstart" data-v-232bd77c${_scopeId}><div class="download-section__overview-top" data-v-232bd77c${_scopeId}><h3 class="download-section__overview-title" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.quickstartTitle"))}</h3><p class="download-section__overview-subtitle" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.quickstartSubtitle"))}</p></div><div class="download-section__install-tabs" data-v-232bd77c${_scopeId}><div class="download-section__install-tabs-label" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.installTabsLabel"))}</div><div class="download-section__install-tabs-row" data-v-232bd77c${_scopeId}><!--[-->`);
            ssrRenderList(unref(quickstartInstallChannels), (channel) => {
              _push2(`<button type="button" class="${ssrRenderClass([{
                "download-section__install-tab--active": channel.id === unref(selectedInstallId)
              }, "download-section__install-tab"])}"${ssrRenderAttr("aria-pressed", channel.id === unref(selectedInstallId))} data-v-232bd77c${_scopeId}><span data-v-232bd77c${_scopeId}>${ssrInterpolate(channel.title)}</span>`);
              if (channel.recommended) {
                _push2(`<span class="download-section__install-tab-badge" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.recommended"))}</span>`);
              } else {
                _push2(`<!---->`);
              }
              _push2(`</button>`);
            });
            _push2(`<!--]--></div>`);
            if (unref(selectedInstallChannel)) {
              _push2(`<p class="download-section__install-tabs-note" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(selectedInstallChannel).description)}</p>`);
            } else {
              _push2(`<!---->`);
            }
            _push2(`</div><div class="download-section__steps" data-v-232bd77c${_scopeId}><!--[-->`);
            ssrRenderList(unref(quickstartSteps), (step, index) => {
              _push2(`<div class="download-section__step" data-v-232bd77c${_scopeId}><div class="download-section__step-index" data-v-232bd77c${_scopeId}>0${ssrInterpolate(index + 1)}</div><div class="download-section__step-body" data-v-232bd77c${_scopeId}><h4 class="download-section__step-title" data-v-232bd77c${_scopeId}>${ssrInterpolate(step.title)}</h4><div class="download-section__command-wrap" data-v-232bd77c${_scopeId}><div class="download-section__command-head" data-v-232bd77c${_scopeId}><span class="download-section__command-label" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.command"))}</span><button type="button" class="download-section__copy-btn"${ssrRenderAttr("aria-label", copyLabel(`step-${step.id}`))} data-v-232bd77c${_scopeId}>${ssrInterpolate(copyLabel(`step-${step.id}`))}</button></div><pre class="download-section__step-command" data-v-232bd77c${_scopeId}><code data-v-232bd77c${_scopeId}><!--[-->`);
              ssrRenderList(renderHighlightedCommand(step.command), (line, lineIndex) => {
                _push2(`<span class="download-section__command-line" data-v-232bd77c${_scopeId}><!--[-->`);
                ssrRenderList(line, (token, tokenIndex) => {
                  _push2(`<span class="${ssrRenderClass([`download-section__token--${token.className}`, "download-section__token"])}" data-v-232bd77c${_scopeId}>${ssrInterpolate(token.text)}</span>`);
                });
                _push2(`<!--]--></span>`);
              });
              _push2(`<!--]--></code></pre></div><p class="download-section__step-note" data-v-232bd77c${_scopeId}>${ssrInterpolate(step.note)}</p></div></div>`);
            });
            _push2(`<!--]--></div></article></div><article class="download-section__overview-card download-section__overview-card--support" data-v-232bd77c${_scopeId}><div class="download-section__overview-top" data-v-232bd77c${_scopeId}><h3 class="download-section__overview-title" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.supportTitle"))}</h3><p class="download-section__overview-subtitle" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.supportSubtitle"))}</p></div><div class="download-section__support-list" data-v-232bd77c${_scopeId}><!--[-->`);
            ssrRenderList(unref(content).supportLanes, (lane, index) => {
              _push2(`<div class="download-section__support-item" style="${ssrRenderStyle({ "--accent": supportAccent[index % supportAccent.length] })}" data-v-232bd77c${_scopeId}><div class="download-section__support-main" data-v-232bd77c${_scopeId}><h4 class="download-section__support-name" data-v-232bd77c${_scopeId}>${ssrInterpolate(lane.name)}</h4><span class="download-section__support-status" data-v-232bd77c${_scopeId}>${ssrInterpolate(lane.status)}</span></div><p class="download-section__support-note" data-v-232bd77c${_scopeId}>${ssrInterpolate(lane.note)}</p></div>`);
            });
            _push2(`<!--]--></div><a class="download-section__support-link"${ssrRenderAttr("href", unref(supportBoundaryUrl))} target="_blank" rel="noopener noreferrer" data-v-232bd77c${_scopeId}>${ssrInterpolate(unref(t)("download.supportLink"))}</a></article>`);
          } else {
            return [
              createVNode("div", { class: "download-section__header" }, [
                createVNode("h2", { class: "download-section__title" }, toDisplayString(unref(content).download.title), 1),
                createVNode("p", { class: "download-section__subtitle" }, toDisplayString(unref(content).download.note), 1),
                unref(releaseVersion) ? (openBlock(), createBlock("p", {
                  key: 0,
                  class: "download-section__release-info"
                }, [
                  createTextVNode(toDisplayString(unref(t)("download.latestRelease")) + " · ", 1),
                  createVNode("a", {
                    href: unref(fallbackUrl),
                    target: "_blank",
                    rel: "noopener noreferrer"
                  }, "v" + toDisplayString(unref(releaseVersion)), 9, ["href"]),
                  unref(releaseDate) ? (openBlock(), createBlock(Fragment, { key: 0 }, [
                    createTextVNode(" · " + toDisplayString(unref(releaseDate)), 1)
                  ], 64)) : createCommentVNode("", true)
                ])) : createCommentVNode("", true)
              ]),
              createVNode("div", { class: "download-section__overview" }, [
                createVNode("article", { class: "download-section__overview-card download-section__overview-card--quickstart" }, [
                  createVNode("div", { class: "download-section__overview-top" }, [
                    createVNode("h3", { class: "download-section__overview-title" }, toDisplayString(unref(t)("download.quickstartTitle")), 1),
                    createVNode("p", { class: "download-section__overview-subtitle" }, toDisplayString(unref(t)("download.quickstartSubtitle")), 1)
                  ]),
                  createVNode("div", { class: "download-section__install-tabs" }, [
                    createVNode("div", { class: "download-section__install-tabs-label" }, toDisplayString(unref(t)("download.installTabsLabel")), 1),
                    createVNode("div", { class: "download-section__install-tabs-row" }, [
                      (openBlock(true), createBlock(Fragment, null, renderList(unref(quickstartInstallChannels), (channel) => {
                        return openBlock(), createBlock("button", {
                          key: channel.id,
                          type: "button",
                          class: ["download-section__install-tab", {
                            "download-section__install-tab--active": channel.id === unref(selectedInstallId)
                          }],
                          "aria-pressed": channel.id === unref(selectedInstallId),
                          onClick: ($event) => selectedInstallId.value = channel.id
                        }, [
                          createVNode("span", null, toDisplayString(channel.title), 1),
                          channel.recommended ? (openBlock(), createBlock("span", {
                            key: 0,
                            class: "download-section__install-tab-badge"
                          }, toDisplayString(unref(t)("download.recommended")), 1)) : createCommentVNode("", true)
                        ], 10, ["aria-pressed", "onClick"]);
                      }), 128))
                    ]),
                    unref(selectedInstallChannel) ? (openBlock(), createBlock("p", {
                      key: 0,
                      class: "download-section__install-tabs-note"
                    }, toDisplayString(unref(selectedInstallChannel).description), 1)) : createCommentVNode("", true)
                  ]),
                  createVNode("div", { class: "download-section__steps" }, [
                    (openBlock(true), createBlock(Fragment, null, renderList(unref(quickstartSteps), (step, index) => {
                      return openBlock(), createBlock("div", {
                        key: step.id,
                        class: "download-section__step"
                      }, [
                        createVNode("div", { class: "download-section__step-index" }, "0" + toDisplayString(index + 1), 1),
                        createVNode("div", { class: "download-section__step-body" }, [
                          createVNode("h4", { class: "download-section__step-title" }, toDisplayString(step.title), 1),
                          createVNode("div", { class: "download-section__command-wrap" }, [
                            createVNode("div", { class: "download-section__command-head" }, [
                              createVNode("span", { class: "download-section__command-label" }, toDisplayString(unref(t)("download.command")), 1),
                              createVNode("button", {
                                type: "button",
                                class: "download-section__copy-btn",
                                "aria-label": copyLabel(`step-${step.id}`),
                                onClick: ($event) => copyCommand(`step-${step.id}`, step.command)
                              }, toDisplayString(copyLabel(`step-${step.id}`)), 9, ["aria-label", "onClick"])
                            ]),
                            createVNode("pre", { class: "download-section__step-command" }, [
                              createVNode("code", null, [
                                (openBlock(true), createBlock(Fragment, null, renderList(renderHighlightedCommand(step.command), (line, lineIndex) => {
                                  return openBlock(), createBlock("span", {
                                    key: `${step.id}-line-${lineIndex}`,
                                    class: "download-section__command-line"
                                  }, [
                                    (openBlock(true), createBlock(Fragment, null, renderList(line, (token, tokenIndex) => {
                                      return openBlock(), createBlock("span", {
                                        key: `${step.id}-line-${lineIndex}-token-${tokenIndex}`,
                                        class: ["download-section__token", `download-section__token--${token.className}`]
                                      }, toDisplayString(token.text), 3);
                                    }), 128))
                                  ]);
                                }), 128))
                              ])
                            ])
                          ]),
                          createVNode("p", { class: "download-section__step-note" }, toDisplayString(step.note), 1)
                        ])
                      ]);
                    }), 128))
                  ])
                ])
              ]),
              createVNode("article", { class: "download-section__overview-card download-section__overview-card--support" }, [
                createVNode("div", { class: "download-section__overview-top" }, [
                  createVNode("h3", { class: "download-section__overview-title" }, toDisplayString(unref(t)("download.supportTitle")), 1),
                  createVNode("p", { class: "download-section__overview-subtitle" }, toDisplayString(unref(t)("download.supportSubtitle")), 1)
                ]),
                createVNode("div", { class: "download-section__support-list" }, [
                  (openBlock(true), createBlock(Fragment, null, renderList(unref(content).supportLanes, (lane, index) => {
                    return openBlock(), createBlock("div", {
                      key: lane.id,
                      class: "download-section__support-item",
                      style: { "--accent": supportAccent[index % supportAccent.length] }
                    }, [
                      createVNode("div", { class: "download-section__support-main" }, [
                        createVNode("h4", { class: "download-section__support-name" }, toDisplayString(lane.name), 1),
                        createVNode("span", { class: "download-section__support-status" }, toDisplayString(lane.status), 1)
                      ]),
                      createVNode("p", { class: "download-section__support-note" }, toDisplayString(lane.note), 1)
                    ], 4);
                  }), 128))
                ]),
                createVNode("a", {
                  class: "download-section__support-link",
                  href: unref(supportBoundaryUrl),
                  target: "_blank",
                  rel: "noopener noreferrer"
                }, toDisplayString(unref(t)("download.supportLink")), 9, ["href"])
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
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/sections/DownloadSection.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const __nuxt_component_0 = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-232bd77c"]]);
export {
  __nuxt_component_0 as default
};
//# sourceMappingURL=DownloadSection-BF4_R9cX.js.map
