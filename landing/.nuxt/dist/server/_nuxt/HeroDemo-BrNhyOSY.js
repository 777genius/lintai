import { defineComponent, computed, ref, watch, mergeProps, unref, useSSRContext } from "vue";
import { ssrRenderAttrs, ssrRenderList, ssrRenderClass, ssrRenderStyle, ssrInterpolate, ssrRenderAttr, ssrRenderComponent } from "vue/server-renderer";
import { mdiCheckCircleOutline, mdiClockOutline } from "@mdi/js";
import { u as useI18n, d as VIcon, _ as _export_sfc } from "../server.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/ofetch@1.5.1/node_modules/ofetch/dist/node.mjs";
import "#internal/nuxt/paths";
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
const intervalError = "[nuxt] `setInterval` should not be used on the server. Consider wrapping it with an `onNuxtReady`, `onBeforeMount` or `onMounted` lifecycle hook, or ensure you only call it in the browser by checking `false`.";
const setInterval = (() => {
  console.error(intervalError);
});
const _sfc_main = /* @__PURE__ */ defineComponent({
  __name: "HeroDemo",
  __ssrInlineRender: true,
  setup(__props) {
    const { t } = useI18n();
    const steps = computed(() => [
      {
        id: "inspect",
        label: t("hero.demo.steps.inspect"),
        caption: t("hero.demo.captions.inspect"),
        accent: "#00f0ff"
      },
      {
        id: "scan",
        label: t("hero.demo.steps.scan"),
        caption: t("hero.demo.captions.scan"),
        accent: "#ff00ff"
      },
      {
        id: "review",
        label: t("hero.demo.steps.review"),
        caption: t("hero.demo.captions.review"),
        accent: "#ffd700"
      },
      {
        id: "gate",
        label: t("hero.demo.steps.gate"),
        caption: t("hero.demo.captions.gate"),
        accent: "#39ff14"
      }
    ]);
    const outputs = ["SKILL.md", "mcp.json", "CLAUDE.md", "hooks", "plugin.json"];
    const repoFiles = [
      "SKILL.md",
      "CLAUDE.md",
      ".cursor/rules/",
      "mcp.json",
      ".cursor-plugin/",
      "lintai.toml"
    ];
    const containerRef = ref(null);
    const activeStep = ref(0);
    let intervalId = null;
    const start = () => {
      if (intervalId) return;
      intervalId = setInterval();
    };
    const stop = () => {
      if (!intervalId) return;
      clearInterval(intervalId);
      intervalId = null;
    };
    const visible = ref(false);
    watch(visible, (value) => {
      if (value) start();
      else stop();
    });
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<div${ssrRenderAttrs(mergeProps({
        ref_key: "containerRef",
        ref: containerRef,
        class: "hero-demo",
        role: "img",
        "aria-label": unref(t)("hero.preview")
      }, _attrs))} data-v-f4a64355><div class="hero-demo__content" data-v-f4a64355><div class="hero-demo__steps" data-v-f4a64355><!--[-->`);
      ssrRenderList(steps.value, (step, index) => {
        _push(`<div class="${ssrRenderClass([{ "hero-demo__step--active": index === activeStep.value }, "hero-demo__step"])}" style="${ssrRenderStyle({ "--accent": step.accent })}" data-v-f4a64355><div class="hero-demo__step-index" data-v-f4a64355>${ssrInterpolate(String(index + 1).padStart(2, "0"))}</div><div class="hero-demo__step-copy" data-v-f4a64355><div class="hero-demo__step-text" data-v-f4a64355><span class="hero-demo__step-label" data-v-f4a64355>${ssrInterpolate(step.label)}</span><span class="hero-demo__step-caption" data-v-f4a64355>${ssrInterpolate(step.caption)}</span></div><span class="hero-demo__step-state"${ssrRenderAttr("aria-label", index <= activeStep.value ? unref(t)("hero.demo.ready") : unref(t)("hero.demo.waiting"))} data-v-f4a64355>`);
        _push(ssrRenderComponent(VIcon, {
          icon: index <= activeStep.value ? unref(mdiCheckCircleOutline) : unref(mdiClockOutline),
          size: "18"
        }, null, _parent));
        _push(`</span></div></div>`);
      });
      _push(`<!--]--></div><div class="hero-demo__files" data-v-f4a64355><div class="hero-demo__file-card" data-v-f4a64355><div class="hero-demo__file-header" data-v-f4a64355><span data-v-f4a64355>${ssrInterpolate(unref(t)("hero.demo.repo"))}</span><span data-v-f4a64355>${ssrInterpolate(unref(t)("hero.demo.sourceOfTruth"))}</span></div><div class="hero-demo__file-list" data-v-f4a64355>${ssrInterpolate(repoFiles.join("\n"))}</div></div><div class="hero-demo__output-card" data-v-f4a64355><div class="hero-demo__file-header" data-v-f4a64355><span data-v-f4a64355>${ssrInterpolate(unref(t)("hero.demo.outputs"))}</span><span data-v-f4a64355>${ssrInterpolate(unref(t)("hero.demo.supportedAgents"))}</span></div><div class="hero-demo__output-list" data-v-f4a64355><!--[-->`);
      ssrRenderList(outputs, (output) => {
        _push(`<span class="hero-demo__output hero-demo__output--active" data-v-f4a64355>${ssrInterpolate(output)}</span>`);
      });
      _push(`<!--]--></div></div></div></div></div>`);
    };
  }
});
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/ui/HeroDemo.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const HeroDemo = /* @__PURE__ */ _export_sfc(_sfc_main, [["__scopeId", "data-v-f4a64355"]]);
export {
  HeroDemo as default
};
//# sourceMappingURL=HeroDemo-BrNhyOSY.js.map
