import { mergeProps, withCtx, createVNode, renderSlot, defineComponent, ref, computed, unref, createTextVNode, toDisplayString, openBlock, createBlock, Fragment, renderList, Teleport, Transition, withModifiers, createCommentVNode, watch, nextTick, isRef, withDirectives, withKeys, vModelText, useId, toRef, inject, shallowRef, provide, normalizeStyle, normalizeClass, createElementVNode, vShow, h, resolveComponent, toRaw, toValue, watchEffect, cloneVNode, onScopeDispose, reactive, readonly, TransitionGroup, capitalize, camelize, useSSRContext } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { _ as _export_sfc, aZ as VApp, u as useI18n, j as useRoute$1, n as useRouter$1, A as useLocalePath, V as VContainer, c as VBtn, e as useRuntimeConfig, f as useNuxtApp, k as useSwitchLocalePath, g as genericComponent, a0 as useProxiedModel, C as useRender, af as useRtl, aL as isClickInsideElement, Q as VDefaultsProvider, L as provideTheme, G as useBackgroundColor, M as useBorder, O as useDensity, B as useDimension, ao as useElevation, H as useRounded, a1 as provideDefaults, J as convertToUnit, a2 as Ripple, aq as useLink, N as useVariant, aw as deprecate, R as genOverlays, d as VIcon, w as navigateTo, a8 as useLocale, a5 as useTextColor, a4 as wrapInArray, aY as noop, aW as ensureValidVNode, I as getCurrentInstance$1, aK as useRouter, ae as useToggleScope, a7 as omit, p as propsFactory, o as parseQuery, q as encodeRoutePath, az as focusChild, aM as getNextElement, an as focusableChildren, S as IconValue, T as makeVariantProps, U as makeThemeProps, m as makeTagProps, K as makeRoundedProps, at as makeElevationProps, D as makeDimensionProps, X as makeDensityProps, a as makeComponentProps, Y as makeBorderProps, Z as EventProp, P as useSize, ar as makeRouterProps, ax as isPrimitive, a3 as filterInputAttrs, aX as checkPrintable, a6 as matchesSelector, aN as useLocation, aO as usePosition, $ as deepEqual, ap as useGroupItem, aJ as templateRef, E as isObject, F as onlyDefinedProps, r as hasProtocol, s as resolveRouteObject$1, v as joinURL, au as consoleError, W as makeSizeProps, ag as pick, ay as getPropertyFromItem, ad as getCurrentInstanceName, aR as useLoader, aS as LoaderSlot, a9 as callEvent, aP as makePositionProps, aQ as makeLocationProps, aj as useDisplay, al as useResizeObserver, aU as debounce, aH as clamp, as as makeGroupItemProps, aa as acceleratedEasing, ab as standardEasing, ac as deceleratedEasing, av as defineComponent$1, aT as makeLoaderProps, aA as destructComputed, aB as parseAnchor, aC as flipSide, aD as flipAlign, aE as flipCorner, aF as CircularBuffer, aG as getAxis, x as withTrailingSlash, y as withoutTrailingSlash, aI as defer, z as nuxtLinkDefaults, ah as makeGroupProps, ai as makeDisplayProps, ak as useGroup, am as useGoTo, aV as camelizeProps } from './server.mjs';
import { ssrRenderComponent, ssrRenderSlot, ssrRenderAttrs, ssrRenderList, ssrInterpolate, ssrRenderTeleport, ssrRenderStyle, ssrRenderAttr } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/server-renderer/index.mjs';
import __nuxt_component_0$3 from './Icon-D1LAQcan.mjs';
import { u as useDocsLinks, s as supportedLocales } from './i18n-B_nLlkZy.mjs';
import { defineStore } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/pinia@3.0.4_typescript@6.0.2_vue@3.5.31/node_modules/pinia/dist/pinia.prod.cjs';
import { u as useLazy, a as useAnalytics, V as VExpandXTransition, m as makeLazyProps, b as VExpandTransition, c as VSlideYTransition, d as VFadeTransition } from './lazy-CNBWeTG7.mjs';
import { mdiGithub, mdiMenu, mdiClose, mdiWeatherSunny, mdiWeatherNight } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@mdi+js@7.4.47/node_modules/@mdi/js/commonjs/mdi.js';
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
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-router@4.6.4_vue@3.5.31/node_modules/vue-router/vue-router.node.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/cookie-es@2.0.1/node_modules/cookie-es/dist/index.mjs';
import 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue-devtools-stub@0.1.0/node_modules/vue-devtools-stub/dist/index.mjs';
import './index-7WrDIlZh.mjs';

const firstNonUndefined = (...args) => args.find((arg) => arg !== void 0);
// @__NO_SIDE_EFFECTS__
function defineNuxtLink(options) {
  const componentName = options.componentName || "NuxtLink";
  function isHashLinkWithoutHashMode(link) {
    return typeof link === "string" && link.startsWith("#");
  }
  function resolveTrailingSlashBehavior(to, resolve, trailingSlash) {
    const effectiveTrailingSlash = trailingSlash != null ? trailingSlash : options.trailingSlash;
    if (!to || effectiveTrailingSlash !== "append" && effectiveTrailingSlash !== "remove") {
      return to;
    }
    if (typeof to === "string") {
      return applyTrailingSlashBehavior(to, effectiveTrailingSlash);
    }
    const path = "path" in to && to.path !== void 0 ? to.path : resolve(to).path;
    const resolvedPath = {
      ...to,
      name: void 0,
      // named routes would otherwise always override trailing slash behavior
      path: applyTrailingSlashBehavior(path, effectiveTrailingSlash)
    };
    return resolvedPath;
  }
  function useNuxtLink(props) {
    var _a, _b, _c;
    const router = useRouter$1();
    const config = useRuntimeConfig();
    const hasTarget = computed(() => !!unref(props.target) && unref(props.target) !== "_self");
    const isAbsoluteUrl = computed(() => {
      const path = unref(props.to) || unref(props.href) || "";
      return typeof path === "string" && hasProtocol(path, { acceptRelative: true });
    });
    const builtinRouterLink = resolveComponent("RouterLink");
    const useBuiltinLink = builtinRouterLink && typeof builtinRouterLink !== "string" ? builtinRouterLink.useLink : void 0;
    const isExternal = computed(() => {
      if (unref(props.external)) {
        return true;
      }
      const path = unref(props.to) || unref(props.href) || "";
      if (typeof path === "object") {
        return false;
      }
      return path === "" || isAbsoluteUrl.value;
    });
    const to = computed(() => {
      const path = unref(props.to) || unref(props.href) || "";
      if (isExternal.value) {
        return path;
      }
      return resolveTrailingSlashBehavior(path, router.resolve, unref(props.trailingSlash));
    });
    const link = isExternal.value ? void 0 : useBuiltinLink == null ? void 0 : useBuiltinLink({ ...props, to, viewTransition: unref(props.viewTransition) });
    const href = computed(() => {
      var _a2, _b2, _c2;
      const effectiveTrailingSlash = (_a2 = unref(props.trailingSlash)) != null ? _a2 : options.trailingSlash;
      if (!to.value || isAbsoluteUrl.value || isHashLinkWithoutHashMode(to.value)) {
        return to.value;
      }
      if (isExternal.value) {
        const path = typeof to.value === "object" && "path" in to.value ? resolveRouteObject$1(to.value) : to.value;
        const href2 = typeof path === "object" ? router.resolve(path).href : path;
        return applyTrailingSlashBehavior(href2, effectiveTrailingSlash);
      }
      if (typeof to.value === "object") {
        return (_c2 = (_b2 = router.resolve(to.value)) == null ? void 0 : _b2.href) != null ? _c2 : null;
      }
      return applyTrailingSlashBehavior(joinURL(config.app.baseURL, to.value), effectiveTrailingSlash);
    });
    return {
      to,
      hasTarget,
      isAbsoluteUrl,
      isExternal,
      //
      href,
      isActive: (_a = link == null ? void 0 : link.isActive) != null ? _a : computed(() => to.value === router.currentRoute.value.path),
      isExactActive: (_b = link == null ? void 0 : link.isExactActive) != null ? _b : computed(() => to.value === router.currentRoute.value.path),
      route: (_c = link == null ? void 0 : link.route) != null ? _c : computed(() => router.resolve(to.value)),
      async navigate(_e) {
        await navigateTo(href.value, { replace: unref(props.replace), external: isExternal.value || hasTarget.value });
      }
    };
  }
  return defineComponent({
    name: componentName,
    props: {
      // Routing
      to: {
        type: [String, Object],
        default: void 0,
        required: false
      },
      href: {
        type: [String, Object],
        default: void 0,
        required: false
      },
      // Attributes
      target: {
        type: String,
        default: void 0,
        required: false
      },
      rel: {
        type: String,
        default: void 0,
        required: false
      },
      noRel: {
        type: Boolean,
        default: void 0,
        required: false
      },
      // Prefetching
      prefetch: {
        type: Boolean,
        default: void 0,
        required: false
      },
      prefetchOn: {
        type: [String, Object],
        default: void 0,
        required: false
      },
      noPrefetch: {
        type: Boolean,
        default: void 0,
        required: false
      },
      // Styling
      activeClass: {
        type: String,
        default: void 0,
        required: false
      },
      exactActiveClass: {
        type: String,
        default: void 0,
        required: false
      },
      prefetchedClass: {
        type: String,
        default: void 0,
        required: false
      },
      // Vue Router's `<RouterLink>` additional props
      replace: {
        type: Boolean,
        default: void 0,
        required: false
      },
      ariaCurrentValue: {
        type: String,
        default: void 0,
        required: false
      },
      // Edge cases handling
      external: {
        type: Boolean,
        default: void 0,
        required: false
      },
      // Slot API
      custom: {
        type: Boolean,
        default: void 0,
        required: false
      },
      // Behavior
      trailingSlash: {
        type: String,
        default: void 0,
        required: false
      }
    },
    useLink: useNuxtLink,
    setup(props, { slots }) {
      const router = useRouter$1();
      const { to, href, navigate, isExternal, hasTarget, isAbsoluteUrl } = useNuxtLink(props);
      shallowRef(false);
      const el = void 0;
      const elRef = void 0;
      async function prefetch(nuxtApp = useNuxtApp()) {
        {
          return;
        }
      }
      return () => {
        var _a;
        if (!isExternal.value && !hasTarget.value && !isHashLinkWithoutHashMode(to.value)) {
          const routerLinkProps = {
            ref: elRef,
            to: to.value,
            activeClass: props.activeClass || options.activeClass,
            exactActiveClass: props.exactActiveClass || options.exactActiveClass,
            replace: props.replace,
            ariaCurrentValue: props.ariaCurrentValue,
            custom: props.custom
          };
          if (!props.custom) {
            routerLinkProps.rel = props.rel || void 0;
          }
          return h(
            resolveComponent("RouterLink"),
            routerLinkProps,
            slots.default
          );
        }
        const target = props.target || null;
        const rel = firstNonUndefined(
          // converts `""` to `null` to prevent the attribute from being added as empty (`rel=""`)
          props.noRel ? "" : props.rel,
          options.externalRelAttribute,
          /*
          * A fallback rel of `noopener noreferrer` is applied for external links or links that open in a new tab.
          * This solves a reverse tabnapping security flaw in browsers pre-2021 as well as improving privacy.
          */
          isAbsoluteUrl.value || hasTarget.value ? "noopener noreferrer" : ""
        ) || null;
        if (props.custom) {
          if (!slots.default) {
            return null;
          }
          return slots.default({
            href: href.value,
            navigate,
            prefetch,
            get route() {
              if (!href.value) {
                return void 0;
              }
              const url = new URL(href.value, "http://localhost");
              return {
                path: url.pathname,
                fullPath: url.pathname,
                get query() {
                  return parseQuery(url.search);
                },
                hash: url.hash,
                params: {},
                name: void 0,
                matched: [],
                redirectedFrom: void 0,
                meta: {},
                href: href.value
              };
            },
            rel,
            target,
            isExternal: isExternal.value || hasTarget.value,
            isActive: false,
            isExactActive: false
          });
        }
        return h("a", {
          ref: el,
          href: href.value || null,
          // converts `""` to `null` to prevent the attribute from being added as empty (`href=""`)
          rel,
          target,
          onClick: async (event) => {
            if (isExternal.value || hasTarget.value) {
              return;
            }
            event.preventDefault();
            try {
              const encodedHref = encodeRoutePath(href.value);
              return await (props.replace ? router.replace(encodedHref) : router.push(encodedHref));
            } finally {
            }
          }
        }, (_a = slots.default) == null ? void 0 : _a.call(slots));
      };
    }
  });
}
const __nuxt_component_0$2 = /* @__PURE__ */ defineNuxtLink(nuxtLinkDefaults);
function applyTrailingSlashBehavior(to, trailingSlash) {
  const normalizeFn = trailingSlash === "append" ? withTrailingSlash : withoutTrailingSlash;
  const hasProtocolDifferentFromHttp = hasProtocol(to) && !to.startsWith("http");
  if (hasProtocolDifferentFromHttp) {
    return to;
  }
  return normalizeFn(to, true);
}
class Box {
  constructor(args) {
    var _a;
    const pageScale = (_a = (void 0).body.currentCSSZoom) != null ? _a : 1;
    const isElement = args instanceof Element;
    const factor = isElement ? 1 + (1 - pageScale) / pageScale : 1;
    const {
      x,
      y,
      width,
      height
    } = isElement ? args.getBoundingClientRect() : args;
    this.x = x * factor;
    this.y = y * factor;
    this.width = width * factor;
    this.height = height * factor;
  }
  get top() {
    return this.y;
  }
  get bottom() {
    return this.y + this.height;
  }
  get left() {
    return this.x;
  }
  get right() {
    return this.x + this.width;
  }
}
function getOverflow(a, b) {
  return {
    x: {
      before: Math.max(0, b.left - a.left),
      after: Math.max(0, a.right - b.right)
    },
    y: {
      before: Math.max(0, b.top - a.top),
      after: Math.max(0, a.bottom - b.bottom)
    }
  };
}
function getTargetBox(target) {
  var _a;
  if (Array.isArray(target)) {
    const pageScale = (_a = (void 0).body.currentCSSZoom) != null ? _a : 1;
    const factor = 1 + (1 - pageScale) / pageScale;
    return new Box({
      x: target[0] * factor,
      y: target[1] * factor,
      width: 0 * factor,
      height: 0 * factor
    });
  } else {
    return new Box(target);
  }
}
function getElementBox(el) {
  var _a;
  if (el === (void 0).documentElement) {
    if (!visualViewport) {
      return new Box({
        x: 0,
        y: 0,
        width: (void 0).documentElement.clientWidth,
        height: (void 0).documentElement.clientHeight
      });
    } else {
      const pageScale = (_a = (void 0).body.currentCSSZoom) != null ? _a : 1;
      return new Box({
        x: visualViewport.scale > 1 ? 0 : visualViewport.offsetLeft,
        y: visualViewport.scale > 1 ? 0 : visualViewport.offsetTop,
        width: visualViewport.width * visualViewport.scale / pageScale,
        height: visualViewport.height * visualViewport.scale / pageScale
      });
    }
  } else {
    return new Box(el);
  }
}
function nullifyTransforms(el) {
  const rect = new Box(el);
  const style = getComputedStyle(el);
  const tx = style.transform;
  if (tx) {
    let ta, sx, sy, dx, dy;
    if (tx.startsWith("matrix3d(")) {
      ta = tx.slice(9, -1).split(/, /);
      sx = Number(ta[0]);
      sy = Number(ta[5]);
      dx = Number(ta[12]);
      dy = Number(ta[13]);
    } else if (tx.startsWith("matrix(")) {
      ta = tx.slice(7, -1).split(/, /);
      sx = Number(ta[0]);
      sy = Number(ta[3]);
      dx = Number(ta[4]);
      dy = Number(ta[5]);
    } else {
      return new Box(rect);
    }
    const to = style.transformOrigin;
    const x = rect.x - dx - (1 - sx) * parseFloat(to);
    const y = rect.y - dy - (1 - sy) * parseFloat(to.slice(to.indexOf(" ") + 1));
    const w = sx ? rect.width / sx : el.offsetWidth + 1;
    const h2 = sy ? rect.height / sy : el.offsetHeight + 1;
    return new Box({
      x,
      y,
      width: w,
      height: h2
    });
  } else {
    return new Box(rect);
  }
}
function animate(el, keyframes, options) {
  if (typeof el.animate === "undefined") return {
    finished: Promise.resolve()
  };
  let animation;
  try {
    animation = el.animate(keyframes, options);
  } catch (err) {
    return {
      finished: Promise.resolve()
    };
  }
  if (typeof animation.finished === "undefined") {
    animation.finished = new Promise((resolve) => {
      animation.onfinish = () => {
        resolve(animation);
      };
    });
  }
  return animation;
}
function createSimpleFunctional(klass) {
  let tag = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : "div";
  let name = arguments.length > 2 ? arguments[2] : void 0;
  return genericComponent()({
    name: name != null ? name : capitalize(camelize(klass.replace(/__/g, "-"))),
    props: {
      tag: {
        type: String,
        default: tag
      },
      ...makeComponentProps()
    },
    setup(props, _ref) {
      let {
        slots
      } = _ref;
      return () => {
        var _a;
        return h(props.tag, {
          class: [klass, props.class],
          style: props.style
        }, (_a = slots.default) == null ? void 0 : _a.call(slots));
      };
    }
  });
}
function attachedRoot(node) {
  if (typeof node.getRootNode !== "function") {
    while (node.parentNode) node = node.parentNode;
    if (node !== void 0) return null;
    return void 0;
  }
  const root = node.getRootNode();
  if (root !== void 0 && root.getRootNode({
    composed: true
  }) !== void 0) return null;
  return root;
}
function getScrollParent(el) {
  let includeHidden = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : false;
  while (el) {
    if (includeHidden ? isPotentiallyScrollable(el) : hasScrollbar(el)) return el;
    el = el.parentElement;
  }
  return (void 0).scrollingElement;
}
function getScrollParents(el, stopAt) {
  const elements = [];
  if (stopAt && el && !stopAt.contains(el)) return elements;
  while (el) {
    if (hasScrollbar(el)) elements.push(el);
    if (el === stopAt) break;
    el = el.parentElement;
  }
  return elements;
}
function hasScrollbar(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
  const style = (void 0).getComputedStyle(el);
  const hasVerticalScrollbar = style.overflowY === "scroll" || style.overflowY === "auto" && el.scrollHeight > el.clientHeight;
  const hasHorizontalScrollbar = style.overflowX === "scroll" || style.overflowX === "auto" && el.scrollWidth > el.clientWidth;
  return hasVerticalScrollbar || hasHorizontalScrollbar;
}
function isPotentiallyScrollable(el) {
  if (!el || el.nodeType !== Node.ELEMENT_NODE) return false;
  const style = (void 0).getComputedStyle(el);
  return ["scroll", "auto"].includes(style.overflowY);
}
function isFixedPosition(el) {
  while (el) {
    if ((void 0).getComputedStyle(el).position === "fixed") {
      return true;
    }
    el = el.offsetParent;
  }
  return false;
}
function throttle(fn, delay) {
  let options = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : {
    leading: true,
    trailing: true
  };
  let timeoutId = 0;
  let lastExec = 0;
  let throttling = false;
  let start = 0;
  function clear() {
    clearTimeout(timeoutId);
    throttling = false;
    start = 0;
  }
  const wrap = function() {
    for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }
    clearTimeout(timeoutId);
    const now = Date.now();
    if (!start) start = now;
    const elapsed = now - Math.max(start, lastExec);
    function invoke() {
      lastExec = Date.now();
      timeoutId = setTimeout(clear, delay);
      fn(...args);
    }
    if (!throttling) {
      throttling = true;
      if (options.leading) {
        invoke();
      }
    } else if (elapsed >= delay) {
      invoke();
    } else if (options.trailing) {
      timeoutId = setTimeout(invoke, delay - elapsed);
    }
  };
  wrap.clear = clear;
  wrap.immediate = fn;
  return wrap;
}
const _sfc_main$5 = /* @__PURE__ */ defineComponent({
  __name: "AppLogo",
  __ssrInlineRender: true,
  setup(__props) {
    const localePath = useLocalePath();
    const homePath = computed(() => localePath("/"));
    return (_ctx, _push, _parent, _attrs) => {
      const _component_NuxtLink = __nuxt_component_0$2;
      _push(ssrRenderComponent(_component_NuxtLink, mergeProps({
        to: unref(homePath),
        class: "app-logo"
      }, _attrs), {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<span class="app-logo__mark" data-v-8a8ac13a${_scopeId}>L</span><span class="app-logo__copy" data-v-8a8ac13a${_scopeId}><span class="app-logo__text" data-v-8a8ac13a${_scopeId}>lintai</span><span class="app-logo__subtext" data-v-8a8ac13a${_scopeId}>agent security</span></span>`);
          } else {
            return [
              createVNode("span", { class: "app-logo__mark" }, "L"),
              createVNode("span", { class: "app-logo__copy" }, [
                createVNode("span", { class: "app-logo__text" }, "lintai"),
                createVNode("span", { class: "app-logo__subtext" }, "agent security")
              ])
            ];
          }
        }),
        _: 1
      }, _parent));
    };
  }
});
const _sfc_setup$5 = _sfc_main$5.setup;
_sfc_main$5.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/common/AppLogo.vue");
  return _sfc_setup$5 ? _sfc_setup$5(props, ctx) : void 0;
};
const __nuxt_component_0$1 = /* @__PURE__ */ _export_sfc(_sfc_main$5, [["__scopeId", "data-v-8a8ac13a"]]);
const useLocaleStore = defineStore("locale", {
  state: () => ({
    current: "en",
    userSelected: false
  }),
  actions: {
    setLocale(locale, fromUser) {
      this.current = locale;
      if (fromUser) {
        this.userSelected = true;
      }
    }
  }
});
function useAspectStyles(props) {
  return {
    aspectStyles: computed(() => {
      const ratio = Number(props.aspectRatio);
      return ratio ? {
        paddingBottom: String(1 / ratio * 100) + "%"
      } : void 0;
    })
  };
}
const makeVResponsiveProps = propsFactory({
  aspectRatio: [String, Number],
  contentClass: null,
  inline: Boolean,
  ...makeComponentProps(),
  ...makeDimensionProps()
}, "VResponsive");
const VResponsive = genericComponent()({
  name: "VResponsive",
  props: makeVResponsiveProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      aspectStyles
    } = useAspectStyles(props);
    const {
      dimensionStyles
    } = useDimension(props);
    useRender(() => {
      var _a;
      return createElementVNode("div", {
        "class": normalizeClass(["v-responsive", {
          "v-responsive--inline": props.inline
        }, props.class]),
        "style": normalizeStyle([dimensionStyles.value, props.style])
      }, [createElementVNode("div", {
        "class": "v-responsive__sizer",
        "style": normalizeStyle(aspectStyles.value)
      }, null), (_a = slots.additional) == null ? void 0 : _a.call(slots), slots.default && createElementVNode("div", {
        "class": normalizeClass(["v-responsive__content", props.contentClass])
      }, [slots.default()])]);
    });
    return {};
  }
});
const makeTransitionProps = propsFactory({
  transition: {
    type: null,
    default: "fade-transition",
    validator: (val) => val !== true
  }
}, "transition");
const MaybeTransition = (props, _ref) => {
  let {
    slots
  } = _ref;
  const {
    transition,
    disabled,
    group,
    ...rest
  } = props;
  const {
    component = group ? TransitionGroup : Transition,
    ...customProps
  } = isObject(transition) ? transition : {};
  let transitionProps;
  if (isObject(transition)) {
    transitionProps = mergeProps(customProps, onlyDefinedProps({
      disabled,
      group
    }), rest);
  } else {
    transitionProps = mergeProps({
      name: disabled || !transition ? "" : transition
    }, rest);
  }
  return h(component, transitionProps, slots);
};
function mounted(el, binding) {
  return;
}
function unmounted(el, binding) {
  var _a;
  const observe = (_a = el._observe) == null ? void 0 : _a[binding.instance.$.uid];
  if (!observe) return;
  observe.observer.unobserve(el);
  delete el._observe[binding.instance.$.uid];
}
const Intersect = {
  mounted,
  unmounted,
  updated: (el, binding) => {
    var _a;
    if ((_a = el._observe) == null ? void 0 : _a[binding.instance.$.uid]) {
      unmounted(el, binding);
    }
  }
};
const makeVImgProps = propsFactory({
  absolute: Boolean,
  alt: String,
  cover: Boolean,
  color: String,
  draggable: {
    type: [Boolean, String],
    default: void 0
  },
  eager: Boolean,
  gradient: String,
  imageClass: null,
  lazySrc: String,
  options: {
    type: Object,
    // For more information on types, navigate to:
    // https://developer.mozilla.org/en-US/docs/Web/API/Intersection_Observer_API
    default: () => ({
      root: void 0,
      rootMargin: void 0,
      threshold: void 0
    })
  },
  sizes: String,
  src: {
    type: [String, Object],
    default: ""
  },
  crossorigin: String,
  referrerpolicy: String,
  srcset: String,
  position: String,
  ...makeVResponsiveProps(),
  ...makeComponentProps(),
  ...makeRoundedProps(),
  ...makeTransitionProps()
}, "VImg");
const VImg = genericComponent()({
  name: "VImg",
  directives: {
    vIntersect: Intersect
  },
  props: makeVImgProps(),
  emits: {
    loadstart: (value) => true,
    load: (value) => true,
    error: (value) => true
  },
  setup(props, _ref) {
    let {
      emit,
      slots
    } = _ref;
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.color);
    const {
      roundedClasses
    } = useRounded(props);
    const vm = getCurrentInstance$1("VImg");
    const currentSrc = shallowRef("");
    const image = ref();
    const state = shallowRef(props.eager ? "loading" : "idle");
    const naturalWidth = shallowRef();
    const naturalHeight = shallowRef();
    const normalisedSrc = computed(() => {
      return props.src && typeof props.src === "object" ? {
        src: props.src.src,
        srcset: props.srcset || props.src.srcset,
        lazySrc: props.lazySrc || props.src.lazySrc,
        aspect: Number(props.aspectRatio || props.src.aspect || 0)
      } : {
        src: props.src,
        srcset: props.srcset,
        lazySrc: props.lazySrc,
        aspect: Number(props.aspectRatio || 0)
      };
    });
    const aspectRatio = computed(() => {
      return normalisedSrc.value.aspect || naturalWidth.value / naturalHeight.value || 0;
    });
    watch(() => props.src, () => {
      init(state.value !== "idle");
    });
    watch(aspectRatio, (val, oldVal) => {
      if (!val && oldVal && image.value) {
        pollForSize(image.value);
      }
    });
    function init(isIntersecting) {
      if (props.eager && isIntersecting) return;
      state.value = "loading";
      if (normalisedSrc.value.lazySrc) {
        const lazyImg = new Image();
        lazyImg.src = normalisedSrc.value.lazySrc;
        pollForSize(lazyImg, null);
      }
      if (!normalisedSrc.value.src) return;
      nextTick(() => {
        var _a;
        emit("loadstart", ((_a = image.value) == null ? void 0 : _a.currentSrc) || normalisedSrc.value.src);
        setTimeout(() => {
          var _a2;
          if (vm.isUnmounted) return;
          if ((_a2 = image.value) == null ? void 0 : _a2.complete) {
            if (!image.value.naturalWidth) {
              onError();
            }
            if (state.value === "error") return;
            if (!aspectRatio.value) pollForSize(image.value, null);
            if (state.value === "loading") onLoad();
          } else {
            if (!aspectRatio.value) pollForSize(image.value);
            getSrc();
          }
        });
      });
    }
    function onLoad() {
      var _a;
      if (vm.isUnmounted) return;
      getSrc();
      pollForSize(image.value);
      state.value = "loaded";
      emit("load", ((_a = image.value) == null ? void 0 : _a.currentSrc) || normalisedSrc.value.src);
    }
    function onError() {
      var _a;
      if (vm.isUnmounted) return;
      state.value = "error";
      emit("error", ((_a = image.value) == null ? void 0 : _a.currentSrc) || normalisedSrc.value.src);
    }
    function getSrc() {
      const img = image.value;
      if (img) currentSrc.value = img.currentSrc || img.src;
    }
    let timer = -1;
    function pollForSize(img) {
      let timeout = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : 100;
      const poll = () => {
        clearTimeout(timer);
        if (vm.isUnmounted) return;
        const {
          naturalHeight: imgHeight,
          naturalWidth: imgWidth
        } = img;
        if (imgHeight || imgWidth) {
          naturalWidth.value = imgWidth;
          naturalHeight.value = imgHeight;
        } else if (!img.complete && state.value === "loading" && timeout != null) {
          timer = (void 0).setTimeout(poll, timeout);
        } else if (img.currentSrc.endsWith(".svg") || img.currentSrc.startsWith("data:image/svg+xml")) {
          naturalWidth.value = 1;
          naturalHeight.value = 1;
        }
      };
      poll();
    }
    const containClasses = toRef(() => ({
      "v-img__img--cover": props.cover,
      "v-img__img--contain": !props.cover
    }));
    const __image = () => {
      var _a;
      if (!normalisedSrc.value.src || state.value === "idle") return null;
      const img = createElementVNode("img", {
        "class": normalizeClass(["v-img__img", containClasses.value, props.imageClass]),
        "style": {
          objectPosition: props.position
        },
        "crossorigin": props.crossorigin,
        "src": normalisedSrc.value.src,
        "srcset": normalisedSrc.value.srcset,
        "alt": props.alt,
        "referrerpolicy": props.referrerpolicy,
        "draggable": props.draggable,
        "sizes": props.sizes,
        "ref": image,
        "onLoad": onLoad,
        "onError": onError
      }, null);
      const sources = (_a = slots.sources) == null ? void 0 : _a.call(slots);
      return createVNode(MaybeTransition, {
        "transition": props.transition,
        "appear": true
      }, {
        default: () => [withDirectives(sources ? createElementVNode("picture", {
          "class": "v-img__picture"
        }, [sources, img]) : img, [[vShow, state.value === "loaded"]])]
      });
    };
    const __preloadImage = () => createVNode(MaybeTransition, {
      "transition": props.transition
    }, {
      default: () => [normalisedSrc.value.lazySrc && state.value !== "loaded" && createElementVNode("img", {
        "class": normalizeClass(["v-img__img", "v-img__img--preload", containClasses.value]),
        "style": {
          objectPosition: props.position
        },
        "crossorigin": props.crossorigin,
        "src": normalisedSrc.value.lazySrc,
        "alt": props.alt,
        "referrerpolicy": props.referrerpolicy,
        "draggable": props.draggable
      }, null)]
    });
    const __placeholder = () => {
      if (!slots.placeholder) return null;
      return createVNode(MaybeTransition, {
        "transition": props.transition,
        "appear": true
      }, {
        default: () => [(state.value === "loading" || state.value === "error" && !slots.error) && createElementVNode("div", {
          "class": "v-img__placeholder"
        }, [slots.placeholder()])]
      });
    };
    const __error = () => {
      if (!slots.error) return null;
      return createVNode(MaybeTransition, {
        "transition": props.transition,
        "appear": true
      }, {
        default: () => [state.value === "error" && createElementVNode("div", {
          "class": "v-img__error"
        }, [slots.error()])]
      });
    };
    const __gradient = () => {
      if (!props.gradient) return null;
      return createElementVNode("div", {
        "class": "v-img__gradient",
        "style": {
          backgroundImage: `linear-gradient(${props.gradient})`
        }
      }, null);
    };
    const isBooted = shallowRef(false);
    {
      const stop = watch(aspectRatio, (val) => {
        if (val) {
          requestAnimationFrame(() => {
            requestAnimationFrame(() => {
              isBooted.value = true;
            });
          });
          stop();
        }
      });
    }
    useRender(() => {
      const responsiveProps = VResponsive.filterProps(props);
      return withDirectives(createVNode(VResponsive, mergeProps({
        "class": ["v-img", {
          "v-img--absolute": props.absolute,
          "v-img--booting": !isBooted.value,
          "v-img--fit-content": props.width === "fit-content"
        }, backgroundColorClasses.value, roundedClasses.value, props.class],
        "style": [{
          width: convertToUnit(props.width === "auto" ? naturalWidth.value : props.width)
        }, backgroundColorStyles.value, props.style]
      }, responsiveProps, {
        "aspectRatio": aspectRatio.value,
        "aria-label": props.alt,
        "role": props.alt ? "img" : void 0
      }), {
        additional: () => createElementVNode(Fragment, null, [createVNode(__image, null, null), createVNode(__preloadImage, null, null), createVNode(__gradient, null, null), createVNode(__placeholder, null, null), createVNode(__error, null, null)]),
        default: slots.default
      }), [[Intersect, {
        handler: init,
        options: props.options
      }, null, {
        once: true
      }]]);
    });
    return {
      currentSrc,
      image,
      state,
      naturalWidth,
      naturalHeight
    };
  }
});
const makeVAvatarProps = propsFactory({
  start: Boolean,
  end: Boolean,
  icon: IconValue,
  image: String,
  text: String,
  ...makeBorderProps(),
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...makeRoundedProps(),
  ...makeSizeProps(),
  ...makeTagProps(),
  ...makeThemeProps(),
  ...makeVariantProps({
    variant: "flat"
  })
}, "VAvatar");
const VAvatar = genericComponent()({
  name: "VAvatar",
  props: makeVAvatarProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      themeClasses
    } = provideTheme(props);
    const {
      borderClasses
    } = useBorder(props);
    const {
      colorClasses,
      colorStyles,
      variantClasses
    } = useVariant(props);
    const {
      densityClasses
    } = useDensity(props);
    const {
      roundedClasses
    } = useRounded(props);
    const {
      sizeClasses,
      sizeStyles
    } = useSize(props);
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-avatar", {
        "v-avatar--start": props.start,
        "v-avatar--end": props.end
      }, themeClasses.value, borderClasses.value, colorClasses.value, densityClasses.value, roundedClasses.value, sizeClasses.value, variantClasses.value, props.class]),
      "style": normalizeStyle([colorStyles.value, sizeStyles.value, props.style])
    }, {
      default: () => [!slots.default ? props.image ? createVNode(VImg, {
        "key": "image",
        "src": props.image,
        "alt": "",
        "cover": true
      }, null) : props.icon ? createVNode(VIcon, {
        "key": "icon",
        "icon": props.icon
      }, null) : props.text : createVNode(VDefaultsProvider, {
        "key": "content-defaults",
        "defaults": {
          VImg: {
            cover: true,
            src: props.image
          },
          VIcon: {
            icon: props.icon
          }
        }
      }, {
        default: () => [slots.default()]
      }), genOverlays(false, "v-avatar")]
    }));
    return {};
  }
});
const makeVLabelProps = propsFactory({
  text: String,
  onClick: EventProp(),
  ...makeComponentProps(),
  ...makeThemeProps()
}, "VLabel");
const VLabel = genericComponent()({
  name: "VLabel",
  props: makeVLabelProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    useRender(() => {
      var _a;
      return createElementVNode("label", {
        "class": normalizeClass(["v-label", {
          "v-label--clickable": !!props.onClick
        }, props.class]),
        "style": normalizeStyle(props.style),
        "onClick": props.onClick
      }, [props.text, (_a = slots.default) == null ? void 0 : _a.call(slots)]);
    });
    return {};
  }
});
const VSelectionControlGroupSymbol = /* @__PURE__ */ Symbol.for("vuetify:selection-control-group");
const makeSelectionControlGroupProps = propsFactory({
  color: String,
  disabled: {
    type: Boolean,
    default: null
  },
  defaultsTarget: String,
  error: Boolean,
  id: String,
  inline: Boolean,
  falseIcon: IconValue,
  trueIcon: IconValue,
  ripple: {
    type: [Boolean, Object],
    default: true
  },
  multiple: {
    type: Boolean,
    default: null
  },
  name: String,
  readonly: {
    type: Boolean,
    default: null
  },
  modelValue: null,
  type: String,
  valueComparator: {
    type: Function,
    default: deepEqual
  },
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...makeThemeProps()
}, "SelectionControlGroup");
const makeVSelectionControlGroupProps = propsFactory({
  ...makeSelectionControlGroupProps({
    defaultsTarget: "VSelectionControl"
  })
}, "VSelectionControlGroup");
genericComponent()({
  name: "VSelectionControlGroup",
  props: makeVSelectionControlGroupProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const modelValue = useProxiedModel(props, "modelValue");
    const uid = useId();
    const id = toRef(() => props.id || `v-selection-control-group-${uid}`);
    const name = toRef(() => props.name || id.value);
    const updateHandlers = /* @__PURE__ */ new Set();
    provide(VSelectionControlGroupSymbol, {
      modelValue,
      forceUpdate: () => {
        updateHandlers.forEach((fn) => fn());
      },
      onForceUpdate: (cb) => {
        updateHandlers.add(cb);
        onScopeDispose(() => {
          updateHandlers.delete(cb);
        });
      }
    });
    provideDefaults({
      [props.defaultsTarget]: {
        color: toRef(() => props.color),
        disabled: toRef(() => props.disabled),
        density: toRef(() => props.density),
        error: toRef(() => props.error),
        inline: toRef(() => props.inline),
        modelValue,
        multiple: toRef(() => !!props.multiple || props.multiple == null && Array.isArray(modelValue.value)),
        name,
        falseIcon: toRef(() => props.falseIcon),
        trueIcon: toRef(() => props.trueIcon),
        readonly: toRef(() => props.readonly),
        ripple: toRef(() => props.ripple),
        type: toRef(() => props.type),
        valueComparator: toRef(() => props.valueComparator)
      }
    });
    useRender(() => {
      var _a;
      return createElementVNode("div", {
        "class": normalizeClass(["v-selection-control-group", {
          "v-selection-control-group--inline": props.inline
        }, props.class]),
        "style": normalizeStyle(props.style),
        "role": props.type === "radio" ? "radiogroup" : void 0
      }, [(_a = slots.default) == null ? void 0 : _a.call(slots)]);
    });
    return {};
  }
});
const makeVSelectionControlProps = propsFactory({
  label: String,
  baseColor: String,
  trueValue: null,
  falseValue: null,
  value: null,
  ...makeComponentProps(),
  ...makeSelectionControlGroupProps()
}, "VSelectionControl");
function useSelectionControl(props) {
  const group = inject(VSelectionControlGroupSymbol, void 0);
  const {
    densityClasses
  } = useDensity(props);
  const modelValue = useProxiedModel(props, "modelValue");
  const trueValue = computed(() => props.trueValue !== void 0 ? props.trueValue : props.value !== void 0 ? props.value : true);
  const falseValue = computed(() => props.falseValue !== void 0 ? props.falseValue : false);
  const isMultiple = computed(() => !!props.multiple || props.multiple == null && Array.isArray(modelValue.value));
  const model = computed({
    get() {
      const val = group ? group.modelValue.value : modelValue.value;
      return isMultiple.value ? wrapInArray(val).some((v) => props.valueComparator(v, trueValue.value)) : props.valueComparator(val, trueValue.value);
    },
    set(val) {
      if (props.readonly) return;
      const currentValue = val ? trueValue.value : falseValue.value;
      let newVal = currentValue;
      if (isMultiple.value) {
        newVal = val ? [...wrapInArray(modelValue.value), currentValue] : wrapInArray(modelValue.value).filter((item) => !props.valueComparator(item, trueValue.value));
      }
      if (group) {
        group.modelValue.value = newVal;
      } else {
        modelValue.value = newVal;
      }
    }
  });
  const {
    textColorClasses,
    textColorStyles
  } = useTextColor(() => {
    if (props.error || props.disabled) return void 0;
    return model.value ? props.color : props.baseColor;
  });
  const {
    backgroundColorClasses,
    backgroundColorStyles
  } = useBackgroundColor(() => {
    return model.value && !props.error && !props.disabled ? props.color : props.baseColor;
  });
  const icon = computed(() => model.value ? props.trueIcon : props.falseIcon);
  return {
    group,
    densityClasses,
    trueValue,
    falseValue,
    model,
    textColorClasses,
    textColorStyles,
    backgroundColorClasses,
    backgroundColorStyles,
    icon
  };
}
const VSelectionControl = genericComponent()({
  name: "VSelectionControl",
  directives: {
    vRipple: Ripple
  },
  inheritAttrs: false,
  props: makeVSelectionControlProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      slots
    } = _ref;
    const {
      group,
      densityClasses,
      icon,
      model,
      textColorClasses,
      textColorStyles,
      backgroundColorClasses,
      backgroundColorStyles,
      trueValue
    } = useSelectionControl(props);
    const uid = useId();
    const isFocused = shallowRef(false);
    const isFocusVisible = shallowRef(false);
    const input = ref();
    const id = toRef(() => props.id || `input-${uid}`);
    const isInteractive = toRef(() => !props.disabled && !props.readonly);
    group == null ? void 0 : group.onForceUpdate(() => {
      if (input.value) {
        input.value.checked = model.value;
      }
    });
    function onFocus(e) {
      if (!isInteractive.value) return;
      isFocused.value = true;
      if (matchesSelector(e.target) !== false) {
        isFocusVisible.value = true;
      }
    }
    function onBlur() {
      isFocused.value = false;
      isFocusVisible.value = false;
    }
    function onClickLabel(e) {
      e.stopPropagation();
    }
    function onInput(e) {
      if (!isInteractive.value) {
        if (input.value) {
          input.value.checked = model.value;
        }
        return;
      }
      if (props.readonly && group) {
        nextTick(() => group.forceUpdate());
      }
      model.value = e.target.checked;
    }
    useRender(() => {
      var _a, _b, _c;
      const label = slots.label ? slots.label({
        label: props.label,
        props: {
          for: id.value
        }
      }) : props.label;
      const [rootAttrs, inputAttrs] = filterInputAttrs(attrs);
      const inputNode = createElementVNode("input", mergeProps({
        "ref": input,
        "checked": model.value,
        "disabled": !!props.disabled,
        "id": id.value,
        "onBlur": onBlur,
        "onFocus": onFocus,
        "onInput": onInput,
        "aria-disabled": !!props.disabled,
        "aria-label": props.label,
        "type": props.type,
        "value": trueValue.value,
        "name": props.name,
        "aria-checked": props.type === "checkbox" ? model.value : void 0
      }, inputAttrs), null);
      return createElementVNode("div", mergeProps({
        "class": ["v-selection-control", {
          "v-selection-control--dirty": model.value,
          "v-selection-control--disabled": props.disabled,
          "v-selection-control--error": props.error,
          "v-selection-control--focused": isFocused.value,
          "v-selection-control--focus-visible": isFocusVisible.value,
          "v-selection-control--inline": props.inline
        }, densityClasses.value, props.class]
      }, rootAttrs, {
        "style": props.style
      }), [createElementVNode("div", {
        "class": normalizeClass(["v-selection-control__wrapper", textColorClasses.value]),
        "style": normalizeStyle(textColorStyles.value)
      }, [(_a = slots.default) == null ? void 0 : _a.call(slots, {
        backgroundColorClasses,
        backgroundColorStyles
      }), withDirectives(createElementVNode("div", {
        "class": normalizeClass(["v-selection-control__input"])
      }, [(_c = (_b = slots.input) == null ? void 0 : _b.call(slots, {
        model,
        textColorClasses,
        textColorStyles,
        backgroundColorClasses,
        backgroundColorStyles,
        inputNode,
        icon: icon.value,
        props: {
          onFocus,
          onBlur,
          id: id.value
        }
      })) != null ? _c : createElementVNode(Fragment, null, [icon.value && createVNode(VIcon, {
        "key": "icon",
        "icon": icon.value
      }, null), inputNode])]), [[Ripple, !props.disabled && !props.readonly && props.ripple, null, {
        center: true,
        circle: true
      }]])]), label && createVNode(VLabel, {
        "for": id.value,
        "onClick": onClickLabel
      }, {
        default: () => [label]
      })]);
    });
    return {
      isFocused,
      input
    };
  }
});
const makeVCheckboxBtnProps = propsFactory({
  indeterminate: Boolean,
  indeterminateIcon: {
    type: IconValue,
    default: "$checkboxIndeterminate"
  },
  ...makeVSelectionControlProps({
    falseIcon: "$checkboxOff",
    trueIcon: "$checkboxOn"
  })
}, "VCheckboxBtn");
const VCheckboxBtn = genericComponent()({
  name: "VCheckboxBtn",
  props: makeVCheckboxBtnProps(),
  emits: {
    "update:modelValue": (value) => true,
    "update:indeterminate": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const indeterminate = useProxiedModel(props, "indeterminate");
    const model = useProxiedModel(props, "modelValue");
    function onChange(v) {
      if (indeterminate.value) {
        indeterminate.value = false;
      }
    }
    const falseIcon = toRef(() => {
      return indeterminate.value ? props.indeterminateIcon : props.falseIcon;
    });
    const trueIcon = toRef(() => {
      return indeterminate.value ? props.indeterminateIcon : props.trueIcon;
    });
    useRender(() => {
      const controlProps = omit(VSelectionControl.filterProps(props), ["modelValue"]);
      return createVNode(VSelectionControl, mergeProps(controlProps, {
        "modelValue": model.value,
        "onUpdate:modelValue": [($event) => model.value = $event, onChange],
        "class": ["v-checkbox-btn", props.class],
        "style": props.style,
        "type": "checkbox",
        "falseIcon": falseIcon.value,
        "trueIcon": trueIcon.value,
        "aria-checked": indeterminate.value ? "mixed" : void 0
      }), slots);
    });
    return {};
  }
});
function useInputIcon(props) {
  const {
    t
  } = useLocale();
  function InputIcon(_ref) {
    var _a;
    let {
      name,
      color,
      ...attrs
    } = _ref;
    const localeKey = {
      prepend: "prependAction",
      prependInner: "prependAction",
      append: "appendAction",
      appendInner: "appendAction",
      clear: "clear"
    }[name];
    const listener = props[`onClick:${name}`];
    function onKeydown2(e) {
      if (e.key !== "Enter" && e.key !== " ") return;
      e.preventDefault();
      e.stopPropagation();
      callEvent(listener, new PointerEvent("click", e));
    }
    const label = listener && localeKey ? t(`$vuetify.input.${localeKey}`, (_a = props.label) != null ? _a : "") : void 0;
    return createVNode(VIcon, mergeProps({
      "icon": props[`${name}Icon`],
      "aria-label": label,
      "onClick": listener,
      "onKeydown": onKeydown2,
      "color": color
    }, attrs), null);
  }
  return {
    InputIcon
  };
}
const makeVDialogTransitionProps = propsFactory({
  target: [Object, Array]
}, "v-dialog-transition");
const saved = /* @__PURE__ */ new WeakMap();
const VDialogTransition = genericComponent()({
  name: "VDialogTransition",
  props: makeVDialogTransitionProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const functions = {
      onBeforeEnter(el) {
        el.style.pointerEvents = "none";
        el.style.visibility = "hidden";
      },
      async onEnter(el, done) {
        var _a;
        await new Promise((resolve) => requestAnimationFrame(resolve));
        await new Promise((resolve) => requestAnimationFrame(resolve));
        el.style.visibility = "";
        const dimensions = getDimensions(props.target, el);
        const {
          x,
          y,
          sx,
          sy,
          speed
        } = dimensions;
        saved.set(el, dimensions);
        {
          const animation = animate(el, [{
            transform: `translate(${x}px, ${y}px) scale(${sx}, ${sy})`,
            opacity: 0
          }, {}], {
            duration: 225 * speed,
            easing: deceleratedEasing
          });
          (_a = getChildren(el)) == null ? void 0 : _a.forEach((el2) => {
            animate(el2, [{
              opacity: 0
            }, {
              opacity: 0,
              offset: 0.33
            }, {}], {
              duration: 225 * 2 * speed,
              easing: standardEasing
            });
          });
          animation.finished.then(() => done());
        }
      },
      onAfterEnter(el) {
        el.style.removeProperty("pointer-events");
      },
      onBeforeLeave(el) {
        el.style.pointerEvents = "none";
      },
      async onLeave(el, done) {
        var _a;
        await new Promise((resolve) => requestAnimationFrame(resolve));
        let dimensions;
        if (!saved.has(el) || Array.isArray(props.target) || props.target.offsetParent || props.target.getClientRects().length) {
          dimensions = getDimensions(props.target, el);
        } else {
          dimensions = saved.get(el);
        }
        const {
          x,
          y,
          sx,
          sy,
          speed
        } = dimensions;
        {
          const animation = animate(el, [{}, {
            transform: `translate(${x}px, ${y}px) scale(${sx}, ${sy})`,
            opacity: 0
          }], {
            duration: 125 * speed,
            easing: acceleratedEasing
          });
          animation.finished.then(() => done());
          (_a = getChildren(el)) == null ? void 0 : _a.forEach((el2) => {
            animate(el2, [{}, {
              opacity: 0,
              offset: 0.2
            }, {
              opacity: 0
            }], {
              duration: 125 * 2 * speed,
              easing: standardEasing
            });
          });
        }
      },
      onAfterLeave(el) {
        el.style.removeProperty("pointer-events");
      }
    };
    return () => {
      return props.target ? createVNode(Transition, mergeProps({
        "name": "dialog-transition"
      }, functions, {
        "css": false
      }), slots) : createVNode(Transition, {
        "name": "dialog-transition"
      }, slots);
    };
  }
});
function getChildren(el) {
  var _a;
  const els = (_a = el.querySelector(":scope > .v-card, :scope > .v-sheet, :scope > .v-list")) == null ? void 0 : _a.children;
  return els && [...els];
}
function getDimensions(target, el) {
  const targetBox = getTargetBox(target);
  const elBox = nullifyTransforms(el);
  const [originX, originY] = getComputedStyle(el).transformOrigin.split(" ").map((v) => parseFloat(v));
  const [anchorSide, anchorOffset] = getComputedStyle(el).getPropertyValue("--v-overlay-anchor-origin").split(" ");
  let offsetX = targetBox.left + targetBox.width / 2;
  if (anchorSide === "left" || anchorOffset === "left") {
    offsetX -= targetBox.width / 2;
  } else if (anchorSide === "right" || anchorOffset === "right") {
    offsetX += targetBox.width / 2;
  }
  let offsetY = targetBox.top + targetBox.height / 2;
  if (anchorSide === "top" || anchorOffset === "top") {
    offsetY -= targetBox.height / 2;
  } else if (anchorSide === "bottom" || anchorOffset === "bottom") {
    offsetY += targetBox.height / 2;
  }
  const tsx = targetBox.width / elBox.width;
  const tsy = targetBox.height / elBox.height;
  const maxs = Math.max(1, tsx, tsy);
  const sx = tsx / maxs || 0;
  const sy = tsy / maxs || 0;
  const asa = elBox.width * elBox.height / ((void 0).innerWidth * (void 0).innerHeight);
  const speed = asa > 0.12 ? Math.min(1.5, (asa - 0.12) * 10 + 1) : 1;
  return {
    x: offsetX - (originX + elBox.left),
    y: offsetY - (originY + elBox.top),
    sx,
    sy,
    speed
  };
}
const makeVMessagesProps = propsFactory({
  active: Boolean,
  color: String,
  messages: {
    type: [Array, String],
    default: () => []
  },
  ...makeComponentProps(),
  ...makeTransitionProps({
    transition: {
      component: VSlideYTransition,
      leaveAbsolute: true,
      group: true
    }
  })
}, "VMessages");
const VMessages = genericComponent()({
  name: "VMessages",
  props: makeVMessagesProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const messages = computed(() => wrapInArray(props.messages));
    const {
      textColorClasses,
      textColorStyles
    } = useTextColor(() => props.color);
    useRender(() => createVNode(MaybeTransition, {
      "transition": props.transition,
      "tag": "div",
      "class": normalizeClass(["v-messages", textColorClasses.value, props.class]),
      "style": normalizeStyle([textColorStyles.value, props.style])
    }, {
      default: () => [props.active && messages.value.map((message, i) => createElementVNode("div", {
        "class": "v-messages__message",
        "key": `${i}-${messages.value}`
      }, [slots.message ? slots.message({
        message
      }) : message]))]
    }));
    return {};
  }
});
const makeFocusProps = propsFactory({
  focused: Boolean,
  "onUpdate:focused": EventProp()
}, "focus");
function useFocus(props) {
  let name = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : getCurrentInstanceName();
  const isFocused = useProxiedModel(props, "focused");
  const focusClasses = toRef(() => {
    return {
      [`${name}--focused`]: isFocused.value
    };
  });
  function focus() {
    isFocused.value = true;
  }
  function blur() {
    isFocused.value = false;
  }
  return {
    focusClasses,
    isFocused,
    focus,
    blur
  };
}
const FormKey = /* @__PURE__ */ Symbol.for("vuetify:form");
function useForm(props) {
  const form = inject(FormKey, null);
  return {
    ...form,
    isReadonly: computed(() => {
      var _a;
      return !!((_a = props == null ? void 0 : props.readonly) != null ? _a : form == null ? void 0 : form.isReadonly.value);
    }),
    isDisabled: computed(() => {
      var _a;
      return !!((_a = props == null ? void 0 : props.disabled) != null ? _a : form == null ? void 0 : form.isDisabled.value);
    })
  };
}
const RulesSymbol = /* @__PURE__ */ Symbol.for("vuetify:rules");
function useRules(fn) {
  var _a;
  const rules = inject(RulesSymbol, null);
  if (!fn) {
    if (!rules) {
      throw new Error("Could not find Vuetify rules injection");
    }
    return rules.aliases;
  }
  return (_a = rules == null ? void 0 : rules.resolve(fn)) != null ? _a : toRef(fn);
}
const makeValidationProps = propsFactory({
  disabled: {
    type: Boolean,
    default: null
  },
  error: Boolean,
  errorMessages: {
    type: [Array, String],
    default: () => []
  },
  maxErrors: {
    type: [Number, String],
    default: 1
  },
  name: String,
  label: String,
  readonly: {
    type: Boolean,
    default: null
  },
  rules: {
    type: Array,
    default: () => []
  },
  modelValue: null,
  validateOn: String,
  validationValue: null,
  ...makeFocusProps()
}, "validation");
function useValidation(props) {
  let name = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : getCurrentInstanceName();
  let id = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : useId();
  const model = useProxiedModel(props, "modelValue");
  const validationModel = computed(() => props.validationValue === void 0 ? model.value : props.validationValue);
  const form = useForm(props);
  const rules = useRules(() => props.rules);
  const internalErrorMessages = ref([]);
  const isPristine = shallowRef(true);
  const isDirty = computed(() => !!(wrapInArray(model.value === "" ? null : model.value).length || wrapInArray(validationModel.value === "" ? null : validationModel.value).length));
  const errorMessages = computed(() => {
    var _a;
    return ((_a = props.errorMessages) == null ? void 0 : _a.length) ? wrapInArray(props.errorMessages).concat(internalErrorMessages.value).slice(0, Math.max(0, Number(props.maxErrors))) : internalErrorMessages.value;
  });
  const validateOn = computed(() => {
    var _a, _b, _c;
    let value = ((_b = props.validateOn) != null ? _b : (_a = form.validateOn) == null ? void 0 : _a.value) || "input";
    if (value === "lazy") value = "input lazy";
    if (value === "eager") value = "input eager";
    const set = new Set((_c = value == null ? void 0 : value.split(" ")) != null ? _c : []);
    return {
      input: set.has("input"),
      blur: set.has("blur") || set.has("input") || set.has("invalid-input"),
      invalidInput: set.has("invalid-input"),
      lazy: set.has("lazy"),
      eager: set.has("eager")
    };
  });
  const isValid = computed(() => {
    var _a;
    if (props.error || ((_a = props.errorMessages) == null ? void 0 : _a.length)) return false;
    if (!props.rules.length) return true;
    if (isPristine.value) {
      return internalErrorMessages.value.length || validateOn.value.lazy ? null : true;
    } else {
      return !internalErrorMessages.value.length;
    }
  });
  const isValidating = shallowRef(false);
  const validationClasses = computed(() => {
    return {
      [`${name}--error`]: isValid.value === false,
      [`${name}--dirty`]: isDirty.value,
      [`${name}--disabled`]: form.isDisabled.value,
      [`${name}--readonly`]: form.isReadonly.value
    };
  });
  getCurrentInstance$1("validation");
  const uid = computed(() => {
    var _a;
    return (_a = props.name) != null ? _a : unref(id);
  });
  useToggleScope(() => validateOn.value.input || validateOn.value.invalidInput && isValid.value === false, () => {
    watch(validationModel, () => {
      if (validationModel.value != null) {
        validate();
      } else if (props.focused) {
        const unwatch = watch(() => props.focused, (val) => {
          if (!val) validate();
          unwatch();
        });
      }
    });
  });
  useToggleScope(() => validateOn.value.blur, () => {
    watch(() => props.focused, (val) => {
      if (!val) validate();
    });
  });
  watch([isValid, errorMessages], () => {
    var _a;
    (_a = form.update) == null ? void 0 : _a.call(form, uid.value, isValid.value, errorMessages.value);
  });
  async function reset() {
    model.value = null;
    await nextTick();
    await resetValidation();
  }
  async function resetValidation() {
    isPristine.value = true;
    if (!validateOn.value.lazy) {
      await validate(!validateOn.value.eager);
    } else {
      internalErrorMessages.value = [];
    }
  }
  async function validate() {
    var _a;
    let silent = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : false;
    const results = [];
    isValidating.value = true;
    for (const rule of rules.value) {
      if (results.length >= Number((_a = props.maxErrors) != null ? _a : 1)) {
        break;
      }
      const handler = typeof rule === "function" ? rule : () => rule;
      const result = await handler(validationModel.value);
      if (result === true) continue;
      if (result !== false && typeof result !== "string") {
        console.warn(`${result} is not a valid value. Rule functions must return boolean true or a string.`);
        continue;
      }
      results.push(result || "");
    }
    internalErrorMessages.value = results;
    isValidating.value = false;
    isPristine.value = silent;
    return internalErrorMessages.value;
  }
  return {
    errorMessages,
    isDirty,
    isDisabled: form.isDisabled,
    isReadonly: form.isReadonly,
    isPristine,
    isValid,
    isValidating,
    reset,
    resetValidation,
    validate,
    validationClasses
  };
}
const makeVInputProps = propsFactory({
  id: String,
  appendIcon: IconValue,
  baseColor: String,
  centerAffix: {
    type: Boolean,
    default: true
  },
  color: String,
  glow: Boolean,
  iconColor: [Boolean, String],
  prependIcon: IconValue,
  hideDetails: [Boolean, String],
  hideSpinButtons: Boolean,
  hint: String,
  persistentHint: Boolean,
  messages: {
    type: [Array, String],
    default: () => []
  },
  direction: {
    type: String,
    default: "horizontal",
    validator: (v) => ["horizontal", "vertical"].includes(v)
  },
  "onClick:prepend": EventProp(),
  "onClick:append": EventProp(),
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...pick(makeDimensionProps(), ["maxWidth", "minWidth", "width"]),
  ...makeThemeProps(),
  ...makeValidationProps()
}, "VInput");
const VInput = genericComponent()({
  name: "VInput",
  props: {
    ...makeVInputProps()
  },
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      slots,
      emit
    } = _ref;
    const {
      densityClasses
    } = useDensity(props);
    const {
      dimensionStyles
    } = useDimension(props);
    const {
      themeClasses
    } = provideTheme(props);
    const {
      rtlClasses
    } = useRtl();
    const {
      InputIcon
    } = useInputIcon(props);
    const uid = useId();
    const id = computed(() => props.id || `input-${uid}`);
    const {
      errorMessages,
      isDirty,
      isDisabled,
      isReadonly,
      isPristine,
      isValid,
      isValidating,
      reset,
      resetValidation,
      validate,
      validationClasses
    } = useValidation(props, "v-input", id);
    const messages = computed(() => {
      var _a;
      if (((_a = props.errorMessages) == null ? void 0 : _a.length) || !isPristine.value && errorMessages.value.length) {
        return errorMessages.value;
      } else if (props.hint && (props.persistentHint || props.focused)) {
        return props.hint;
      } else {
        return props.messages;
      }
    });
    const hasMessages = toRef(() => messages.value.length > 0);
    const hasDetails = toRef(() => !props.hideDetails || props.hideDetails === "auto" && (hasMessages.value || !!slots.details));
    const messagesId = computed(() => hasDetails.value ? `${id.value}-messages` : void 0);
    const slotProps = computed(() => ({
      id,
      messagesId,
      isDirty,
      isDisabled,
      isReadonly,
      isPristine,
      isValid,
      isValidating,
      hasDetails,
      reset,
      resetValidation,
      validate
    }));
    const color = toRef(() => {
      return props.error || props.disabled ? void 0 : props.focused ? props.color : props.baseColor;
    });
    const iconColor = toRef(() => {
      if (!props.iconColor) return void 0;
      return props.iconColor === true ? color.value : props.iconColor;
    });
    useRender(() => {
      var _a, _b;
      const hasPrepend = !!(slots.prepend || props.prependIcon);
      const hasAppend = !!(slots.append || props.appendIcon);
      return createElementVNode("div", {
        "class": normalizeClass(["v-input", `v-input--${props.direction}`, {
          "v-input--center-affix": props.centerAffix,
          "v-input--focused": props.focused,
          "v-input--glow": props.glow,
          "v-input--hide-spin-buttons": props.hideSpinButtons
        }, densityClasses.value, themeClasses.value, rtlClasses.value, validationClasses.value, props.class]),
        "style": normalizeStyle([dimensionStyles.value, props.style])
      }, [hasPrepend && createElementVNode("div", {
        "key": "prepend",
        "class": "v-input__prepend"
      }, [slots.prepend ? slots.prepend(slotProps.value) : props.prependIcon && createVNode(InputIcon, {
        "key": "prepend-icon",
        "name": "prepend",
        "color": iconColor.value
      }, null)]), slots.default && createElementVNode("div", {
        "class": "v-input__control"
      }, [(_a = slots.default) == null ? void 0 : _a.call(slots, slotProps.value)]), hasAppend && createElementVNode("div", {
        "key": "append",
        "class": "v-input__append"
      }, [slots.append ? slots.append(slotProps.value) : props.appendIcon && createVNode(InputIcon, {
        "key": "append-icon",
        "name": "append",
        "color": iconColor.value
      }, null)]), hasDetails.value && createElementVNode("div", {
        "id": messagesId.value,
        "class": "v-input__details",
        "role": "alert",
        "aria-live": "polite"
      }, [createVNode(VMessages, {
        "active": hasMessages.value,
        "messages": messages.value
      }, {
        message: slots.message
      }), (_b = slots.details) == null ? void 0 : _b.call(slots, slotProps.value)])]);
    });
    return {
      reset,
      resetValidation,
      validate,
      isValid,
      errorMessages
    };
  }
});
const Refs = /* @__PURE__ */ Symbol("Forwarded refs");
function getDescriptor(obj, key) {
  let currentObj = obj;
  while (currentObj) {
    const descriptor = Reflect.getOwnPropertyDescriptor(currentObj, key);
    if (descriptor) return descriptor;
    currentObj = Object.getPrototypeOf(currentObj);
  }
  return void 0;
}
function forwardRefs(target) {
  for (var _len = arguments.length, refs = new Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
    refs[_key - 1] = arguments[_key];
  }
  target[Refs] = refs;
  return new Proxy(target, {
    get(target2, key) {
      if (Reflect.has(target2, key)) {
        return Reflect.get(target2, key);
      }
      if (typeof key === "symbol" || key.startsWith("$") || key.startsWith("__")) return;
      for (const ref2 of refs) {
        if (ref2.value && Reflect.has(ref2.value, key)) {
          const val = Reflect.get(ref2.value, key);
          return typeof val === "function" ? val.bind(ref2.value) : val;
        }
      }
    },
    has(target2, key) {
      if (Reflect.has(target2, key)) {
        return true;
      }
      if (typeof key === "symbol" || key.startsWith("$") || key.startsWith("__")) return false;
      for (const ref2 of refs) {
        if (ref2.value && Reflect.has(ref2.value, key)) {
          return true;
        }
      }
      return false;
    },
    set(target2, key, value) {
      if (Reflect.has(target2, key)) {
        return Reflect.set(target2, key, value);
      }
      if (typeof key === "symbol" || key.startsWith("$") || key.startsWith("__")) return false;
      for (const ref2 of refs) {
        if (ref2.value && Reflect.has(ref2.value, key)) {
          return Reflect.set(ref2.value, key, value);
        }
      }
      return false;
    },
    getOwnPropertyDescriptor(target2, key) {
      var _a, _b;
      const descriptor = Reflect.getOwnPropertyDescriptor(target2, key);
      if (descriptor) return descriptor;
      if (typeof key === "symbol" || key.startsWith("$") || key.startsWith("__")) return;
      for (const ref2 of refs) {
        if (!ref2.value) continue;
        const descriptor2 = (_b = getDescriptor(ref2.value, key)) != null ? _b : "_" in ref2.value ? getDescriptor((_a = ref2.value._) == null ? void 0 : _a.setupState, key) : void 0;
        if (descriptor2) return descriptor2;
      }
      for (const ref2 of refs) {
        const childRefs = ref2.value && ref2.value[Refs];
        if (!childRefs) continue;
        const queue = childRefs.slice();
        while (queue.length) {
          const ref3 = queue.shift();
          const descriptor2 = getDescriptor(ref3.value, key);
          if (descriptor2) return descriptor2;
          const childRefs2 = ref3.value && ref3.value[Refs];
          if (childRefs2) queue.push(...childRefs2);
        }
      }
      return void 0;
    }
  });
}
function calculateUpdatedTarget(_ref) {
  let {
    selectedElement,
    containerElement,
    isRtl,
    isHorizontal
  } = _ref;
  const containerSize = getOffsetSize(isHorizontal, containerElement);
  const scrollPosition = getScrollPosition(isHorizontal, isRtl, containerElement);
  const childrenSize = getOffsetSize(isHorizontal, selectedElement);
  const childrenStartPosition = getOffsetPosition(isHorizontal, selectedElement);
  const additionalOffset = childrenSize * 0.4;
  if (scrollPosition > childrenStartPosition) {
    return childrenStartPosition - additionalOffset;
  } else if (scrollPosition + containerSize < childrenStartPosition + childrenSize) {
    return childrenStartPosition - containerSize + childrenSize + additionalOffset;
  }
  return scrollPosition;
}
function getScrollSize(isHorizontal, element) {
  const key = isHorizontal ? "scrollWidth" : "scrollHeight";
  return (element == null ? void 0 : element[key]) || 0;
}
function getClientSize(isHorizontal, element) {
  const key = isHorizontal ? "clientWidth" : "clientHeight";
  return (element == null ? void 0 : element[key]) || 0;
}
function getScrollPosition(isHorizontal, rtl, element) {
  if (!element) {
    return 0;
  }
  const {
    scrollLeft,
    offsetWidth,
    scrollWidth
  } = element;
  if (isHorizontal) {
    return rtl ? scrollWidth - offsetWidth + scrollLeft : scrollLeft;
  }
  return element.scrollTop;
}
function getOffsetSize(isHorizontal, element) {
  const key = isHorizontal ? "offsetWidth" : "offsetHeight";
  return (element == null ? void 0 : element[key]) || 0;
}
function getOffsetPosition(isHorizontal, element) {
  const key = isHorizontal ? "offsetLeft" : "offsetTop";
  return (element == null ? void 0 : element[key]) || 0;
}
const VSlideGroupSymbol = /* @__PURE__ */ Symbol.for("vuetify:v-slide-group");
const makeVSlideGroupProps = propsFactory({
  centerActive: Boolean,
  scrollToActive: {
    type: Boolean,
    default: true
  },
  contentClass: null,
  direction: {
    type: String,
    default: "horizontal"
  },
  symbol: {
    type: null,
    default: VSlideGroupSymbol
  },
  nextIcon: {
    type: IconValue,
    default: "$next"
  },
  prevIcon: {
    type: IconValue,
    default: "$prev"
  },
  showArrows: {
    type: [Boolean, String],
    validator: (v) => typeof v === "boolean" || ["always", "desktop", "mobile", "never"].includes(v)
  },
  ...makeComponentProps(),
  ...makeDisplayProps({
    mobile: null
  }),
  ...makeTagProps(),
  ...makeGroupProps({
    selectedClass: "v-slide-group-item--active"
  })
}, "VSlideGroup");
const VSlideGroup = genericComponent()({
  name: "VSlideGroup",
  props: makeVSlideGroupProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      isRtl
    } = useRtl();
    const {
      displayClasses,
      mobile
    } = useDisplay(props);
    const group = useGroup(props, props.symbol);
    const isOverflowing = shallowRef(false);
    const scrollOffset = shallowRef(0);
    const containerSize = shallowRef(0);
    shallowRef(0);
    const isHorizontal = computed(() => props.direction === "horizontal");
    const {
      resizeRef: containerRef
    } = useResizeObserver();
    const {
      resizeRef: contentRef
    } = useResizeObserver();
    useGoTo();
    computed(() => {
      return {
        container: containerRef.el,
        duration: 200,
        easing: "easeOutQuart"
      };
    });
    computed(() => {
      if (!group.selected.value.length) return -1;
      return group.items.value.findIndex((item) => item.id === group.selected.value[0]);
    });
    computed(() => {
      if (!group.selected.value.length) return -1;
      return group.items.value.findIndex((item) => item.id === group.selected.value[group.selected.value.length - 1]);
    });
    const isFocused = shallowRef(false);
    function scrollToChildren(children, center) {
      {
        calculateUpdatedTarget({
          containerElement: containerRef.el,
          isHorizontal: isHorizontal.value,
          isRtl: isRtl.value,
          selectedElement: children
        });
      }
    }
    function onScroll(e) {
      const {
        scrollTop,
        scrollLeft
      } = e.target;
      scrollOffset.value = isHorizontal.value ? scrollLeft : scrollTop;
    }
    function onFocusin(e) {
      isFocused.value = true;
      if (!isOverflowing.value || !contentRef.el) return;
      for (const el of e.composedPath()) {
        for (const item of contentRef.el.children) {
          if (item === el) {
            scrollToChildren(item);
            return;
          }
        }
      }
    }
    function onFocusout(e) {
      isFocused.value = false;
    }
    let ignoreFocusEvent = false;
    function onFocus(e) {
      var _a;
      if (!ignoreFocusEvent && !isFocused.value && !(e.relatedTarget && ((_a = contentRef.el) == null ? void 0 : _a.contains(e.relatedTarget)))) focus();
      ignoreFocusEvent = false;
    }
    function onFocusAffixes() {
      ignoreFocusEvent = true;
    }
    function onKeydown2(e) {
      if (!contentRef.el) return;
      function toFocus(location) {
        e.preventDefault();
        focus(location);
      }
      if (isHorizontal.value) {
        if (e.key === "ArrowRight") {
          toFocus(isRtl.value ? "prev" : "next");
        } else if (e.key === "ArrowLeft") {
          toFocus(isRtl.value ? "next" : "prev");
        }
      } else {
        if (e.key === "ArrowDown") {
          toFocus("next");
        } else if (e.key === "ArrowUp") {
          toFocus("prev");
        }
      }
      if (e.key === "Home") {
        toFocus("first");
      } else if (e.key === "End") {
        toFocus("last");
      }
    }
    function getSiblingElement(el, location) {
      if (!el) return void 0;
      let sibling = el;
      do {
        sibling = sibling == null ? void 0 : sibling[location === "next" ? "nextElementSibling" : "previousElementSibling"];
      } while (sibling == null ? void 0 : sibling.hasAttribute("disabled"));
      return sibling;
    }
    function focus(location) {
      if (!contentRef.el) return;
      let el;
      if (!location) {
        const focusable = focusableChildren(contentRef.el);
        el = focusable[0];
      } else if (location === "next") {
        el = getSiblingElement(contentRef.el.querySelector(":focus"), location);
        if (!el) return focus("first");
      } else if (location === "prev") {
        el = getSiblingElement(contentRef.el.querySelector(":focus"), location);
        if (!el) return focus("last");
      } else if (location === "first") {
        el = contentRef.el.firstElementChild;
        if (el == null ? void 0 : el.hasAttribute("disabled")) el = getSiblingElement(el, "next");
      } else if (location === "last") {
        el = contentRef.el.lastElementChild;
        if (el == null ? void 0 : el.hasAttribute("disabled")) el = getSiblingElement(el, "prev");
      }
      if (el) {
        el.focus({
          preventScroll: true
        });
      }
    }
    function scrollTo(location) {
      const direction = isHorizontal.value && isRtl.value ? -1 : 1;
      const offsetStep = (location === "prev" ? -direction : direction) * containerSize.value;
      scrollOffset.value + offsetStep;
      if (isHorizontal.value && isRtl.value && containerRef.el) {
        const {
          scrollWidth,
          offsetWidth: containerWidth
        } = containerRef.el;
      }
    }
    const slotProps = computed(() => ({
      next: group.next,
      prev: group.prev,
      select: group.select,
      isSelected: group.isSelected
    }));
    const hasOverflowOrScroll = computed(() => isOverflowing.value || Math.abs(scrollOffset.value) > 0);
    const hasAffixes = computed(() => {
      switch (props.showArrows) {
        case "never":
          return false;
        // Always show arrows on desktop & mobile
        case "always":
          return true;
        // Always show arrows on desktop
        case "desktop":
          return !mobile.value;
        // Show arrows on mobile when overflowing.
        // This matches the default 2.2 behavior
        case true:
          return hasOverflowOrScroll.value;
        // Always show on mobile
        case "mobile":
          return mobile.value || hasOverflowOrScroll.value;
        // https://material.io/components/tabs#scrollable-tabs
        // Always show arrows when
        // overflowed on desktop
        default:
          return !mobile.value && hasOverflowOrScroll.value;
      }
    });
    const hasPrev = computed(() => {
      return Math.abs(scrollOffset.value) > 1;
    });
    const hasNext = computed(() => {
      if (!containerRef.value || !hasOverflowOrScroll.value) return false;
      const scrollSize = getScrollSize(isHorizontal.value, containerRef.el);
      const clientSize = getClientSize(isHorizontal.value, containerRef.el);
      const scrollSizeMax = scrollSize - clientSize;
      return scrollSizeMax - Math.abs(scrollOffset.value) > 1;
    });
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-slide-group", {
        "v-slide-group--vertical": !isHorizontal.value,
        "v-slide-group--has-affixes": hasAffixes.value,
        "v-slide-group--is-overflowing": isOverflowing.value
      }, displayClasses.value, props.class]),
      "style": normalizeStyle(props.style),
      "tabindex": isFocused.value || group.selected.value.length ? -1 : 0,
      "onFocus": onFocus
    }, {
      default: () => {
        var _a, _b, _c, _d, _e;
        return [hasAffixes.value && createElementVNode("div", {
          "key": "prev",
          "class": normalizeClass(["v-slide-group__prev", {
            "v-slide-group__prev--disabled": !hasPrev.value
          }]),
          "onMousedown": onFocusAffixes,
          "onClick": () => hasPrev.value && scrollTo("prev")
        }, [(_b = (_a = slots.prev) == null ? void 0 : _a.call(slots, slotProps.value)) != null ? _b : createVNode(VFadeTransition, null, {
          default: () => [createVNode(VIcon, {
            "icon": isRtl.value ? props.nextIcon : props.prevIcon
          }, null)]
        })]), createElementVNode("div", {
          "key": "container",
          "ref": containerRef,
          "class": normalizeClass(["v-slide-group__container", props.contentClass]),
          "onScroll": onScroll
        }, [createElementVNode("div", {
          "ref": contentRef,
          "class": "v-slide-group__content",
          "onFocusin": onFocusin,
          "onFocusout": onFocusout,
          "onKeydown": onKeydown2
        }, [(_c = slots.default) == null ? void 0 : _c.call(slots, slotProps.value)])]), hasAffixes.value && createElementVNode("div", {
          "key": "next",
          "class": normalizeClass(["v-slide-group__next", {
            "v-slide-group__next--disabled": !hasNext.value
          }]),
          "onMousedown": onFocusAffixes,
          "onClick": () => hasNext.value && scrollTo("next")
        }, [(_e = (_d = slots.next) == null ? void 0 : _d.call(slots, slotProps.value)) != null ? _e : createVNode(VFadeTransition, null, {
          default: () => [createVNode(VIcon, {
            "icon": isRtl.value ? props.prevIcon : props.nextIcon
          }, null)]
        })])];
      }
    }));
    return {
      selected: group.selected,
      scrollTo,
      scrollOffset,
      focus,
      hasPrev,
      hasNext
    };
  }
});
const VChipGroupSymbol = /* @__PURE__ */ Symbol.for("vuetify:v-chip-group");
const makeVChipGroupProps = propsFactory({
  baseColor: String,
  column: Boolean,
  filter: Boolean,
  valueComparator: {
    type: Function,
    default: deepEqual
  },
  ...makeVSlideGroupProps({
    scrollToActive: false
  }),
  ...makeComponentProps(),
  ...makeGroupProps({
    selectedClass: "v-chip--selected"
  }),
  ...makeTagProps(),
  ...makeThemeProps(),
  ...makeVariantProps({
    variant: "tonal"
  })
}, "VChipGroup");
genericComponent()({
  name: "VChipGroup",
  props: makeVChipGroupProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      themeClasses
    } = provideTheme(props);
    const {
      isSelected,
      select,
      next,
      prev,
      selected
    } = useGroup(props, VChipGroupSymbol);
    provideDefaults({
      VChip: {
        baseColor: toRef(() => props.baseColor),
        color: toRef(() => props.color),
        disabled: toRef(() => props.disabled),
        filter: toRef(() => props.filter),
        variant: toRef(() => props.variant)
      }
    });
    useRender(() => {
      const slideGroupProps = VSlideGroup.filterProps(props);
      return createVNode(VSlideGroup, mergeProps(slideGroupProps, {
        "class": ["v-chip-group", {
          "v-chip-group--column": props.column
        }, themeClasses.value, props.class],
        "style": props.style
      }), {
        default: () => {
          var _a;
          return [(_a = slots.default) == null ? void 0 : _a.call(slots, {
            isSelected,
            select,
            next,
            prev,
            selected: selected.value
          })];
        }
      });
    });
    return {};
  }
});
const makeVChipProps = propsFactory({
  activeClass: String,
  appendAvatar: String,
  appendIcon: IconValue,
  baseColor: String,
  closable: Boolean,
  closeIcon: {
    type: IconValue,
    default: "$delete"
  },
  closeLabel: {
    type: String,
    default: "$vuetify.close"
  },
  draggable: Boolean,
  filter: Boolean,
  filterIcon: {
    type: IconValue,
    default: "$complete"
  },
  label: Boolean,
  link: {
    type: Boolean,
    default: void 0
  },
  pill: Boolean,
  prependAvatar: String,
  prependIcon: IconValue,
  ripple: {
    type: [Boolean, Object],
    default: true
  },
  text: {
    type: [String, Number, Boolean],
    default: void 0
  },
  modelValue: {
    type: Boolean,
    default: true
  },
  onClick: EventProp(),
  onClickOnce: EventProp(),
  ...makeBorderProps(),
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...makeElevationProps(),
  ...makeGroupItemProps(),
  ...makeRoundedProps(),
  ...makeRouterProps(),
  ...makeSizeProps(),
  ...makeTagProps({
    tag: "span"
  }),
  ...makeThemeProps(),
  ...makeVariantProps({
    variant: "tonal"
  })
}, "VChip");
const VChip = genericComponent()({
  name: "VChip",
  directives: {
    vRipple: Ripple
  },
  props: makeVChipProps(),
  emits: {
    "click:close": (e) => true,
    "update:modelValue": (value) => true,
    "group:selected": (val) => true,
    click: (e) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      emit,
      slots
    } = _ref;
    const {
      t
    } = useLocale();
    const {
      borderClasses
    } = useBorder(props);
    const {
      densityClasses
    } = useDensity(props);
    const {
      elevationClasses
    } = useElevation(props);
    const {
      roundedClasses
    } = useRounded(props);
    const {
      sizeClasses
    } = useSize(props);
    const {
      themeClasses
    } = provideTheme(props);
    const isActive = useProxiedModel(props, "modelValue");
    const group = useGroupItem(props, VChipGroupSymbol, false);
    const slideGroup = useGroupItem(props, VSlideGroupSymbol, false);
    const link = useLink(props, attrs);
    const isLink = toRef(() => props.link !== false && link.isLink.value);
    const isClickable = computed(() => !props.disabled && props.link !== false && (!!group || props.link || link.isClickable.value));
    const closeProps = toRef(() => ({
      "aria-label": t(props.closeLabel),
      disabled: props.disabled,
      onClick(e) {
        e.preventDefault();
        e.stopPropagation();
        isActive.value = false;
        emit("click:close", e);
      }
    }));
    watch(isActive, (val) => {
      if (val) {
        group == null ? void 0 : group.register();
        slideGroup == null ? void 0 : slideGroup.register();
      } else {
        group == null ? void 0 : group.unregister();
        slideGroup == null ? void 0 : slideGroup.unregister();
      }
    });
    const {
      colorClasses,
      colorStyles,
      variantClasses
    } = useVariant(() => {
      var _a;
      const showColor = !group || group.isSelected.value;
      return {
        color: showColor ? (_a = props.color) != null ? _a : props.baseColor : props.baseColor,
        variant: props.variant
      };
    });
    function onClick(e) {
      var _a, _b;
      emit("click", e);
      if (!isClickable.value) return;
      (_b = (_a = link.navigate).value) == null ? void 0 : _b.call(_a, e);
      group == null ? void 0 : group.toggle();
    }
    function onKeyDown(e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onClick(e);
      }
    }
    return () => {
      var _a;
      const Tag = link.isLink.value ? "a" : props.tag;
      const hasAppendMedia = !!(props.appendIcon || props.appendAvatar);
      const hasAppend = !!(hasAppendMedia || slots.append);
      const hasClose = !!(slots.close || props.closable);
      const hasFilter = !!(slots.filter || props.filter) && group;
      const hasPrependMedia = !!(props.prependIcon || props.prependAvatar);
      const hasPrepend = !!(hasPrependMedia || slots.prepend);
      return isActive.value && withDirectives(createVNode(Tag, mergeProps(link.linkProps, {
        "class": ["v-chip", {
          "v-chip--disabled": props.disabled,
          "v-chip--label": props.label,
          "v-chip--link": isClickable.value,
          "v-chip--filter": hasFilter,
          "v-chip--pill": props.pill,
          [`${props.activeClass}`]: props.activeClass && ((_a = link.isActive) == null ? void 0 : _a.value)
        }, themeClasses.value, borderClasses.value, colorClasses.value, densityClasses.value, elevationClasses.value, roundedClasses.value, sizeClasses.value, variantClasses.value, group == null ? void 0 : group.selectedClass.value, props.class],
        "style": [colorStyles.value, props.style],
        "disabled": props.disabled || void 0,
        "draggable": props.draggable,
        "tabindex": isClickable.value ? 0 : void 0,
        "onClick": onClick,
        "onKeydown": isClickable.value && !isLink.value && onKeyDown
      }), {
        default: () => {
          var _a2, _b;
          return [genOverlays(isClickable.value, "v-chip"), hasFilter && createVNode(VExpandXTransition, {
            "key": "filter"
          }, {
            default: () => [withDirectives(createElementVNode("div", {
              "class": "v-chip__filter"
            }, [!slots.filter ? createVNode(VIcon, {
              "key": "filter-icon",
              "icon": props.filterIcon
            }, null) : createVNode(VDefaultsProvider, {
              "key": "filter-defaults",
              "disabled": !props.filterIcon,
              "defaults": {
                VIcon: {
                  icon: props.filterIcon
                }
              }
            }, slots.filter)]), [[vShow, group.isSelected.value]])]
          }), hasPrepend && createElementVNode("div", {
            "key": "prepend",
            "class": "v-chip__prepend"
          }, [!slots.prepend ? createElementVNode(Fragment, null, [props.prependIcon && createVNode(VIcon, {
            "key": "prepend-icon",
            "icon": props.prependIcon,
            "start": true
          }, null), props.prependAvatar && createVNode(VAvatar, {
            "key": "prepend-avatar",
            "image": props.prependAvatar,
            "start": true
          }, null)]) : createVNode(VDefaultsProvider, {
            "key": "prepend-defaults",
            "disabled": !hasPrependMedia,
            "defaults": {
              VAvatar: {
                image: props.prependAvatar,
                start: true
              },
              VIcon: {
                icon: props.prependIcon,
                start: true
              }
            }
          }, slots.prepend)]), createElementVNode("div", {
            "class": "v-chip__content",
            "data-no-activator": ""
          }, [(_b = (_a2 = slots.default) == null ? void 0 : _a2.call(slots, {
            isSelected: group == null ? void 0 : group.isSelected.value,
            selectedClass: group == null ? void 0 : group.selectedClass.value,
            select: group == null ? void 0 : group.select,
            toggle: group == null ? void 0 : group.toggle,
            value: group == null ? void 0 : group.value.value,
            disabled: props.disabled
          })) != null ? _b : toDisplayString(props.text)]), hasAppend && createElementVNode("div", {
            "key": "append",
            "class": "v-chip__append"
          }, [!slots.append ? createElementVNode(Fragment, null, [props.appendIcon && createVNode(VIcon, {
            "key": "append-icon",
            "end": true,
            "icon": props.appendIcon
          }, null), props.appendAvatar && createVNode(VAvatar, {
            "key": "append-avatar",
            "end": true,
            "image": props.appendAvatar
          }, null)]) : createVNode(VDefaultsProvider, {
            "key": "append-defaults",
            "disabled": !hasAppendMedia,
            "defaults": {
              VAvatar: {
                end: true,
                image: props.appendAvatar
              },
              VIcon: {
                end: true,
                icon: props.appendIcon
              }
            }
          }, slots.append)]), hasClose && createElementVNode("button", mergeProps({
            "key": "close",
            "class": "v-chip__close",
            "type": "button",
            "data-testid": "close-chip"
          }, closeProps.value), [!slots.close ? createVNode(VIcon, {
            "key": "close-icon",
            "icon": props.closeIcon,
            "size": "x-small"
          }, null) : createVNode(VDefaultsProvider, {
            "key": "close-defaults",
            "defaults": {
              VIcon: {
                icon: props.closeIcon,
                size: "x-small"
              }
            }
          }, slots.close)])];
        }
      }), [[Ripple, isClickable.value && props.ripple, null]]);
    };
  }
});
const allowedVariants$1 = ["dotted", "dashed", "solid", "double"];
const makeVDividerProps = propsFactory({
  color: String,
  contentOffset: [Number, String, Array],
  gradient: Boolean,
  inset: Boolean,
  length: [Number, String],
  opacity: [Number, String],
  thickness: [Number, String],
  vertical: Boolean,
  variant: {
    type: String,
    default: "solid",
    validator: (v) => allowedVariants$1.includes(v)
  },
  ...makeComponentProps(),
  ...makeThemeProps()
}, "VDivider");
const VDivider = genericComponent()({
  name: "VDivider",
  props: makeVDividerProps(),
  setup(props, _ref) {
    let {
      attrs,
      slots
    } = _ref;
    const {
      themeClasses
    } = provideTheme(props);
    const {
      textColorClasses,
      textColorStyles
    } = useTextColor(() => props.color);
    const dividerStyles = computed(() => {
      const styles = {};
      if (props.length) {
        styles[props.vertical ? "height" : "width"] = convertToUnit(props.length);
      }
      if (props.thickness) {
        styles[props.vertical ? "borderRightWidth" : "borderTopWidth"] = convertToUnit(props.thickness);
      }
      return styles;
    });
    const contentStyles = toRef(() => {
      const margin = Array.isArray(props.contentOffset) ? props.contentOffset[0] : props.contentOffset;
      const shift = Array.isArray(props.contentOffset) ? props.contentOffset[1] : 0;
      return {
        marginBlock: props.vertical && margin ? convertToUnit(margin) : void 0,
        marginInline: !props.vertical && margin ? convertToUnit(margin) : void 0,
        transform: shift ? `translate${props.vertical ? "X" : "Y"}(${convertToUnit(shift)})` : void 0
      };
    });
    useRender(() => {
      const divider = createElementVNode("hr", {
        "class": normalizeClass([{
          "v-divider": true,
          "v-divider--gradient": props.gradient && !slots.default,
          "v-divider--inset": props.inset,
          "v-divider--vertical": props.vertical
        }, themeClasses.value, textColorClasses.value, props.class]),
        "style": normalizeStyle([dividerStyles.value, textColorStyles.value, {
          "--v-border-opacity": props.opacity
        }, {
          "border-style": props.variant
        }, props.style]),
        "aria-orientation": !attrs.role || attrs.role === "separator" ? props.vertical ? "vertical" : "horizontal" : void 0,
        "role": `${attrs.role || "separator"}`
      }, null);
      if (!slots.default) return divider;
      return createElementVNode("div", {
        "class": normalizeClass(["v-divider__wrapper", {
          "v-divider__wrapper--gradient": props.gradient,
          "v-divider__wrapper--inset": props.inset,
          "v-divider__wrapper--vertical": props.vertical
        }])
      }, [divider, createElementVNode("div", {
        "class": "v-divider__content",
        "style": normalizeStyle(contentStyles.value)
      }, [slots.default()]), divider]);
    });
    return {};
  }
});
const ListKey = /* @__PURE__ */ Symbol.for("vuetify:list");
function createList() {
  let options = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : {
    filterable: false
  };
  const parent = inject(ListKey, {
    filterable: false,
    hasPrepend: shallowRef(false),
    updateHasPrepend: () => null,
    trackingIndex: shallowRef(-1),
    navigationStrategy: shallowRef("focus"),
    uid: ""
  });
  const {
    filterable,
    trackingIndex = parent.trackingIndex,
    navigationStrategy = parent.navigationStrategy,
    uid = parent.uid || useId()
  } = options;
  const data = {
    filterable: parent.filterable || filterable,
    hasPrepend: shallowRef(false),
    updateHasPrepend: (value) => {
      if (value) data.hasPrepend.value = value;
    },
    trackingIndex,
    navigationStrategy,
    uid
  };
  provide(ListKey, data);
  return parent;
}
function useList() {
  return inject(ListKey, null);
}
const independentActiveStrategy = (mandatory) => {
  const strategy = {
    activate: (_ref) => {
      let {
        id,
        value,
        activated
      } = _ref;
      id = toRaw(id);
      if (mandatory && !value && activated.size === 1 && activated.has(id)) return activated;
      if (value) {
        activated.add(id);
      } else {
        activated.delete(id);
      }
      return activated;
    },
    in: (v, children, parents) => {
      let set = /* @__PURE__ */ new Set();
      if (v != null) {
        for (const id of wrapInArray(v)) {
          set = strategy.activate({
            id,
            value: true,
            activated: new Set(set),
            children,
            parents
          });
        }
      }
      return set;
    },
    out: (v) => {
      return Array.from(v);
    }
  };
  return strategy;
};
const independentSingleActiveStrategy = (mandatory) => {
  const parentStrategy = independentActiveStrategy(mandatory);
  const strategy = {
    activate: (_ref2) => {
      let {
        activated,
        id,
        ...rest
      } = _ref2;
      id = toRaw(id);
      const singleSelected = activated.has(id) ? /* @__PURE__ */ new Set([id]) : /* @__PURE__ */ new Set();
      return parentStrategy.activate({
        ...rest,
        id,
        activated: singleSelected
      });
    },
    in: (v, children, parents) => {
      let set = /* @__PURE__ */ new Set();
      if (v != null) {
        const arr = wrapInArray(v);
        if (arr.length) {
          set = parentStrategy.in(arr.slice(0, 1), children, parents);
        }
      }
      return set;
    },
    out: (v, children, parents) => {
      return parentStrategy.out(v, children, parents);
    }
  };
  return strategy;
};
const leafActiveStrategy = (mandatory) => {
  const parentStrategy = independentActiveStrategy(mandatory);
  const strategy = {
    activate: (_ref3) => {
      let {
        id,
        activated,
        children,
        ...rest
      } = _ref3;
      id = toRaw(id);
      if (children.has(id)) return activated;
      return parentStrategy.activate({
        id,
        activated,
        children,
        ...rest
      });
    },
    in: parentStrategy.in,
    out: parentStrategy.out
  };
  return strategy;
};
const leafSingleActiveStrategy = (mandatory) => {
  const parentStrategy = independentSingleActiveStrategy(mandatory);
  const strategy = {
    activate: (_ref4) => {
      let {
        id,
        activated,
        children,
        ...rest
      } = _ref4;
      id = toRaw(id);
      if (children.has(id)) return activated;
      return parentStrategy.activate({
        id,
        activated,
        children,
        ...rest
      });
    },
    in: parentStrategy.in,
    out: parentStrategy.out
  };
  return strategy;
};
const singleOpenStrategy = {
  open: (_ref) => {
    let {
      id,
      value,
      opened,
      parents
    } = _ref;
    if (value) {
      const newOpened = /* @__PURE__ */ new Set();
      newOpened.add(id);
      let parent = parents.get(id);
      while (parent != null) {
        newOpened.add(parent);
        parent = parents.get(parent);
      }
      return newOpened;
    } else {
      opened.delete(id);
      return opened;
    }
  },
  select: () => null
};
const multipleOpenStrategy = {
  open: (_ref2) => {
    let {
      id,
      value,
      opened,
      parents
    } = _ref2;
    if (value) {
      let parent = parents.get(id);
      opened.add(id);
      while (parent != null && parent !== id) {
        opened.add(parent);
        parent = parents.get(parent);
      }
      return opened;
    } else {
      opened.delete(id);
    }
    return opened;
  },
  select: () => null
};
const listOpenStrategy = {
  open: multipleOpenStrategy.open,
  select: (_ref3) => {
    let {
      id,
      value,
      opened,
      parents
    } = _ref3;
    if (!value) return opened;
    const path = [];
    let parent = parents.get(id);
    while (parent != null) {
      path.push(parent);
      parent = parents.get(parent);
    }
    return new Set(path);
  }
};
const independentSelectStrategy = (mandatory) => {
  const strategy = {
    select: (_ref) => {
      let {
        id,
        value,
        selected
      } = _ref;
      id = toRaw(id);
      if (mandatory && !value) {
        const on = Array.from(selected.entries()).reduce((arr, _ref2) => {
          let [key, value2] = _ref2;
          if (value2 === "on") arr.push(key);
          return arr;
        }, []);
        if (on.length === 1 && on[0] === id) return selected;
      }
      selected.set(id, value ? "on" : "off");
      return selected;
    },
    in: (v, children, parents, disabled) => {
      const map = /* @__PURE__ */ new Map();
      for (const id of v || []) {
        strategy.select({
          id,
          value: true,
          selected: map,
          children,
          parents,
          disabled
        });
      }
      return map;
    },
    out: (v) => {
      const arr = [];
      for (const [key, value] of v.entries()) {
        if (value === "on") arr.push(key);
      }
      return arr;
    }
  };
  return strategy;
};
const independentSingleSelectStrategy = (mandatory) => {
  const parentStrategy = independentSelectStrategy(mandatory);
  const strategy = {
    select: (_ref3) => {
      let {
        selected,
        id,
        ...rest
      } = _ref3;
      id = toRaw(id);
      const singleSelected = selected.has(id) ? /* @__PURE__ */ new Map([[id, selected.get(id)]]) : /* @__PURE__ */ new Map();
      return parentStrategy.select({
        ...rest,
        id,
        selected: singleSelected
      });
    },
    in: (v, children, parents, disabled) => {
      if (v == null ? void 0 : v.length) {
        return parentStrategy.in(v.slice(0, 1), children, parents, disabled);
      }
      return /* @__PURE__ */ new Map();
    },
    out: (v, children, parents) => {
      return parentStrategy.out(v, children, parents);
    }
  };
  return strategy;
};
const leafSelectStrategy = (mandatory) => {
  const parentStrategy = independentSelectStrategy(mandatory);
  const strategy = {
    select: (_ref4) => {
      let {
        id,
        selected,
        children,
        ...rest
      } = _ref4;
      id = toRaw(id);
      if (children.has(id)) return selected;
      return parentStrategy.select({
        id,
        selected,
        children,
        ...rest
      });
    },
    in: parentStrategy.in,
    out: parentStrategy.out
  };
  return strategy;
};
const leafSingleSelectStrategy = (mandatory) => {
  const parentStrategy = independentSingleSelectStrategy(mandatory);
  const strategy = {
    select: (_ref5) => {
      let {
        id,
        selected,
        children,
        ...rest
      } = _ref5;
      id = toRaw(id);
      if (children.has(id)) return selected;
      return parentStrategy.select({
        id,
        selected,
        children,
        ...rest
      });
    },
    in: parentStrategy.in,
    out: parentStrategy.out
  };
  return strategy;
};
const classicSelectStrategy = (mandatory) => {
  const strategy = {
    select: (_ref6) => {
      let {
        id,
        value,
        selected,
        children,
        parents,
        disabled
      } = _ref6;
      id = toRaw(id);
      const original = new Map(selected);
      const items = [id];
      while (items.length) {
        const item = items.shift();
        if (!disabled.has(item)) {
          selected.set(toRaw(item), value ? "on" : "off");
        }
        if (children.has(item)) {
          items.push(...children.get(item));
        }
      }
      let parent = toRaw(parents.get(id));
      while (parent) {
        let everySelected = true;
        let noneSelected = true;
        for (const child of children.get(parent)) {
          const cid = toRaw(child);
          if (disabled.has(cid)) continue;
          if (selected.get(cid) !== "on") everySelected = false;
          if (selected.has(cid) && selected.get(cid) !== "off") noneSelected = false;
          if (!everySelected && !noneSelected) break;
        }
        selected.set(parent, everySelected ? "on" : noneSelected ? "off" : "indeterminate");
        parent = toRaw(parents.get(parent));
      }
      if (mandatory && !value) {
        const on = Array.from(selected.entries()).reduce((arr, _ref7) => {
          let [key, value2] = _ref7;
          if (value2 === "on") arr.push(key);
          return arr;
        }, []);
        if (on.length === 0) return original;
      }
      return selected;
    },
    in: (v, children, parents) => {
      let map = /* @__PURE__ */ new Map();
      for (const id of v || []) {
        map = strategy.select({
          id,
          value: true,
          selected: map,
          children,
          parents,
          disabled: /* @__PURE__ */ new Set()
        });
      }
      return map;
    },
    out: (v, children) => {
      const arr = [];
      for (const [key, value] of v.entries()) {
        if (value === "on" && !children.has(key)) arr.push(key);
      }
      return arr;
    }
  };
  return strategy;
};
const trunkSelectStrategy = (mandatory) => {
  const parentStrategy = classicSelectStrategy(mandatory);
  const strategy = {
    select: parentStrategy.select,
    in: parentStrategy.in,
    out: (v, children, parents) => {
      const arr = [];
      for (const [key, value] of v.entries()) {
        if (value === "on") {
          if (parents.has(key)) {
            const parent = parents.get(key);
            if (v.get(parent) === "on") continue;
          }
          arr.push(key);
        }
      }
      return arr;
    }
  };
  return strategy;
};
const branchSelectStrategy = (mandatory) => {
  const parentStrategy = classicSelectStrategy(mandatory);
  const strategy = {
    select: parentStrategy.select,
    in: (v, children, parents, disabled) => {
      let map = /* @__PURE__ */ new Map();
      for (const id of v || []) {
        if (children.has(id)) continue;
        map = strategy.select({
          id,
          value: true,
          selected: map,
          children,
          parents,
          disabled
        });
      }
      return map;
    },
    out: (v) => {
      const arr = [];
      for (const [key, value] of v.entries()) {
        if (value === "on" || value === "indeterminate") {
          arr.push(key);
        }
      }
      return arr;
    }
  };
  return strategy;
};
const VNestedSymbol = /* @__PURE__ */ Symbol.for("vuetify:nested");
const emptyNested = {
  id: shallowRef(),
  root: {
    itemsRegistration: ref("render"),
    register: () => null,
    unregister: () => null,
    updateDisabled: () => null,
    children: ref(/* @__PURE__ */ new Map()),
    parents: ref(/* @__PURE__ */ new Map()),
    disabled: ref(/* @__PURE__ */ new Set()),
    open: () => null,
    openOnSelect: () => null,
    activate: () => null,
    select: () => null,
    activatable: ref(false),
    scrollToActive: ref(false),
    selectable: ref(false),
    opened: ref(/* @__PURE__ */ new Set()),
    activated: ref(/* @__PURE__ */ new Set()),
    selected: ref(/* @__PURE__ */ new Map()),
    selectedValues: ref([]),
    getPath: () => []
  }
};
const makeNestedProps = propsFactory({
  activatable: Boolean,
  selectable: Boolean,
  activeStrategy: [String, Function, Object],
  selectStrategy: [String, Function, Object],
  openStrategy: [String, Object],
  opened: null,
  activated: null,
  selected: null,
  mandatory: Boolean,
  itemsRegistration: {
    type: String,
    default: "render"
  }
}, "nested");
const useNested = (props, _ref) => {
  let {
    items,
    returnObject,
    scrollToActive
  } = _ref;
  const children = shallowRef(/* @__PURE__ */ new Map());
  const parents = shallowRef(/* @__PURE__ */ new Map());
  const disabled = shallowRef(/* @__PURE__ */ new Set());
  const opened = useProxiedModel(props, "opened", props.opened, (v) => new Set(Array.isArray(v) ? v.map((i) => toRaw(i)) : v), (v) => [...v.values()]);
  const activeStrategy = computed(() => {
    if (typeof props.activeStrategy === "object") return props.activeStrategy;
    if (typeof props.activeStrategy === "function") return props.activeStrategy(props.mandatory);
    switch (props.activeStrategy) {
      case "leaf":
        return leafActiveStrategy(props.mandatory);
      case "single-leaf":
        return leafSingleActiveStrategy(props.mandatory);
      case "independent":
        return independentActiveStrategy(props.mandatory);
      case "single-independent":
      default:
        return independentSingleActiveStrategy(props.mandatory);
    }
  });
  const selectStrategy = computed(() => {
    if (typeof props.selectStrategy === "object") return props.selectStrategy;
    if (typeof props.selectStrategy === "function") return props.selectStrategy(props.mandatory);
    switch (props.selectStrategy) {
      case "single-leaf":
        return leafSingleSelectStrategy(props.mandatory);
      case "leaf":
        return leafSelectStrategy(props.mandatory);
      case "independent":
        return independentSelectStrategy(props.mandatory);
      case "single-independent":
        return independentSingleSelectStrategy(props.mandatory);
      case "trunk":
        return trunkSelectStrategy(props.mandatory);
      case "branch":
        return branchSelectStrategy(props.mandatory);
      case "classic":
      default:
        return classicSelectStrategy(props.mandatory);
    }
  });
  const openStrategy = computed(() => {
    if (typeof props.openStrategy === "object") return props.openStrategy;
    switch (props.openStrategy) {
      case "list":
        return listOpenStrategy;
      case "single":
        return singleOpenStrategy;
      case "multiple":
      default:
        return multipleOpenStrategy;
    }
  });
  const activated = useProxiedModel(props, "activated", props.activated, (v) => activeStrategy.value.in(v, children.value, parents.value), (v) => activeStrategy.value.out(v, children.value, parents.value));
  const selected = useProxiedModel(props, "selected", props.selected, (v) => selectStrategy.value.in(v, children.value, parents.value, disabled.value), (v) => selectStrategy.value.out(v, children.value, parents.value));
  function getPath(id) {
    const path = [];
    let parent = toRaw(id);
    while (parent !== void 0) {
      path.unshift(parent);
      parent = parents.value.get(parent);
    }
    return path;
  }
  const vm = getCurrentInstance$1("nested");
  const nodeIds = /* @__PURE__ */ new Set();
  const itemsUpdatePropagation = throttle(() => {
    nextTick(() => {
      children.value = new Map(children.value);
      parents.value = new Map(parents.value);
    });
  }, 100);
  watch(() => [items.value, toValue(returnObject)], () => {
    if (props.itemsRegistration === "props") {
      updateInternalMaps();
    }
  }, {
    immediate: true
  });
  function updateInternalMaps() {
    const _parents = /* @__PURE__ */ new Map();
    const _children = /* @__PURE__ */ new Map();
    const _disabled = /* @__PURE__ */ new Set();
    const getValue = toValue(returnObject) ? (item) => toRaw(item.raw) : (item) => item.value;
    const stack = [...items.value];
    let i = 0;
    while (i < stack.length) {
      const item = stack[i++];
      const itemValue = getValue(item);
      if (item.children) {
        const childValues = [];
        for (const child of item.children) {
          const childValue = getValue(child);
          _parents.set(childValue, itemValue);
          childValues.push(childValue);
          stack.push(child);
        }
        _children.set(itemValue, childValues);
      }
      if (item.props.disabled) {
        _disabled.add(itemValue);
      }
    }
    children.value = _children;
    parents.value = _parents;
    disabled.value = _disabled;
  }
  const nested = {
    id: shallowRef(),
    root: {
      opened,
      activatable: toRef(() => props.activatable),
      scrollToActive: toRef(() => toValue(scrollToActive)),
      selectable: toRef(() => props.selectable),
      activated,
      selected,
      selectedValues: computed(() => {
        const arr = [];
        for (const [key, value] of selected.value.entries()) {
          if (value === "on") arr.push(key);
        }
        return arr;
      }),
      itemsRegistration: toRef(() => props.itemsRegistration),
      register: (id, parentId, isDisabled, isGroup) => {
        if (nodeIds.has(id)) {
          const path = getPath(id).map(String).join(" -> ");
          const newPath = getPath(parentId).concat(id).map(String).join(" -> ");
          consoleError(`Multiple nodes with the same ID
	${path}
	${newPath}`);
          return;
        } else {
          nodeIds.add(id);
        }
        parentId && id !== parentId && parents.value.set(id, parentId);
        isDisabled && disabled.value.add(id);
        isGroup && children.value.set(id, []);
        if (parentId != null) {
          children.value.set(parentId, [...children.value.get(parentId) || [], id]);
        }
        itemsUpdatePropagation();
      },
      unregister: (id) => {
        var _a;
        nodeIds.delete(id);
        children.value.delete(id);
        disabled.value.delete(id);
        const parent = parents.value.get(id);
        if (parent) {
          const list = (_a = children.value.get(parent)) != null ? _a : [];
          children.value.set(parent, list.filter((child) => child !== id));
        }
        parents.value.delete(id);
        itemsUpdatePropagation();
      },
      updateDisabled: (id, isDisabled) => {
        if (isDisabled) {
          disabled.value.add(id);
        } else {
          disabled.value.delete(id);
        }
      },
      open: (id, value, event) => {
        vm.emit("click:open", {
          id,
          value,
          path: getPath(id),
          event
        });
        const newOpened = openStrategy.value.open({
          id,
          value,
          opened: new Set(opened.value),
          children: children.value,
          parents: parents.value,
          event
        });
        newOpened && (opened.value = newOpened);
      },
      openOnSelect: (id, value, event) => {
        const newOpened = openStrategy.value.select({
          id,
          value,
          selected: new Map(selected.value),
          opened: new Set(opened.value),
          children: children.value,
          parents: parents.value,
          event
        });
        newOpened && (opened.value = newOpened);
      },
      select: (id, value, event) => {
        vm.emit("click:select", {
          id,
          value,
          path: getPath(id),
          event
        });
        const newSelected = selectStrategy.value.select({
          id,
          value,
          selected: new Map(selected.value),
          children: children.value,
          parents: parents.value,
          disabled: disabled.value,
          event
        });
        newSelected && (selected.value = newSelected);
        nested.root.openOnSelect(id, value, event);
      },
      activate: (id, value, event) => {
        if (!props.activatable) {
          return nested.root.select(id, true, event);
        }
        vm.emit("click:activate", {
          id,
          value,
          path: getPath(id),
          event
        });
        const newActivated = activeStrategy.value.activate({
          id,
          value,
          activated: new Set(activated.value),
          children: children.value,
          parents: parents.value,
          event
        });
        if (newActivated.size !== activated.value.size) {
          activated.value = newActivated;
        } else {
          for (const value2 of newActivated) {
            if (!activated.value.has(value2)) {
              activated.value = newActivated;
              return;
            }
          }
          for (const value2 of activated.value) {
            if (!newActivated.has(value2)) {
              activated.value = newActivated;
              return;
            }
          }
        }
      },
      children,
      parents,
      disabled,
      getPath
    }
  };
  provide(VNestedSymbol, nested);
  return nested.root;
};
const useNestedItem = (id, isDisabled, isGroup) => {
  const parent = inject(VNestedSymbol, emptyNested);
  const uidSymbol = /* @__PURE__ */ Symbol("nested item");
  const computedId = computed(() => {
    const idValue = toRaw(toValue(id));
    return idValue !== void 0 ? idValue : uidSymbol;
  });
  const item = {
    ...parent,
    id: computedId,
    open: (open, e) => parent.root.open(computedId.value, open, e),
    openOnSelect: (open, e) => parent.root.openOnSelect(computedId.value, open, e),
    isOpen: computed(() => parent.root.opened.value.has(computedId.value)),
    parent: computed(() => parent.root.parents.value.get(computedId.value)),
    activate: (activated, e) => parent.root.activate(computedId.value, activated, e),
    isActivated: computed(() => parent.root.activated.value.has(computedId.value)),
    scrollToActive: parent.root.scrollToActive,
    select: (selected, e) => parent.root.select(computedId.value, selected, e),
    isSelected: computed(() => parent.root.selected.value.get(computedId.value) === "on"),
    isIndeterminate: computed(() => parent.root.selected.value.get(computedId.value) === "indeterminate"),
    isLeaf: computed(() => !parent.root.children.value.get(computedId.value)),
    isGroupActivator: parent.isGroupActivator
  };
  watch(computedId, (val, oldVal) => {
    if (parent.isGroupActivator || parent.root.itemsRegistration.value === "props") return;
    parent.root.unregister(oldVal);
    nextTick(() => {
      parent.root.register(val, parent.id.value, toValue(isDisabled), isGroup);
    });
  });
  watch(() => toValue(isDisabled), (val) => {
    parent.root.updateDisabled(computedId.value, val);
  });
  isGroup && provide(VNestedSymbol, item);
  return item;
};
const useNestedGroupActivator = () => {
  const parent = inject(VNestedSymbol, emptyNested);
  provide(VNestedSymbol, {
    ...parent,
    isGroupActivator: true
  });
};
function useSsrBoot() {
  const isBooted = shallowRef(false);
  const ssrBootStyles = toRef(() => !isBooted.value ? {
    transition: "none !important"
  } : void 0);
  return {
    ssrBootStyles,
    isBooted: readonly(isBooted)
  };
}
const VListGroupActivator = defineComponent$1({
  name: "VListGroupActivator",
  setup(_, _ref) {
    let {
      slots
    } = _ref;
    useNestedGroupActivator();
    return () => {
      var _a;
      return (_a = slots.default) == null ? void 0 : _a.call(slots);
    };
  }
});
const makeVListGroupProps = propsFactory({
  /* @deprecated */
  activeColor: String,
  baseColor: String,
  color: String,
  collapseIcon: {
    type: IconValue,
    default: "$collapse"
  },
  disabled: Boolean,
  expandIcon: {
    type: IconValue,
    default: "$expand"
  },
  rawId: [String, Number],
  prependIcon: IconValue,
  appendIcon: IconValue,
  fluid: Boolean,
  subgroup: Boolean,
  title: String,
  value: null,
  ...makeComponentProps(),
  ...makeTagProps()
}, "VListGroup");
const VListGroup = genericComponent()({
  name: "VListGroup",
  props: makeVListGroupProps(),
  setup(props, _ref2) {
    let {
      slots
    } = _ref2;
    const {
      isOpen,
      open,
      id: _id
    } = useNestedItem(() => props.value, () => props.disabled, true);
    const id = computed(() => {
      var _a;
      return `v-list-group--id-${String((_a = props.rawId) != null ? _a : _id.value)}`;
    });
    const list = useList();
    const {
      isBooted
    } = useSsrBoot();
    const parent = inject(VNestedSymbol);
    const renderWhenClosed = toRef(() => {
      var _a;
      return ((_a = parent == null ? void 0 : parent.root) == null ? void 0 : _a.itemsRegistration.value) === "render";
    });
    function onClick(e) {
      var _a;
      if (["INPUT", "TEXTAREA"].includes((_a = e.target) == null ? void 0 : _a.tagName)) return;
      open(!isOpen.value, e);
    }
    const activatorProps = computed(() => ({
      onClick,
      class: "v-list-group__header",
      id: id.value
    }));
    const toggleIcon = computed(() => isOpen.value ? props.collapseIcon : props.expandIcon);
    const activatorDefaults = computed(() => ({
      VListItem: {
        activeColor: props.activeColor,
        baseColor: props.baseColor,
        color: props.color,
        prependIcon: props.prependIcon || props.subgroup && toggleIcon.value,
        appendIcon: props.appendIcon || !props.subgroup && toggleIcon.value,
        title: props.title,
        value: props.value
      }
    }));
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-list-group", {
        "v-list-group--prepend": list == null ? void 0 : list.hasPrepend.value,
        "v-list-group--fluid": props.fluid,
        "v-list-group--subgroup": props.subgroup,
        "v-list-group--open": isOpen.value
      }, props.class]),
      "style": normalizeStyle(props.style)
    }, {
      default: () => [slots.activator && createVNode(VDefaultsProvider, {
        "defaults": activatorDefaults.value
      }, {
        default: () => [createVNode(VListGroupActivator, null, {
          default: () => [slots.activator({
            props: activatorProps.value,
            isOpen: isOpen.value
          })]
        })]
      }), createVNode(MaybeTransition, {
        "transition": {
          component: VExpandTransition
        },
        "disabled": !isBooted.value
      }, {
        default: () => {
          var _a, _b;
          return [renderWhenClosed.value ? withDirectives(createElementVNode("div", {
            "class": "v-list-group__items",
            "role": "group",
            "aria-labelledby": id.value
          }, [(_a = slots.default) == null ? void 0 : _a.call(slots)]), [[vShow, isOpen.value]]) : isOpen.value && createElementVNode("div", {
            "class": "v-list-group__items",
            "role": "group",
            "aria-labelledby": id.value
          }, [(_b = slots.default) == null ? void 0 : _b.call(slots)])];
        }
      })]
    }));
    return {
      isOpen
    };
  }
});
const makeVListItemSubtitleProps = propsFactory({
  opacity: [Number, String],
  ...makeComponentProps(),
  ...makeTagProps()
}, "VListItemSubtitle");
const VListItemSubtitle = genericComponent()({
  name: "VListItemSubtitle",
  props: makeVListItemSubtitleProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-list-item-subtitle", props.class]),
      "style": normalizeStyle([{
        "--v-list-item-subtitle-opacity": props.opacity
      }, props.style])
    }, slots));
    return {};
  }
});
const VListItemTitle = createSimpleFunctional("v-list-item-title");
const makeVListItemProps = propsFactory({
  active: {
    type: Boolean,
    default: void 0
  },
  activeClass: String,
  /* @deprecated */
  activeColor: String,
  appendAvatar: String,
  appendIcon: IconValue,
  baseColor: String,
  disabled: Boolean,
  lines: [Boolean, String],
  link: {
    type: Boolean,
    default: void 0
  },
  nav: Boolean,
  prependAvatar: String,
  prependIcon: IconValue,
  ripple: {
    type: [Boolean, Object],
    default: true
  },
  slim: Boolean,
  prependGap: [Number, String],
  subtitle: {
    type: [String, Number, Boolean],
    default: void 0
  },
  title: {
    type: [String, Number, Boolean],
    default: void 0
  },
  value: null,
  index: Number,
  tabindex: [Number, String],
  onClick: EventProp(),
  onClickOnce: EventProp(),
  ...makeBorderProps(),
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...makeDimensionProps(),
  ...makeElevationProps(),
  ...makeRoundedProps(),
  ...makeRouterProps(),
  ...makeTagProps(),
  ...makeThemeProps(),
  ...makeVariantProps({
    variant: "text"
  })
}, "VListItem");
const VListItem = genericComponent()({
  name: "VListItem",
  directives: {
    vRipple: Ripple
  },
  props: makeVListItemProps(),
  emits: {
    click: (e) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      slots,
      emit
    } = _ref;
    const link = useLink(props, attrs);
    const rootEl = ref();
    const id = computed(() => props.value === void 0 ? link.href.value : props.value);
    const {
      activate,
      isActivated,
      select,
      isOpen,
      isSelected,
      isIndeterminate,
      isGroupActivator,
      root,
      parent,
      openOnSelect,
      scrollToActive,
      id: uid
    } = useNestedItem(id, () => props.disabled, false);
    const list = useList();
    const isActive = computed(() => {
      var _a;
      return props.active !== false && (props.active || ((_a = link.isActive) == null ? void 0 : _a.value) || (root.activatable.value ? isActivated.value : isSelected.value));
    });
    const isLink = toRef(() => props.link !== false && link.isLink.value);
    const isSelectable = computed(() => !!list && (root.selectable.value || root.activatable.value || props.value != null));
    const isClickable = computed(() => !props.disabled && props.link !== false && (props.link || link.isClickable.value || isSelectable.value));
    const isTracked = computed(() => list && list.navigationStrategy.value === "track" && props.index !== void 0 && list.trackingIndex.value === props.index);
    const role = computed(() => list ? isLink.value ? "link" : isSelectable.value ? "option" : "listitem" : void 0);
    const ariaSelected = computed(() => {
      if (!isSelectable.value) return void 0;
      return root.activatable.value ? isActivated.value : root.selectable.value ? isSelected.value : isActive.value;
    });
    const roundedProps = toRef(() => props.rounded || props.nav);
    const color = toRef(() => {
      var _a;
      return (_a = props.color) != null ? _a : props.activeColor;
    });
    const variantProps = toRef(() => {
      var _a;
      return {
        color: isActive.value ? (_a = color.value) != null ? _a : props.baseColor : props.baseColor,
        variant: props.variant
      };
    });
    watch(() => {
      var _a;
      return (_a = link.isActive) == null ? void 0 : _a.value;
    }, (val) => {
      if (!val) return;
      handleActiveLink();
    });
    watch(isActivated, (val) => {
      var _a;
      if (!val || !scrollToActive) return;
      (_a = rootEl.value) == null ? void 0 : _a.scrollIntoView({
        block: "nearest",
        behavior: "instant"
      });
    });
    watch(isTracked, (val) => {
      var _a;
      if (!val) return;
      (_a = rootEl.value) == null ? void 0 : _a.scrollIntoView({
        block: "nearest",
        behavior: "instant"
      });
    });
    function handleActiveLink() {
      if (parent.value != null) {
        root.open(parent.value, true);
      }
      openOnSelect(true);
    }
    const {
      themeClasses
    } = provideTheme(props);
    const {
      borderClasses
    } = useBorder(props);
    const {
      colorClasses,
      colorStyles,
      variantClasses
    } = useVariant(variantProps);
    const {
      densityClasses
    } = useDensity(props);
    const {
      dimensionStyles
    } = useDimension(props);
    const {
      elevationClasses
    } = useElevation(props);
    const {
      roundedClasses
    } = useRounded(roundedProps);
    const lineClasses = toRef(() => props.lines ? `v-list-item--${props.lines}-line` : void 0);
    const rippleOptions = toRef(() => props.ripple !== void 0 && !!props.ripple && (list == null ? void 0 : list.filterable) ? {
      keys: ["Enter"]
    } : props.ripple);
    const slotProps = computed(() => ({
      isActive: isActive.value,
      select,
      isOpen: isOpen.value,
      isSelected: isSelected.value,
      isIndeterminate: isIndeterminate.value,
      isDisabled: props.disabled
    }));
    function onClick(e) {
      var _a, _b, _c;
      emit("click", e);
      if (["INPUT", "TEXTAREA"].includes((_a = e.target) == null ? void 0 : _a.tagName)) return;
      if (!isClickable.value) return;
      (_c = (_b = link.navigate).value) == null ? void 0 : _c.call(_b, e);
      if (isGroupActivator) return;
      if (root.activatable.value) {
        activate(!isActivated.value, e);
      } else if (root.selectable.value) {
        select(!isSelected.value, e);
      } else if (props.value != null && !isLink.value) {
        select(!isSelected.value, e);
      }
    }
    function onKeyDown(e) {
      const target = e.target;
      if (["INPUT", "TEXTAREA"].includes(target.tagName)) return;
      if (e.key === "Enter" || e.key === " " && !(list == null ? void 0 : list.filterable)) {
        e.preventDefault();
        e.stopPropagation();
        e.target.dispatchEvent(new MouseEvent("click", e));
      }
    }
    useRender(() => {
      var _a;
      const Tag = isLink.value ? "a" : props.tag;
      const hasTitle = slots.title || props.title != null;
      const hasSubtitle = slots.subtitle || props.subtitle != null;
      const hasAppendMedia = !!(props.appendAvatar || props.appendIcon);
      const hasAppend = !!(hasAppendMedia || slots.append);
      const hasPrependMedia = !!(props.prependAvatar || props.prependIcon);
      const hasPrepend = !!(hasPrependMedia || slots.prepend);
      list == null ? void 0 : list.updateHasPrepend(hasPrepend);
      if (props.activeColor) {
        deprecate("active-color", ["color", "base-color"]);
      }
      return withDirectives(createVNode(Tag, mergeProps(link.linkProps, {
        "ref": rootEl,
        "id": props.index !== void 0 && list ? `v-list-item-${list.uid}-${props.index}` : void 0,
        "class": ["v-list-item", {
          "v-list-item--active": isActive.value,
          "v-list-item--disabled": props.disabled,
          "v-list-item--link": isClickable.value,
          "v-list-item--nav": props.nav,
          "v-list-item--prepend": !hasPrepend && (list == null ? void 0 : list.hasPrepend.value),
          "v-list-item--slim": props.slim,
          "v-list-item--focus-visible": isTracked.value,
          [`${props.activeClass}`]: props.activeClass && isActive.value
        }, themeClasses.value, borderClasses.value, colorClasses.value, densityClasses.value, elevationClasses.value, lineClasses.value, roundedClasses.value, variantClasses.value, props.class],
        "style": [{
          "--v-list-prepend-gap": convertToUnit(props.prependGap)
        }, colorStyles.value, dimensionStyles.value, props.style],
        "tabindex": (_a = props.tabindex) != null ? _a : isClickable.value ? list ? -2 : 0 : void 0,
        "aria-selected": ariaSelected.value,
        "role": role.value,
        "onClick": onClick,
        "onKeydown": isClickable.value && !isLink.value && onKeyDown
      }), {
        default: () => {
          var _a2;
          return [genOverlays(isClickable.value || isActive.value, "v-list-item"), hasPrepend && createElementVNode("div", {
            "key": "prepend",
            "class": "v-list-item__prepend"
          }, [!slots.prepend ? createElementVNode(Fragment, null, [props.prependAvatar && createVNode(VAvatar, {
            "key": "prepend-avatar",
            "density": props.density,
            "image": props.prependAvatar
          }, null), props.prependIcon && createVNode(VIcon, {
            "key": "prepend-icon",
            "density": props.density,
            "icon": props.prependIcon
          }, null)]) : createVNode(VDefaultsProvider, {
            "key": "prepend-defaults",
            "defaults": {
              VAvatar: {
                density: props.density,
                image: props.prependAvatar
              },
              VIcon: {
                density: props.density,
                icon: props.prependIcon
              },
              VListItemAction: {
                start: true
              },
              VCheckboxBtn: {
                density: props.density
              }
            }
          }, {
            default: () => {
              var _a3;
              return [(_a3 = slots.prepend) == null ? void 0 : _a3.call(slots, slotProps.value)];
            }
          }), createElementVNode("div", {
            "class": "v-list-item__spacer"
          }, null)]), createElementVNode("div", {
            "class": "v-list-item__content",
            "data-no-activator": ""
          }, [hasTitle && createVNode(VListItemTitle, {
            "key": "title"
          }, {
            default: () => {
              var _a3, _b;
              return [(_b = (_a3 = slots.title) == null ? void 0 : _a3.call(slots, {
                title: props.title
              })) != null ? _b : toDisplayString(props.title)];
            }
          }), hasSubtitle && createVNode(VListItemSubtitle, {
            "key": "subtitle"
          }, {
            default: () => {
              var _a3, _b;
              return [(_b = (_a3 = slots.subtitle) == null ? void 0 : _a3.call(slots, {
                subtitle: props.subtitle
              })) != null ? _b : toDisplayString(props.subtitle)];
            }
          }), (_a2 = slots.default) == null ? void 0 : _a2.call(slots, slotProps.value)]), hasAppend && createElementVNode("div", {
            "key": "append",
            "class": "v-list-item__append"
          }, [!slots.append ? createElementVNode(Fragment, null, [props.appendIcon && createVNode(VIcon, {
            "key": "append-icon",
            "density": props.density,
            "icon": props.appendIcon
          }, null), props.appendAvatar && createVNode(VAvatar, {
            "key": "append-avatar",
            "density": props.density,
            "image": props.appendAvatar
          }, null)]) : createVNode(VDefaultsProvider, {
            "key": "append-defaults",
            "defaults": {
              VAvatar: {
                density: props.density,
                image: props.appendAvatar
              },
              VIcon: {
                density: props.density,
                icon: props.appendIcon
              },
              VListItemAction: {
                end: true
              },
              VCheckboxBtn: {
                density: props.density
              }
            }
          }, {
            default: () => {
              var _a3;
              return [(_a3 = slots.append) == null ? void 0 : _a3.call(slots, slotProps.value)];
            }
          }), createElementVNode("div", {
            "class": "v-list-item__spacer"
          }, null)])];
        }
      }), [[Ripple, isClickable.value && rippleOptions.value]]);
    });
    return {
      activate,
      isActivated,
      isGroupActivator,
      isSelected,
      list,
      select,
      root,
      id: uid,
      link
    };
  }
});
const makeVListSubheaderProps = propsFactory({
  color: String,
  inset: Boolean,
  sticky: Boolean,
  title: String,
  ...makeComponentProps(),
  ...makeTagProps()
}, "VListSubheader");
const VListSubheader = genericComponent()({
  name: "VListSubheader",
  props: makeVListSubheaderProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      textColorClasses,
      textColorStyles
    } = useTextColor(() => props.color);
    useRender(() => {
      const hasText = !!(slots.default || props.title);
      return createVNode(props.tag, {
        "class": normalizeClass(["v-list-subheader", {
          "v-list-subheader--inset": props.inset,
          "v-list-subheader--sticky": props.sticky
        }, textColorClasses.value, props.class]),
        "style": normalizeStyle([{
          textColorStyles
        }, props.style])
      }, {
        default: () => {
          var _a, _b;
          return [hasText && createElementVNode("div", {
            "class": "v-list-subheader__text"
          }, [(_b = (_a = slots.default) == null ? void 0 : _a.call(slots)) != null ? _b : props.title])];
        }
      });
    });
    return {};
  }
});
const makeVListChildrenProps = propsFactory({
  items: Array,
  returnObject: Boolean
}, "VListChildren");
const VListChildren = genericComponent()({
  name: "VListChildren",
  props: makeVListChildrenProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    createList();
    return () => {
      var _a, _b, _c;
      return (_c = (_a = slots.default) == null ? void 0 : _a.call(slots)) != null ? _c : (_b = props.items) == null ? void 0 : _b.map((_ref2, index) => {
        var _a2, _b2, _c2, _d;
        let {
          children,
          props: itemProps,
          type,
          raw: item
        } = _ref2;
        if (type === "divider") {
          return (_b2 = (_a2 = slots.divider) == null ? void 0 : _a2.call(slots, {
            props: itemProps
          })) != null ? _b2 : createVNode(VDivider, itemProps, null);
        }
        if (type === "subheader") {
          return (_d = (_c2 = slots.subheader) == null ? void 0 : _c2.call(slots, {
            props: itemProps
          })) != null ? _d : createVNode(VListSubheader, itemProps, null);
        }
        const slotsWithItem = {
          subtitle: slots.subtitle ? (slotProps) => {
            var _a3;
            return (_a3 = slots.subtitle) == null ? void 0 : _a3.call(slots, {
              ...slotProps,
              item
            });
          } : void 0,
          prepend: slots.prepend ? (slotProps) => {
            var _a3;
            return (_a3 = slots.prepend) == null ? void 0 : _a3.call(slots, {
              ...slotProps,
              item
            });
          } : void 0,
          append: slots.append ? (slotProps) => {
            var _a3;
            return (_a3 = slots.append) == null ? void 0 : _a3.call(slots, {
              ...slotProps,
              item
            });
          } : void 0,
          title: slots.title ? (slotProps) => {
            var _a3;
            return (_a3 = slots.title) == null ? void 0 : _a3.call(slots, {
              ...slotProps,
              item
            });
          } : void 0
        };
        const listGroupProps = VListGroup.filterProps(itemProps);
        return children ? createVNode(VListGroup, mergeProps(listGroupProps, {
          "value": props.returnObject ? item : itemProps == null ? void 0 : itemProps.value,
          "rawId": itemProps == null ? void 0 : itemProps.value
        }), {
          activator: (_ref3) => {
            let {
              props: activatorProps
            } = _ref3;
            const listItemProps = mergeProps(itemProps, activatorProps, {
              value: props.returnObject ? item : itemProps.value
            });
            return slots.header ? slots.header({
              props: listItemProps
            }) : createVNode(VListItem, mergeProps(listItemProps, {
              "index": index
            }), slotsWithItem);
          },
          default: () => createVNode(VListChildren, {
            "items": children,
            "returnObject": props.returnObject
          }, slots)
        }) : slots.item ? slots.item({
          props: {
            ...itemProps,
            index
          }
        }) : createVNode(VListItem, mergeProps(itemProps, {
          "index": index,
          "value": props.returnObject ? item : itemProps.value
        }), slotsWithItem);
      });
    };
  }
});
const makeItemsProps = propsFactory({
  items: {
    type: Array,
    default: () => []
  },
  itemTitle: {
    type: [String, Array, Function],
    default: "title"
  },
  itemValue: {
    type: [String, Array, Function],
    default: "value"
  },
  itemChildren: {
    type: [Boolean, String, Array, Function],
    default: "children"
  },
  itemProps: {
    type: [Boolean, String, Array, Function],
    default: "props"
  },
  itemType: {
    type: [Boolean, String, Array, Function],
    default: "type"
  },
  returnObject: Boolean,
  valueComparator: Function
}, "list-items");
const itemTypes$1 = /* @__PURE__ */ new Set(["item", "divider", "subheader"]);
function transformItem$1(props, item) {
  var _a;
  const title = getPropertyFromItem(item, props.itemTitle, item);
  const value = getPropertyFromItem(item, props.itemValue, title);
  const children = getPropertyFromItem(item, props.itemChildren);
  const itemProps = props.itemProps === true ? typeof item === "object" && item != null && !Array.isArray(item) ? "children" in item ? omit(item, ["children"]) : item : void 0 : getPropertyFromItem(item, props.itemProps);
  let type = getPropertyFromItem(item, props.itemType, "item");
  if (!itemTypes$1.has(type)) {
    type = "item";
  }
  const _props = {
    title,
    value,
    ...itemProps
  };
  return {
    type,
    title: String((_a = _props.title) != null ? _a : ""),
    value: _props.value,
    props: _props,
    children: type === "item" && Array.isArray(children) ? transformItems$1(props, children) : void 0,
    raw: item
  };
}
transformItem$1.neededProps = ["itemTitle", "itemValue", "itemChildren", "itemProps", "itemType"];
function transformItems$1(props, items) {
  const _props = pick(props, transformItem$1.neededProps);
  const array = [];
  for (const item of items) {
    array.push(transformItem$1(_props, item));
  }
  return array;
}
function useItems(props) {
  const items = computed(() => transformItems$1(props, props.items));
  const hasNullItem = computed(() => items.value.some((item) => item.value === null));
  const itemsMap = shallowRef(/* @__PURE__ */ new Map());
  const keylessItems = shallowRef([]);
  watchEffect(() => {
    const _items = items.value;
    const map = /* @__PURE__ */ new Map();
    const keyless = [];
    for (let i = 0; i < _items.length; i++) {
      const item = _items[i];
      if (isPrimitive(item.value) || item.value === null) {
        let values = map.get(item.value);
        if (!values) {
          values = [];
          map.set(item.value, values);
        }
        values.push(item);
      } else {
        keyless.push(item);
      }
    }
    itemsMap.value = map;
    keylessItems.value = keyless;
  });
  function transformIn(value) {
    const _items = itemsMap.value;
    const _allItems = items.value;
    const _keylessItems = keylessItems.value;
    const _hasNullItem = hasNullItem.value;
    const _returnObject = props.returnObject;
    const hasValueComparator = !!props.valueComparator;
    const valueComparator = props.valueComparator || deepEqual;
    const _props = pick(props, transformItem$1.neededProps);
    const returnValue = [];
    main: for (const v of value) {
      if (!_hasNullItem && v === null) continue;
      if (_returnObject && typeof v === "string") {
        returnValue.push(transformItem$1(_props, v));
        continue;
      }
      const fastItems = _items.get(v);
      if (hasValueComparator || !fastItems) {
        for (const item of hasValueComparator ? _allItems : _keylessItems) {
          if (valueComparator(v, item.value)) {
            returnValue.push(item);
            continue main;
          }
        }
        returnValue.push(transformItem$1(_props, v));
        continue;
      }
      returnValue.push(...fastItems);
    }
    return returnValue;
  }
  function transformOut(value) {
    return props.returnObject ? value.map((_ref) => {
      let {
        raw
      } = _ref;
      return raw;
    }) : value.map((_ref2) => {
      let {
        value: value2
      } = _ref2;
      return value2;
    });
  }
  return {
    items,
    transformIn,
    transformOut
  };
}
const itemTypes = /* @__PURE__ */ new Set(["item", "divider", "subheader"]);
function transformItem(props, item) {
  const title = isPrimitive(item) ? item : getPropertyFromItem(item, props.itemTitle);
  const value = isPrimitive(item) ? item : getPropertyFromItem(item, props.itemValue, void 0);
  const children = getPropertyFromItem(item, props.itemChildren);
  const itemProps = props.itemProps === true ? omit(item, ["children"]) : getPropertyFromItem(item, props.itemProps);
  let type = getPropertyFromItem(item, props.itemType, "item");
  if (!itemTypes.has(type)) {
    type = "item";
  }
  const _props = {
    title,
    value,
    ...itemProps
  };
  return {
    type,
    title: _props.title,
    value: _props.value,
    props: _props,
    children: type === "item" && children ? transformItems(props, children) : void 0,
    raw: item
  };
}
function transformItems(props, items) {
  const array = [];
  for (const item of items) {
    array.push(transformItem(props, item));
  }
  return array;
}
function useListItems(props) {
  const items = computed(() => transformItems(props, props.items));
  return {
    items
  };
}
const makeVListProps = propsFactory({
  baseColor: String,
  /* @deprecated */
  activeColor: String,
  activeClass: String,
  bgColor: String,
  disabled: Boolean,
  filterable: Boolean,
  expandIcon: IconValue,
  collapseIcon: IconValue,
  lines: {
    type: [Boolean, String],
    default: "one"
  },
  slim: Boolean,
  prependGap: [Number, String],
  indent: [Number, String],
  nav: Boolean,
  navigationStrategy: {
    type: String,
    default: "focus"
  },
  navigationIndex: Number,
  "onClick:open": EventProp(),
  "onClick:select": EventProp(),
  "onUpdate:opened": EventProp(),
  ...makeNestedProps({
    selectStrategy: "single-leaf",
    openStrategy: "list"
  }),
  ...makeBorderProps(),
  ...makeComponentProps(),
  ...makeDensityProps(),
  ...makeDimensionProps(),
  ...makeElevationProps(),
  ...makeItemsProps(),
  ...makeRoundedProps(),
  ...makeTagProps(),
  ...makeThemeProps(),
  ...makeVariantProps({
    variant: "text"
  })
}, "VList");
const VList = genericComponent()({
  name: "VList",
  props: makeVListProps(),
  emits: {
    "update:selected": (value) => true,
    "update:activated": (value) => true,
    "update:opened": (value) => true,
    "update:navigationIndex": (value) => true,
    "click:open": (value) => true,
    "click:activate": (value) => true,
    "click:select": (value) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      slots,
      emit
    } = _ref;
    const {
      items
    } = useListItems(props);
    const {
      themeClasses
    } = provideTheme(props);
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.bgColor);
    const {
      borderClasses
    } = useBorder(props);
    const {
      densityClasses
    } = useDensity(props);
    const {
      dimensionStyles
    } = useDimension(props);
    const {
      elevationClasses
    } = useElevation(props);
    const {
      roundedClasses
    } = useRounded(props);
    const {
      children,
      open,
      parents,
      select,
      getPath
    } = useNested(props, {
      items,
      returnObject: toRef(() => props.returnObject),
      scrollToActive: toRef(() => props.navigationStrategy === "track")
    });
    const lineClasses = toRef(() => props.lines ? `v-list--${props.lines}-line` : void 0);
    const activeColor = toRef(() => props.activeColor);
    const baseColor = toRef(() => props.baseColor);
    const color = toRef(() => props.color);
    const isSelectable = toRef(() => props.selectable || props.activatable);
    const navigationIndex = useProxiedModel(props, "navigationIndex", -1, (v) => v != null ? v : -1);
    const uid = useId();
    createList({
      filterable: props.filterable,
      trackingIndex: navigationIndex,
      navigationStrategy: toRef(() => props.navigationStrategy),
      uid
    });
    watch(items, () => {
      if (props.navigationStrategy === "track") {
        navigationIndex.value = -1;
      }
    });
    provideDefaults({
      VListGroup: {
        activeColor,
        baseColor,
        color,
        expandIcon: toRef(() => props.expandIcon),
        collapseIcon: toRef(() => props.collapseIcon)
      },
      VListItem: {
        activeClass: toRef(() => props.activeClass),
        activeColor,
        baseColor,
        color,
        density: toRef(() => props.density),
        disabled: toRef(() => props.disabled),
        lines: toRef(() => props.lines),
        nav: toRef(() => props.nav),
        slim: toRef(() => props.slim),
        variant: toRef(() => props.variant),
        tabindex: toRef(() => props.navigationStrategy === "track" ? -1 : void 0)
      }
    });
    const isFocused = shallowRef(false);
    const contentRef = ref();
    function onFocusin(e) {
      isFocused.value = true;
    }
    function onFocusout(e) {
      isFocused.value = false;
    }
    function onFocus(e) {
      var _a;
      if (props.navigationStrategy === "track") {
        if (!~navigationIndex.value) {
          navigationIndex.value = getNextIndex("first");
        }
      } else if (!isFocused.value && !(e.relatedTarget && ((_a = contentRef.value) == null ? void 0 : _a.contains(e.relatedTarget)))) focus();
    }
    function onBlur() {
      if (props.navigationStrategy === "track") {
        navigationIndex.value = -1;
      }
    }
    function getNavigationDirection(key) {
      switch (key) {
        case "ArrowDown":
          return "next";
        case "ArrowUp":
          return "prev";
        case "Home":
          return "first";
        case "End":
          return "last";
        default:
          return null;
      }
    }
    function getNextIndex(direction) {
      const itemCount = items.value.length;
      if (itemCount === 0) return -1;
      let nextIndex;
      if (direction === "first") {
        nextIndex = 0;
      } else if (direction === "last") {
        nextIndex = itemCount - 1;
      } else {
        nextIndex = navigationIndex.value + (direction === "next" ? 1 : -1);
        if (nextIndex < 0) nextIndex = itemCount - 1;
        if (nextIndex >= itemCount) nextIndex = 0;
      }
      const startIndex = nextIndex;
      let attempts = 0;
      while (attempts < itemCount) {
        const item = items.value[nextIndex];
        if (item && item.type !== "divider" && item.type !== "subheader") {
          return nextIndex;
        }
        nextIndex += direction === "next" || direction === "first" ? 1 : -1;
        if (nextIndex < 0) nextIndex = itemCount - 1;
        if (nextIndex >= itemCount) nextIndex = 0;
        if (nextIndex === startIndex) return -1;
        attempts++;
      }
      return -1;
    }
    function onKeydown2(e) {
      const target = e.target;
      if (!contentRef.value || target.tagName === "INPUT" && ["Home", "End"].includes(e.key) || target.tagName === "TEXTAREA") {
        return;
      }
      const direction = getNavigationDirection(e.key);
      if (direction !== null) {
        e.preventDefault();
        if (props.navigationStrategy === "track") {
          const nextIndex = getNextIndex(direction);
          if (nextIndex !== -1) {
            navigationIndex.value = nextIndex;
          }
        } else {
          focus(direction);
        }
      }
    }
    function onMousedown(e) {
      isFocused.value = true;
    }
    function focus(location) {
      if (contentRef.value) {
        return focusChild(contentRef.value, location);
      }
    }
    useRender(() => {
      var _a, _b;
      const indent = (_a = props.indent) != null ? _a : props.prependGap ? Number(props.prependGap) + 24 : void 0;
      const ariaMultiselectable = isSelectable.value ? (_b = attrs.ariaMultiselectable) != null ? _b : !String(props.selectStrategy).startsWith("single-") : void 0;
      return createVNode(props.tag, {
        "ref": contentRef,
        "class": normalizeClass(["v-list", {
          "v-list--disabled": props.disabled,
          "v-list--nav": props.nav,
          "v-list--slim": props.slim
        }, themeClasses.value, backgroundColorClasses.value, borderClasses.value, densityClasses.value, elevationClasses.value, lineClasses.value, roundedClasses.value, props.class]),
        "style": normalizeStyle([{
          "--v-list-indent": convertToUnit(indent),
          "--v-list-group-prepend": indent ? "0px" : void 0,
          "--v-list-prepend-gap": convertToUnit(props.prependGap)
        }, backgroundColorStyles.value, dimensionStyles.value, props.style]),
        "tabindex": props.disabled ? -1 : 0,
        "role": isSelectable.value ? "listbox" : "list",
        "aria-activedescendant": props.navigationStrategy === "track" && navigationIndex.value >= 0 ? `v-list-item-${uid}-${navigationIndex.value}` : void 0,
        "aria-multiselectable": ariaMultiselectable,
        "onFocusin": onFocusin,
        "onFocusout": onFocusout,
        "onFocus": onFocus,
        "onBlur": onBlur,
        "onKeydown": onKeydown2,
        "onMousedown": onMousedown
      }, {
        default: () => [createVNode(VListChildren, {
          "items": items.value,
          "returnObject": props.returnObject
        }, slots)]
      });
    });
    return {
      open,
      select,
      focus,
      children,
      parents,
      getPath,
      navigationIndex
    };
  }
});
function elementToViewport(point, offset) {
  return {
    x: point.x + offset.x,
    y: point.y + offset.y
  };
}
function getOffset(a, b) {
  return {
    x: a.x - b.x,
    y: a.y - b.y
  };
}
function anchorToPoint(anchor, box) {
  if (anchor.side === "top" || anchor.side === "bottom") {
    const {
      side,
      align
    } = anchor;
    const x = align === "left" ? 0 : align === "center" ? box.width / 2 : align === "right" ? box.width : align;
    const y = side === "top" ? 0 : side === "bottom" ? box.height : side;
    return elementToViewport({
      x,
      y
    }, box);
  } else if (anchor.side === "left" || anchor.side === "right") {
    const {
      side,
      align
    } = anchor;
    const x = side === "left" ? 0 : side === "right" ? box.width : side;
    const y = align === "top" ? 0 : align === "center" ? box.height / 2 : align === "bottom" ? box.height : align;
    return elementToViewport({
      x,
      y
    }, box);
  }
  return elementToViewport({
    x: box.width / 2,
    y: box.height / 2
  }, box);
}
const locationStrategies = {
  static: staticLocationStrategy,
  // specific viewport position, usually centered
  connected: connectedLocationStrategy
  // connected to a certain element
};
const makeLocationStrategyProps = propsFactory({
  locationStrategy: {
    type: [String, Function],
    default: "static",
    validator: (val) => typeof val === "function" || val in locationStrategies
  },
  location: {
    type: String,
    default: "bottom"
  },
  origin: {
    type: String,
    default: "auto"
  },
  offset: [Number, String, Array],
  stickToTarget: Boolean,
  viewportMargin: {
    type: [Number, String],
    default: 12
  }
}, "VOverlay-location-strategies");
function useLocationStrategies(props, data) {
  const contentStyles = ref({});
  const updateLocation = ref();
  return {
    contentStyles,
    updateLocation
  };
}
function staticLocationStrategy() {
}
function getIntrinsicSize(el, isRtl) {
  const contentBox = nullifyTransforms(el);
  if (isRtl) {
    contentBox.x += parseFloat(el.style.right || 0);
  } else {
    contentBox.x -= parseFloat(el.style.left || 0);
  }
  contentBox.y -= parseFloat(el.style.top || 0);
  return contentBox;
}
function connectedLocationStrategy(data, props, contentStyles) {
  const activatorFixed = Array.isArray(data.target.value) || isFixedPosition(data.target.value);
  if (activatorFixed) {
    Object.assign(contentStyles.value, {
      position: "fixed",
      top: 0,
      [data.isRtl.value ? "right" : "left"]: 0
    });
  }
  const {
    preferredAnchor,
    preferredOrigin
  } = destructComputed(() => {
    const parsedAnchor = parseAnchor(props.location, data.isRtl.value);
    const parsedOrigin = props.origin === "overlap" ? parsedAnchor : props.origin === "auto" ? flipSide(parsedAnchor) : parseAnchor(props.origin, data.isRtl.value);
    if (parsedAnchor.side === parsedOrigin.side && parsedAnchor.align === flipAlign(parsedOrigin).align) {
      return {
        preferredAnchor: flipCorner(parsedAnchor),
        preferredOrigin: flipCorner(parsedOrigin)
      };
    } else {
      return {
        preferredAnchor: parsedAnchor,
        preferredOrigin: parsedOrigin
      };
    }
  });
  const [minWidth, minHeight, maxWidth, maxHeight] = ["minWidth", "minHeight", "maxWidth", "maxHeight"].map((key) => {
    return computed(() => {
      const val = parseFloat(props[key]);
      return isNaN(val) ? Infinity : val;
    });
  });
  const offset = computed(() => {
    if (Array.isArray(props.offset)) {
      return props.offset;
    }
    if (typeof props.offset === "string") {
      const offset2 = props.offset.split(" ").map(parseFloat);
      if (offset2.length < 2) offset2.push(0);
      return offset2;
    }
    return typeof props.offset === "number" ? [props.offset, 0] : [0, 0];
  });
  let observe = false;
  let lastFrame = -1;
  const flipped = new CircularBuffer(4);
  const observer = new ResizeObserver(() => {
    if (!observe) return;
    requestAnimationFrame((newTime) => {
      if (newTime !== lastFrame) flipped.clear();
      requestAnimationFrame((newNewTime) => {
        lastFrame = newNewTime;
      });
    });
    if (flipped.isFull) {
      const values = flipped.values();
      if (deepEqual(values.at(-1), values.at(-3)) && !deepEqual(values.at(-1), values.at(-2))) {
        return;
      }
    }
    const result = updateLocation();
    if (result) flipped.push(result.flipped);
  });
  let targetBox = new Box({
    x: 0,
    y: 0,
    width: 0,
    height: 0
  });
  watch(data.target, (newTarget, oldTarget) => {
    if (oldTarget && !Array.isArray(oldTarget)) observer.unobserve(oldTarget);
    if (!Array.isArray(newTarget)) {
      if (newTarget) observer.observe(newTarget);
    } else if (!deepEqual(newTarget, oldTarget)) {
      updateLocation();
    }
  }, {
    immediate: true
  });
  watch(data.contentEl, (newContentEl, oldContentEl) => {
    if (oldContentEl) observer.unobserve(oldContentEl);
    if (newContentEl) observer.observe(newContentEl);
  }, {
    immediate: true
  });
  onScopeDispose(() => {
    observer.disconnect();
  });
  function updateLocation() {
    observe = false;
    requestAnimationFrame(() => observe = true);
    if (!data.target.value || !data.contentEl.value) return;
    if (Array.isArray(data.target.value) || data.target.value.offsetParent || data.target.value.getClientRects().length) {
      targetBox = getTargetBox(data.target.value);
    }
    const contentBox = getIntrinsicSize(data.contentEl.value, data.isRtl.value);
    const scrollParents = getScrollParents(data.contentEl.value);
    const viewportMargin = Number(props.viewportMargin);
    if (!scrollParents.length) {
      scrollParents.push((void 0).documentElement);
      if (!(data.contentEl.value.style.top && data.contentEl.value.style.left)) {
        contentBox.x -= parseFloat((void 0).documentElement.style.getPropertyValue("--v-body-scroll-x") || 0);
        contentBox.y -= parseFloat((void 0).documentElement.style.getPropertyValue("--v-body-scroll-y") || 0);
      }
    }
    const viewport = scrollParents.reduce((box, el) => {
      const scrollBox = getElementBox(el);
      if (box) {
        return new Box({
          x: Math.max(box.left, scrollBox.left),
          y: Math.max(box.top, scrollBox.top),
          width: Math.min(box.right, scrollBox.right) - Math.max(box.left, scrollBox.left),
          height: Math.min(box.bottom, scrollBox.bottom) - Math.max(box.top, scrollBox.top)
        });
      }
      return scrollBox;
    }, void 0);
    if (props.stickToTarget) {
      viewport.x += Math.min(viewportMargin, targetBox.x);
      viewport.y += Math.min(viewportMargin, targetBox.y);
      viewport.width = Math.max(viewport.width - viewportMargin * 2, targetBox.x + targetBox.width - viewportMargin);
      viewport.height = Math.max(viewport.height - viewportMargin * 2, targetBox.y + targetBox.height - viewportMargin);
    } else {
      viewport.x += viewportMargin;
      viewport.y += viewportMargin;
      viewport.width -= viewportMargin * 2;
      viewport.height -= viewportMargin * 2;
    }
    let placement = {
      anchor: preferredAnchor.value,
      origin: preferredOrigin.value
    };
    function checkOverflow(_placement) {
      const box = new Box(contentBox);
      const targetPoint = anchorToPoint(_placement.anchor, targetBox);
      const contentPoint = anchorToPoint(_placement.origin, box);
      let {
        x: x2,
        y: y2
      } = getOffset(targetPoint, contentPoint);
      switch (_placement.anchor.side) {
        case "top":
          y2 -= offset.value[0];
          break;
        case "bottom":
          y2 += offset.value[0];
          break;
        case "left":
          x2 -= offset.value[0];
          break;
        case "right":
          x2 += offset.value[0];
          break;
      }
      switch (_placement.anchor.align) {
        case "top":
          y2 -= offset.value[1];
          break;
        case "bottom":
          y2 += offset.value[1];
          break;
        case "left":
          x2 -= offset.value[1];
          break;
        case "right":
          x2 += offset.value[1];
          break;
      }
      box.x += x2;
      box.y += y2;
      box.width = Math.min(box.width, maxWidth.value);
      box.height = Math.min(box.height, maxHeight.value);
      const overflows = getOverflow(box, viewport);
      return {
        overflows,
        x: x2,
        y: y2
      };
    }
    let x = 0;
    let y = 0;
    const available = {
      x: 0,
      y: 0
    };
    const flipped2 = {
      x: false,
      y: false
    };
    let resets = -1;
    while (true) {
      if (resets++ > 10) {
        consoleError("Infinite loop detected in connectedLocationStrategy");
        break;
      }
      const {
        x: _x,
        y: _y,
        overflows
      } = checkOverflow(placement);
      x += _x;
      y += _y;
      contentBox.x += _x;
      contentBox.y += _y;
      {
        const axis2 = getAxis(placement.anchor);
        const hasOverflowX = overflows.x.before || overflows.x.after;
        const hasOverflowY = overflows.y.before || overflows.y.after;
        let reset = false;
        ["x", "y"].forEach((key) => {
          if (key === "x" && hasOverflowX && !flipped2.x || key === "y" && hasOverflowY && !flipped2.y) {
            const newPlacement = {
              anchor: {
                ...placement.anchor
              },
              origin: {
                ...placement.origin
              }
            };
            const flip = key === "x" ? axis2 === "y" ? flipAlign : flipSide : axis2 === "y" ? flipSide : flipAlign;
            newPlacement.anchor = flip(newPlacement.anchor);
            newPlacement.origin = flip(newPlacement.origin);
            const {
              overflows: newOverflows
            } = checkOverflow(newPlacement);
            if (newOverflows[key].before <= overflows[key].before && newOverflows[key].after <= overflows[key].after || newOverflows[key].before + newOverflows[key].after < (overflows[key].before + overflows[key].after) / 2) {
              placement = newPlacement;
              reset = flipped2[key] = true;
            }
          }
        });
        if (reset) continue;
      }
      if (overflows.x.before) {
        x += overflows.x.before;
        contentBox.x += overflows.x.before;
      }
      if (overflows.x.after) {
        x -= overflows.x.after;
        contentBox.x -= overflows.x.after;
      }
      if (overflows.y.before) {
        y += overflows.y.before;
        contentBox.y += overflows.y.before;
      }
      if (overflows.y.after) {
        y -= overflows.y.after;
        contentBox.y -= overflows.y.after;
      }
      {
        const overflows2 = getOverflow(contentBox, viewport);
        available.x = viewport.width - overflows2.x.before - overflows2.x.after;
        available.y = viewport.height - overflows2.y.before - overflows2.y.after;
        x += overflows2.x.before;
        contentBox.x += overflows2.x.before;
        y += overflows2.y.before;
        contentBox.y += overflows2.y.before;
      }
      break;
    }
    const axis = getAxis(placement.anchor);
    Object.assign(contentStyles.value, {
      "--v-overlay-anchor-origin": `${placement.anchor.side} ${placement.anchor.align}`,
      transformOrigin: `${placement.origin.side} ${placement.origin.align}`,
      // transform: `translate(${pixelRound(x)}px, ${pixelRound(y)}px)`,
      top: convertToUnit(pixelRound(y)),
      left: data.isRtl.value ? void 0 : convertToUnit(pixelRound(x)),
      right: data.isRtl.value ? convertToUnit(pixelRound(-x)) : void 0,
      minWidth: convertToUnit(axis === "y" ? Math.min(minWidth.value, targetBox.width) : minWidth.value),
      maxWidth: convertToUnit(pixelCeil(clamp(available.x, minWidth.value === Infinity ? 0 : minWidth.value, maxWidth.value))),
      maxHeight: convertToUnit(pixelCeil(clamp(available.y, minHeight.value === Infinity ? 0 : minHeight.value, maxHeight.value)))
    });
    return {
      available,
      contentBox,
      flipped: flipped2
    };
  }
  watch(() => [preferredAnchor.value, preferredOrigin.value, props.offset, props.minWidth, props.minHeight, props.maxWidth, props.maxHeight], () => updateLocation());
  nextTick(() => {
    const result = updateLocation();
    if (!result) return;
    const {
      available,
      contentBox
    } = result;
    if (contentBox.height > available.y) {
      requestAnimationFrame(() => {
        updateLocation();
        requestAnimationFrame(() => {
          updateLocation();
        });
      });
    }
  });
  return {
    updateLocation
  };
}
function pixelRound(val) {
  return Math.round(val * devicePixelRatio) / devicePixelRatio;
}
function pixelCeil(val) {
  return Math.ceil(val * devicePixelRatio) / devicePixelRatio;
}
let clean = true;
const frames = [];
function requestNewFrame(cb) {
  if (!clean || frames.length) {
    frames.push(cb);
    run();
  } else {
    clean = false;
    cb();
    run();
  }
}
let raf = -1;
function run() {
  cancelAnimationFrame(raf);
  raf = requestAnimationFrame(() => {
    const frame = frames.shift();
    if (frame) frame();
    if (frames.length) run();
    else clean = true;
  });
}
const scrollStrategies = {
  none: null,
  close: closeScrollStrategy,
  block: blockScrollStrategy,
  reposition: repositionScrollStrategy
};
const makeScrollStrategyProps = propsFactory({
  scrollStrategy: {
    type: [String, Function],
    default: "block",
    validator: (val) => typeof val === "function" || val in scrollStrategies
  }
}, "VOverlay-scroll-strategies");
function closeScrollStrategy(data) {
  function onScroll(e) {
    data.isActive.value = false;
  }
  bindScroll(getTargetEl(data.target.value, data.contentEl.value), onScroll);
}
function blockScrollStrategy(data, props) {
  var _a;
  const offsetParent = (_a = data.root.value) == null ? void 0 : _a.offsetParent;
  const target = getTargetEl(data.target.value, data.contentEl.value);
  const scrollElements = [.../* @__PURE__ */ new Set([...getScrollParents(target, props.contained ? offsetParent : void 0), ...getScrollParents(data.contentEl.value, props.contained ? offsetParent : void 0)])].filter((el) => !el.classList.contains("v-overlay-scroll-blocked"));
  const scrollbarWidth = (void 0).innerWidth - (void 0).documentElement.offsetWidth;
  const scrollableParent = ((el) => hasScrollbar(el) && el)(offsetParent || (void 0).documentElement);
  if (scrollableParent) {
    data.root.value.classList.add("v-overlay--scroll-blocked");
  }
  scrollElements.forEach((el, i) => {
    el.style.setProperty("--v-body-scroll-x", convertToUnit(-el.scrollLeft));
    el.style.setProperty("--v-body-scroll-y", convertToUnit(-el.scrollTop));
    if (el !== (void 0).documentElement) {
      el.style.setProperty("--v-scrollbar-offset", convertToUnit(scrollbarWidth));
    }
    el.classList.add("v-overlay-scroll-blocked");
  });
  onScopeDispose(() => {
    scrollElements.forEach((el, i) => {
      const x = parseFloat(el.style.getPropertyValue("--v-body-scroll-x"));
      const y = parseFloat(el.style.getPropertyValue("--v-body-scroll-y"));
      const scrollBehavior = el.style.scrollBehavior;
      el.style.scrollBehavior = "auto";
      el.style.removeProperty("--v-body-scroll-x");
      el.style.removeProperty("--v-body-scroll-y");
      el.style.removeProperty("--v-scrollbar-offset");
      el.classList.remove("v-overlay-scroll-blocked");
      el.scrollLeft = -x;
      el.scrollTop = -y;
      el.style.scrollBehavior = scrollBehavior;
    });
    if (scrollableParent) {
      data.root.value.classList.remove("v-overlay--scroll-blocked");
    }
  });
}
function repositionScrollStrategy(data, props, scope) {
  let slow = false;
  let raf2 = -1;
  let ric = -1;
  function update(e) {
    requestNewFrame(() => {
      var _a, _b;
      const start = performance.now();
      (_b = (_a = data.updateLocation).value) == null ? void 0 : _b.call(_a, e);
      const time = performance.now() - start;
      slow = time / (1e3 / 60) > 2;
    });
  }
  ric = (typeof requestIdleCallback === "undefined" ? (cb) => cb() : requestIdleCallback)(() => {
    scope.run(() => {
      bindScroll(getTargetEl(data.target.value, data.contentEl.value), (e) => {
        if (slow) {
          cancelAnimationFrame(raf2);
          raf2 = requestAnimationFrame(() => {
            raf2 = requestAnimationFrame(() => {
              update(e);
            });
          });
        } else {
          update(e);
        }
      });
    });
  });
  onScopeDispose(() => {
    typeof cancelIdleCallback !== "undefined" && cancelIdleCallback(ric);
    cancelAnimationFrame(raf2);
  });
}
function getTargetEl(target, contentEl) {
  return Array.isArray(target) ? (void 0).elementsFromPoint(...target).find((el) => !(contentEl == null ? void 0 : contentEl.contains(el))) : target != null ? target : contentEl;
}
function bindScroll(el, onScroll) {
  const scrollElements = [void 0, ...getScrollParents(el)];
  scrollElements.forEach((el2) => {
    el2.addEventListener("scroll", onScroll, {
      passive: true
    });
  });
  onScopeDispose(() => {
    scrollElements.forEach((el2) => {
      el2.removeEventListener("scroll", onScroll);
    });
  });
}
const VMenuSymbol = /* @__PURE__ */ Symbol.for("vuetify:v-menu");
const makeDelayProps = propsFactory({
  closeDelay: [Number, String],
  openDelay: [Number, String]
}, "delay");
function useDelay(props, cb) {
  let clearDelay = () => {
  };
  function runDelay(isOpening, options) {
    var _a;
    clearDelay == null ? void 0 : clearDelay();
    const delay = isOpening ? props.openDelay : props.closeDelay;
    const normalizedDelay = Math.max((_a = options == null ? void 0 : options.minDelay) != null ? _a : 0, Number(delay != null ? delay : 0));
    return new Promise((resolve) => {
      clearDelay = defer(normalizedDelay, () => {
        cb == null ? void 0 : cb(isOpening);
        resolve(isOpening);
      });
    });
  }
  function runOpenDelay() {
    return runDelay(true);
  }
  function runCloseDelay(options) {
    return runDelay(false, options);
  }
  return {
    clearDelay,
    runOpenDelay,
    runCloseDelay
  };
}
const makeActivatorProps = propsFactory({
  target: [String, Object],
  activator: [String, Object],
  activatorProps: {
    type: Object,
    default: () => ({})
  },
  openOnClick: {
    type: Boolean,
    default: void 0
  },
  openOnHover: Boolean,
  openOnFocus: {
    type: Boolean,
    default: void 0
  },
  closeOnContentClick: Boolean,
  ...makeDelayProps()
}, "VOverlay-activator");
function useActivator(props, _ref) {
  let {
    isActive,
    isTop,
    contentEl
  } = _ref;
  const vm = getCurrentInstance$1("useActivator");
  const activatorEl = ref();
  let isHovered = false;
  let isFocused = false;
  let firstEnter = true;
  const openOnFocus = computed(() => props.openOnFocus || props.openOnFocus == null && props.openOnHover);
  const openOnClick = computed(() => props.openOnClick || props.openOnClick == null && !props.openOnHover && !openOnFocus.value);
  const {
    runOpenDelay,
    runCloseDelay
  } = useDelay(props, (value) => {
    if (value === (props.openOnHover && isHovered || openOnFocus.value && isFocused) && !(props.openOnHover && isActive.value && !isTop.value)) {
      if (isActive.value !== value) {
        firstEnter = true;
      }
      isActive.value = value;
    }
  });
  const cursorTarget = ref();
  const availableEvents = {
    onClick: (e) => {
      e.stopPropagation();
      activatorEl.value = e.currentTarget || e.target;
      if (!isActive.value) {
        cursorTarget.value = [e.clientX, e.clientY];
      }
      isActive.value = !isActive.value;
    },
    onMouseenter: (e) => {
      isHovered = true;
      activatorEl.value = e.currentTarget || e.target;
      runOpenDelay();
    },
    onMouseleave: (e) => {
      isHovered = false;
      runCloseDelay();
    },
    onFocus: (e) => {
      if (matchesSelector(e.target) === false) ;
      isFocused = true;
      e.stopPropagation();
      activatorEl.value = e.currentTarget || e.target;
      runOpenDelay();
    },
    onBlur: (e) => {
      isFocused = false;
      e.stopPropagation();
      runCloseDelay({
        minDelay: 1
      });
    }
  };
  const activatorEvents = computed(() => {
    const events = {};
    if (openOnClick.value) {
      events.onClick = availableEvents.onClick;
    }
    if (props.openOnHover) {
      events.onMouseenter = availableEvents.onMouseenter;
      events.onMouseleave = availableEvents.onMouseleave;
    }
    if (openOnFocus.value) {
      events.onFocus = availableEvents.onFocus;
      events.onBlur = availableEvents.onBlur;
    }
    return events;
  });
  const contentEvents = computed(() => {
    const events = {};
    if (props.openOnHover) {
      events.onMouseenter = () => {
        isHovered = true;
        runOpenDelay();
      };
      events.onMouseleave = () => {
        isHovered = false;
        runCloseDelay();
      };
    }
    if (openOnFocus.value) {
      events.onFocusin = (e) => {
        if (!e.target.matches(":focus-visible")) return;
        isFocused = true;
        runOpenDelay();
      };
      events.onFocusout = () => {
        isFocused = false;
        runCloseDelay({
          minDelay: 1
        });
      };
    }
    if (props.closeOnContentClick) {
      const menu = inject(VMenuSymbol, null);
      events.onClick = () => {
        isActive.value = false;
        menu == null ? void 0 : menu.closeParents();
      };
    }
    return events;
  });
  const scrimEvents = computed(() => {
    const events = {};
    if (props.openOnHover) {
      events.onMouseenter = () => {
        if (firstEnter) {
          isHovered = true;
          firstEnter = false;
          runOpenDelay();
        }
      };
      events.onMouseleave = () => {
        isHovered = false;
        runCloseDelay();
      };
    }
    return events;
  });
  watch(isTop, (val) => {
    var _a;
    if (val && (props.openOnHover && !isHovered && (!openOnFocus.value || !isFocused) || openOnFocus.value && !isFocused && (!props.openOnHover || !isHovered)) && !((_a = contentEl.value) == null ? void 0 : _a.contains((void 0).activeElement))) {
      runCloseDelay();
    }
  });
  watch(isActive, (val) => {
    if (!val) {
      setTimeout(() => {
        cursorTarget.value = void 0;
      });
    }
  }, {
    flush: "post"
  });
  const activatorRef = templateRef();
  watchEffect(() => {
    if (!activatorRef.value) return;
    nextTick(() => {
      activatorEl.value = activatorRef.el;
    });
  });
  const targetRef = templateRef();
  const target = computed(() => {
    if (props.target === "cursor" && cursorTarget.value) return cursorTarget.value;
    if (targetRef.value) return targetRef.el;
    return getTarget(props.target, vm) || activatorEl.value;
  });
  const targetEl = computed(() => {
    return Array.isArray(target.value) ? void 0 : target.value;
  });
  watch(() => !!props.activator, (val) => {
  }, {
    flush: "post",
    immediate: true
  });
  onScopeDispose(() => {
  });
  return {
    activatorEl,
    activatorRef,
    target,
    targetEl,
    targetRef,
    activatorEvents,
    contentEvents,
    scrimEvents
  };
}
function getTarget(selector, vm) {
  var _a, _b;
  if (!selector) return;
  let target;
  if (selector === "parent") {
    let el = (_b = (_a = vm == null ? void 0 : vm.proxy) == null ? void 0 : _a.$el) == null ? void 0 : _b.parentNode;
    while (el == null ? void 0 : el.hasAttribute("data-no-activator")) {
      el = el.parentNode;
    }
    target = el;
  } else if (typeof selector === "string") {
    target = (void 0).querySelector(selector);
  } else if ("$el" in selector) {
    target = selector.$el;
  } else {
    target = selector;
  }
  return target;
}
const makeFocusTrapProps = propsFactory({
  retainFocus: Boolean,
  captureFocus: Boolean,
  /** @deprecated */
  disableInitialFocus: Boolean
}, "focusTrap");
const registry = /* @__PURE__ */ new Map();
let subscribers = 0;
function onKeydown(e) {
  const activeElement = (void 0).activeElement;
  if (e.key !== "Tab" || !activeElement) return;
  const parentTraps = Array.from(registry.values()).filter((_ref) => {
    var _a;
    let {
      isActive,
      contentEl
    } = _ref;
    return isActive.value && ((_a = contentEl.value) == null ? void 0 : _a.contains(activeElement));
  }).map((x) => x.contentEl.value);
  let closestTrap;
  let currentParent = activeElement.parentElement;
  while (currentParent) {
    if (parentTraps.includes(currentParent)) {
      closestTrap = currentParent;
      break;
    }
    currentParent = currentParent.parentElement;
  }
  if (!closestTrap) return;
  const focusable = focusableChildren(closestTrap).filter((x) => x.tabIndex >= 0);
  if (!focusable.length) return;
  const active = (void 0).activeElement;
  if (focusable.length === 1 && focusable[0].classList.contains("v-list") && focusable[0].contains(active)) {
    e.preventDefault();
    return;
  }
  const firstElement = focusable[0];
  const lastElement = focusable[focusable.length - 1];
  if (e.shiftKey && (active === firstElement || firstElement.classList.contains("v-list") && firstElement.contains(active))) {
    e.preventDefault();
    lastElement.focus();
  }
  if (!e.shiftKey && (active === lastElement || lastElement.classList.contains("v-list") && lastElement.contains(active))) {
    e.preventDefault();
    firstElement.focus();
  }
}
function useFocusTrap(props, _ref2) {
  let {
    isActive,
    localTop,
    contentEl
  } = _ref2;
  const trapId = /* @__PURE__ */ Symbol("trap");
  let focusTrapSuppressed = false;
  let focusTrapSuppressionTimeout = -1;
  async function onPointerdown() {
    focusTrapSuppressed = true;
    focusTrapSuppressionTimeout = (void 0).setTimeout(() => {
      focusTrapSuppressed = false;
    }, 100);
  }
  async function captureOnFocus(e) {
    var _a;
    const before = e.relatedTarget;
    const after = e.target;
    (void 0).removeEventListener("pointerdown", onPointerdown);
    (void 0).removeEventListener("keydown", captureOnKeydown);
    await nextTick();
    if (isActive.value && !focusTrapSuppressed && before !== after && contentEl.value && // We're the menu without open submenus or overlays
    toValue(localTop) && // It isn't the document or the container body
    ![void 0, contentEl.value].includes(after) && // It isn't inside the container body
    !contentEl.value.contains(after)) {
      const focusable = focusableChildren(contentEl.value);
      (_a = focusable[0]) == null ? void 0 : _a.focus();
    }
  }
  function captureOnKeydown(e) {
    if (e.key !== "Tab") return;
    (void 0).removeEventListener("keydown", captureOnKeydown);
    if (isActive.value && contentEl.value && e.target && !contentEl.value.contains(e.target)) {
      const allFocusableElements = focusableChildren((void 0).documentElement);
      if (e.shiftKey && e.target === allFocusableElements.at(0) || !e.shiftKey && e.target === allFocusableElements.at(-1)) {
        const focusable = focusableChildren(contentEl.value);
        if (focusable.length > 0) {
          e.preventDefault();
          focusable[0].focus();
        }
      }
    }
  }
  toRef(() => isActive.value && props.captureFocus && !props.disableInitialFocus);
  onScopeDispose(() => {
    registry.delete(trapId);
    clearTimeout(focusTrapSuppressionTimeout);
    (void 0).removeEventListener("pointerdown", onPointerdown);
    (void 0).removeEventListener("focusin", captureOnFocus);
    (void 0).removeEventListener("keydown", captureOnKeydown);
    if (--subscribers < 1) {
      (void 0).removeEventListener("keydown", onKeydown);
    }
  });
}
function useHydration() {
  return shallowRef(false);
}
function useScopeId() {
  const vm = getCurrentInstance$1("useScopeId");
  const scopeId = vm.vnode.scopeId;
  return {
    scopeId: scopeId ? {
      [scopeId]: ""
    } : void 0
  };
}
const StackSymbol = /* @__PURE__ */ Symbol.for("vuetify:stack");
const globalStack = reactive([]);
function useStack(isActive, zIndex, disableGlobalStack) {
  const vm = getCurrentInstance$1("useStack");
  const createStackEntry = !disableGlobalStack;
  const parent = inject(StackSymbol, void 0);
  const stack = reactive({
    activeChildren: /* @__PURE__ */ new Set()
  });
  provide(StackSymbol, stack);
  const _zIndex = shallowRef(Number(toValue(zIndex)));
  useToggleScope(isActive, () => {
    var _a;
    const lastZIndex = (_a = globalStack.at(-1)) == null ? void 0 : _a[1];
    _zIndex.value = lastZIndex ? lastZIndex + 10 : Number(toValue(zIndex));
    if (createStackEntry) {
      globalStack.push([vm.uid, _zIndex.value]);
    }
    parent == null ? void 0 : parent.activeChildren.add(vm.uid);
    onScopeDispose(() => {
      if (createStackEntry) {
        const idx = toRaw(globalStack).findIndex((v) => v[0] === vm.uid);
        globalStack.splice(idx, 1);
      }
      parent == null ? void 0 : parent.activeChildren.delete(vm.uid);
    });
  });
  const globalTop = shallowRef(true);
  if (createStackEntry) {
    watchEffect(() => {
      var _a;
      const _isTop = ((_a = globalStack.at(-1)) == null ? void 0 : _a[0]) === vm.uid;
      setTimeout(() => globalTop.value = _isTop);
    });
  }
  const localTop = toRef(() => !stack.activeChildren.size);
  return {
    globalTop: readonly(globalTop),
    localTop,
    stackStyles: toRef(() => ({
      zIndex: _zIndex.value
    }))
  };
}
function useTeleport(target) {
  const teleportTarget = computed(() => {
    target();
    return void 0;
  });
  return {
    teleportTarget
  };
}
function defaultConditional() {
  return true;
}
function checkEvent(e, el, binding) {
  if (!e || checkIsActive(e, binding) === false) return false;
  const root = attachedRoot(el);
  if (typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot && root.host === e.target) return false;
  const elements = (typeof binding.value === "object" && binding.value.include || (() => []))();
  elements.push(el);
  return !elements.some((el2) => el2 == null ? void 0 : el2.contains(e.target));
}
function checkIsActive(e, binding) {
  const isActive = typeof binding.value === "object" && binding.value.closeConditional || defaultConditional;
  return isActive(e);
}
function directive(e, el, binding) {
  const handler = typeof binding.value === "function" ? binding.value : binding.value.handler;
  e.shadowTarget = e.target;
  el._clickOutside.lastMousedownWasOutside && checkEvent(e, el, binding) && setTimeout(() => {
    checkIsActive(e, binding) && handler && handler(e);
  }, 0);
}
function handleShadow(el, callback) {
  const root = attachedRoot(el);
  callback(void 0);
  if (typeof ShadowRoot !== "undefined" && root instanceof ShadowRoot) {
    callback(root);
  }
}
const ClickOutside = {
  // [data-app] may not be found
  // if using bind, inserted makes
  // sure that the root element is
  // available, iOS does not support
  // clicks on body
  mounted(el, binding) {
    const onClick = (e) => directive(e, el, binding);
    const onMousedown = (e) => {
      el._clickOutside.lastMousedownWasOutside = checkEvent(e, el, binding);
    };
    handleShadow(el, (app) => {
      app.addEventListener("click", onClick, true);
      app.addEventListener("mousedown", onMousedown, true);
    });
    if (!el._clickOutside) {
      el._clickOutside = {
        lastMousedownWasOutside: false
      };
    }
    el._clickOutside[binding.instance.$.uid] = {
      onClick,
      onMousedown
    };
  },
  beforeUnmount(el, binding) {
    if (!el._clickOutside) return;
    handleShadow(el, (app) => {
      var _a;
      if (!app || !((_a = el._clickOutside) == null ? void 0 : _a[binding.instance.$.uid])) return;
      const {
        onClick,
        onMousedown
      } = el._clickOutside[binding.instance.$.uid];
      app.removeEventListener("click", onClick, true);
      app.removeEventListener("mousedown", onMousedown, true);
    });
    delete el._clickOutside[binding.instance.$.uid];
  }
};
function Scrim(props) {
  const {
    modelValue,
    color,
    ...rest
  } = props;
  return createVNode(Transition, {
    "name": "fade-transition",
    "appear": true
  }, {
    default: () => [props.modelValue && createElementVNode("div", mergeProps({
      "class": ["v-overlay__scrim", props.color.backgroundColorClasses.value],
      "style": props.color.backgroundColorStyles.value
    }, rest), null)]
  });
}
const makeVOverlayProps = propsFactory({
  absolute: Boolean,
  attach: [Boolean, String, Object],
  closeOnBack: {
    type: Boolean,
    default: true
  },
  contained: Boolean,
  contentClass: null,
  contentProps: null,
  disabled: Boolean,
  opacity: [Number, String],
  noClickAnimation: Boolean,
  modelValue: Boolean,
  persistent: Boolean,
  scrim: {
    type: [Boolean, String],
    default: true
  },
  zIndex: {
    type: [Number, String],
    default: 2e3
  },
  ...makeActivatorProps(),
  ...makeComponentProps(),
  ...makeDimensionProps(),
  ...makeLazyProps(),
  ...makeLocationStrategyProps(),
  ...makeScrollStrategyProps(),
  ...makeFocusTrapProps(),
  ...makeThemeProps(),
  ...makeTransitionProps()
}, "VOverlay");
const VOverlay = genericComponent()({
  name: "VOverlay",
  directives: {
    vClickOutside: ClickOutside
  },
  inheritAttrs: false,
  props: {
    _disableGlobalStack: Boolean,
    ...omit(makeVOverlayProps(), ["disableInitialFocus"])
  },
  emits: {
    "click:outside": (e) => true,
    "update:modelValue": (value) => true,
    keydown: (e) => true,
    afterEnter: () => true,
    afterLeave: () => true
  },
  setup(props, _ref) {
    let {
      slots,
      attrs,
      emit
    } = _ref;
    const vm = getCurrentInstance$1("VOverlay");
    const root = ref();
    const scrimEl = ref();
    const contentEl = ref();
    const model = useProxiedModel(props, "modelValue");
    const isActive = computed({
      get: () => model.value,
      set: (v) => {
        if (!(v && props.disabled)) model.value = v;
      }
    });
    const {
      themeClasses
    } = provideTheme(props);
    const {
      rtlClasses
    } = useRtl();
    const {
      hasContent,
      onAfterLeave: _onAfterLeave
    } = useLazy(props, isActive);
    const scrimColor = useBackgroundColor(() => {
      return typeof props.scrim === "string" ? props.scrim : null;
    });
    const {
      globalTop,
      localTop,
      stackStyles
    } = useStack(isActive, () => props.zIndex, props._disableGlobalStack);
    const {
      activatorEl,
      activatorRef,
      target,
      targetRef,
      activatorEvents,
      contentEvents,
      scrimEvents
    } = useActivator(props, {
      isActive,
      isTop: localTop,
      contentEl
    });
    const {
      teleportTarget
    } = useTeleport(() => {
      var _a, _b, _c;
      const target2 = props.attach || props.contained;
      if (target2) return target2;
      const rootNode = ((_a = activatorEl == null ? void 0 : activatorEl.value) == null ? void 0 : _a.getRootNode()) || ((_c = (_b = vm.proxy) == null ? void 0 : _b.$el) == null ? void 0 : _c.getRootNode());
      if (rootNode instanceof ShadowRoot) return rootNode;
      return false;
    });
    const {
      dimensionStyles
    } = useDimension(props);
    const isMounted = useHydration();
    const {
      scopeId
    } = useScopeId();
    watch(() => props.disabled, (v) => {
      if (v) isActive.value = false;
    });
    const {
      contentStyles,
      updateLocation
    } = useLocationStrategies();
    function onClickOutside(e) {
      emit("click:outside", e);
      if (!props.persistent) isActive.value = false;
      else animateClick();
    }
    function closeConditional(e) {
      return isActive.value && localTop.value && // If using scrim, only close if clicking on it rather than anything opened on top
      (!props.scrim || e.target === scrimEl.value || e instanceof MouseEvent && e.shadowTarget === scrimEl.value);
    }
    useFocusTrap(props, {
      isActive,
      localTop,
      contentEl
    });
    function onKeydownSelf(e) {
      if (e.key === "Escape" && !globalTop.value) return;
      emit("keydown", e);
    }
    useRouter();
    useToggleScope(() => props.closeOnBack, () => {
    });
    const top = ref();
    watch(() => isActive.value && (props.absolute || props.contained) && teleportTarget.value == null, (val) => {
      if (val) {
        const scrollParent = getScrollParent(root.value);
        if (scrollParent && scrollParent !== (void 0).scrollingElement) {
          top.value = scrollParent.scrollTop;
        }
      }
    });
    function animateClick() {
      if (props.noClickAnimation) return;
      contentEl.value && animate(contentEl.value, [{
        transformOrigin: "center"
      }, {
        transform: "scale(1.03)"
      }, {
        transformOrigin: "center"
      }], {
        duration: 150,
        easing: standardEasing
      });
    }
    function onAfterEnter() {
      emit("afterEnter");
    }
    function onAfterLeave() {
      _onAfterLeave();
      emit("afterLeave");
    }
    useRender(() => {
      var _a;
      return createElementVNode(Fragment, null, [(_a = slots.activator) == null ? void 0 : _a.call(slots, {
        isActive: isActive.value,
        targetRef,
        props: mergeProps({
          ref: activatorRef
        }, activatorEvents.value, props.activatorProps)
      }), isMounted.value && hasContent.value && createVNode(Teleport, {
        "disabled": !teleportTarget.value,
        "to": teleportTarget.value
      }, {
        default: () => [createElementVNode("div", mergeProps({
          "class": ["v-overlay", {
            "v-overlay--absolute": props.absolute || props.contained,
            "v-overlay--active": isActive.value,
            "v-overlay--contained": props.contained
          }, themeClasses.value, rtlClasses.value, props.class],
          "style": [stackStyles.value, {
            "--v-overlay-opacity": props.opacity,
            top: convertToUnit(top.value)
          }, props.style],
          "ref": root,
          "onKeydown": onKeydownSelf
        }, scopeId, attrs), [createVNode(Scrim, mergeProps({
          "color": scrimColor,
          "modelValue": isActive.value && !!props.scrim,
          "ref": scrimEl
        }, scrimEvents.value), null), createVNode(MaybeTransition, {
          "appear": true,
          "persisted": true,
          "transition": props.transition,
          "target": target.value,
          "onAfterEnter": onAfterEnter,
          "onAfterLeave": onAfterLeave
        }, {
          default: () => {
            var _a2;
            return [withDirectives(createElementVNode("div", mergeProps({
              "ref": contentEl,
              "class": ["v-overlay__content", props.contentClass],
              "style": [dimensionStyles.value, contentStyles.value]
            }, contentEvents.value, props.contentProps), [(_a2 = slots.default) == null ? void 0 : _a2.call(slots, {
              isActive
            })]), [[vShow, isActive.value], [ClickOutside, {
              handler: onClickOutside,
              closeConditional,
              include: () => [activatorEl.value]
            }]])];
          }
        })])]
      })]);
    });
    return {
      activatorEl,
      scrimEl,
      target,
      animateClick,
      contentEl,
      rootEl: root,
      globalTop,
      localTop,
      updateLocation
    };
  }
});
const makeVMenuProps = propsFactory({
  // TODO
  // disableKeys: Boolean,
  id: String,
  submenu: Boolean,
  ...omit(makeVOverlayProps({
    captureFocus: true,
    closeDelay: 250,
    closeOnContentClick: true,
    locationStrategy: "connected",
    location: void 0,
    openDelay: 300,
    scrim: false,
    scrollStrategy: "reposition",
    transition: {
      component: VDialogTransition
    }
  }), ["absolute"])
}, "VMenu");
const VMenu = genericComponent()({
  name: "VMenu",
  props: makeVMenuProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const isActive = useProxiedModel(props, "modelValue");
    const {
      scopeId
    } = useScopeId();
    const {
      isRtl
    } = useRtl();
    const uid = useId();
    const id = toRef(() => props.id || `v-menu-${uid}`);
    const overlay = ref();
    const parent = inject(VMenuSymbol, null);
    const openChildren = shallowRef(/* @__PURE__ */ new Set());
    provide(VMenuSymbol, {
      register() {
        openChildren.value.add(uid);
      },
      unregister() {
        openChildren.value.delete(uid);
      },
      closeParents(e) {
        setTimeout(() => {
          var _a;
          if (!openChildren.value.size && !props.persistent && (e == null || ((_a = overlay.value) == null ? void 0 : _a.contentEl) && !isClickInsideElement(e, overlay.value.contentEl))) {
            isActive.value = false;
            parent == null ? void 0 : parent.closeParents();
          }
        }, 40);
      }
    });
    watch(isActive, (val) => {
      val ? parent == null ? void 0 : parent.register() : parent == null ? void 0 : parent.unregister();
    }, {
      immediate: true
    });
    function onClickOutside(e) {
      parent == null ? void 0 : parent.closeParents(e);
    }
    function onKeydown2(e) {
      var _a, _b, _c, _d, _e;
      if (props.disabled) return;
      if (e.key === "Tab" || e.key === "Enter" && !props.closeOnContentClick) {
        if (e.key === "Enter" && (e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLInputElement && !!e.target.closest("form"))) return;
        if (e.key === "Enter") e.preventDefault();
        const nextElement = getNextElement(focusableChildren((_a = overlay.value) == null ? void 0 : _a.contentEl, false), e.shiftKey ? "prev" : "next", (el) => el.tabIndex >= 0);
        if (!nextElement && !props.retainFocus) {
          isActive.value = false;
          (_c = (_b = overlay.value) == null ? void 0 : _b.activatorEl) == null ? void 0 : _c.focus();
        }
      } else if (props.submenu && e.key === (isRtl.value ? "ArrowRight" : "ArrowLeft")) {
        isActive.value = false;
        (_e = (_d = overlay.value) == null ? void 0 : _d.activatorEl) == null ? void 0 : _e.focus();
      }
    }
    function onActivatorKeydown(e) {
      var _a;
      if (props.disabled) return;
      const el = (_a = overlay.value) == null ? void 0 : _a.contentEl;
      if (el && isActive.value) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          e.stopImmediatePropagation();
          focusChild(el, "next");
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          e.stopImmediatePropagation();
          focusChild(el, "prev");
        } else if (props.submenu) {
          if (e.key === (isRtl.value ? "ArrowRight" : "ArrowLeft")) {
            isActive.value = false;
          } else if (e.key === (isRtl.value ? "ArrowLeft" : "ArrowRight")) {
            e.preventDefault();
            focusChild(el, "first");
          }
        }
      } else if (props.submenu ? e.key === (isRtl.value ? "ArrowLeft" : "ArrowRight") : ["ArrowDown", "ArrowUp"].includes(e.key)) {
        isActive.value = true;
        e.preventDefault();
        setTimeout(() => setTimeout(() => onActivatorKeydown(e)));
      }
    }
    const activatorProps = computed(() => mergeProps({
      "aria-haspopup": "menu",
      "aria-expanded": String(isActive.value),
      "aria-controls": id.value,
      "aria-owns": id.value,
      onKeydown: onActivatorKeydown
    }, props.activatorProps));
    useRender(() => {
      var _a;
      const overlayProps = VOverlay.filterProps(props);
      return createVNode(VOverlay, mergeProps({
        "ref": overlay,
        "id": id.value,
        "class": ["v-menu", props.class],
        "style": props.style
      }, overlayProps, {
        "modelValue": isActive.value,
        "onUpdate:modelValue": ($event) => isActive.value = $event,
        "absolute": true,
        "activatorProps": activatorProps.value,
        "location": (_a = props.location) != null ? _a : props.submenu ? "end" : "bottom",
        "onClick:outside": onClickOutside,
        "onKeydown": onKeydown2
      }, scopeId), {
        activator: slots.activator,
        default: function() {
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          return createVNode(VDefaultsProvider, {
            "root": "VMenu"
          }, {
            default: () => {
              var _a2;
              return [(_a2 = slots.default) == null ? void 0 : _a2.call(slots, ...args)];
            }
          });
        }
      });
    });
    return forwardRefs({
      id,
      \u03A8openChildren: openChildren
    }, overlay);
  }
});
const makeVSheetProps = propsFactory({
  color: String,
  ...makeBorderProps(),
  ...makeComponentProps(),
  ...makeDimensionProps(),
  ...makeElevationProps(),
  ...makeLocationProps(),
  ...makePositionProps(),
  ...makeRoundedProps(),
  ...makeTagProps(),
  ...makeThemeProps()
}, "VSheet");
const VSheet = genericComponent()({
  name: "VSheet",
  props: makeVSheetProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      themeClasses
    } = provideTheme(props);
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.color);
    const {
      borderClasses
    } = useBorder(props);
    const {
      dimensionStyles
    } = useDimension(props);
    const {
      elevationClasses
    } = useElevation(props);
    const {
      locationStyles
    } = useLocation(props);
    const {
      positionClasses
    } = usePosition(props);
    const {
      roundedClasses
    } = useRounded(props);
    useRender(() => createVNode(props.tag, {
      "class": normalizeClass(["v-sheet", themeClasses.value, backgroundColorClasses.value, borderClasses.value, elevationClasses.value, positionClasses.value, roundedClasses.value, props.class]),
      "style": normalizeStyle([backgroundColorStyles.value, dimensionStyles.value, locationStyles.value, props.style])
    }, slots));
    return {};
  }
});
const makeVCounterProps = propsFactory({
  active: Boolean,
  disabled: Boolean,
  max: [Number, String],
  value: {
    type: [Number, String],
    default: 0
  },
  ...makeComponentProps(),
  ...makeTransitionProps({
    transition: {
      component: VSlideYTransition
    }
  })
}, "VCounter");
const VCounter = genericComponent()({
  name: "VCounter",
  functional: true,
  props: makeVCounterProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const counter = toRef(() => {
      return props.max ? `${props.value} / ${props.max}` : String(props.value);
    });
    useRender(() => createVNode(MaybeTransition, {
      "transition": props.transition
    }, {
      default: () => [withDirectives(createElementVNode("div", {
        "class": normalizeClass(["v-counter", {
          "text-error": props.max && !props.disabled && parseFloat(props.value) > parseFloat(props.max)
        }, props.class]),
        "style": normalizeStyle(props.style)
      }, [slots.default ? slots.default({
        counter: counter.value,
        max: props.max,
        value: props.value
      }) : counter.value]), [[vShow, props.active]])]
    }));
    return {};
  }
});
const makeVFieldLabelProps = propsFactory({
  floating: Boolean,
  ...makeComponentProps()
}, "VFieldLabel");
const VFieldLabel = genericComponent()({
  name: "VFieldLabel",
  props: makeVFieldLabelProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    useRender(() => createVNode(VLabel, {
      "class": normalizeClass(["v-field-label", {
        "v-field-label--floating": props.floating
      }, props.class]),
      "style": normalizeStyle(props.style)
    }, slots));
    return {};
  }
});
const allowedVariants = ["underlined", "outlined", "filled", "solo", "solo-inverted", "solo-filled", "plain"];
const makeVFieldProps = propsFactory({
  appendInnerIcon: IconValue,
  bgColor: String,
  clearable: Boolean,
  clearIcon: {
    type: IconValue,
    default: "$clear"
  },
  active: Boolean,
  centerAffix: {
    type: Boolean,
    default: void 0
  },
  color: String,
  baseColor: String,
  dirty: Boolean,
  disabled: {
    type: Boolean,
    default: null
  },
  glow: Boolean,
  error: Boolean,
  flat: Boolean,
  iconColor: [Boolean, String],
  label: String,
  persistentClear: Boolean,
  prependInnerIcon: IconValue,
  reverse: Boolean,
  singleLine: Boolean,
  variant: {
    type: String,
    default: "filled",
    validator: (v) => allowedVariants.includes(v)
  },
  "onClick:clear": EventProp(),
  "onClick:appendInner": EventProp(),
  "onClick:prependInner": EventProp(),
  ...makeComponentProps(),
  ...makeLoaderProps(),
  ...makeRoundedProps(),
  ...makeThemeProps()
}, "VField");
const VField = genericComponent()({
  name: "VField",
  inheritAttrs: false,
  props: {
    id: String,
    details: Boolean,
    labelId: String,
    ...makeFocusProps(),
    ...makeVFieldProps()
  },
  emits: {
    "update:focused": (focused) => true,
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      emit,
      slots
    } = _ref;
    const {
      themeClasses
    } = provideTheme(props);
    const {
      loaderClasses
    } = useLoader(props);
    const {
      focusClasses,
      isFocused,
      focus,
      blur
    } = useFocus(props);
    const {
      InputIcon
    } = useInputIcon(props);
    const {
      roundedClasses
    } = useRounded(props);
    const {
      rtlClasses
    } = useRtl();
    const isActive = toRef(() => props.dirty || props.active);
    const hasLabel = toRef(() => !!(props.label || slots.label));
    const hasFloatingLabel = toRef(() => !props.singleLine && hasLabel.value);
    const uid = useId();
    const id = computed(() => props.id || `input-${uid}`);
    const messagesId = toRef(() => !props.details ? void 0 : `${id.value}-messages`);
    const labelRef = ref();
    const floatingLabelRef = ref();
    const controlRef = ref();
    const isPlainOrUnderlined = computed(() => ["plain", "underlined"].includes(props.variant));
    const color = computed(() => {
      return props.error || props.disabled ? void 0 : isActive.value && isFocused.value ? props.color : props.baseColor;
    });
    const iconColor = computed(() => {
      if (!props.iconColor || props.glow && !isFocused.value) return void 0;
      return props.iconColor === true ? color.value : props.iconColor;
    });
    const {
      backgroundColorClasses,
      backgroundColorStyles
    } = useBackgroundColor(() => props.bgColor);
    const {
      textColorClasses,
      textColorStyles
    } = useTextColor(color);
    watch(isActive, (val) => {
      if (hasFloatingLabel.value && true) {
        const el = labelRef.value.$el;
        const targetEl = floatingLabelRef.value.$el;
        requestAnimationFrame(() => {
          const rect = nullifyTransforms(el);
          const targetRect = new Box(targetEl);
          const x = targetRect.x - rect.x;
          const y = targetRect.y - rect.y - (rect.height / 2 - targetRect.height / 2);
          const targetWidth = targetRect.width / 0.75;
          const width = Math.abs(targetWidth - rect.width) > 1 ? {
            maxWidth: convertToUnit(targetWidth)
          } : void 0;
          const style = getComputedStyle(el);
          const targetStyle = getComputedStyle(targetEl);
          const duration = parseFloat(style.transitionDuration) * 1e3 || 150;
          const scale = parseFloat(targetStyle.getPropertyValue("--v-field-label-scale"));
          const color2 = targetStyle.getPropertyValue("color");
          el.style.visibility = "visible";
          targetEl.style.visibility = "hidden";
          animate(el, {
            transform: `translate(${x}px, ${y}px) scale(${scale})`,
            color: color2,
            ...width
          }, {
            duration,
            easing: standardEasing,
            direction: val ? "normal" : "reverse"
          }).finished.then(() => {
            el.style.removeProperty("visibility");
            targetEl.style.removeProperty("visibility");
          });
        });
      }
    }, {
      flush: "post"
    });
    const slotProps = computed(() => ({
      isActive,
      isFocused,
      controlRef,
      iconColor,
      blur,
      focus
    }));
    const floatingLabelProps = toRef(() => {
      const ariaHidden = !isActive.value;
      return {
        "aria-hidden": ariaHidden,
        for: ariaHidden ? void 0 : id.value
      };
    });
    const mainLabelProps = toRef(() => {
      const ariaHidden = hasFloatingLabel.value && isActive.value;
      return {
        "aria-hidden": ariaHidden,
        for: ariaHidden ? void 0 : id.value
      };
    });
    function onClick(e) {
      if (e.target !== (void 0).activeElement) {
        e.preventDefault();
      }
    }
    useRender(() => {
      var _a, _b, _c;
      const isOutlined = props.variant === "outlined";
      const hasPrepend = !!(slots["prepend-inner"] || props.prependInnerIcon);
      const hasClear = !!(props.clearable || slots.clear) && !props.disabled;
      const hasAppend = !!(slots["append-inner"] || props.appendInnerIcon || hasClear);
      const label = () => slots.label ? slots.label({
        ...slotProps.value,
        label: props.label,
        props: {
          for: id.value
        }
      }) : props.label;
      return createElementVNode("div", mergeProps({
        "class": ["v-field", {
          "v-field--active": isActive.value,
          "v-field--appended": hasAppend,
          "v-field--center-affix": (_a = props.centerAffix) != null ? _a : !isPlainOrUnderlined.value,
          "v-field--disabled": props.disabled,
          "v-field--dirty": props.dirty,
          "v-field--error": props.error,
          "v-field--glow": props.glow,
          "v-field--flat": props.flat,
          "v-field--has-background": !!props.bgColor,
          "v-field--persistent-clear": props.persistentClear,
          "v-field--prepended": hasPrepend,
          "v-field--reverse": props.reverse,
          "v-field--single-line": props.singleLine,
          "v-field--no-label": !label(),
          [`v-field--variant-${props.variant}`]: true
        }, themeClasses.value, backgroundColorClasses.value, focusClasses.value, loaderClasses.value, roundedClasses.value, rtlClasses.value, props.class],
        "style": [backgroundColorStyles.value, props.style],
        "onClick": onClick
      }, attrs), [createElementVNode("div", {
        "class": "v-field__overlay"
      }, null), createVNode(LoaderSlot, {
        "name": "v-field",
        "active": !!props.loading,
        "color": props.error ? "error" : typeof props.loading === "string" ? props.loading : props.color
      }, {
        default: slots.loader
      }), hasPrepend && createElementVNode("div", {
        "key": "prepend",
        "class": "v-field__prepend-inner"
      }, [slots["prepend-inner"] ? slots["prepend-inner"](slotProps.value) : props.prependInnerIcon && createVNode(InputIcon, {
        "key": "prepend-icon",
        "name": "prependInner",
        "color": iconColor.value
      }, null)]), createElementVNode("div", {
        "class": "v-field__field",
        "data-no-activator": ""
      }, [["filled", "solo", "solo-inverted", "solo-filled"].includes(props.variant) && hasFloatingLabel.value && createVNode(VFieldLabel, mergeProps({
        "key": "floating-label",
        "ref": floatingLabelRef,
        "class": [textColorClasses.value],
        "floating": true
      }, floatingLabelProps.value, {
        "style": textColorStyles.value
      }), {
        default: () => [label()]
      }), hasLabel.value && createVNode(VFieldLabel, mergeProps({
        "key": "label",
        "ref": labelRef,
        "id": props.labelId
      }, mainLabelProps.value), {
        default: () => [label()]
      }), (_c = (_b = slots.default) == null ? void 0 : _b.call(slots, {
        ...slotProps.value,
        props: {
          id: id.value,
          class: "v-field__input",
          "aria-describedby": messagesId.value
        },
        focus,
        blur
      })) != null ? _c : createElementVNode("div", {
        "id": id.value,
        "class": "v-field__input",
        "aria-describedby": messagesId.value
      }, null)]), hasClear && createVNode(VExpandXTransition, {
        "key": "clear"
      }, {
        default: () => [withDirectives(createElementVNode("div", {
          "class": "v-field__clearable",
          "onMousedown": (e) => {
            e.preventDefault();
            e.stopPropagation();
          }
        }, [createVNode(VDefaultsProvider, {
          "defaults": {
            VIcon: {
              icon: props.clearIcon
            }
          }
        }, {
          default: () => [slots.clear ? slots.clear({
            ...slotProps.value,
            props: {
              onFocus: focus,
              onBlur: blur,
              onClick: props["onClick:clear"],
              tabindex: -1
            }
          }) : createVNode(InputIcon, {
            "name": "clear",
            "onFocus": focus,
            "onBlur": blur,
            "tabindex": -1
          }, null)]
        })]), [[vShow, props.dirty]])]
      }), hasAppend && createElementVNode("div", {
        "key": "append",
        "class": "v-field__append-inner"
      }, [slots["append-inner"] ? slots["append-inner"](slotProps.value) : props.appendInnerIcon && createVNode(InputIcon, {
        "key": "append-icon",
        "name": "appendInner",
        "color": iconColor.value
      }, null)]), createElementVNode("div", {
        "class": normalizeClass(["v-field__outline", textColorClasses.value]),
        "style": normalizeStyle(textColorStyles.value)
      }, [isOutlined && createElementVNode(Fragment, null, [createElementVNode("div", {
        "class": "v-field__outline__start"
      }, null), hasFloatingLabel.value && createElementVNode("div", {
        "class": "v-field__outline__notch"
      }, [createVNode(VFieldLabel, mergeProps({
        "ref": floatingLabelRef,
        "floating": true
      }, floatingLabelProps.value), {
        default: () => [label()]
      })]), createElementVNode("div", {
        "class": "v-field__outline__end"
      }, null)]), isPlainOrUnderlined.value && hasFloatingLabel.value && createVNode(VFieldLabel, mergeProps({
        "ref": floatingLabelRef,
        "floating": true
      }, floatingLabelProps.value), {
        default: () => [label()]
      })])]);
    });
    return {
      controlRef,
      fieldIconColor: iconColor
    };
  }
});
const makeAutocompleteProps = propsFactory({
  autocomplete: String
}, "autocomplete");
function useAutocomplete(props) {
  const uniqueId = useId();
  const reloadTrigger = shallowRef(0);
  const isSuppressing = toRef(() => props.autocomplete === "suppress");
  const fieldName = toRef(() => {
    if (!props.name) return void 0;
    return isSuppressing.value ? `${props.name}-${uniqueId}-${reloadTrigger.value}` : props.name;
  });
  const fieldAutocomplete = toRef(() => {
    return isSuppressing.value ? "off" : props.autocomplete;
  });
  return {
    isSuppressing,
    fieldAutocomplete,
    fieldName,
    update: () => reloadTrigger.value = (/* @__PURE__ */ new Date()).getTime()
  };
}
function useAutofocus(props) {
  function onIntersect(isIntersecting, entries) {
    if (!props.autofocus || !isIntersecting) return;
    const el = entries[0].target;
    const target = el.matches("input,textarea") ? el : el.querySelector("input,textarea");
    target == null ? void 0 : target.focus();
  }
  return {
    onIntersect
  };
}
const activeTypes = ["color", "file", "time", "date", "datetime-local", "week", "month"];
const makeVTextFieldProps = propsFactory({
  autofocus: Boolean,
  counter: [Boolean, Number, String],
  counterValue: [Number, Function],
  prefix: String,
  placeholder: String,
  persistentPlaceholder: Boolean,
  persistentCounter: Boolean,
  suffix: String,
  role: String,
  type: {
    type: String,
    default: "text"
  },
  modelModifiers: Object,
  ...makeAutocompleteProps(),
  ...omit(makeVInputProps(), ["direction"]),
  ...makeVFieldProps()
}, "VTextField");
const VTextField = genericComponent()({
  name: "VTextField",
  directives: {
    vIntersect: Intersect
  },
  inheritAttrs: false,
  props: makeVTextFieldProps(),
  emits: {
    "click:control": (e) => true,
    "mousedown:control": (e) => true,
    "update:focused": (focused) => true,
    "update:modelValue": (val) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      emit,
      slots
    } = _ref;
    const model = useProxiedModel(props, "modelValue", void 0, (v) => {
      if (Object.is(v, -0)) return "-0";
      return v;
    });
    const {
      isFocused,
      focus,
      blur
    } = useFocus(props);
    const {
      onIntersect
    } = useAutofocus(props);
    const counterValue = computed(() => {
      var _a;
      return typeof props.counterValue === "function" ? props.counterValue(model.value) : typeof props.counterValue === "number" ? props.counterValue : ((_a = model.value) != null ? _a : "").toString().length;
    });
    const max = computed(() => {
      if (attrs.maxlength) return attrs.maxlength;
      if (!props.counter || typeof props.counter !== "number" && typeof props.counter !== "string") return void 0;
      return props.counter;
    });
    const isPlainOrUnderlined = computed(() => ["plain", "underlined"].includes(props.variant));
    const vInputRef = ref();
    const vFieldRef = ref();
    const inputRef = ref();
    const autocomplete = useAutocomplete(props);
    const isActive = computed(() => activeTypes.includes(props.type) || props.persistentPlaceholder || isFocused.value || props.active);
    function onFocus() {
      if (autocomplete.isSuppressing.value) {
        autocomplete.update();
      }
      if (!isFocused.value) focus();
      nextTick(() => {
        var _a;
        if (inputRef.value !== (void 0).activeElement) {
          (_a = inputRef.value) == null ? void 0 : _a.focus();
        }
      });
    }
    function onControlMousedown(e) {
      emit("mousedown:control", e);
      if (e.target === inputRef.value) return;
      onFocus();
      e.preventDefault();
    }
    function onControlClick(e) {
      emit("click:control", e);
    }
    function onClear(e, reset) {
      e.stopPropagation();
      onFocus();
      nextTick(() => {
        reset();
        callEvent(props["onClick:clear"], e);
      });
    }
    function onInput(e) {
      var _a;
      const el = e.target;
      if (!(((_a = props.modelModifiers) == null ? void 0 : _a.trim) && ["text", "search", "password", "tel", "url"].includes(props.type))) {
        model.value = el.value;
        return;
      }
      const value = el.value;
      const start = el.selectionStart;
      const end = el.selectionEnd;
      model.value = value;
      nextTick(() => {
        let offset = 0;
        if (value.trimStart().length === el.value.length) {
          offset = value.length - el.value.length;
        }
        if (start != null) el.selectionStart = start - offset;
        if (end != null) el.selectionEnd = end - offset;
      });
    }
    useRender(() => {
      const hasCounter = !!(slots.counter || props.counter !== false && props.counter != null);
      const hasDetails = !!(hasCounter || slots.details);
      const [rootAttrs, inputAttrs] = filterInputAttrs(attrs);
      const {
        modelValue: _,
        ...inputProps
      } = VInput.filterProps(props);
      const fieldProps = VField.filterProps(props);
      return createVNode(VInput, mergeProps({
        "ref": vInputRef,
        "modelValue": model.value,
        "onUpdate:modelValue": ($event) => model.value = $event,
        "class": ["v-text-field", {
          "v-text-field--prefixed": props.prefix,
          "v-text-field--suffixed": props.suffix,
          "v-input--plain-underlined": isPlainOrUnderlined.value
        }, props.class],
        "style": props.style
      }, rootAttrs, inputProps, {
        "centerAffix": !isPlainOrUnderlined.value,
        "focused": isFocused.value
      }), {
        ...slots,
        default: (_ref2) => {
          let {
            id,
            isDisabled,
            isDirty,
            isReadonly,
            isValid,
            hasDetails: hasDetails2,
            reset
          } = _ref2;
          return createVNode(VField, mergeProps({
            "ref": vFieldRef,
            "onMousedown": onControlMousedown,
            "onClick": onControlClick,
            "onClick:clear": (e) => onClear(e, reset),
            "role": props.role
          }, omit(fieldProps, ["onClick:clear"]), {
            "id": id.value,
            "labelId": `${id.value}-label`,
            "active": isActive.value || isDirty.value,
            "dirty": isDirty.value || props.dirty,
            "disabled": isDisabled.value,
            "focused": isFocused.value,
            "details": hasDetails2.value,
            "error": isValid.value === false
          }), {
            ...slots,
            default: (_ref3) => {
              let {
                props: {
                  class: fieldClass,
                  ...slotProps
                },
                controlRef
              } = _ref3;
              const inputNode = createElementVNode("input", mergeProps({
                "ref": (val) => inputRef.value = controlRef.value = val,
                "value": model.value,
                "onInput": onInput,
                "autofocus": props.autofocus,
                "readonly": isReadonly.value,
                "disabled": isDisabled.value,
                "name": autocomplete.fieldName.value,
                "autocomplete": autocomplete.fieldAutocomplete.value,
                "placeholder": props.placeholder,
                "size": 1,
                "role": props.role,
                "type": props.type,
                "onFocus": focus,
                "onBlur": blur,
                "aria-labelledby": `${id.value}-label`
              }, slotProps, inputAttrs), null);
              return createElementVNode(Fragment, null, [props.prefix && createElementVNode("span", {
                "class": "v-text-field__prefix"
              }, [createElementVNode("span", {
                "class": "v-text-field__prefix__text"
              }, [props.prefix])]), withDirectives(slots.default ? createElementVNode("div", {
                "class": normalizeClass(fieldClass),
                "data-no-activator": ""
              }, [slots.default({
                id
              }), inputNode]) : cloneVNode(inputNode, {
                class: fieldClass
              }), [[Intersect, onIntersect, null, {
                once: true
              }]]), props.suffix && createElementVNode("span", {
                "class": "v-text-field__suffix"
              }, [createElementVNode("span", {
                "class": "v-text-field__suffix__text"
              }, [props.suffix])])]);
            }
          });
        },
        details: hasDetails ? (slotProps) => {
          var _a;
          return createElementVNode(Fragment, null, [(_a = slots.details) == null ? void 0 : _a.call(slots, slotProps), hasCounter && createElementVNode(Fragment, null, [createElementVNode("span", null, null), createVNode(VCounter, {
            "active": props.persistentCounter || isFocused.value,
            "value": counterValue.value,
            "max": max.value,
            "disabled": props.disabled
          }, slots.counter)])]);
        } : void 0
      });
    });
    return forwardRefs({}, vInputRef, vFieldRef, inputRef);
  }
});
const makeVVirtualScrollItemProps = propsFactory({
  renderless: Boolean,
  ...makeComponentProps()
}, "VVirtualScrollItem");
const VVirtualScrollItem = genericComponent()({
  name: "VVirtualScrollItem",
  inheritAttrs: false,
  props: makeVVirtualScrollItemProps(),
  emits: {
    "update:height": (height) => true
  },
  setup(props, _ref) {
    let {
      attrs,
      emit,
      slots
    } = _ref;
    const {
      resizeRef,
      contentRect
    } = useResizeObserver();
    watch(() => {
      var _a;
      return (_a = contentRect.value) == null ? void 0 : _a.height;
    }, (height) => {
      if (height != null) emit("update:height", height);
    });
    useRender(() => {
      var _a, _b;
      return props.renderless ? createElementVNode(Fragment, null, [(_a = slots.default) == null ? void 0 : _a.call(slots, {
        itemRef: resizeRef
      })]) : createElementVNode("div", mergeProps({
        "ref": resizeRef,
        "class": ["v-virtual-scroll__item", props.class],
        "style": props.style
      }, attrs), [(_b = slots.default) == null ? void 0 : _b.call(slots)]);
    });
  }
});
const UP = -1;
const DOWN = 1;
const BUFFER_PX = 100;
const makeVirtualProps = propsFactory({
  itemHeight: {
    type: [Number, String],
    default: null
  },
  itemKey: {
    type: [String, Array, Function],
    default: null
  },
  height: [Number, String]
}, "virtual");
function useVirtual(props, items) {
  const display = useDisplay();
  const itemHeight = shallowRef(0);
  watchEffect(() => {
    itemHeight.value = parseFloat(props.itemHeight || 0);
  });
  const first = shallowRef(0);
  const last = shallowRef(Math.ceil(
    // Assume 16px items filling the entire screen height if
    // not provided. This is probably incorrect but it minimises
    // the chance of ending up with empty space at the bottom.
    // The default value is set here to avoid poisoning getSize()
    (parseInt(props.height) || display.height.value) / (itemHeight.value || 16)
  ) || 1);
  const paddingTop = shallowRef(0);
  const paddingBottom = shallowRef(0);
  const containerRef = ref();
  const markerRef = ref();
  let markerOffset = 0;
  const {
    resizeRef,
    contentRect
  } = useResizeObserver();
  watchEffect(() => {
    resizeRef.value = containerRef.value;
  });
  const viewportHeight = computed(() => {
    var _a;
    return containerRef.value === (void 0).documentElement ? display.height.value : ((_a = contentRect.value) == null ? void 0 : _a.height) || parseInt(props.height) || 0;
  });
  const hasInitialRender = computed(() => {
    return !!(containerRef.value && markerRef.value && viewportHeight.value && itemHeight.value);
  });
  let sizes = Array.from({
    length: items.value.length
  });
  let offsets = Array.from({
    length: items.value.length
  });
  const updateTime = shallowRef(0);
  let targetScrollIndex = -1;
  function getSize(index) {
    return sizes[index] || itemHeight.value;
  }
  const updateOffsets = debounce(() => {
    const start = performance.now();
    offsets[0] = 0;
    const length = items.value.length;
    for (let i = 1; i <= length; i++) {
      offsets[i] = (offsets[i - 1] || 0) + getSize(i - 1);
    }
    updateTime.value = Math.max(updateTime.value, performance.now() - start);
  }, updateTime);
  const unwatch = watch(hasInitialRender, (v) => {
    if (!v) return;
    unwatch();
    markerOffset = markerRef.value.offsetTop;
    updateOffsets.immediate();
    calculateVisibleItems();
    if (!~targetScrollIndex) return;
    nextTick(() => {
    });
  });
  onScopeDispose(() => {
    updateOffsets.clear();
  });
  function handleItemResize(index, height) {
    const prevHeight = sizes[index];
    const prevMinHeight = itemHeight.value;
    itemHeight.value = prevMinHeight ? Math.min(itemHeight.value, height) : height;
    if (prevHeight !== height || prevMinHeight !== itemHeight.value) {
      sizes[index] = height;
      updateOffsets();
    }
  }
  function calculateOffset(index) {
    index = clamp(index, 0, items.value.length);
    const whole = Math.floor(index);
    const fraction = index % 1;
    const next = whole + 1;
    const wholeOffset = offsets[whole] || 0;
    const nextOffset = offsets[next] || wholeOffset;
    return wholeOffset + (nextOffset - wholeOffset) * fraction;
  }
  function calculateIndex(scrollTop) {
    return binaryClosest(offsets, scrollTop);
  }
  let lastScrollTop = 0;
  let scrollVelocity = 0;
  let lastScrollTime = 0;
  watch(viewportHeight, (val, oldVal) => {
    calculateVisibleItems();
    if (val < oldVal) {
      requestAnimationFrame(() => {
        scrollVelocity = 0;
        calculateVisibleItems();
      });
    }
  });
  let scrollTimeout = -1;
  function handleScroll() {
    if (!containerRef.value || !markerRef.value) return;
    const scrollTop = containerRef.value.scrollTop;
    const scrollTime = performance.now();
    const scrollDeltaT = scrollTime - lastScrollTime;
    if (scrollDeltaT > 500) {
      scrollVelocity = Math.sign(scrollTop - lastScrollTop);
      markerOffset = markerRef.value.offsetTop;
    } else {
      scrollVelocity = scrollTop - lastScrollTop;
    }
    lastScrollTop = scrollTop;
    lastScrollTime = scrollTime;
    (void 0).clearTimeout(scrollTimeout);
    scrollTimeout = (void 0).setTimeout(handleScrollend, 500);
    calculateVisibleItems();
  }
  function handleScrollend() {
    if (!containerRef.value || !markerRef.value) return;
    scrollVelocity = 0;
    lastScrollTime = 0;
    (void 0).clearTimeout(scrollTimeout);
    calculateVisibleItems();
  }
  let raf2 = -1;
  function calculateVisibleItems() {
    cancelAnimationFrame(raf2);
    raf2 = requestAnimationFrame(_calculateVisibleItems);
  }
  function _calculateVisibleItems() {
    if (!containerRef.value || !viewportHeight.value || !itemHeight.value) return;
    const scrollTop = lastScrollTop - markerOffset;
    const direction = Math.sign(scrollVelocity);
    const startPx = Math.max(0, scrollTop - BUFFER_PX);
    const start = clamp(calculateIndex(startPx), 0, items.value.length);
    const endPx = scrollTop + viewportHeight.value + BUFFER_PX;
    const end = clamp(calculateIndex(endPx) + 1, start + 1, items.value.length);
    if (
      // Only update the side we're scrolling towards,
      // the other side will be updated incidentally
      (direction !== UP || start < first.value) && (direction !== DOWN || end > last.value)
    ) {
      const topOverflow = calculateOffset(first.value) - calculateOffset(start);
      const bottomOverflow = calculateOffset(end) - calculateOffset(last.value);
      const bufferOverflow = Math.max(topOverflow, bottomOverflow);
      if (bufferOverflow > BUFFER_PX) {
        first.value = start;
        last.value = end;
      } else {
        if (start <= 0) first.value = start;
        if (end >= items.value.length) last.value = end;
      }
    }
    paddingTop.value = calculateOffset(first.value);
    paddingBottom.value = calculateOffset(items.value.length) - calculateOffset(last.value);
  }
  function scrollToIndex(index) {
    const offset = calculateOffset(index);
    if (!containerRef.value || index && !offset) {
      targetScrollIndex = index;
    } else {
      containerRef.value.scrollTop = offset;
    }
  }
  const computedItems = computed(() => {
    return items.value.slice(first.value, last.value).map((item, index) => {
      const _index = index + first.value;
      return {
        raw: item,
        index: _index,
        key: getPropertyFromItem(item, props.itemKey, _index)
      };
    });
  });
  watch(items, () => {
    sizes = Array.from({
      length: items.value.length
    });
    offsets = Array.from({
      length: items.value.length
    });
    updateOffsets.immediate();
    calculateVisibleItems();
  }, {
    deep: 1
  });
  return {
    calculateVisibleItems,
    containerRef,
    markerRef,
    computedItems,
    paddingTop,
    paddingBottom,
    scrollToIndex,
    handleScroll,
    handleScrollend,
    handleItemResize
  };
}
function binaryClosest(arr, val) {
  let high = arr.length - 1;
  let low = 0;
  let mid = 0;
  let item = null;
  let target = -1;
  if (arr[high] < val) {
    return high;
  }
  while (low <= high) {
    mid = low + high >> 1;
    item = arr[mid];
    if (item > val) {
      high = mid - 1;
    } else if (item < val) {
      target = mid;
      low = mid + 1;
    } else if (item === val) {
      return mid;
    } else {
      return low;
    }
  }
  return target;
}
const makeVVirtualScrollProps = propsFactory({
  items: {
    type: Array,
    default: () => []
  },
  renderless: Boolean,
  ...makeVirtualProps(),
  ...makeComponentProps(),
  ...makeDimensionProps()
}, "VVirtualScroll");
const VVirtualScroll = genericComponent()({
  name: "VVirtualScroll",
  props: makeVVirtualScrollProps(),
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    getCurrentInstance$1("VVirtualScroll");
    const {
      dimensionStyles
    } = useDimension(props);
    const {
      calculateVisibleItems,
      containerRef,
      markerRef,
      handleScroll,
      handleScrollend,
      handleItemResize,
      scrollToIndex,
      paddingTop,
      paddingBottom,
      computedItems
    } = useVirtual(props, toRef(() => props.items));
    useToggleScope(() => props.renderless, () => {
      function handleListeners() {
        var _a, _b;
        let add = arguments.length > 0 && arguments[0] !== void 0 ? arguments[0] : false;
        const method = add ? "addEventListener" : "removeEventListener";
        if (containerRef.value === (void 0).documentElement) {
          (void 0)[method]("scroll", handleScroll, {
            passive: true
          });
          (void 0)[method]("scrollend", handleScrollend);
        } else {
          (_a = containerRef.value) == null ? void 0 : _a[method]("scroll", handleScroll, {
            passive: true
          });
          (_b = containerRef.value) == null ? void 0 : _b[method]("scrollend", handleScrollend);
        }
      }
      onScopeDispose(handleListeners);
    });
    useRender(() => {
      const children = computedItems.value.map((item) => createVNode(VVirtualScrollItem, {
        "key": item.key,
        "renderless": props.renderless,
        "onUpdate:height": (height) => handleItemResize(item.index, height)
      }, {
        default: (slotProps) => {
          var _a;
          return (_a = slots.default) == null ? void 0 : _a.call(slots, {
            item: item.raw,
            index: item.index,
            ...slotProps
          });
        }
      }));
      return props.renderless ? createElementVNode(Fragment, null, [createElementVNode("div", {
        "ref": markerRef,
        "class": "v-virtual-scroll__spacer",
        "style": {
          paddingTop: convertToUnit(paddingTop.value)
        }
      }, null), children, createElementVNode("div", {
        "class": "v-virtual-scroll__spacer",
        "style": {
          paddingBottom: convertToUnit(paddingBottom.value)
        }
      }, null)]) : createElementVNode("div", {
        "ref": containerRef,
        "class": normalizeClass(["v-virtual-scroll", props.class]),
        "onScrollPassive": handleScroll,
        "onScrollend": handleScrollend,
        "style": normalizeStyle([dimensionStyles.value, props.style])
      }, [createElementVNode("div", {
        "ref": markerRef,
        "class": "v-virtual-scroll__container",
        "style": {
          paddingTop: convertToUnit(paddingTop.value),
          paddingBottom: convertToUnit(paddingBottom.value)
        }
      }, [children])]);
    });
    return {
      calculateVisibleItems,
      scrollToIndex
    };
  }
});
function useScrolling(listRef, textFieldRef) {
  const isScrolling = shallowRef(false);
  let scrollTimeout;
  function onListScroll(e) {
    cancelAnimationFrame(scrollTimeout);
    isScrolling.value = true;
    scrollTimeout = requestAnimationFrame(() => {
      scrollTimeout = requestAnimationFrame(() => {
        isScrolling.value = false;
      });
    });
  }
  async function finishScrolling() {
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await new Promise((resolve) => requestAnimationFrame(resolve));
    await new Promise((resolve) => {
      if (isScrolling.value) {
        const stop = watch(isScrolling, () => {
          stop();
          resolve();
        });
      } else resolve();
    });
  }
  async function onListKeydown(e) {
    var _a, _b;
    if (e.key === "Tab") {
      (_a = textFieldRef.value) == null ? void 0 : _a.focus();
    }
    if (!["PageDown", "PageUp", "Home", "End"].includes(e.key)) return;
    const el = (_b = listRef.value) == null ? void 0 : _b.$el;
    if (!el) return;
    if (e.key === "Home" || e.key === "End") {
      el.scrollTo({
        top: e.key === "Home" ? 0 : el.scrollHeight,
        behavior: "smooth"
      });
    }
    await finishScrolling();
    const children = el.querySelectorAll(":scope > :not(.v-virtual-scroll__spacer)");
    if (e.key === "PageDown" || e.key === "Home") {
      const top = el.getBoundingClientRect().top;
      for (const child of children) {
        if (child.getBoundingClientRect().top >= top) {
          child.focus();
          break;
        }
      }
    } else {
      const bottom = el.getBoundingClientRect().bottom;
      for (const child of [...children].reverse()) {
        if (child.getBoundingClientRect().bottom <= bottom) {
          child.focus();
          break;
        }
      }
    }
  }
  return {
    onScrollPassive: onListScroll,
    onKeydown: onListKeydown
  };
}
function useFocusGroups(_ref) {
  let {
    groups,
    onLeave
  } = _ref;
  function getContentRef(group) {
    var _a;
    return group.type === "list" ? (_a = group.contentRef.value) == null ? void 0 : _a.$el : group.contentRef.value;
  }
  function getChildren2(group) {
    const contentRef = getContentRef(group);
    return contentRef ? focusableChildren(contentRef) : [];
  }
  function onTabKeydown(e) {
    var _a;
    const target = e.target;
    const direction = e.shiftKey ? "backward" : "forward";
    const children = groups.map(getChildren2);
    const currentGroupIndex = groups.map((g) => {
      var _a2;
      return g.type === "list" ? (_a2 = g.contentRef.value) == null ? void 0 : _a2.$el : g.contentRef.value;
    }).findIndex((el) => el == null ? void 0 : el.contains(target));
    const nextIndex = nextFocusGroup(children, currentGroupIndex, direction, target);
    if (nextIndex === null) {
      const originGroup = groups[currentGroupIndex];
      const origin = children[currentGroupIndex];
      const isListGroup = originGroup.type === "list";
      const atEdge = isListGroup || (direction === "forward" ? origin.at(-1) === e.target : origin.at(0) === e.target);
      if (atEdge) {
        onLeave();
      }
    } else {
      e.preventDefault();
      e.stopImmediatePropagation();
      const nextGroup = groups[nextIndex];
      if (nextGroup.type === "list" && toValue(nextGroup.displayItemsCount) > 0) {
        (_a = nextGroup.contentRef.value) == null ? void 0 : _a.focus(0);
      } else {
        const fromBefore = direction === "forward";
        children[nextIndex].at(fromBefore ? 0 : -1).focus();
      }
    }
  }
  function nextFocusGroup(children, currentIndex, direction, target) {
    const originGroup = groups[currentIndex];
    const origin = children[currentIndex];
    if (originGroup.type !== "list") {
      const isAtEdge = direction === "forward" ? origin.at(-1) === target : origin.at(0) === target;
      if (!isAtEdge) return null;
    }
    const step = direction === "forward" ? 1 : -1;
    for (let i = currentIndex + step; i >= 0 && i < groups.length; i += step) {
      const group = groups[i];
      if (children[i].length > 0 || group.type === "list" && toValue(group.displayItemsCount) > 0) {
        return i;
      }
    }
    return null;
  }
  return {
    onTabKeydown
  };
}
const defaultFilter = (value, query, item) => {
  if (value == null || query == null) return -1;
  if (!query.length) return 0;
  value = value.toString().toLocaleLowerCase();
  query = query.toString().toLocaleLowerCase();
  const result = [];
  let idx = value.indexOf(query);
  while (~idx) {
    result.push([idx, idx + query.length]);
    idx = value.indexOf(query, idx + query.length);
  }
  return result.length ? result : -1;
};
function normaliseMatch(match, query) {
  if (match == null || typeof match === "boolean" || match === -1) return;
  if (typeof match === "number") return [[match, match + query.length]];
  if (Array.isArray(match[0])) return match;
  return [match];
}
const makeFilterProps = propsFactory({
  customFilter: Function,
  customKeyFilter: Object,
  filterKeys: [Array, String],
  filterMode: {
    type: String,
    default: "intersection"
  },
  noFilter: Boolean
}, "filter");
function filterItems(items, query, options) {
  var _a, _b, _c, _d;
  const array = [];
  const filter = (_a = options == null ? void 0 : options.default) != null ? _a : defaultFilter;
  const keys = (options == null ? void 0 : options.filterKeys) ? wrapInArray(options.filterKeys) : false;
  const customFiltersLength = Object.keys((_b = options == null ? void 0 : options.customKeyFilter) != null ? _b : {}).length;
  if (!(items == null ? void 0 : items.length)) return array;
  let lookAheadItems = [];
  loop: for (let i = 0; i < items.length; i++) {
    const [item, transformed = item] = wrapInArray(items[i]);
    const customMatches = {};
    const defaultMatches = {};
    let match = -1;
    if ((query || customFiltersLength > 0) && !(options == null ? void 0 : options.noFilter)) {
      let hasOnlyCustomFilters = false;
      if (typeof item === "object") {
        if (item.type === "divider" || item.type === "subheader") {
          if (((_c = lookAheadItems.at(-1)) == null ? void 0 : _c.type) !== "divider" || item.type !== "subheader") {
            lookAheadItems = [];
          }
          lookAheadItems.push({
            index: i,
            matches: {},
            type: item.type
          });
          continue;
        }
        const filterKeys = keys || Object.keys(transformed);
        hasOnlyCustomFilters = filterKeys.length === customFiltersLength;
        for (const key of filterKeys) {
          const value = getPropertyFromItem(transformed, key);
          const keyFilter = (_d = options == null ? void 0 : options.customKeyFilter) == null ? void 0 : _d[key];
          match = keyFilter ? keyFilter(value, query, item) : filter(value, query, item);
          if (match !== -1 && match !== false) {
            if (keyFilter) customMatches[key] = normaliseMatch(match, query);
            else defaultMatches[key] = normaliseMatch(match, query);
          } else if ((options == null ? void 0 : options.filterMode) === "every") {
            continue loop;
          }
        }
      } else {
        match = filter(item, query, item);
        if (match !== -1 && match !== false) {
          defaultMatches.title = normaliseMatch(match, query);
        }
      }
      const defaultMatchesLength = Object.keys(defaultMatches).length;
      const customMatchesLength = Object.keys(customMatches).length;
      if (!defaultMatchesLength && !customMatchesLength) continue;
      if ((options == null ? void 0 : options.filterMode) === "union" && customMatchesLength !== customFiltersLength && !defaultMatchesLength) continue;
      if ((options == null ? void 0 : options.filterMode) === "intersection" && (customMatchesLength !== customFiltersLength || !defaultMatchesLength && customFiltersLength > 0 && !hasOnlyCustomFilters)) continue;
    }
    if (lookAheadItems.length) {
      array.push(...lookAheadItems);
      lookAheadItems = [];
    }
    array.push({
      index: i,
      matches: {
        ...defaultMatches,
        ...customMatches
      }
    });
  }
  return array;
}
function useFilter(props, items, query, options) {
  const filteredItems = shallowRef([]);
  const filteredMatches = shallowRef(/* @__PURE__ */ new Map());
  const transformedItems = computed(() => unref(items));
  watchEffect(() => {
    const _query = typeof query === "function" ? query() : unref(query);
    const strQuery = typeof _query !== "string" && typeof _query !== "number" ? "" : String(_query);
    const results = filterItems(transformedItems.value, strQuery, {
      customKeyFilter: {
        ...props.customKeyFilter,
        ...unref(void 0 )
      },
      default: props.customFilter,
      filterKeys: props.filterKeys,
      filterMode: props.filterMode,
      noFilter: props.noFilter
    });
    const originalItems = unref(items);
    const _filteredItems = [];
    const _filteredMatches = /* @__PURE__ */ new Map();
    results.forEach((_ref) => {
      let {
        index,
        matches
      } = _ref;
      const item = originalItems[index];
      _filteredItems.push(item);
      _filteredMatches.set(item.value, matches);
    });
    filteredItems.value = _filteredItems;
    filteredMatches.value = _filteredMatches;
  });
  function getMatches(item) {
    return filteredMatches.value.get(item.value);
  }
  return {
    filteredItems,
    filteredMatches,
    getMatches
  };
}
function highlightResult(name, text, matches) {
  if (matches == null || !matches.length) return text;
  return matches.map((match, i) => {
    const start = i === 0 ? 0 : matches[i - 1][1];
    const result = [createElementVNode("span", {
      "class": normalizeClass(`${name}__unmask`)
    }, [text.slice(start, match[0])]), createElementVNode("span", {
      "class": normalizeClass(`${name}__mask`)
    }, [text.slice(match[0], match[1])])];
    if (i === matches.length - 1) {
      result.push(createElementVNode("span", {
        "class": normalizeClass(`${name}__unmask`)
      }, [text.slice(match[1])]));
    }
    return createElementVNode(Fragment, null, [result]);
  });
}
const makeMenuActivatorProps = propsFactory({
  closeText: {
    type: String,
    default: "$vuetify.close"
  },
  openText: {
    type: String,
    default: "$vuetify.open"
  }
}, "autocomplete");
function useMenuActivator(props, isOpen) {
  const uid = useId();
  const menuId = computed(() => `menu-${uid}`);
  const ariaExpanded = toRef(() => toValue(isOpen));
  const ariaControls = toRef(() => menuId.value);
  return {
    menuId,
    ariaExpanded,
    ariaControls
  };
}
const makeSelectProps = propsFactory({
  chips: Boolean,
  closableChips: Boolean,
  eager: Boolean,
  hideNoData: Boolean,
  hideSelected: Boolean,
  listProps: {
    type: Object
  },
  menu: Boolean,
  menuIcon: {
    type: IconValue,
    default: "$dropdown"
  },
  menuProps: {
    type: Object
  },
  multiple: Boolean,
  noDataText: {
    type: String,
    default: "$vuetify.noDataText"
  },
  openOnClear: Boolean,
  itemColor: String,
  noAutoScroll: Boolean,
  ...makeMenuActivatorProps(),
  ...makeItemsProps({
    itemChildren: false
  })
}, "Select");
const makeVSelectProps = propsFactory({
  search: String,
  ...makeFilterProps({
    filterKeys: ["title"]
  }),
  ...makeSelectProps(),
  ...omit(makeVTextFieldProps({
    modelValue: null,
    role: "combobox"
  }), ["validationValue", "dirty"]),
  ...makeTransitionProps({
    transition: {
      component: VDialogTransition
    }
  })
}, "VSelect");
genericComponent()({
  name: "VSelect",
  props: makeVSelectProps(),
  emits: {
    "update:focused": (focused) => true,
    "update:modelValue": (value) => true,
    "update:menu": (ue) => true,
    "update:search": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      t
    } = useLocale();
    const vTextFieldRef = ref();
    const vMenuRef = ref();
    const headerRef = ref();
    const footerRef = ref();
    const vVirtualScrollRef = ref();
    const {
      items,
      transformIn,
      transformOut
    } = useItems(props);
    const search = useProxiedModel(props, "search", "");
    const {
      filteredItems,
      getMatches
    } = useFilter(props, items, () => search.value);
    const model = useProxiedModel(props, "modelValue", [], (v) => transformIn(v === null ? [null] : wrapInArray(v)), (v) => {
      var _a;
      const transformed = transformOut(v);
      return props.multiple ? transformed : (_a = transformed[0]) != null ? _a : null;
    });
    const counterValue = computed(() => {
      return typeof props.counterValue === "function" ? props.counterValue(model.value) : typeof props.counterValue === "number" ? props.counterValue : model.value.length;
    });
    const form = useForm(props);
    const autocomplete = useAutocomplete(props);
    const selectedValues = computed(() => model.value.map((selection) => selection.value));
    const isFocused = shallowRef(false);
    const closableChips = toRef(() => props.closableChips && !form.isReadonly.value && !form.isDisabled.value);
    const {
      InputIcon
    } = useInputIcon(props);
    let keyboardLookupPrefix = "";
    let keyboardLookupIndex = 0;
    let keyboardLookupLastTime;
    const displayItems = computed(() => {
      const baseItems = search.value ? filteredItems.value : items.value;
      if (props.hideSelected) {
        return baseItems.filter((item) => !model.value.some((s) => (props.valueComparator || deepEqual)(s, item)));
      }
      return baseItems;
    });
    const menuDisabled = computed(() => props.hideNoData && !displayItems.value.length || form.isReadonly.value || form.isDisabled.value);
    const _menu = useProxiedModel(props, "menu");
    const menu = computed({
      get: () => _menu.value,
      set: (v) => {
        var _a;
        if (_menu.value && !v && ((_a = vMenuRef.value) == null ? void 0 : _a.\u03A8openChildren.size)) return;
        if (v && menuDisabled.value) return;
        _menu.value = v;
      }
    });
    const {
      menuId,
      ariaExpanded,
      ariaControls
    } = useMenuActivator(props, menu);
    const computedMenuProps = computed(() => {
      var _a;
      return {
        ...props.menuProps,
        activatorProps: {
          ...((_a = props.menuProps) == null ? void 0 : _a.activatorProps) || {},
          "aria-haspopup": "listbox"
          // Set aria-haspopup to 'listbox'
        }
      };
    });
    const listRef = ref();
    const listEvents = useScrolling(listRef, vTextFieldRef);
    const {
      onTabKeydown
    } = useFocusGroups({
      groups: [{
        type: "element",
        contentRef: headerRef
      }, {
        type: "list",
        contentRef: listRef,
        displayItemsCount: () => displayItems.value.length
      }, {
        type: "element",
        contentRef: footerRef
      }],
      onLeave: () => {
        var _a;
        menu.value = false;
        (_a = vTextFieldRef.value) == null ? void 0 : _a.focus();
      }
    });
    function onClear(e) {
      if (props.openOnClear) {
        menu.value = true;
      }
    }
    function onMousedownControl() {
      if (menuDisabled.value) return;
      menu.value = !menu.value;
    }
    function onMenuKeydown(e) {
      var _a;
      if (e.key === "Tab") {
        onTabKeydown(e);
      }
      if (((_a = listRef.value) == null ? void 0 : _a.$el.contains(e.target)) && checkPrintable(e)) {
        onKeydown2(e);
      }
    }
    function onKeydown2(e) {
      var _a, _b, _c;
      if (!e.key || form.isReadonly.value) return;
      if (["Enter", " ", "ArrowDown", "ArrowUp", "Home", "End"].includes(e.key)) {
        e.preventDefault();
      }
      if (["Enter", "ArrowDown", " "].includes(e.key)) {
        menu.value = true;
      }
      if (["Escape", "Tab"].includes(e.key)) {
        menu.value = false;
      }
      if (props.clearable && e.key === "Backspace") {
        e.preventDefault();
        model.value = [];
        onClear();
        return;
      }
      if (e.key === "Home") {
        (_a = listRef.value) == null ? void 0 : _a.focus("first");
      } else if (e.key === "End") {
        (_b = listRef.value) == null ? void 0 : _b.focus("last");
      }
      const KEYBOARD_LOOKUP_THRESHOLD = 1e3;
      if (!checkPrintable(e)) return;
      const now = performance.now();
      if (now - keyboardLookupLastTime > KEYBOARD_LOOKUP_THRESHOLD) {
        keyboardLookupPrefix = "";
        keyboardLookupIndex = 0;
      }
      keyboardLookupPrefix += e.key.toLowerCase();
      keyboardLookupLastTime = now;
      const items2 = displayItems.value;
      function findItem() {
        let result2 = findItemBase();
        if (result2) return result2;
        if (keyboardLookupPrefix.at(-1) === keyboardLookupPrefix.at(-2)) {
          keyboardLookupPrefix = keyboardLookupPrefix.slice(0, -1);
          keyboardLookupIndex++;
          result2 = findItemBase();
          if (result2) return result2;
        }
        keyboardLookupIndex = 0;
        result2 = findItemBase();
        if (result2) return result2;
        keyboardLookupPrefix = e.key.toLowerCase();
        return findItemBase();
      }
      function findItemBase() {
        for (let i = keyboardLookupIndex; i < items2.length; i++) {
          const _item = items2[i];
          if (_item.title.toLowerCase().startsWith(keyboardLookupPrefix)) {
            return [_item, i];
          }
        }
        return void 0;
      }
      const result = findItem();
      if (!result) return;
      const [item, index] = result;
      keyboardLookupIndex = index;
      (_c = listRef.value) == null ? void 0 : _c.focus(index);
      if (!props.multiple) {
        model.value = [item];
      }
    }
    function select(item) {
      let set = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : true;
      if (item.props.disabled) return;
      if (props.multiple) {
        const index = model.value.findIndex((selection) => (props.valueComparator || deepEqual)(selection.value, item.value));
        const add = set == null ? !~index : set;
        if (~index) {
          const value = add ? [...model.value, item] : [...model.value];
          value.splice(index, 1);
          model.value = value;
        } else if (add) {
          model.value = [...model.value, item];
        }
      } else {
        const add = set !== false;
        model.value = add ? [item] : [];
        nextTick(() => {
          menu.value = false;
        });
      }
    }
    function onBlur(e) {
      var _a;
      const target = e.target;
      if (!((_a = vTextFieldRef.value) == null ? void 0 : _a.$el.contains(target))) {
        menu.value = false;
      }
    }
    function getSelectedIndex() {
      return displayItems.value.findIndex((item) => model.value.some((s) => (props.valueComparator || deepEqual)(s.value, item.value)));
    }
    function getSelectedFocusableIndex() {
      if (!model.value.length) return -1;
      const comparator = props.valueComparator || deepEqual;
      let focusableIndex = 0;
      for (const item of displayItems.value) {
        const isSelected = model.value.some((s) => comparator(s.value, item.value));
        if (isSelected) return item.props.disabled ? -1 : focusableIndex;
        if (!item.props.disabled) focusableIndex++;
      }
      return -1;
    }
    function onAfterEnter() {
      var _a;
      if (props.eager) {
        (_a = vVirtualScrollRef.value) == null ? void 0 : _a.calculateVisibleItems();
      }
      if (listRef.value && isFocused.value) {
        const index = getSelectedFocusableIndex();
        listRef.value.focus(index >= 0 ? index : "first");
      }
    }
    function onAfterLeave() {
      var _a;
      search.value = "";
      if (isFocused.value) {
        (_a = vTextFieldRef.value) == null ? void 0 : _a.focus();
      }
    }
    function onFocusin(e) {
      isFocused.value = true;
    }
    function onFocusout(e) {
      var _a;
      if (!((_a = vTextFieldRef.value) == null ? void 0 : _a.$el.contains(e.relatedTarget))) {
        isFocused.value = false;
      }
    }
    function onModelUpdate(v) {
      if (v == null) model.value = [];
      else if (matchesSelector(vTextFieldRef.value) || matchesSelector(vTextFieldRef.value)) ; else if (vTextFieldRef.value) {
        vTextFieldRef.value.value = "";
      }
    }
    watch(menu, () => {
      if (!props.hideSelected && menu.value && model.value.length) {
        getSelectedIndex();
      }
    });
    watch(items, (newVal, oldVal) => {
      if (menu.value) return;
      if (isFocused.value && props.hideNoData && !oldVal.length && newVal.length) {
        menu.value = true;
      }
    });
    useRender(() => {
      const hasChips = !!(props.chips || slots.chip);
      const hasList = !!(!props.hideNoData || displayItems.value.length || slots["prepend-item"] || slots["append-item"] || slots["no-data"]);
      const isDirty = model.value.length > 0;
      const textFieldProps = VTextField.filterProps(props);
      const placeholder = isDirty || !isFocused.value && props.label && !props.persistentPlaceholder ? void 0 : props.placeholder;
      const menuSlotProps = {
        search,
        filteredItems: filteredItems.value
      };
      return createVNode(VTextField, mergeProps({
        "ref": vTextFieldRef
      }, textFieldProps, {
        "modelValue": model.value.map((v) => v.props.title).join(", "),
        "name": void 0,
        "onUpdate:modelValue": onModelUpdate,
        "focused": isFocused.value,
        "onUpdate:focused": ($event) => isFocused.value = $event,
        "validationValue": model.externalValue,
        "counterValue": counterValue.value,
        "dirty": isDirty,
        "class": ["v-select", {
          "v-select--active-menu": menu.value,
          "v-select--chips": !!props.chips,
          [`v-select--${props.multiple ? "multiple" : "single"}`]: true,
          "v-select--selected": model.value.length,
          "v-select--selection-slot": !!slots.selection
        }, props.class],
        "style": props.style,
        "inputmode": "none",
        "placeholder": placeholder,
        "onClick:clear": onClear,
        "onMousedown:control": onMousedownControl,
        "onBlur": onBlur,
        "onKeydown": onKeydown2,
        "aria-expanded": ariaExpanded.value,
        "aria-controls": ariaControls.value
      }), {
        ...slots,
        default: (_ref2) => {
          let {
            id
          } = _ref2;
          return createElementVNode(Fragment, null, [createElementVNode("select", {
            "hidden": true,
            "multiple": props.multiple,
            "name": autocomplete.fieldName.value
          }, [items.value.map((item) => createElementVNode("option", {
            "key": item.value,
            "value": item.value,
            "selected": selectedValues.value.includes(item.value)
          }, null))]), createVNode(VMenu, mergeProps({
            "id": menuId.value,
            "ref": vMenuRef,
            "modelValue": menu.value,
            "onUpdate:modelValue": ($event) => menu.value = $event,
            "activator": "parent",
            "contentClass": "v-select__content",
            "disabled": menuDisabled.value,
            "eager": props.eager,
            "maxHeight": 310,
            "openOnClick": false,
            "closeOnContentClick": false,
            "transition": props.transition,
            "onAfterEnter": onAfterEnter,
            "onAfterLeave": onAfterLeave
          }, computedMenuProps.value), {
            default: () => [createVNode(VSheet, {
              "onFocusin": onFocusin,
              "onFocusout": onFocusout,
              "onKeydown": onMenuKeydown
            }, {
              default: () => {
                var _a;
                return [slots["menu-header"] && createElementVNode("header", {
                  "ref": headerRef
                }, [slots["menu-header"](menuSlotProps)]), hasList && createVNode(VList, mergeProps({
                  "key": "select-list",
                  "ref": listRef,
                  "selected": selectedValues.value,
                  "selectStrategy": props.multiple ? "independent" : "single-independent",
                  "tabindex": "-1",
                  "selectable": !!displayItems.value.length,
                  "aria-live": "polite",
                  "aria-labelledby": `${id.value}-label`,
                  "aria-multiselectable": props.multiple,
                  "color": (_a = props.itemColor) != null ? _a : props.color
                }, listEvents, props.listProps), {
                  default: () => {
                    var _a2, _b, _c, _d;
                    return [(_a2 = slots["prepend-item"]) == null ? void 0 : _a2.call(slots), !displayItems.value.length && !props.hideNoData && ((_c = (_b = slots["no-data"]) == null ? void 0 : _b.call(slots)) != null ? _c : createVNode(VListItem, {
                      "key": "no-data",
                      "title": t(props.noDataText)
                    }, null)), createVNode(VVirtualScroll, {
                      "ref": vVirtualScrollRef,
                      "renderless": true,
                      "items": displayItems.value,
                      "itemKey": "value"
                    }, {
                      default: (_ref3) => {
                        var _a3, _b2, _c2, _d2, _e, _f;
                        let {
                          item,
                          index,
                          itemRef
                        } = _ref3;
                        const camelizedProps = camelizeProps(item.props);
                        const itemProps = mergeProps(item.props, {
                          ref: itemRef,
                          key: item.value,
                          onClick: () => select(item, null),
                          "aria-posinset": index + 1,
                          "aria-setsize": displayItems.value.length
                        });
                        if (item.type === "divider") {
                          return (_b2 = (_a3 = slots.divider) == null ? void 0 : _a3.call(slots, {
                            props: item.raw,
                            index
                          })) != null ? _b2 : createVNode(VDivider, mergeProps(item.props, {
                            "key": `divider-${index}`
                          }), null);
                        }
                        if (item.type === "subheader") {
                          return (_d2 = (_c2 = slots.subheader) == null ? void 0 : _c2.call(slots, {
                            props: item.raw,
                            index
                          })) != null ? _d2 : createVNode(VListSubheader, mergeProps(item.props, {
                            "key": `subheader-${index}`
                          }), null);
                        }
                        return (_f = (_e = slots.item) == null ? void 0 : _e.call(slots, {
                          item,
                          index,
                          props: itemProps
                        })) != null ? _f : createVNode(VListItem, mergeProps(itemProps, {
                          "role": "option"
                        }), {
                          prepend: (_ref4) => {
                            let {
                              isSelected
                            } = _ref4;
                            return createElementVNode(Fragment, null, [props.multiple && !props.hideSelected ? createVNode(VCheckboxBtn, {
                              "key": item.value,
                              "modelValue": isSelected,
                              "ripple": false,
                              "tabindex": "-1",
                              "aria-hidden": true,
                              "onClick": (event) => event.preventDefault()
                            }, null) : void 0, camelizedProps.prependAvatar && createVNode(VAvatar, {
                              "image": camelizedProps.prependAvatar
                            }, null), camelizedProps.prependIcon && createVNode(VIcon, {
                              "icon": camelizedProps.prependIcon
                            }, null)]);
                          },
                          title: () => {
                            var _a4;
                            return search.value ? highlightResult("v-select", item.title, (_a4 = getMatches(item)) == null ? void 0 : _a4.title) : item.title;
                          }
                        });
                      }
                    }), (_d = slots["append-item"]) == null ? void 0 : _d.call(slots)];
                  }
                }), slots["menu-footer"] && createElementVNode("footer", {
                  "ref": footerRef
                }, [slots["menu-footer"](menuSlotProps)])];
              }
            })]
          }), model.value.map((item, index) => {
            function onChipClose(e) {
              e.stopPropagation();
              e.preventDefault();
              select(item, false);
            }
            const slotProps = mergeProps(VChip.filterProps(item.props), {
              "onClick:close": onChipClose,
              onKeydown(e) {
                if (e.key !== "Enter" && e.key !== " ") return;
                e.preventDefault();
                e.stopPropagation();
                onChipClose(e);
              },
              onMousedown(e) {
                e.preventDefault();
                e.stopPropagation();
              },
              modelValue: true,
              "onUpdate:modelValue": void 0
            });
            const hasSlot = hasChips ? !!slots.chip : !!slots.selection;
            const slotContent = hasSlot ? ensureValidVNode(hasChips ? slots.chip({
              item,
              index,
              props: slotProps
            }) : slots.selection({
              item,
              index
            })) : void 0;
            if (hasSlot && !slotContent) return void 0;
            return createElementVNode("div", {
              "key": item.value,
              "class": "v-select__selection"
            }, [hasChips ? !slots.chip ? createVNode(VChip, mergeProps({
              "key": "chip",
              "closable": closableChips.value,
              "size": "small",
              "text": item.title,
              "disabled": item.props.disabled
            }, slotProps), null) : createVNode(VDefaultsProvider, {
              "key": "chip-defaults",
              "defaults": {
                VChip: {
                  closable: closableChips.value,
                  size: "small",
                  text: item.title
                }
              }
            }, {
              default: () => [slotContent]
            }) : slotContent != null ? slotContent : createElementVNode("span", {
              "class": "v-select__selection-text"
            }, [item.title, props.multiple && index < model.value.length - 1 && createElementVNode("span", {
              "class": "v-select__selection-comma"
            }, [createTextVNode(",")])])]);
          })]);
        },
        "append-inner": function() {
          var _a, _b;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          return createElementVNode(Fragment, null, [(_a = slots["append-inner"]) == null ? void 0 : _a.call(slots, ...args), props.menuIcon ? createVNode(VIcon, {
            "class": "v-select__menu-icon",
            "color": (_b = vTextFieldRef.value) == null ? void 0 : _b.fieldIconColor,
            "icon": props.menuIcon,
            "aria-hidden": true
          }, null) : void 0, props.appendInnerIcon && createVNode(InputIcon, {
            "key": "append-icon",
            "name": "appendInner",
            "color": args[0].iconColor.value
          }, null)]);
        }
      });
    });
    return forwardRefs({
      isFocused,
      menu,
      search,
      filteredItems,
      select
    }, vTextFieldRef);
  }
});
const makeVAutocompleteProps = propsFactory({
  autoSelectFirst: {
    type: [Boolean, String]
  },
  clearOnSelect: Boolean,
  search: String,
  ...makeFilterProps({
    filterKeys: ["title"]
  }),
  ...makeSelectProps(),
  ...omit(makeVTextFieldProps({
    modelValue: null,
    role: "combobox"
  }), ["validationValue", "dirty"])
}, "VAutocomplete");
const VAutocomplete = genericComponent()({
  name: "VAutocomplete",
  props: makeVAutocompleteProps(),
  emits: {
    "update:focused": (focused) => true,
    "update:search": (value) => true,
    "update:modelValue": (value) => true,
    "update:menu": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const {
      t
    } = useLocale();
    const vTextFieldRef = ref();
    const isFocused = shallowRef(false);
    const isPristine = shallowRef(true);
    const listHasFocus = shallowRef(false);
    const vMenuRef = ref();
    const vVirtualScrollRef = ref();
    const selectionIndex = shallowRef(-1);
    const _searchLock = shallowRef(null);
    const {
      items,
      transformIn,
      transformOut
    } = useItems(props);
    const {
      textColorClasses,
      textColorStyles
    } = useTextColor(() => {
      var _a;
      return (_a = vTextFieldRef.value) == null ? void 0 : _a.color;
    });
    const {
      InputIcon
    } = useInputIcon(props);
    const search = useProxiedModel(props, "search", "");
    const model = useProxiedModel(props, "modelValue", [], (v) => transformIn(v === null ? [null] : wrapInArray(v)), (v) => {
      var _a;
      const transformed = transformOut(v);
      return props.multiple ? transformed : (_a = transformed[0]) != null ? _a : null;
    });
    const counterValue = computed(() => {
      return typeof props.counterValue === "function" ? props.counterValue(model.value) : typeof props.counterValue === "number" ? props.counterValue : model.value.length;
    });
    const form = useForm(props);
    const {
      filteredItems,
      getMatches
    } = useFilter(props, items, () => {
      var _a;
      return (_a = _searchLock.value) != null ? _a : isPristine.value ? "" : search.value;
    });
    const displayItems = computed(() => {
      if (props.hideSelected && _searchLock.value === null) {
        return filteredItems.value.filter((filteredItem) => !model.value.some((s) => s.value === filteredItem.value));
      }
      return filteredItems.value;
    });
    const closableChips = toRef(() => props.closableChips && !form.isReadonly.value && !form.isDisabled.value);
    const hasChips = computed(() => !!(props.chips || slots.chip));
    const hasSelectionSlot = computed(() => hasChips.value || !!slots.selection);
    const selectedValues = computed(() => model.value.map((selection) => selection.props.value));
    const firstSelectableItem = computed(() => displayItems.value.find((x) => x.type === "item" && !x.props.disabled));
    const highlightFirst = computed(() => {
      var _a;
      const selectFirst = props.autoSelectFirst === true || props.autoSelectFirst === "exact" && search.value === ((_a = firstSelectableItem.value) == null ? void 0 : _a.title);
      return selectFirst && displayItems.value.length > 0 && !isPristine.value && !listHasFocus.value;
    });
    const menuDisabled = computed(() => props.hideNoData && !displayItems.value.length || form.isReadonly.value || form.isDisabled.value);
    const _menu = useProxiedModel(props, "menu");
    const menu = computed({
      get: () => _menu.value,
      set: (v) => {
        var _a;
        if (_menu.value && !v && ((_a = vMenuRef.value) == null ? void 0 : _a.\u03A8openChildren.size)) return;
        if (v && menuDisabled.value) return;
        _menu.value = v;
      }
    });
    const {
      menuId,
      ariaExpanded,
      ariaControls
    } = useMenuActivator(props, menu);
    const listRef = ref();
    const headerRef = ref();
    const footerRef = ref();
    const listEvents = useScrolling(listRef, vTextFieldRef);
    const {
      onTabKeydown
    } = useFocusGroups({
      groups: [{
        type: "element",
        contentRef: headerRef
      }, {
        type: "list",
        contentRef: listRef,
        displayItemsCount: () => displayItems.value.length
      }, {
        type: "element",
        contentRef: footerRef
      }],
      onLeave: () => {
        var _a;
        menu.value = false;
        (_a = vTextFieldRef.value) == null ? void 0 : _a.focus();
      }
    });
    function onClear(e) {
      if (props.openOnClear) {
        menu.value = true;
      }
      search.value = "";
    }
    function onMousedownControl() {
      if (menuDisabled.value) return;
      menu.value = true;
    }
    function onMousedownMenuIcon(e) {
      if (menuDisabled.value) return;
      if (isFocused.value) {
        e.preventDefault();
        e.stopPropagation();
      }
      menu.value = !menu.value;
    }
    function onMenuKeydown(e) {
      var _a, _b;
      if (e.key === "Tab") {
        onTabKeydown(e);
      }
      if (((_a = listRef.value) == null ? void 0 : _a.$el.contains(e.target)) && (checkPrintable(e) || e.key === "Backspace")) {
        (_b = vTextFieldRef.value) == null ? void 0 : _b.focus();
      }
    }
    function onKeydown2(e) {
      var _a, _b, _c, _d, _e, _f;
      if (form.isReadonly.value) return;
      const selectionStart = (_a = vTextFieldRef.value) == null ? void 0 : _a.selectionStart;
      const length = model.value.length;
      if (["Enter", "ArrowDown", "ArrowUp"].includes(e.key)) {
        e.preventDefault();
      }
      if (["Enter", "ArrowDown"].includes(e.key)) {
        menu.value = true;
      }
      if (["Escape"].includes(e.key)) {
        menu.value = false;
      }
      if (highlightFirst.value && ["Enter", "Tab"].includes(e.key) && firstSelectableItem.value && !model.value.some((_ref2) => {
        let {
          value
        } = _ref2;
        return value === firstSelectableItem.value.value;
      })) {
        select(firstSelectableItem.value);
      }
      if (e.key === "ArrowDown" && highlightFirst.value) {
        (_b = listRef.value) == null ? void 0 : _b.focus("next");
      }
      if (["Backspace", "Delete"].includes(e.key)) {
        if (!props.multiple && hasSelectionSlot.value && model.value.length > 0 && !search.value) return select(model.value[0], false);
        if (~selectionIndex.value) {
          e.preventDefault();
          const originalSelectionIndex = selectionIndex.value;
          select(model.value[selectionIndex.value], false);
          selectionIndex.value = originalSelectionIndex >= length - 1 ? length - 2 : originalSelectionIndex;
        } else if (e.key === "Backspace" && !search.value) {
          selectionIndex.value = length - 1;
        }
        return;
      }
      if (!props.multiple) return;
      if (e.key === "ArrowLeft") {
        if (selectionIndex.value < 0 && selectionStart && selectionStart > 0) return;
        const prev = selectionIndex.value > -1 ? selectionIndex.value - 1 : length - 1;
        if (model.value[prev]) {
          selectionIndex.value = prev;
        } else {
          const searchLength = (_d = (_c = search.value) == null ? void 0 : _c.length) != null ? _d : null;
          selectionIndex.value = -1;
          (_e = vTextFieldRef.value) == null ? void 0 : _e.setSelectionRange(searchLength, searchLength);
        }
      } else if (e.key === "ArrowRight") {
        if (selectionIndex.value < 0) return;
        const next = selectionIndex.value + 1;
        if (model.value[next]) {
          selectionIndex.value = next;
        } else {
          selectionIndex.value = -1;
          (_f = vTextFieldRef.value) == null ? void 0 : _f.setSelectionRange(0, 0);
        }
      } else if (~selectionIndex.value && checkPrintable(e)) {
        selectionIndex.value = -1;
      }
    }
    function onChange(e) {
      if (matchesSelector(vTextFieldRef.value) || matchesSelector(vTextFieldRef.value)) ;
    }
    function onAfterEnter() {
      var _a;
      if (props.eager) {
        (_a = vVirtualScrollRef.value) == null ? void 0 : _a.calculateVisibleItems();
      }
    }
    function onAfterLeave() {
      var _a;
      if (isFocused.value) {
        isPristine.value = true;
        (_a = vTextFieldRef.value) == null ? void 0 : _a.focus();
      }
      _searchLock.value = null;
    }
    function onFocusin(e) {
      isFocused.value = true;
      setTimeout(() => {
        listHasFocus.value = true;
      });
    }
    function onFocusout(e) {
      var _a;
      listHasFocus.value = false;
      if (!((_a = vTextFieldRef.value) == null ? void 0 : _a.$el.contains(e.relatedTarget))) {
        isFocused.value = false;
      }
    }
    function onUpdateModelValue(v) {
      if (v == null || v === "" && !props.multiple && !hasSelectionSlot.value) model.value = [];
    }
    function onBlur(e) {
      var _a;
      const menuContent = (_a = vMenuRef.value) == null ? void 0 : _a.contentEl;
      if (menuContent == null ? void 0 : menuContent.contains(e.relatedTarget)) {
        isFocused.value = true;
      }
    }
    const isSelecting = shallowRef(false);
    function select(item) {
      var _a;
      let set = arguments.length > 1 && arguments[1] !== void 0 ? arguments[1] : true;
      if (!item || item.props.disabled) return;
      if (props.multiple) {
        const index = model.value.findIndex((selection) => (props.valueComparator || deepEqual)(selection.value, item.value));
        const add = set == null ? !~index : set;
        if (~index) {
          const value = add ? [...model.value, item] : [...model.value];
          value.splice(index, 1);
          model.value = value;
        } else if (add) {
          model.value = [...model.value, item];
        }
        if (props.clearOnSelect) {
          search.value = "";
        }
      } else {
        const add = set !== false;
        model.value = add ? [item] : [];
        _searchLock.value = isPristine.value ? "" : (_a = search.value) != null ? _a : "";
        search.value = add && !hasSelectionSlot.value ? item.title : "";
        nextTick(() => {
          menu.value = false;
          isPristine.value = true;
        });
      }
    }
    watch(isFocused, (val, oldVal) => {
      var _a, _b;
      if (val === oldVal) return;
      if (val) {
        isSelecting.value = true;
        search.value = props.multiple || hasSelectionSlot.value ? "" : String((_b = (_a = model.value.at(-1)) == null ? void 0 : _a.props.title) != null ? _b : "");
        isPristine.value = true;
        nextTick(() => isSelecting.value = false);
      } else {
        if (!props.multiple && search.value == null) model.value = [];
        menu.value = false;
        if (!isPristine.value && search.value) {
          _searchLock.value = search.value;
        }
        search.value = "";
        selectionIndex.value = -1;
      }
    });
    watch(search, (val) => {
      if (!isFocused.value || isSelecting.value) return;
      if (val) menu.value = true;
      isPristine.value = !val;
    });
    watch(menu, (val) => {
      if (!props.hideSelected && val && model.value.length && isPristine.value) {
        displayItems.value.findIndex((item) => model.value.some((s) => item.value === s.value));
      }
      if (val) _searchLock.value = null;
    });
    watch(items, (newVal, oldVal) => {
      if (menu.value) return;
      if (isFocused.value && !oldVal.length && newVal.length) {
        menu.value = true;
      }
    });
    useRender(() => {
      const hasList = !!(!props.hideNoData || displayItems.value.length || slots["prepend-item"] || slots["append-item"] || slots["no-data"]);
      const isDirty = model.value.length > 0;
      const textFieldProps = VTextField.filterProps(props);
      const menuSlotProps = {
        search,
        filteredItems: filteredItems.value
      };
      return createVNode(VTextField, mergeProps({
        "ref": vTextFieldRef
      }, textFieldProps, {
        "modelValue": search.value,
        "onUpdate:modelValue": [($event) => search.value = $event, onUpdateModelValue],
        "focused": isFocused.value,
        "onUpdate:focused": ($event) => isFocused.value = $event,
        "validationValue": model.externalValue,
        "counterValue": counterValue.value,
        "dirty": isDirty,
        "onChange": onChange,
        "class": ["v-autocomplete", `v-autocomplete--${props.multiple ? "multiple" : "single"}`, {
          "v-autocomplete--active-menu": menu.value,
          "v-autocomplete--chips": !!props.chips,
          "v-autocomplete--selection-slot": !!hasSelectionSlot.value,
          "v-autocomplete--selecting-index": selectionIndex.value > -1
        }, props.class],
        "style": props.style,
        "readonly": form.isReadonly.value,
        "placeholder": isDirty ? void 0 : props.placeholder,
        "onClick:clear": onClear,
        "onMousedown:control": onMousedownControl,
        "onKeydown": onKeydown2,
        "onBlur": onBlur,
        "aria-expanded": ariaExpanded.value,
        "aria-controls": ariaControls.value
      }), {
        ...slots,
        default: (_ref3) => {
          let {
            id
          } = _ref3;
          return createElementVNode(Fragment, null, [createVNode(VMenu, mergeProps({
            "id": menuId.value,
            "ref": vMenuRef,
            "modelValue": menu.value,
            "onUpdate:modelValue": ($event) => menu.value = $event,
            "activator": "parent",
            "contentClass": "v-autocomplete__content",
            "disabled": menuDisabled.value,
            "eager": props.eager,
            "maxHeight": 310,
            "openOnClick": false,
            "closeOnContentClick": false,
            "onAfterEnter": onAfterEnter,
            "onAfterLeave": onAfterLeave
          }, props.menuProps), {
            default: () => [createVNode(VSheet, {
              "onFocusin": onFocusin,
              "onKeydown": onMenuKeydown
            }, {
              default: () => {
                var _a;
                return [slots["menu-header"] && createElementVNode("header", {
                  "ref": headerRef
                }, [slots["menu-header"](menuSlotProps)]), hasList && createVNode(VList, mergeProps({
                  "key": "autocomplete-list",
                  "ref": listRef,
                  "filterable": true,
                  "selected": selectedValues.value,
                  "selectStrategy": props.multiple ? "independent" : "single-independent",
                  "onMousedown": (e) => e.preventDefault(),
                  "onFocusout": onFocusout,
                  "tabindex": "-1",
                  "selectable": !!displayItems.value.length,
                  "aria-live": "polite",
                  "aria-labelledby": `${id.value}-label`,
                  "aria-multiselectable": props.multiple,
                  "color": (_a = props.itemColor) != null ? _a : props.color
                }, listEvents, props.listProps), {
                  default: () => {
                    var _a2, _b, _c, _d;
                    return [(_a2 = slots["prepend-item"]) == null ? void 0 : _a2.call(slots), !displayItems.value.length && !props.hideNoData && ((_c = (_b = slots["no-data"]) == null ? void 0 : _b.call(slots)) != null ? _c : createVNode(VListItem, {
                      "key": "no-data",
                      "title": t(props.noDataText)
                    }, null)), createVNode(VVirtualScroll, {
                      "ref": vVirtualScrollRef,
                      "renderless": true,
                      "items": displayItems.value,
                      "itemKey": "value"
                    }, {
                      default: (_ref4) => {
                        var _a3, _b2, _c2, _d2, _e, _f;
                        let {
                          item,
                          index,
                          itemRef
                        } = _ref4;
                        const itemProps = mergeProps(item.props, {
                          ref: itemRef,
                          key: item.value,
                          active: highlightFirst.value && item === firstSelectableItem.value ? true : void 0,
                          onClick: () => select(item, null),
                          "aria-posinset": index + 1,
                          "aria-setsize": displayItems.value.length
                        });
                        if (item.type === "divider") {
                          return (_b2 = (_a3 = slots.divider) == null ? void 0 : _a3.call(slots, {
                            props: item.raw,
                            index
                          })) != null ? _b2 : createVNode(VDivider, mergeProps(item.props, {
                            "key": `divider-${index}`
                          }), null);
                        }
                        if (item.type === "subheader") {
                          return (_d2 = (_c2 = slots.subheader) == null ? void 0 : _c2.call(slots, {
                            props: item.raw,
                            index
                          })) != null ? _d2 : createVNode(VListSubheader, mergeProps(item.props, {
                            "key": `subheader-${index}`
                          }), null);
                        }
                        return (_f = (_e = slots.item) == null ? void 0 : _e.call(slots, {
                          item,
                          index,
                          props: itemProps
                        })) != null ? _f : createVNode(VListItem, mergeProps(itemProps, {
                          "role": "option"
                        }), {
                          prepend: (_ref5) => {
                            let {
                              isSelected
                            } = _ref5;
                            return createElementVNode(Fragment, null, [props.multiple && !props.hideSelected ? createVNode(VCheckboxBtn, {
                              "key": item.value,
                              "modelValue": isSelected,
                              "ripple": false,
                              "tabindex": "-1",
                              "aria-hidden": true,
                              "onClick": (event) => event.preventDefault()
                            }, null) : void 0, item.props.prependAvatar && createVNode(VAvatar, {
                              "image": item.props.prependAvatar
                            }, null), item.props.prependIcon && createVNode(VIcon, {
                              "icon": item.props.prependIcon
                            }, null)]);
                          },
                          title: () => {
                            var _a4;
                            return isPristine.value ? item.title : highlightResult("v-autocomplete", item.title, (_a4 = getMatches(item)) == null ? void 0 : _a4.title);
                          }
                        });
                      }
                    }), (_d = slots["append-item"]) == null ? void 0 : _d.call(slots)];
                  }
                }), slots["menu-footer"] && createElementVNode("footer", {
                  "ref": footerRef
                }, [slots["menu-footer"](menuSlotProps)])];
              }
            })]
          }), model.value.map((item, index) => {
            function onChipClose(e) {
              e.stopPropagation();
              e.preventDefault();
              select(item, false);
            }
            const slotProps = mergeProps(VChip.filterProps(item.props), {
              "onClick:close": onChipClose,
              onKeydown(e) {
                if (e.key !== "Enter" && e.key !== " ") return;
                e.preventDefault();
                e.stopPropagation();
                onChipClose(e);
              },
              onMousedown(e) {
                e.preventDefault();
                e.stopPropagation();
              },
              modelValue: true,
              "onUpdate:modelValue": void 0
            });
            const hasSlot = hasChips.value ? !!slots.chip : !!slots.selection;
            const slotContent = hasSlot ? ensureValidVNode(hasChips.value ? slots.chip({
              item,
              index,
              props: slotProps
            }) : slots.selection({
              item,
              index
            })) : void 0;
            if (hasSlot && !slotContent) return void 0;
            return createElementVNode("div", {
              "key": item.value,
              "class": normalizeClass(["v-autocomplete__selection", index === selectionIndex.value && ["v-autocomplete__selection--selected", textColorClasses.value]]),
              "style": normalizeStyle(index === selectionIndex.value ? textColorStyles.value : {})
            }, [hasChips.value ? !slots.chip ? createVNode(VChip, mergeProps({
              "key": "chip",
              "closable": closableChips.value,
              "size": "small",
              "text": item.title,
              "disabled": item.props.disabled
            }, slotProps), null) : createVNode(VDefaultsProvider, {
              "key": "chip-defaults",
              "defaults": {
                VChip: {
                  closable: closableChips.value,
                  size: "small",
                  text: item.title
                }
              }
            }, {
              default: () => [slotContent]
            }) : slotContent != null ? slotContent : createElementVNode("span", {
              "class": "v-autocomplete__selection-text"
            }, [item.title, props.multiple && index < model.value.length - 1 && createElementVNode("span", {
              "class": "v-autocomplete__selection-comma"
            }, [createTextVNode(",")])])]);
          })]);
        },
        "append-inner": function() {
          var _a, _b;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          return createElementVNode(Fragment, null, [(_a = slots["append-inner"]) == null ? void 0 : _a.call(slots, ...args), props.menuIcon ? createVNode(VIcon, {
            "class": "v-autocomplete__menu-icon",
            "color": (_b = vTextFieldRef.value) == null ? void 0 : _b.fieldIconColor,
            "icon": props.menuIcon,
            "onMousedown": onMousedownMenuIcon,
            "onClick": noop,
            "aria-hidden": true,
            "tabindex": "-1"
          }, null) : void 0, props.appendInnerIcon && createVNode(InputIcon, {
            "key": "append-icon",
            "name": "appendInner",
            "color": args[0].iconColor.value
          }, null)]);
        }
      });
    });
    return forwardRefs({
      isFocused,
      isPristine,
      menu,
      search,
      filteredItems,
      select
    }, vTextFieldRef);
  }
});
const _sfc_main$4 = /* @__PURE__ */ defineComponent({
  __name: "LanguageSwitcher",
  __ssrInlineRender: true,
  props: {
    fullWidth: { type: Boolean },
    compact: { type: Boolean },
    iconOnly: { type: Boolean }
  },
  setup(__props) {
    const { t, locale } = useI18n();
    const nuxtApp = useNuxtApp();
    const switchLocalePath = useSwitchLocalePath();
    const props = __props;
    const localeStore = useLocaleStore();
    const i18nClient = nuxtApp.$i18n;
    const flagIconMap = {
      en: "circle-flags:gb",
      ru: "circle-flags:ru"
    };
    const items = computed(
      () => supportedLocales.map((item) => {
        var _a;
        return {
          title: item.name,
          value: item.code,
          flagIcon: (_a = flagIconMap[item.code]) != null ? _a : "circle-flags:xx"
        };
      })
    );
    const dropdownItems = computed(() => items.value.filter((item) => item.value !== locale.value));
    const currentFlagIcon = computed(() => {
      var _a;
      return (_a = flagIconMap[locale.value]) != null ? _a : "circle-flags:xx";
    });
    const iconMenuOpen = ref(false);
    const searchQuery = ref("");
    const searchInputRef = ref(null);
    const filteredDropdownItems = computed(() => {
      const q = searchQuery.value.toLowerCase().trim();
      if (!q) return dropdownItems.value;
      return dropdownItems.value.filter(
        (item) => item.title.toLowerCase().includes(q) || item.value.toLowerCase().includes(q)
      );
    });
    watch(iconMenuOpen, (open) => {
      if (open) {
        searchQuery.value = "";
        nextTick(() => {
          var _a;
          return (_a = searchInputRef.value) == null ? void 0 : _a.focus();
        });
      }
    });
    const { trackLanguageSwitch } = useAnalytics();
    const onChange = async (value) => {
      const nextLocale = value;
      iconMenuOpen.value = false;
      trackLanguageSwitch(locale.value, nextLocale);
      localeStore.setLocale(nextLocale, true);
      if (i18nClient == null ? void 0 : i18nClient.setLocale) {
        await i18nClient.setLocale(nextLocale);
      } else {
        locale.value = nextLocale;
      }
      const path = switchLocalePath(nextLocale);
      if (path) {
        await navigateTo(path);
      }
    };
    return (_ctx, _push, _parent, _attrs) => {
      const _component_Icon = __nuxt_component_0$3;
      if (props.iconOnly) {
        _push(ssrRenderComponent(VMenu, mergeProps({
          modelValue: unref(iconMenuOpen),
          "onUpdate:modelValue": ($event) => isRef(iconMenuOpen) ? iconMenuOpen.value = $event : null,
          location: "bottom end",
          "close-on-content-click": false
        }, _attrs), {
          activator: withCtx(({ props: menuProps }, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(ssrRenderComponent(VBtn, mergeProps({ variant: "text" }, menuProps, {
                "aria-label": unref(t)("language.label")
              }), {
                default: withCtx((_, _push3, _parent3, _scopeId2) => {
                  if (_push3) {
                    _push3(ssrRenderComponent(_component_Icon, {
                      name: unref(currentFlagIcon),
                      class: "language-switcher__flag-icon"
                    }, null, _parent3, _scopeId2));
                  } else {
                    return [
                      createVNode(_component_Icon, {
                        name: unref(currentFlagIcon),
                        class: "language-switcher__flag-icon"
                      }, null, 8, ["name"])
                    ];
                  }
                }),
                _: 2
              }, _parent2, _scopeId));
            } else {
              return [
                createVNode(VBtn, mergeProps({ variant: "text" }, menuProps, {
                  "aria-label": unref(t)("language.label")
                }), {
                  default: withCtx(() => [
                    createVNode(_component_Icon, {
                      name: unref(currentFlagIcon),
                      class: "language-switcher__flag-icon"
                    }, null, 8, ["name"])
                  ]),
                  _: 1
                }, 16, ["aria-label"])
              ];
            }
          }),
          default: withCtx((_, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(`<div class="language-switcher__dropdown-panel" data-v-d919842e${_scopeId}><div class="language-switcher__search-wrap" data-v-d919842e${_scopeId}><input${ssrRenderAttr("value", unref(searchQuery))} type="text" class="language-switcher__search-input"${ssrRenderAttr("placeholder", unref(t)("language.search"))} data-v-d919842e${_scopeId}></div>`);
              _push2(ssrRenderComponent(VList, {
                density: "compact",
                class: "language-switcher__menu-list"
              }, {
                default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                  if (_push3) {
                    _push3(`<!--[-->`);
                    ssrRenderList(unref(filteredDropdownItems), (item) => {
                      _push3(ssrRenderComponent(VListItem, {
                        key: item.value,
                        onClick: ($event) => onChange(item.value)
                      }, {
                        title: withCtx((_3, _push4, _parent4, _scopeId3) => {
                          if (_push4) {
                            _push4(`<span class="language-switcher__item" data-v-d919842e${_scopeId3}>`);
                            _push4(ssrRenderComponent(_component_Icon, {
                              name: item.flagIcon,
                              class: "language-switcher__flag-icon"
                            }, null, _parent4, _scopeId3));
                            _push4(`<span data-v-d919842e${_scopeId3}>${ssrInterpolate(item.title)}</span></span>`);
                          } else {
                            return [
                              createVNode("span", { class: "language-switcher__item" }, [
                                createVNode(_component_Icon, {
                                  name: item.flagIcon,
                                  class: "language-switcher__flag-icon"
                                }, null, 8, ["name"]),
                                createVNode("span", null, toDisplayString(item.title), 1)
                              ])
                            ];
                          }
                        }),
                        _: 2
                      }, _parent3, _scopeId2));
                    });
                    _push3(`<!--]-->`);
                    if (unref(filteredDropdownItems).length === 0) {
                      _push3(ssrRenderComponent(VListItem, { disabled: "" }, {
                        title: withCtx((_3, _push4, _parent4, _scopeId3) => {
                          if (_push4) {
                            _push4(`<span class="language-switcher__no-results" data-v-d919842e${_scopeId3}>\u2014</span>`);
                          } else {
                            return [
                              createVNode("span", { class: "language-switcher__no-results" }, "\u2014")
                            ];
                          }
                        }),
                        _: 1
                      }, _parent3, _scopeId2));
                    } else {
                      _push3(`<!---->`);
                    }
                  } else {
                    return [
                      (openBlock(true), createBlock(Fragment, null, renderList(unref(filteredDropdownItems), (item) => {
                        return openBlock(), createBlock(VListItem, {
                          key: item.value,
                          onClick: ($event) => onChange(item.value)
                        }, {
                          title: withCtx(() => [
                            createVNode("span", { class: "language-switcher__item" }, [
                              createVNode(_component_Icon, {
                                name: item.flagIcon,
                                class: "language-switcher__flag-icon"
                              }, null, 8, ["name"]),
                              createVNode("span", null, toDisplayString(item.title), 1)
                            ])
                          ]),
                          _: 2
                        }, 1032, ["onClick"]);
                      }), 128)),
                      unref(filteredDropdownItems).length === 0 ? (openBlock(), createBlock(VListItem, {
                        key: 0,
                        disabled: ""
                      }, {
                        title: withCtx(() => [
                          createVNode("span", { class: "language-switcher__no-results" }, "\u2014")
                        ]),
                        _: 1
                      })) : createCommentVNode("", true)
                    ];
                  }
                }),
                _: 1
              }, _parent2, _scopeId));
              _push2(`</div>`);
            } else {
              return [
                createVNode("div", { class: "language-switcher__dropdown-panel" }, [
                  createVNode("div", { class: "language-switcher__search-wrap" }, [
                    withDirectives(createVNode("input", {
                      ref_key: "searchInputRef",
                      ref: searchInputRef,
                      "onUpdate:modelValue": ($event) => isRef(searchQuery) ? searchQuery.value = $event : null,
                      type: "text",
                      class: "language-switcher__search-input",
                      placeholder: unref(t)("language.search"),
                      onKeydown: withKeys(($event) => iconMenuOpen.value = false, ["esc"])
                    }, null, 40, ["onUpdate:modelValue", "placeholder", "onKeydown"]), [
                      [vModelText, unref(searchQuery)]
                    ])
                  ]),
                  createVNode(VList, {
                    density: "compact",
                    class: "language-switcher__menu-list"
                  }, {
                    default: withCtx(() => [
                      (openBlock(true), createBlock(Fragment, null, renderList(unref(filteredDropdownItems), (item) => {
                        return openBlock(), createBlock(VListItem, {
                          key: item.value,
                          onClick: ($event) => onChange(item.value)
                        }, {
                          title: withCtx(() => [
                            createVNode("span", { class: "language-switcher__item" }, [
                              createVNode(_component_Icon, {
                                name: item.flagIcon,
                                class: "language-switcher__flag-icon"
                              }, null, 8, ["name"]),
                              createVNode("span", null, toDisplayString(item.title), 1)
                            ])
                          ]),
                          _: 2
                        }, 1032, ["onClick"]);
                      }), 128)),
                      unref(filteredDropdownItems).length === 0 ? (openBlock(), createBlock(VListItem, {
                        key: 0,
                        disabled: ""
                      }, {
                        title: withCtx(() => [
                          createVNode("span", { class: "language-switcher__no-results" }, "\u2014")
                        ]),
                        _: 1
                      })) : createCommentVNode("", true)
                    ]),
                    _: 1
                  })
                ])
              ];
            }
          }),
          _: 1
        }, _parent));
      } else {
        _push(ssrRenderComponent(VAutocomplete, mergeProps({
          label: props.compact ? void 0 : unref(t)("language.label"),
          placeholder: props.compact ? unref(t)("language.label") : void 0,
          items: unref(dropdownItems),
          "model-value": unref(locale),
          density: "compact",
          variant: props.compact ? "plain" : "outlined",
          "hide-details": "",
          "auto-select-first": "",
          "menu-props": { contentClass: "language-switcher__dropdown" },
          style: props.fullWidth ? { maxWidth: "100%", width: "100%" } : { maxWidth: "220px" },
          class: {
            "language-switcher--full": props.fullWidth,
            "language-switcher--compact": props.compact
          },
          "aria-label": unref(t)("language.label"),
          "single-line": props.compact,
          "onUpdate:modelValue": onChange
        }, _attrs), {
          selection: withCtx((_, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(ssrRenderComponent(_component_Icon, {
                name: unref(currentFlagIcon),
                class: "language-switcher__flag-icon"
              }, null, _parent2, _scopeId));
            } else {
              return [
                createVNode(_component_Icon, {
                  name: unref(currentFlagIcon),
                  class: "language-switcher__flag-icon"
                }, null, 8, ["name"])
              ];
            }
          }),
          item: withCtx(({ item, props: itemProps }, _push2, _parent2, _scopeId) => {
            if (_push2) {
              _push2(ssrRenderComponent(VListItem, itemProps, {
                title: withCtx((_, _push3, _parent3, _scopeId2) => {
                  if (_push3) {
                    _push3(`<span class="language-switcher__item" data-v-d919842e${_scopeId2}>`);
                    _push3(ssrRenderComponent(_component_Icon, {
                      name: item.raw.flagIcon,
                      class: "language-switcher__flag-icon"
                    }, null, _parent3, _scopeId2));
                    _push3(`<span data-v-d919842e${_scopeId2}>${ssrInterpolate(item.raw.title)}</span></span>`);
                  } else {
                    return [
                      createVNode("span", { class: "language-switcher__item" }, [
                        createVNode(_component_Icon, {
                          name: item.raw.flagIcon,
                          class: "language-switcher__flag-icon"
                        }, null, 8, ["name"]),
                        createVNode("span", null, toDisplayString(item.raw.title), 1)
                      ])
                    ];
                  }
                }),
                _: 2
              }, _parent2, _scopeId));
            } else {
              return [
                createVNode(VListItem, itemProps, {
                  title: withCtx(() => [
                    createVNode("span", { class: "language-switcher__item" }, [
                      createVNode(_component_Icon, {
                        name: item.raw.flagIcon,
                        class: "language-switcher__flag-icon"
                      }, null, 8, ["name"]),
                      createVNode("span", null, toDisplayString(item.raw.title), 1)
                    ])
                  ]),
                  _: 2
                }, 1040)
              ];
            }
          }),
          _: 1
        }, _parent));
      }
    };
  }
});
const _sfc_setup$4 = _sfc_main$4.setup;
_sfc_main$4.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/layout/LanguageSwitcher.vue");
  return _sfc_setup$4 ? _sfc_setup$4(props, ctx) : void 0;
};
const __nuxt_component_1$1 = /* @__PURE__ */ _export_sfc(_sfc_main$4, [["__scopeId", "data-v-d919842e"]]);
const useThemeStore = defineStore("theme", {
  state: () => ({
    current: "dark",
    userSelected: false
  }),
  actions: {
    getInitialTheme() {
      return "dark";
    },
    setTheme(theme, fromUser) {
      this.current = theme;
    }
  }
});
const useBrowserTheme = () => {
  const themeStore = useThemeStore();
  const { $vuetifyTheme } = useNuxtApp();
  const vuetifyTheme = $vuetifyTheme;
  const applyVuetifyTheme = (name) => {
    if (!vuetifyTheme) return;
    if (typeof vuetifyTheme.change === "function") {
      vuetifyTheme.change(name);
    } else {
      vuetifyTheme.global.name.value = name;
    }
  };
  const applyTheme = (name) => {
    themeStore.setTheme(name, true);
    applyVuetifyTheme(name);
  };
  const initTheme = () => {
    return;
  };
  const toggleTheme = () => {
    applyTheme(themeStore.current === "dark" ? "light" : "dark");
  };
  watch(
    () => themeStore.current,
    (value) => {
      applyVuetifyTheme(value);
    }
  );
  return {
    currentTheme: computed(() => themeStore.current),
    isDark: computed(() => themeStore.current === "dark"),
    initTheme,
    toggleTheme
  };
};
const makeVTooltipProps = propsFactory({
  id: String,
  interactive: Boolean,
  text: String,
  ...omit(makeVOverlayProps({
    closeOnBack: false,
    location: "end",
    locationStrategy: "connected",
    eager: true,
    minWidth: 0,
    offset: 10,
    openOnClick: false,
    openOnHover: true,
    origin: "auto",
    scrim: false,
    scrollStrategy: "reposition",
    transition: null
  }), ["absolute", "retainFocus", "captureFocus", "disableInitialFocus"])
}, "VTooltip");
const VTooltip = genericComponent()({
  name: "VTooltip",
  props: makeVTooltipProps(),
  emits: {
    "update:modelValue": (value) => true
  },
  setup(props, _ref) {
    let {
      slots
    } = _ref;
    const isActive = useProxiedModel(props, "modelValue");
    const {
      scopeId
    } = useScopeId();
    const uid = useId();
    const id = toRef(() => props.id || `v-tooltip-${uid}`);
    const overlay = ref();
    const location = computed(() => {
      return props.location.split(" ").length > 1 ? props.location : props.location + " center";
    });
    const origin = computed(() => {
      return props.origin === "auto" || props.origin === "overlap" || props.origin.split(" ").length > 1 || props.location.split(" ").length > 1 ? props.origin : props.origin + " center";
    });
    const transition = toRef(() => {
      if (props.transition != null) return props.transition;
      return isActive.value ? "scale-transition" : "fade-transition";
    });
    const activatorProps = computed(() => mergeProps({
      "aria-describedby": id.value
    }, props.activatorProps));
    useRender(() => {
      const overlayProps = VOverlay.filterProps(props);
      return createVNode(VOverlay, mergeProps({
        "ref": overlay,
        "class": ["v-tooltip", {
          "v-tooltip--interactive": props.interactive
        }, props.class],
        "style": props.style,
        "id": id.value
      }, overlayProps, {
        "modelValue": isActive.value,
        "onUpdate:modelValue": ($event) => isActive.value = $event,
        "transition": transition.value,
        "absolute": true,
        "location": location.value,
        "origin": origin.value,
        "role": "tooltip",
        "activatorProps": activatorProps.value,
        "_disableGlobalStack": true
      }, scopeId), {
        activator: slots.activator,
        default: function() {
          var _a, _b;
          for (var _len = arguments.length, args = new Array(_len), _key = 0; _key < _len; _key++) {
            args[_key] = arguments[_key];
          }
          return (_b = (_a = slots.default) == null ? void 0 : _a.call(slots, ...args)) != null ? _b : props.text;
        }
      });
    });
    return forwardRefs({}, overlay);
  }
});
const _sfc_main$3 = /* @__PURE__ */ defineComponent({
  __name: "ThemeToggle",
  __ssrInlineRender: true,
  setup(__props) {
    const { t } = useI18n();
    const { isDark, toggleTheme } = useBrowserTheme();
    const tooltip = computed(() => isDark.value ? t("theme.light") : t("theme.dark"));
    const ariaLabel = computed(() => t("theme.toggle"));
    const onToggle = () => {
      isDark.value ? "light" : "dark";
      toggleTheme();
    };
    return (_ctx, _push, _parent, _attrs) => {
      _push(ssrRenderComponent(VTooltip, mergeProps({
        text: unref(tooltip),
        location: "bottom"
      }, _attrs), {
        activator: withCtx(({ props }, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(VBtn, mergeProps(props, {
              icon: unref(isDark) ? unref(mdiWeatherSunny) : unref(mdiWeatherNight),
              variant: "text",
              size: "small",
              "aria-label": unref(ariaLabel),
              onClick: onToggle
            }), null, _parent2, _scopeId));
          } else {
            return [
              createVNode(VBtn, mergeProps(props, {
                icon: unref(isDark) ? unref(mdiWeatherSunny) : unref(mdiWeatherNight),
                variant: "text",
                size: "small",
                "aria-label": unref(ariaLabel),
                onClick: onToggle
              }), null, 16, ["icon", "aria-label"])
            ];
          }
        }),
        _: 1
      }, _parent));
    };
  }
});
const _sfc_setup$3 = _sfc_main$3.setup;
_sfc_main$3.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/common/ThemeToggle.vue");
  return _sfc_setup$3 ? _sfc_setup$3(props, ctx) : void 0;
};
const _sfc_main$2 = /* @__PURE__ */ defineComponent({
  __name: "AppHeader",
  __ssrInlineRender: true,
  setup(__props) {
    const { t } = useI18n();
    const route = useRoute$1();
    const router = useRouter$1();
    const localePath = useLocalePath();
    const config = useRuntimeConfig();
    const menuOpen = ref(false);
    const interactiveReady = ref(false);
    const githubUrl = `https://github.com/${config.public.githubRepo}`;
    const homePath = computed(() => localePath("/"));
    const homeHref = computed(() => router.resolve(homePath.value).href);
    const navItems = computed(() => [
      { id: "features", label: t("nav.features") },
      { id: "featured-rules", label: t("nav.featuredRules") },
      { id: "download", label: t("nav.download") },
      { id: "comparison", label: t("nav.comparison") },
      { id: "faq", label: t("nav.faq") }
    ]);
    const normalizePath = (value) => value !== "/" ? value.replace(/\/+$/, "") : "/";
    const isHomePage = computed(() => normalizePath(route.path) === normalizePath(homePath.value));
    const sectionHref = (sectionId) => isHomePage.value ? `#${sectionId}` : `${homeHref.value}#${sectionId}`;
    return (_ctx, _push, _parent, _attrs) => {
      const _component_AppLogo = __nuxt_component_0$1;
      const _component_LanguageSwitcher = __nuxt_component_1$1;
      const _component_ThemeToggle = _sfc_main$3;
      _push(`<header${ssrRenderAttrs(mergeProps({ class: "app-header" }, _attrs))} data-v-457e104a>`);
      _push(ssrRenderComponent(VContainer, { class: "app-header__inner" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(ssrRenderComponent(_component_AppLogo, null, null, _parent2, _scopeId));
            _push2(`<nav class="app-header__nav" data-v-457e104a${_scopeId}><!--[-->`);
            ssrRenderList(unref(navItems), (item) => {
              _push2(ssrRenderComponent(VBtn, {
                key: item.id,
                variant: "text",
                href: sectionHref(item.id)
              }, {
                default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                  if (_push3) {
                    _push3(`${ssrInterpolate(item.label)}`);
                  } else {
                    return [
                      createTextVNode(toDisplayString(item.label), 1)
                    ];
                  }
                }),
                _: 2
              }, _parent2, _scopeId));
            });
            _push2(`<!--]--></nav><div class="app-header__spacer" data-v-457e104a${_scopeId}></div><div class="app-header__desktop-actions" data-v-457e104a${_scopeId}>`);
            if (unref(interactiveReady)) {
              _push2(ssrRenderComponent(_component_LanguageSwitcher, { "icon-only": "" }, null, _parent2, _scopeId));
            } else {
              _push2(`<div class="app-header__control-fallback" aria-hidden="true" data-v-457e104a${_scopeId}></div>`);
            }
            _push2(ssrRenderComponent(VBtn, {
              variant: "outlined",
              size: "small",
              href: githubUrl,
              target: "_blank",
              rel: "noopener noreferrer",
              class: "app-header__github-btn",
              "prepend-icon": unref(mdiGithub)
            }, {
              default: withCtx((_2, _push3, _parent3, _scopeId2) => {
                if (_push3) {
                  _push3(`${ssrInterpolate(unref(t)("nav.viewOnGithub"))}`);
                } else {
                  return [
                    createTextVNode(toDisplayString(unref(t)("nav.viewOnGithub")), 1)
                  ];
                }
              }),
              _: 1
            }, _parent2, _scopeId));
            if (unref(interactiveReady)) {
              _push2(ssrRenderComponent(_component_ThemeToggle, null, null, _parent2, _scopeId));
            } else {
              _push2(`<div class="app-header__control-fallback" aria-hidden="true" data-v-457e104a${_scopeId}></div>`);
            }
            _push2(`</div><div class="app-header__mobile-actions" data-v-457e104a${_scopeId}>`);
            _push2(ssrRenderComponent(VBtn, {
              icon: unref(mdiMenu),
              variant: "text",
              onClick: ($event) => menuOpen.value = true
            }, null, _parent2, _scopeId));
            ssrRenderTeleport(_push2, (_push3) => {
              if (unref(menuOpen)) {
                _push3(`<div class="mobile-menu-overlay" data-v-457e104a${_scopeId}><div class="mobile-menu" data-v-457e104a${_scopeId}><div class="mobile-menu__header" data-v-457e104a${_scopeId}><div data-v-457e104a${_scopeId}>`);
                _push3(ssrRenderComponent(_component_AppLogo, null, null, _parent2, _scopeId));
                _push3(`</div><div style="${ssrRenderStyle({ "flex": "1" })}" data-v-457e104a${_scopeId}></div>`);
                _push3(ssrRenderComponent(VBtn, {
                  icon: unref(mdiClose),
                  variant: "text",
                  onClick: ($event) => menuOpen.value = false
                }, null, _parent2, _scopeId));
                _push3(`</div><hr class="mobile-menu__divider" data-v-457e104a${_scopeId}><nav class="mobile-menu__list" data-v-457e104a${_scopeId}><!--[-->`);
                ssrRenderList(unref(navItems), (item) => {
                  _push3(`<a${ssrRenderAttr("href", sectionHref(item.id))} class="mobile-menu__link" data-v-457e104a${_scopeId}>${ssrInterpolate(item.label)}</a>`);
                });
                _push3(`<!--]--><a${ssrRenderAttr("href", githubUrl)} target="_blank" rel="noopener noreferrer" class="mobile-menu__link" data-v-457e104a${_scopeId}>${ssrInterpolate(unref(t)("nav.viewOnGithub"))}</a></nav><hr class="mobile-menu__divider" data-v-457e104a${_scopeId}><div class="mobile-menu__actions" data-v-457e104a${_scopeId}>`);
                if (unref(interactiveReady)) {
                  _push3(`<!--[-->`);
                  _push3(ssrRenderComponent(_component_LanguageSwitcher, { compact: "" }, null, _parent2, _scopeId));
                  _push3(ssrRenderComponent(_component_ThemeToggle, null, null, _parent2, _scopeId));
                  _push3(`<!--]-->`);
                } else {
                  _push3(`<!--[--><div class="app-header__control-fallback app-header__control-fallback--wide" aria-hidden="true" data-v-457e104a${_scopeId}></div><div class="app-header__control-fallback" aria-hidden="true" data-v-457e104a${_scopeId}></div><!--]-->`);
                }
                _push3(`</div></div></div>`);
              } else {
                _push3(`<!---->`);
              }
            }, "body", false, _parent2);
            _push2(`</div>`);
          } else {
            return [
              createVNode(_component_AppLogo),
              createVNode("nav", { class: "app-header__nav" }, [
                (openBlock(true), createBlock(Fragment, null, renderList(unref(navItems), (item) => {
                  return openBlock(), createBlock(VBtn, {
                    key: item.id,
                    variant: "text",
                    href: sectionHref(item.id)
                  }, {
                    default: withCtx(() => [
                      createTextVNode(toDisplayString(item.label), 1)
                    ]),
                    _: 2
                  }, 1032, ["href"]);
                }), 128))
              ]),
              createVNode("div", { class: "app-header__spacer" }),
              createVNode("div", { class: "app-header__desktop-actions" }, [
                unref(interactiveReady) ? (openBlock(), createBlock(_component_LanguageSwitcher, {
                  key: 0,
                  "icon-only": ""
                })) : (openBlock(), createBlock("div", {
                  key: 1,
                  class: "app-header__control-fallback",
                  "aria-hidden": "true"
                })),
                createVNode(VBtn, {
                  variant: "outlined",
                  size: "small",
                  href: githubUrl,
                  target: "_blank",
                  rel: "noopener noreferrer",
                  class: "app-header__github-btn",
                  "prepend-icon": unref(mdiGithub)
                }, {
                  default: withCtx(() => [
                    createTextVNode(toDisplayString(unref(t)("nav.viewOnGithub")), 1)
                  ]),
                  _: 1
                }, 8, ["prepend-icon"]),
                unref(interactiveReady) ? (openBlock(), createBlock(_component_ThemeToggle, { key: 2 })) : (openBlock(), createBlock("div", {
                  key: 3,
                  class: "app-header__control-fallback",
                  "aria-hidden": "true"
                }))
              ]),
              createVNode("div", { class: "app-header__mobile-actions" }, [
                createVNode(VBtn, {
                  icon: unref(mdiMenu),
                  variant: "text",
                  onClick: ($event) => menuOpen.value = true
                }, null, 8, ["icon", "onClick"]),
                (openBlock(), createBlock(Teleport, { to: "body" }, [
                  createVNode(Transition, { name: "mobile-menu-fade" }, {
                    default: withCtx(() => [
                      unref(menuOpen) ? (openBlock(), createBlock("div", {
                        key: 0,
                        class: "mobile-menu-overlay",
                        onClick: withModifiers(($event) => menuOpen.value = false, ["self"])
                      }, [
                        createVNode("div", { class: "mobile-menu" }, [
                          createVNode("div", { class: "mobile-menu__header" }, [
                            createVNode("div", {
                              onClick: ($event) => menuOpen.value = false
                            }, [
                              createVNode(_component_AppLogo)
                            ], 8, ["onClick"]),
                            createVNode("div", { style: { "flex": "1" } }),
                            createVNode(VBtn, {
                              icon: unref(mdiClose),
                              variant: "text",
                              onClick: ($event) => menuOpen.value = false
                            }, null, 8, ["icon", "onClick"])
                          ]),
                          createVNode("hr", { class: "mobile-menu__divider" }),
                          createVNode("nav", { class: "mobile-menu__list" }, [
                            (openBlock(true), createBlock(Fragment, null, renderList(unref(navItems), (item) => {
                              return openBlock(), createBlock("a", {
                                key: item.id,
                                href: sectionHref(item.id),
                                class: "mobile-menu__link",
                                onClick: ($event) => menuOpen.value = false
                              }, toDisplayString(item.label), 9, ["href", "onClick"]);
                            }), 128)),
                            createVNode("a", {
                              href: githubUrl,
                              target: "_blank",
                              rel: "noopener noreferrer",
                              class: "mobile-menu__link",
                              onClick: ($event) => menuOpen.value = false
                            }, toDisplayString(unref(t)("nav.viewOnGithub")), 9, ["onClick"])
                          ]),
                          createVNode("hr", { class: "mobile-menu__divider" }),
                          createVNode("div", { class: "mobile-menu__actions" }, [
                            unref(interactiveReady) ? (openBlock(), createBlock(Fragment, { key: 0 }, [
                              createVNode(_component_LanguageSwitcher, { compact: "" }),
                              createVNode(_component_ThemeToggle)
                            ], 64)) : (openBlock(), createBlock(Fragment, { key: 1 }, [
                              createVNode("div", {
                                class: "app-header__control-fallback app-header__control-fallback--wide",
                                "aria-hidden": "true"
                              }),
                              createVNode("div", {
                                class: "app-header__control-fallback",
                                "aria-hidden": "true"
                              })
                            ], 64))
                          ])
                        ])
                      ], 8, ["onClick"])) : createCommentVNode("", true)
                    ]),
                    _: 1
                  })
                ]))
              ])
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</header>`);
    };
  }
});
const _sfc_setup$2 = _sfc_main$2.setup;
_sfc_main$2.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/layout/AppHeader.vue");
  return _sfc_setup$2 ? _sfc_setup$2(props, ctx) : void 0;
};
const __nuxt_component_0 = /* @__PURE__ */ _export_sfc(_sfc_main$2, [["__scopeId", "data-v-457e104a"]]);
const _sfc_main$1 = /* @__PURE__ */ defineComponent({
  __name: "AppFooter",
  __ssrInlineRender: true,
  setup(__props) {
    const { t } = useI18n();
    const config = useRuntimeConfig();
    const year = (/* @__PURE__ */ new Date()).getFullYear();
    const githubUrl = `https://github.com/${config.public.githubRepo}`;
    const githubOwner = (config.public.githubRepo || "777genius/lintai").split("/")[0] || "777genius";
    const githubOwnerUrl = `https://github.com/${githubOwner}`;
    const { docsUrl } = useDocsLinks();
    return (_ctx, _push, _parent, _attrs) => {
      _push(`<footer${ssrRenderAttrs(mergeProps({ class: "app-footer" }, _attrs))} data-v-7333d9da>`);
      _push(ssrRenderComponent(VContainer, { class: "app-footer__inner" }, {
        default: withCtx((_, _push2, _parent2, _scopeId) => {
          if (_push2) {
            _push2(`<span class="app-footer__copy" data-v-7333d9da${_scopeId}>${ssrInterpolate(unref(t)("footer.copyright", { year: unref(year) }))} <a class="app-footer__author"${ssrRenderAttr("href", githubOwnerUrl)} target="_blank" rel="noopener noreferrer" data-v-7333d9da${_scopeId}>${ssrInterpolate(unref(githubOwner))}</a> \xB7 ${ssrInterpolate(unref(t)("footer.tagline"))}</span><div class="app-footer__links" data-v-7333d9da${_scopeId}><a class="app-footer__link"${ssrRenderAttr("href", githubUrl)} target="_blank" rel="noopener noreferrer" data-v-7333d9da${_scopeId}>${ssrInterpolate(unref(t)("footer.github"))}</a><span class="app-footer__divider" data-v-7333d9da${_scopeId}></span><a class="app-footer__link"${ssrRenderAttr("href", unref(docsUrl))} target="_blank" rel="noopener noreferrer" data-v-7333d9da${_scopeId}>${ssrInterpolate(unref(t)("footer.docs"))}</a></div>`);
          } else {
            return [
              createVNode("span", { class: "app-footer__copy" }, [
                createTextVNode(toDisplayString(unref(t)("footer.copyright", { year: unref(year) })) + " ", 1),
                createVNode("a", {
                  class: "app-footer__author",
                  href: githubOwnerUrl,
                  target: "_blank",
                  rel: "noopener noreferrer"
                }, toDisplayString(unref(githubOwner)), 1),
                createTextVNode(" \xB7 " + toDisplayString(unref(t)("footer.tagline")), 1)
              ]),
              createVNode("div", { class: "app-footer__links" }, [
                createVNode("a", {
                  class: "app-footer__link",
                  href: githubUrl,
                  target: "_blank",
                  rel: "noopener noreferrer"
                }, toDisplayString(unref(t)("footer.github")), 1),
                createVNode("span", { class: "app-footer__divider" }),
                createVNode("a", {
                  class: "app-footer__link",
                  href: unref(docsUrl),
                  target: "_blank",
                  rel: "noopener noreferrer"
                }, toDisplayString(unref(t)("footer.docs")), 9, ["href"])
              ])
            ];
          }
        }),
        _: 1
      }, _parent));
      _push(`</footer>`);
    };
  }
});
const _sfc_setup$1 = _sfc_main$1.setup;
_sfc_main$1.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("components/layout/AppFooter.vue");
  return _sfc_setup$1 ? _sfc_setup$1(props, ctx) : void 0;
};
const __nuxt_component_1 = /* @__PURE__ */ _export_sfc(_sfc_main$1, [["__scopeId", "data-v-7333d9da"]]);
const _sfc_main = {};
function _sfc_ssrRender(_ctx, _push, _parent, _attrs) {
  const _component_AppHeader = __nuxt_component_0;
  const _component_AppFooter = __nuxt_component_1;
  _push(ssrRenderComponent(VApp, mergeProps({ class: "app-layout" }, _attrs), {
    default: withCtx((_, _push2, _parent2, _scopeId) => {
      if (_push2) {
        _push2(ssrRenderComponent(_component_AppHeader, null, null, _parent2, _scopeId));
        _push2(`<main class="app-layout__main" data-v-d675d545${_scopeId}>`);
        ssrRenderSlot(_ctx.$slots, "default", {}, null, _push2, _parent2, _scopeId);
        _push2(`</main>`);
        _push2(ssrRenderComponent(_component_AppFooter, null, null, _parent2, _scopeId));
      } else {
        return [
          createVNode(_component_AppHeader),
          createVNode("main", { class: "app-layout__main" }, [
            renderSlot(_ctx.$slots, "default", {}, void 0, true)
          ]),
          createVNode(_component_AppFooter)
        ];
      }
    }),
    _: 3
  }, _parent));
}
const _sfc_setup = _sfc_main.setup;
_sfc_main.setup = (props, ctx) => {
  const ssrContext = useSSRContext();
  (ssrContext.modules || (ssrContext.modules = /* @__PURE__ */ new Set())).add("layouts/default.vue");
  return _sfc_setup ? _sfc_setup(props, ctx) : void 0;
};
const _default = /* @__PURE__ */ _export_sfc(_sfc_main, [["ssrRender", _sfc_ssrRender], ["__scopeId", "data-v-d675d545"]]);

export { _default as default };
//# sourceMappingURL=default-BTnztuR8.mjs.map
