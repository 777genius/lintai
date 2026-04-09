import { computed, toValue, hasInjectionContext, inject, getCurrentInstance, onServerPrefetch, ref, shallowRef, nextTick, unref, toRef } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/vue@3.5.31_typescript@6.0.2/node_modules/vue/index.mjs';
import { u as useI18n, j as useRoute$1, k as useSwitchLocalePath, e as useRuntimeConfig, t as tryUseNuxtApp, f as useNuxtApp, h as asyncDataDefaults, i as createError } from './server.mjs';
import { debounce } from 'file:///Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs';
import { u as useDocsLinks, s as supportedLocales, d as defaultLocale } from './i18n-B_nLlkZy.mjs';
import { u as useSeoMeta$1, a as useHead$1, h as headSymbol } from '../_/renderer.mjs';

function injectHead(nuxtApp) {
  var _a;
  const nuxt = nuxtApp || tryUseNuxtApp();
  return ((_a = nuxt == null ? void 0 : nuxt.ssrContext) == null ? void 0 : _a.head) || (nuxt == null ? void 0 : nuxt.runWithContext(() => {
    if (hasInjectionContext()) {
      return inject(headSymbol);
    }
  }));
}
function useHead(input, options = {}) {
  const head = injectHead(options.nuxt);
  if (head) {
    return useHead$1(input, { head, ...options });
  }
}
function useSeoMeta(input, options = {}) {
  const head = injectHead(options.nuxt);
  if (head) {
    return useSeoMeta$1(input, { head, ...options });
  }
}
const isDefer = (dedupe) => dedupe === "defer" || dedupe === false;
function useAsyncData(...args) {
  var _a, _b, _c, _d, _e, _f, _g;
  const autoKey = typeof args[args.length - 1] === "string" ? args.pop() : void 0;
  if (_isAutoKeyNeeded(args[0], args[1])) {
    args.unshift(autoKey);
  }
  let [_key, _handler, options = {}] = args;
  const key = computed(() => toValue(_key));
  if (typeof key.value !== "string") {
    throw new TypeError("[nuxt] [useAsyncData] key must be a string.");
  }
  if (typeof _handler !== "function") {
    throw new TypeError("[nuxt] [useAsyncData] handler must be a function.");
  }
  const nuxtApp = useNuxtApp();
  (_a = options.server) != null ? _a : options.server = true;
  (_b = options.default) != null ? _b : options.default = getDefault;
  (_c = options.getCachedData) != null ? _c : options.getCachedData = getDefaultCachedData;
  (_d = options.lazy) != null ? _d : options.lazy = false;
  (_e = options.immediate) != null ? _e : options.immediate = true;
  (_f = options.deep) != null ? _f : options.deep = asyncDataDefaults.deep;
  (_g = options.dedupe) != null ? _g : options.dedupe = "cancel";
  options._functionName || "useAsyncData";
  nuxtApp._asyncData[key.value];
  function createInitialFetch() {
    var _a2;
    const initialFetchOptions = { cause: "initial", dedupe: options.dedupe };
    if (!((_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2._init)) {
      initialFetchOptions.cachedData = options.getCachedData(key.value, nuxtApp, { cause: "initial" });
      nuxtApp._asyncData[key.value] = createAsyncData(nuxtApp, key.value, _handler, options, initialFetchOptions.cachedData);
    }
    return () => nuxtApp._asyncData[key.value].execute(initialFetchOptions);
  }
  const initialFetch = createInitialFetch();
  const asyncData = nuxtApp._asyncData[key.value];
  asyncData._deps++;
  const fetchOnServer = options.server !== false && nuxtApp.payload.serverRendered;
  if (fetchOnServer && options.immediate) {
    const promise = initialFetch();
    if (getCurrentInstance()) {
      onServerPrefetch(() => promise);
    } else {
      nuxtApp.hook("app:created", async () => {
        await promise;
      });
    }
  }
  const asyncReturn = {
    data: writableComputedRef(() => {
      var _a2;
      return (_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2.data;
    }),
    pending: writableComputedRef(() => {
      var _a2;
      return (_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2.pending;
    }),
    status: writableComputedRef(() => {
      var _a2;
      return (_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2.status;
    }),
    error: writableComputedRef(() => {
      var _a2;
      return (_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2.error;
    }),
    refresh: (...args2) => {
      var _a2;
      if (!((_a2 = nuxtApp._asyncData[key.value]) == null ? void 0 : _a2._init)) {
        const initialFetch2 = createInitialFetch();
        return initialFetch2();
      }
      return nuxtApp._asyncData[key.value].execute(...args2);
    },
    execute: (...args2) => asyncReturn.refresh(...args2),
    clear: () => {
      const entry = nuxtApp._asyncData[key.value];
      if (entry == null ? void 0 : entry._abortController) {
        try {
          entry._abortController.abort(new DOMException("AsyncData aborted by user.", "AbortError"));
        } finally {
          entry._abortController = void 0;
        }
      }
      clearNuxtDataByKey(nuxtApp, key.value);
    }
  };
  const asyncDataPromise = Promise.resolve(nuxtApp._asyncDataPromises[key.value]).then(() => asyncReturn);
  Object.assign(asyncDataPromise, asyncReturn);
  Object.defineProperties(asyncDataPromise, {
    then: { enumerable: true, value: asyncDataPromise.then.bind(asyncDataPromise) },
    catch: { enumerable: true, value: asyncDataPromise.catch.bind(asyncDataPromise) },
    finally: { enumerable: true, value: asyncDataPromise.finally.bind(asyncDataPromise) }
  });
  return asyncDataPromise;
}
function writableComputedRef(getter) {
  return computed({
    get() {
      var _a;
      return (_a = getter()) == null ? void 0 : _a.value;
    },
    set(value) {
      const ref2 = getter();
      if (ref2) {
        ref2.value = value;
      }
    }
  });
}
function _isAutoKeyNeeded(keyOrFetcher, fetcher) {
  if (typeof keyOrFetcher === "string") {
    return false;
  }
  if (typeof keyOrFetcher === "object" && keyOrFetcher !== null) {
    return false;
  }
  if (typeof keyOrFetcher === "function" && typeof fetcher === "function") {
    return false;
  }
  return true;
}
function clearNuxtDataByKey(nuxtApp, key) {
  if (key in nuxtApp.payload.data) {
    nuxtApp.payload.data[key] = void 0;
  }
  if (key in nuxtApp.payload._errors) {
    nuxtApp.payload._errors[key] = asyncDataDefaults.errorValue;
  }
  if (nuxtApp._asyncData[key]) {
    nuxtApp._asyncData[key].data.value = void 0;
    nuxtApp._asyncData[key].error.value = asyncDataDefaults.errorValue;
    {
      nuxtApp._asyncData[key].pending.value = false;
    }
    nuxtApp._asyncData[key].status.value = "idle";
  }
  if (key in nuxtApp._asyncDataPromises) {
    nuxtApp._asyncDataPromises[key] = void 0;
  }
}
function pick(obj, keys) {
  const newObj = {};
  for (const key of keys) {
    newObj[key] = obj[key];
  }
  return newObj;
}
function createAsyncData(nuxtApp, key, _handler, options, initialCachedData) {
  var _a, _b, _c;
  (_b = (_a = nuxtApp.payload._errors)[key]) != null ? _b : _a[key] = asyncDataDefaults.errorValue;
  const hasCustomGetCachedData = options.getCachedData !== getDefaultCachedData;
  const handler = !((_c = nuxtApp.ssrContext) == null ? void 0 : _c["~sharedPrerenderCache"]) ? _handler : (nuxtApp2, options2) => {
    const value = nuxtApp2.ssrContext["~sharedPrerenderCache"].get(key);
    if (value) {
      return value;
    }
    const promise = Promise.resolve().then(() => nuxtApp2.runWithContext(() => _handler(nuxtApp2, options2)));
    nuxtApp2.ssrContext["~sharedPrerenderCache"].set(key, promise);
    return promise;
  };
  const _ref = options.deep ? ref : shallowRef;
  const hasCachedData = initialCachedData != null;
  const unsubRefreshAsyncData = nuxtApp.hook("app:data:refresh", async (keys) => {
    if (!keys || keys.includes(key)) {
      await asyncData.execute({ cause: "refresh:hook" });
    }
  });
  const asyncData = {
    data: _ref(hasCachedData ? initialCachedData : options.default()),
    pending: shallowRef(!hasCachedData),
    error: toRef(nuxtApp.payload._errors, key),
    status: shallowRef("idle"),
    execute: (...args) => {
      var _a2, _b2;
      const [_opts, newValue = void 0] = args;
      const opts = _opts && newValue === void 0 && typeof _opts === "object" ? _opts : {};
      if (nuxtApp._asyncDataPromises[key]) {
        if (isDefer((_a2 = opts.dedupe) != null ? _a2 : options.dedupe)) {
          return nuxtApp._asyncDataPromises[key];
        }
      }
      if (opts.cause === "initial" || nuxtApp.isHydrating) {
        const cachedData = "cachedData" in opts ? opts.cachedData : options.getCachedData(key, nuxtApp, { cause: (_b2 = opts.cause) != null ? _b2 : "refresh:manual" });
        if (cachedData != null) {
          nuxtApp.payload.data[key] = asyncData.data.value = cachedData;
          asyncData.error.value = asyncDataDefaults.errorValue;
          asyncData.status.value = "success";
          return Promise.resolve(cachedData);
        }
      }
      {
        asyncData.pending.value = true;
      }
      if (asyncData._abortController) {
        asyncData._abortController.abort(new DOMException("AsyncData request cancelled by deduplication", "AbortError"));
      }
      asyncData._abortController = new AbortController();
      asyncData.status.value = "pending";
      const cleanupController = new AbortController();
      const promise = new Promise(
        (resolve, reject) => {
          var _a3, _b3;
          try {
            const timeout = (_a3 = opts.timeout) != null ? _a3 : options.timeout;
            const mergedSignal = mergeAbortSignals([(_b3 = asyncData._abortController) == null ? void 0 : _b3.signal, opts == null ? void 0 : opts.signal], cleanupController.signal, timeout);
            if (mergedSignal.aborted) {
              const reason = mergedSignal.reason;
              reject(reason instanceof Error ? reason : new DOMException(String(reason != null ? reason : "Aborted"), "AbortError"));
              return;
            }
            mergedSignal.addEventListener("abort", () => {
              const reason = mergedSignal.reason;
              reject(reason instanceof Error ? reason : new DOMException(String(reason != null ? reason : "Aborted"), "AbortError"));
            }, { once: true, signal: cleanupController.signal });
            return Promise.resolve(handler(nuxtApp, { signal: mergedSignal })).then(resolve, reject);
          } catch (err) {
            reject(err);
          }
        }
      ).then(async (_result) => {
        let result = _result;
        if (options.transform) {
          result = await options.transform(_result);
        }
        if (options.pick) {
          result = pick(result, options.pick);
        }
        nuxtApp.payload.data[key] = result;
        asyncData.data.value = result;
        asyncData.error.value = asyncDataDefaults.errorValue;
        asyncData.status.value = "success";
      }).catch((error) => {
        var _a3;
        if (nuxtApp._asyncDataPromises[key] && nuxtApp._asyncDataPromises[key] !== promise) {
          return nuxtApp._asyncDataPromises[key];
        }
        if ((_a3 = asyncData._abortController) == null ? void 0 : _a3.signal.aborted) {
          return nuxtApp._asyncDataPromises[key];
        }
        if (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError") {
          asyncData.status.value = "idle";
          return nuxtApp._asyncDataPromises[key];
        }
        asyncData.error.value = createError(error);
        asyncData.data.value = unref(options.default());
        asyncData.status.value = "error";
      }).finally(() => {
        {
          asyncData.pending.value = false;
        }
        cleanupController.abort();
        delete nuxtApp._asyncDataPromises[key];
      });
      nuxtApp._asyncDataPromises[key] = promise;
      return nuxtApp._asyncDataPromises[key];
    },
    _execute: debounce((...args) => asyncData.execute(...args), 0, { leading: true }),
    _default: options.default,
    _deps: 0,
    _init: true,
    _hash: void 0,
    _off: () => {
      var _a2;
      unsubRefreshAsyncData();
      if ((_a2 = nuxtApp._asyncData[key]) == null ? void 0 : _a2._init) {
        nuxtApp._asyncData[key]._init = false;
      }
      if (!hasCustomGetCachedData) {
        nextTick(() => {
          var _a3;
          if (!((_a3 = nuxtApp._asyncData[key]) == null ? void 0 : _a3._init)) {
            clearNuxtDataByKey(nuxtApp, key);
            asyncData.execute = () => Promise.resolve();
            asyncData.data.value = asyncDataDefaults.value;
          }
        });
      }
    }
  };
  return asyncData;
}
const getDefault = () => asyncDataDefaults.value;
const getDefaultCachedData = (key, nuxtApp, ctx) => {
  if (nuxtApp.isHydrating) {
    return nuxtApp.payload.data[key];
  }
  if (ctx.cause !== "refresh:manual" && ctx.cause !== "refresh:hook") {
    return nuxtApp.static.data[key];
  }
};
function mergeAbortSignals(signals, cleanupSignal, timeout) {
  var _a, _b, _c;
  const list = signals.filter((s) => !!s);
  if (typeof timeout === "number" && timeout >= 0) {
    const timeoutSignal = (_a = AbortSignal.timeout) == null ? void 0 : _a.call(AbortSignal, timeout);
    if (timeoutSignal) {
      list.push(timeoutSignal);
    }
  }
  if (AbortSignal.any) {
    return AbortSignal.any(list);
  }
  const controller = new AbortController();
  for (const sig of list) {
    if (sig.aborted) {
      const reason = (_b = sig.reason) != null ? _b : new DOMException("Aborted", "AbortError");
      try {
        controller.abort(reason);
      } catch {
        controller.abort();
      }
      return controller.signal;
    }
  }
  const onAbort = () => {
    var _a2;
    const abortedSignal = list.find((s) => s.aborted);
    const reason = (_a2 = abortedSignal == null ? void 0 : abortedSignal.reason) != null ? _a2 : new DOMException("Aborted", "AbortError");
    try {
      controller.abort(reason);
    } catch {
      controller.abort();
    }
  };
  for (const sig of list) {
    (_c = sig.addEventListener) == null ? void 0 : _c.call(sig, "abort", onAbort, { once: true, signal: cleanupSignal });
  }
  return controller.signal;
}
const hero$1 = { "title": "lintai", "subtitle": "Fast offline security checks for AI agent artifacts in your repo. lintai helps teams verify skills, MCP configs, agent rules, hooks, and plugin manifests before they trust them in local workflows or CI." };
const features$1 = [{ "id": "offlineFirst", "title": "Offline-first by default", "description": "lintai is built for local runs, CI gates, and private repositories where you do not want a cloud upload path just to review agent artifacts." }, { "id": "deterministic", "title": "Deterministic findings with evidence", "description": "Stable rule ids, structured evidence, and predictable exit codes make lintai easier to trust in repeatable local and CI workflows." }, { "id": "repoSurfaces", "title": "Targets the files that actually steer agents", "description": "Skills, MCP configs, agent rules, hooks, Cursor Plugin surfaces, and related repository-local files are the core scope in the current beta." }, { "id": "ciReady", "title": "Built for CI and SARIF from the start", "description": "Text, JSON, and SARIF output let teams gate pull requests and keep lintai inside normal DevSecOps flows instead of inventing a parallel review loop." }, { "id": "honestBoundary", "title": "Honest Stable vs Preview boundary", "description": "lintai does not pretend every signal is equally mature. Stable findings are the baseline trust bar, while Preview stays useful but explicitly non-baseline." }, { "id": "installedAudit", "title": "More than repository scans when you need it", "description": "scan-known, inventory-os, and policy-os help audit what local AI clients already have configured, without changing the core repo-scan story." }];
const featuredRules$1 = [{ "id": "sec352", "eyebrow": "Featured rule", "code": "SEC352", "title": "Unscoped Bash grant in AI-native frontmatter", "description": "Flags shared AI-native markdown frontmatter when tool grants expose broad Bash authority without a narrower reviewed scope.", "whyItMatters": "This is currently the strongest skills-markdown rule for ordinary community repos because it catches high-blast-radius shell authority without relying on vague prose heuristics.", "evidence": "Best signal/noise from the latest external validation pass.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec352.html" }, { "id": "sec347", "eyebrow": "Featured rule", "code": "SEC347", "title": "Mutable MCP launcher in markdown setup docs", "description": "Flags setup-style markdown that teaches mutable package launchers for MCP tooling instead of a reproducible install or pinned path.", "whyItMatters": "It catches copy-paste setup guidance that can silently drift under users, which is one of the clearest operational risks in markdown-heavy agent repositories.", "evidence": "Top operational docs rule for MCP setup surfaces.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec347.html" }, { "id": "sec340", "eyebrow": "Featured rule", "code": "SEC340", "title": "Mutable package launcher in committed Claude hook settings", "description": "Flags committed Claude settings when hook commands launch mutable package tooling instead of a reviewed, reproducible executable path.", "whyItMatters": "Committed hook settings act like executable policy. Mutable launchers there are easier to defend as a real operational smell than many broader markdown heuristics.", "evidence": "One of the strongest committed-config rules in the beta set.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec340.html" }, { "id": "sec329", "eyebrow": "Featured rule", "code": "SEC329", "title": "Mutable package launcher in committed mcp.json", "description": "Flags committed MCP client config when it launches package tooling through mutable execution paths instead of a reviewed install surface.", "whyItMatters": "This is one of the cleanest config-level rules in the product because it matches an executable trust decision, not just documentation language.", "evidence": "High-confidence committed-config rule for MCP wiring.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec329.html" }];
const comparisonRows$1 = [{ "id": "offline", "feature": "Offline-first local workflow", "lintai": { "status": "yes", "note": "Built for local and CI runs" }, "manualReview": { "status": "partial", "note": "Depends on reviewer discipline" }, "scripts": { "status": "partial", "note": "Possible, but usually incomplete" }, "cloudScanners": { "status": "no", "note": "Often requires upload or hosted state" } }, { "id": "signal", "feature": "Deterministic findings with evidence", "lintai": { "status": "yes", "note": "Stable rule ids and structured evidence" }, "manualReview": { "status": "partial", "note": "Review quality varies by person" }, "scripts": { "status": "partial", "note": "Hard to keep consistent across repos" }, "cloudScanners": { "status": "partial", "note": "May be broader, but not always explainable" } }, { "id": "scope", "feature": "Targets AI-native repo surfaces directly", "lintai": { "status": "yes", "note": "Skills, MCP, hooks, plugins, agent policy files" }, "manualReview": { "status": "partial", "note": "Easy to miss non-code files" }, "scripts": { "status": "partial", "note": "Usually one narrow file family only" }, "cloudScanners": { "status": "partial", "note": "Often broader than needed for this niche" } }, { "id": "ci", "feature": "CI and SARIF integration", "lintai": { "status": "yes", "note": "Text, JSON, and SARIF are first-class" }, "manualReview": { "status": "no", "note": "No machine-readable contract by default" }, "scripts": { "status": "partial", "note": "Usually needs custom glue per repo" }, "cloudScanners": { "status": "yes", "note": "Usually strong, but not repo-local by default" } }, { "id": "boundary", "feature": "Honest Stable vs Preview boundary", "lintai": { "status": "yes", "note": "Documented in the shipped product posture" }, "manualReview": { "status": "no", "note": "Usually lives in tribal knowledge" }, "scripts": { "status": "no", "note": "Rarely separated into maturity lanes" }, "cloudScanners": { "status": "partial", "note": "May be broad, but not always explicit about noise" } }, { "id": "installed", "feature": "Audit what is already installed locally", "lintai": { "status": "yes", "note": "scan-known and inventory-os are built in" }, "manualReview": { "status": "no", "note": "Tedious and incomplete" }, "scripts": { "status": "partial", "note": "Possible, but platform-specific" }, "cloudScanners": { "status": "no", "note": "Usually not aimed at local client state" } }];
const faq$1 = [{ "id": "whatIsIt", "question": "What is lintai?", "answer": "lintai is an offline-first, precision-first security linter for repository-local AI agent artifacts: skills, MCP configs, agent rules, hooks, and related plugin surfaces." }, { "id": "whatDoesItScan", "question": "What does lintai scan in the current beta?", "answer": "The current beta focuses on repository-local trust surfaces such as <code>SKILL.md</code>, <code>CLAUDE.md</code>, Cursor rules, MCP configs, hooks, Cursor Plugin files, and the opt-in advisory lane for committed npm lockfiles." }, { "id": "offlineFirst", "question": "Is lintai really offline-first?", "answer": "Yes. The core repo-scan workflow is designed for local runs and CI without live network lookups during scan. Even the advisory lane uses the bundled offline snapshot by default unless you explicitly point it at another normalized dataset." }, { "id": "stablePreview", "question": "What is the difference between Stable and Preview findings?", "answer": "<code>Stable</code> findings are the release-quality baseline. <code>Preview</code> findings are still useful, but they are not yet the default trust bar and should be evaluated as deeper guidance rather than the main gating signal." }, { "id": "fastestStart", "question": "What is the fastest way to try lintai?", "answer": "Install the public beta CLI from GitHub Releases, run <code>lintai scan .</code> on a repo that already contains supported AI-native files, and then compare the <code>Stable</code> vs <code>Preview</code> findings before deciding how hard to gate it in CI." }, { "id": "cloudVsLintai", "question": "Does lintai replace cloud scanners or broad supply-chain platforms?", "answer": "No. The current beta is intentionally narrower. Think of it as a focused repo-local linter for agent trust surfaces, not a hosted platform for registry reputation, broad ecosystem crawling, or every possible AI security problem." }];
const download$1 = { "title": "Get started", "note": "Pick an install path, open the docs, and start with a fast repo-local scan." };
const installChannels$1 = [{ "id": "script", "title": "Verified shell installer", "description": "Recommended Unix-like install path for the public beta. The installer downloads the tagged archive plus SHA256SUMS and verifies the checksum.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh", "note": "Best default on macOS and Linux when you want the supported beta flow.", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh", "recommended": true }, { "id": "powershell", "title": "PowerShell installer", "description": "Supported Windows beta path. Downloads the tagged archive plus SHA256SUMS and installs into a user-level bin directory.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1", "note": "Use this on Windows when you want the same release-asset flow as the Unix installer.", "command": "Invoke-WebRequest -Uri https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1 -OutFile .\\lintai-installer.ps1\npowershell -ExecutionPolicy Bypass -File .\\lintai-installer.ps1" }, { "id": "archive", "title": "Direct archive + verify", "description": "Manual path when you want the raw release assets and checksum verification without the convenience installer.", "href": "https://github.com/777genius/lintai/releases", "note": "Good when you want the release artifacts directly and will verify them yourself.", "command": "TAG=v0.1.0-beta.1\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/lintai-$TAG-x86_64-unknown-linux-gnu.tar.gz\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/SHA256SUMS" }, { "id": "releases", "title": "GitHub Releases", "description": "Browse published release notes, artifacts, and version history directly.", "href": "https://github.com/777genius/lintai/releases", "note": "Use this when you want the raw release surface.", "command": "https://github.com/777genius/lintai/releases" }, { "id": "docs", "title": "Docs index", "description": "Open the rules, presets, and project docs published under GitHub Pages.", "href": "https://777genius.github.io/lintai/docs/", "note": "Best next step once the CLI is installed.", "command": "https://777genius.github.io/lintai/docs/" }];
const quickstartSteps$1 = [{ "id": "install", "title": "Install the CLI", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh\nlintai version", "note": "Use the install channel that matches your machine, then confirm the CLI is on PATH." }, { "id": "scan", "title": "Run the first repo scan", "command": "lintai scan .", "note": "Start on a repository that already contains supported AI-native files so the first run is representative." }, { "id": "sarif", "title": "Export SARIF for CI or code scanning", "command": "lintai scan . --format sarif", "note": "Use SARIF when you want the same scan integrated into CI and downstream tooling." }, { "id": "explain", "title": "Inspect resolved policy when you add config", "command": "lintai explain-config lintai.toml", "note": "Useful once the target repo has a local lintai policy and you want to confirm the active preset and rule posture." }];
const supportLanes$1 = [{ "id": "repo-scan", "name": "Repository-local scan surface", "status": "Public beta", "note": "The current product story is the repo-local scan path for AI-native files such as skills, MCP configs, hooks, and plugin surfaces." }, { "id": "signal-policy", "name": "Stable vs Preview policy", "status": "Documented now", "note": "Stable findings are the release-quality baseline. Preview remains useful but explicitly non-baseline and more context-sensitive." }, { "id": "advisory", "name": "Offline advisory lane", "status": "Opt-in", "note": "Dependency advisory matching is intentionally opt-in and limited to committed npm lockfiles against the active offline snapshot." }, { "id": "installed-audit", "name": "Installed artifact audit", "status": "Available now", "note": "scan-known, inventory-os, and policy-os extend lintai beyond repo scans when you need to inspect what local AI clients already have configured." }];
const enContent = {
  hero: hero$1,
  features: features$1,
  featuredRules: featuredRules$1,
  comparisonRows: comparisonRows$1,
  faq: faq$1,
  download: download$1,
  installChannels: installChannels$1,
  quickstartSteps: quickstartSteps$1,
  supportLanes: supportLanes$1
};
const hero = { "title": "lintai", "subtitle": "\u0411\u044B\u0441\u0442\u0440\u044B\u0435 offline security checks \u0434\u043B\u044F AI agent artifacts \u0432 \u0432\u0430\u0448\u0435\u043C \u0440\u0435\u043F\u043E\u0437\u0438\u0442\u043E\u0440\u0438\u0438. lintai \u043F\u043E\u043C\u043E\u0433\u0430\u0435\u0442 \u043F\u0440\u043E\u0432\u0435\u0440\u044F\u0442\u044C skills, MCP-\u043A\u043E\u043D\u0444\u0438\u0433\u0438, agent rules, hooks \u0438 plugin manifests \u0434\u043E \u0442\u043E\u0433\u043E, \u043A\u0430\u043A \u0438\u043C \u043D\u0430\u0447\u043D\u0443\u0442 \u0434\u043E\u0432\u0435\u0440\u044F\u0442\u044C \u0432 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u043C workflow \u0438\u043B\u0438 CI." };
const features = [{ "id": "offlineFirst", "title": "Offline-first \u043F\u043E \u0443\u043C\u043E\u043B\u0447\u0430\u043D\u0438\u044E", "description": "lintai \u0440\u0430\u0441\u0441\u0447\u0438\u0442\u0430\u043D \u043D\u0430 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u043F\u0440\u043E\u0433\u043E\u043D\u044B, CI-gate \u0438 \u043F\u0440\u0438\u0432\u0430\u0442\u043D\u044B\u0435 \u0440\u0435\u043F\u043E\u0437\u0438\u0442\u043E\u0440\u0438\u0438, \u0433\u0434\u0435 \u043D\u0435 \u043D\u0443\u0436\u0435\u043D cloud upload \u0442\u043E\u043B\u044C\u043A\u043E \u0440\u0430\u0434\u0438 review agent artifacts." }, { "id": "deterministic", "title": "\u0414\u0435\u0442\u0435\u0440\u043C\u0438\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 finding'\u0438 \u0441 evidence", "description": "Stable rule id, \u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u043E\u0435 evidence \u0438 \u043F\u0440\u0435\u0434\u0441\u043A\u0430\u0437\u0443\u0435\u043C\u044B\u0435 exit code \u0434\u0435\u043B\u0430\u044E\u0442 lintai \u0443\u0434\u043E\u0431\u043D\u0435\u0435 \u0434\u043B\u044F \u043F\u043E\u0432\u0442\u043E\u0440\u044F\u0435\u043C\u043E\u0433\u043E \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u0433\u043E \u0438 CI workflow." }, { "id": "repoSurfaces", "title": "\u0426\u0435\u043B\u0438\u0442\u0441\u044F \u0432 \u0444\u0430\u0439\u043B\u044B, \u043A\u043E\u0442\u043E\u0440\u044B\u0435 \u0440\u0435\u0430\u043B\u044C\u043D\u043E \u0443\u043F\u0440\u0430\u0432\u043B\u044F\u044E\u0442 \u0430\u0433\u0435\u043D\u0442\u043E\u043C", "description": "Skills, MCP configs, agent rules, hooks, Cursor Plugin surfaces \u0438 \u0441\u043E\u0441\u0435\u0434\u043D\u0438\u0435 repository-local \u0444\u0430\u0439\u043B\u044B \u0441\u043E\u0441\u0442\u0430\u0432\u043B\u044F\u044E\u0442 \u043E\u0441\u043D\u043E\u0432\u043D\u043E\u0439 scope \u0442\u0435\u043A\u0443\u0449\u0435\u0439 beta." }, { "id": "ciReady", "title": "\u0421\u0440\u0430\u0437\u0443 \u0433\u043E\u0442\u043E\u0432 \u0434\u043B\u044F CI \u0438 SARIF", "description": "Text, JSON \u0438 SARIF output \u043F\u043E\u0437\u0432\u043E\u043B\u044F\u044E\u0442 \u0437\u0430\u0432\u043E\u0434\u0438\u0442\u044C lintai \u0432 \u043E\u0431\u044B\u0447\u043D\u044B\u0439 DevSecOps workflow, \u0430 \u043D\u0435 \u0441\u0442\u0440\u043E\u0438\u0442\u044C \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u044B\u0439 review-\u043F\u0440\u043E\u0446\u0435\u0441\u0441 \u0432\u043E\u043A\u0440\u0443\u0433 \u043D\u043E\u0432\u044B\u0445 tooling." }, { "id": "honestBoundary", "title": "\u0427\u0435\u0441\u0442\u043D\u0430\u044F \u0433\u0440\u0430\u043D\u0438\u0446\u0430 Stable vs Preview", "description": "lintai \u043D\u0435 \u0434\u0435\u043B\u0430\u0435\u0442 \u0432\u0438\u0434, \u0447\u0442\u043E \u0432\u0441\u0435 \u0441\u0438\u0433\u043D\u0430\u043B\u044B \u043E\u0434\u0438\u043D\u0430\u043A\u043E\u0432\u043E \u0437\u0440\u0435\u043B\u044B\u0435. Stable findings - \u0431\u0430\u0437\u043E\u0432\u0430\u044F \u043F\u043B\u0430\u043D\u043A\u0430 \u0434\u043E\u0432\u0435\u0440\u0438\u044F, \u0430 Preview \u043E\u0441\u0442\u0430\u0451\u0442\u0441\u044F \u043F\u043E\u043B\u0435\u0437\u043D\u044B\u043C, \u043D\u043E \u044F\u0432\u043D\u043E \u043D\u0435-\u0431\u0430\u0437\u043E\u0432\u044B\u043C \u0441\u043B\u043E\u0435\u043C." }, { "id": "installedAudit", "title": "\u041D\u0435 \u0442\u043E\u043B\u044C\u043A\u043E repo scans, \u043A\u043E\u0433\u0434\u0430 \u043D\u0443\u0436\u043D\u043E \u0431\u043E\u043B\u044C\u0448\u0435", "description": "scan-known, inventory-os \u0438 policy-os \u043F\u043E\u043C\u043E\u0433\u0430\u044E\u0442 \u043F\u0440\u043E\u0432\u0435\u0440\u044F\u0442\u044C, \u0447\u0442\u043E \u0443\u0436\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u043E \u0432 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0445 AI clients, \u043D\u0435 \u043B\u043E\u043C\u0430\u044F \u043E\u0441\u043D\u043E\u0432\u043D\u043E\u0439 repo-scan story." }];
const featuredRules = [{ "id": "sec352", "eyebrow": "\u041A\u043B\u044E\u0447\u0435\u0432\u043E\u0435 \u043F\u0440\u0430\u0432\u0438\u043B\u043E", "code": "SEC352", "title": "Unscoped Bash grant \u0432 AI-native frontmatter", "description": "\u041B\u043E\u0432\u0438\u0442 shared AI-native markdown frontmatter, \u0433\u0434\u0435 tool grant \u0434\u0430\u0451\u0442 \u0441\u043B\u0438\u0448\u043A\u043E\u043C \u0448\u0438\u0440\u043E\u043A\u0443\u044E Bash-\u0432\u043B\u0430\u0441\u0442\u044C \u0431\u0435\u0437 \u0431\u043E\u043B\u0435\u0435 \u0443\u0437\u043A\u043E\u0433\u043E reviewed scope.", "whyItMatters": "\u0421\u0435\u0439\u0447\u0430\u0441 \u044D\u0442\u043E \u0441\u0430\u043C\u044B\u0439 \u0441\u0438\u043B\u044C\u043D\u044B\u0439 skills-markdown rule \u0434\u043B\u044F \u043E\u0431\u044B\u0447\u043D\u044B\u0445 community repos, \u043F\u043E\u0442\u043E\u043C\u0443 \u0447\u0442\u043E \u043E\u043D \u043B\u043E\u0432\u0438\u0442 \u0440\u0435\u0430\u043B\u044C\u043D\u043E \u043E\u043F\u0430\u0441\u043D\u044B\u0439 shell blast radius \u0431\u0435\u0437 \u0440\u0430\u0441\u043F\u043B\u044B\u0432\u0447\u0430\u0442\u044B\u0445 prose-\u044D\u0432\u0440\u0438\u0441\u0442\u0438\u043A.", "evidence": "\u041B\u0443\u0447\u0448\u0438\u0439 signal/noise \u043F\u043E \u043F\u043E\u0441\u043B\u0435\u0434\u043D\u0435\u043C\u0443 external validation pass.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec352.html" }, { "id": "sec347", "eyebrow": "\u041A\u043B\u044E\u0447\u0435\u0432\u043E\u0435 \u043F\u0440\u0430\u0432\u0438\u043B\u043E", "code": "SEC347", "title": "Mutable MCP launcher \u0432 markdown setup docs", "description": "\u041B\u043E\u0432\u0438\u0442 setup-style markdown, \u0433\u0434\u0435 \u0434\u043B\u044F MCP tooling \u043F\u0440\u0435\u0434\u043B\u0430\u0433\u0430\u044E\u0442\u0441\u044F mutable package launcher path \u0432\u043C\u0435\u0441\u0442\u043E reproducible install flow \u0438\u043B\u0438 pinned path.", "whyItMatters": "\u042D\u0442\u043E \u043E\u0434\u0438\u043D \u0438\u0437 \u0441\u0430\u043C\u044B\u0445 \u043F\u043E\u043D\u044F\u0442\u043D\u044B\u0445 operational risks \u0432 markdown-heavy agent repos, \u043F\u043E\u0442\u043E\u043C\u0443 \u0447\u0442\u043E copy-paste setup \u043B\u0435\u0433\u043A\u043E \u043D\u0430\u0447\u0438\u043D\u0430\u0435\u0442 quietly drift'\u0438\u0442\u044C \u0443 \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u0439.", "evidence": "\u041E\u0434\u0438\u043D \u0438\u0437 \u043B\u0443\u0447\u0448\u0438\u0445 operational docs rules \u0434\u043B\u044F MCP setup surfaces.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec347.html" }, { "id": "sec340", "eyebrow": "\u041A\u043B\u044E\u0447\u0435\u0432\u043E\u0435 \u043F\u0440\u0430\u0432\u0438\u043B\u043E", "code": "SEC340", "title": "Mutable package launcher \u0432 committed Claude hook settings", "description": "\u041B\u043E\u0432\u0438\u0442 committed Claude settings, \u0433\u0434\u0435 hook-\u043A\u043E\u043C\u0430\u043D\u0434\u044B \u0437\u0430\u043F\u0443\u0441\u043A\u0430\u044E\u0442 mutable package tooling \u0432\u043C\u0435\u0441\u0442\u043E reviewed \u0438 reproducible executable path.", "whyItMatters": "Committed hook settings - \u044D\u0442\u043E \u0438\u0441\u043F\u043E\u043B\u043D\u044F\u0435\u043C\u0430\u044F policy-\u043F\u043E\u0432\u0435\u0440\u0445\u043D\u043E\u0441\u0442\u044C. Mutable launcher \u0442\u0430\u043C \u0437\u0430\u0449\u0438\u0449\u0430\u0435\u0442\u0441\u044F \u043A\u0430\u043A \u0440\u0435\u0430\u043B\u044C\u043D\u044B\u0439 operational smell \u043B\u0443\u0447\u0448\u0435, \u0447\u0435\u043C \u043C\u043D\u043E\u0433\u0438\u0435 \u0431\u043E\u043B\u0435\u0435 \u0448\u0438\u0440\u043E\u043A\u0438\u0435 markdown-\u044D\u0432\u0440\u0438\u0441\u0442\u0438\u043A\u0438.", "evidence": "\u041E\u0434\u0438\u043D \u0438\u0437 \u0441\u0430\u043C\u044B\u0445 \u0441\u0438\u043B\u044C\u043D\u044B\u0445 committed-config rules \u0432 \u0442\u0435\u043A\u0443\u0449\u0435\u043C beta-\u043D\u0430\u0431\u043E\u0440\u0435.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec340.html" }, { "id": "sec329", "eyebrow": "\u041A\u043B\u044E\u0447\u0435\u0432\u043E\u0435 \u043F\u0440\u0430\u0432\u0438\u043B\u043E", "code": "SEC329", "title": "Mutable package launcher \u0432 committed mcp.json", "description": "\u041B\u043E\u0432\u0438\u0442 committed MCP client config, \u0433\u0434\u0435 package tooling \u0437\u0430\u043F\u0443\u0441\u043A\u0430\u0435\u0442\u0441\u044F \u0447\u0435\u0440\u0435\u0437 mutable execution path \u0432\u043C\u0435\u0441\u0442\u043E reviewed install surface.", "whyItMatters": "\u042D\u0442\u043E \u043E\u0434\u0438\u043D \u0438\u0437 \u0441\u0430\u043C\u044B\u0445 \u0447\u0438\u0441\u0442\u044B\u0445 config-level rules \u0432 \u043F\u0440\u043E\u0434\u0443\u043A\u0442\u0435, \u043F\u043E\u0442\u043E\u043C\u0443 \u0447\u0442\u043E \u043E\u043D \u0441\u043E\u0432\u043F\u0430\u0434\u0430\u0435\u0442 \u0441 \u0440\u0435\u0430\u043B\u044C\u043D\u044B\u043C executable trust decision, \u0430 \u043D\u0435 \u0442\u043E\u043B\u044C\u043A\u043E \u0441 \u044F\u0437\u044B\u043A\u043E\u043C \u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u0430\u0446\u0438\u0438.", "evidence": "High-confidence committed-config rule \u0434\u043B\u044F MCP wiring.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec329.html" }];
const comparisonRows = [{ "id": "offline", "feature": "Offline-first \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0439 workflow", "lintai": { "status": "yes", "note": "\u0421\u0434\u0435\u043B\u0430\u043D \u043F\u043E\u0434 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u0438 CI-\u043F\u0440\u043E\u0433\u043E\u043D\u044B" }, "manualReview": { "status": "partial", "note": "\u0417\u0430\u0432\u0438\u0441\u0438\u0442 \u043E\u0442 \u0434\u0438\u0441\u0446\u0438\u043F\u043B\u0438\u043D\u044B reviewer'\u0430" }, "scripts": { "status": "partial", "note": "\u0412\u043E\u0437\u043C\u043E\u0436\u043D\u043E, \u043D\u043E \u043E\u0431\u044B\u0447\u043D\u043E \u043D\u0435\u043F\u043E\u043B\u043D\u043E" }, "cloudScanners": { "status": "no", "note": "\u0427\u0430\u0441\u0442\u043E \u0442\u0440\u0435\u0431\u0443\u044E\u0442 upload \u0438\u043B\u0438 hosted state" } }, { "id": "signal", "feature": "\u0414\u0435\u0442\u0435\u0440\u043C\u0438\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u0435 finding'\u0438 \u0441 evidence", "lintai": { "status": "yes", "note": "Stable rule id \u0438 \u0441\u0442\u0440\u0443\u043A\u0442\u0443\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u043E\u0435 evidence" }, "manualReview": { "status": "partial", "note": "\u041A\u0430\u0447\u0435\u0441\u0442\u0432\u043E review \u043F\u043B\u0430\u0432\u0430\u0435\u0442 \u043E\u0442 \u0447\u0435\u043B\u043E\u0432\u0435\u043A\u0430 \u043A \u0447\u0435\u043B\u043E\u0432\u0435\u043A\u0443" }, "scripts": { "status": "partial", "note": "\u0422\u0440\u0443\u0434\u043D\u043E \u0434\u0435\u0440\u0436\u0430\u0442\u044C \u043A\u043E\u043D\u0441\u0438\u0441\u0442\u0435\u043D\u0442\u043D\u043E \u043F\u043E \u0440\u0435\u043F\u043E\u0437\u0438\u0442\u043E\u0440\u0438\u044F\u043C" }, "cloudScanners": { "status": "partial", "note": "\u041C\u043E\u0433\u0443\u0442 \u0431\u044B\u0442\u044C \u0448\u0438\u0440\u0435, \u043D\u043E \u043D\u0435 \u0432\u0441\u0435\u0433\u0434\u0430 \u043E\u0431\u044A\u044F\u0441\u043D\u0438\u043C\u044B" } }, { "id": "scope", "feature": "\u0411\u044C\u0451\u0442 \u043F\u0440\u044F\u043C\u043E \u043F\u043E AI-native repo surfaces", "lintai": { "status": "yes", "note": "Skills, MCP, hooks, plugins, agent policy files" }, "manualReview": { "status": "partial", "note": "\u041D\u0435-\u043A\u043E\u0434\u043E\u0432\u044B\u0435 \u0444\u0430\u0439\u043B\u044B \u043B\u0435\u0433\u043A\u043E \u043F\u0440\u043E\u043F\u0443\u0441\u0442\u0438\u0442\u044C" }, "scripts": { "status": "partial", "note": "\u041E\u0431\u044B\u0447\u043D\u043E \u0437\u0430\u043A\u0440\u044B\u0432\u0430\u044E\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u043E\u0434\u043D\u043E \u0441\u0435\u043C\u0435\u0439\u0441\u0442\u0432\u043E \u0444\u0430\u0439\u043B\u043E\u0432" }, "cloudScanners": { "status": "partial", "note": "\u0427\u0430\u0441\u0442\u043E \u0448\u0438\u0440\u0435, \u0447\u0435\u043C \u043D\u0443\u0436\u043D\u043E \u044D\u0442\u043E\u0439 \u043D\u0438\u0448\u0435" } }, { "id": "ci", "feature": "CI \u0438 SARIF integration", "lintai": { "status": "yes", "note": "Text, JSON \u0438 SARIF - first-class output" }, "manualReview": { "status": "no", "note": "\u041D\u0435\u0442 machine-readable \u043A\u043E\u043D\u0442\u0440\u0430\u043A\u0442\u0430 \u043F\u043E \u0443\u043C\u043E\u043B\u0447\u0430\u043D\u0438\u044E" }, "scripts": { "status": "partial", "note": "\u041E\u0431\u044B\u0447\u043D\u043E \u0442\u0440\u0435\u0431\u0443\u044E\u0442 custom glue \u043D\u0430 \u043A\u0430\u0436\u0434\u044B\u0439 repo" }, "cloudScanners": { "status": "yes", "note": "\u0427\u0430\u0441\u0442\u043E \u0441\u0438\u043B\u044C\u043D\u044B \u0437\u0434\u0435\u0441\u044C, \u043D\u043E \u043D\u0435 repo-local \u043F\u043E \u0434\u0435\u0444\u043E\u043B\u0442\u0443" } }, { "id": "boundary", "feature": "\u0427\u0435\u0441\u0442\u043D\u0430\u044F \u0433\u0440\u0430\u043D\u0438\u0446\u0430 Stable vs Preview", "lintai": { "status": "yes", "note": "\u0417\u0430\u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u0438\u0440\u043E\u0432\u0430\u043D\u0430 \u0432 shipped product posture" }, "manualReview": { "status": "no", "note": "\u041E\u0431\u044B\u0447\u043D\u043E \u0436\u0438\u0432\u0451\u0442 \u043A\u0430\u043A tribal knowledge" }, "scripts": { "status": "no", "note": "\u0420\u0435\u0434\u043A\u043E \u0440\u0430\u0437\u0434\u0435\u043B\u044F\u044E\u0442\u0441\u044F \u043F\u043E maturity lanes" }, "cloudScanners": { "status": "partial", "note": "\u041C\u043E\u0433\u0443\u0442 \u0431\u044B\u0442\u044C \u0448\u0438\u0440\u043E\u043A\u0438\u043C\u0438, \u043D\u043E \u043D\u0435 \u0432\u0441\u0435\u0433\u0434\u0430 \u0447\u0435\u0441\u0442\u043D\u044B \u043F\u0440\u043E noise" } }, { "id": "installed", "feature": "\u0410\u0443\u0434\u0438\u0442 \u0443\u0436\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u043E\u0433\u043E \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u043E\u0433\u043E state", "lintai": { "status": "yes", "note": "scan-known \u0438 inventory-os \u0432\u0441\u0442\u0440\u043E\u0435\u043D\u044B" }, "manualReview": { "status": "no", "note": "\u0421\u043A\u0443\u0447\u043D\u043E \u0438 \u043D\u0435\u043F\u043E\u043B\u043D\u043E" }, "scripts": { "status": "partial", "note": "\u0412\u043E\u0437\u043C\u043E\u0436\u043D\u043E, \u043D\u043E \u0441\u0438\u043B\u044C\u043D\u043E platform-specific" }, "cloudScanners": { "status": "no", "note": "\u041E\u0431\u044B\u0447\u043D\u043E \u043D\u0435 \u0440\u0430\u0441\u0441\u0447\u0438\u0442\u0430\u043D\u044B \u043D\u0430 local client state" } }];
const faq = [{ "id": "whatIsIt", "question": "\u0427\u0442\u043E \u0442\u0430\u043A\u043E\u0435 lintai?", "answer": "lintai - \u044D\u0442\u043E offline-first \u0438 precision-first security linter \u0434\u043B\u044F repository-local AI agent artifacts: skills, MCP configs, agent rules, hooks \u0438 \u0441\u0432\u044F\u0437\u0430\u043D\u043D\u044B\u0445 plugin surfaces." }, { "id": "whatDoesItScan", "question": "\u0427\u0442\u043E lintai \u0441\u043A\u0430\u043D\u0438\u0440\u0443\u0435\u0442 \u0432 \u0442\u0435\u043A\u0443\u0449\u0435\u0439 beta?", "answer": "\u0422\u0435\u043A\u0443\u0449\u0430\u044F beta \u0441\u0444\u043E\u043A\u0443\u0441\u0438\u0440\u043E\u0432\u0430\u043D\u0430 \u043D\u0430 repository-local trust surfaces \u0432\u0440\u043E\u0434\u0435 <code>SKILL.md</code>, <code>CLAUDE.md</code>, Cursor rules, MCP configs, hooks, Cursor Plugin files \u0438 opt-in advisory lane \u0434\u043B\u044F committed npm lockfiles." }, { "id": "offlineFirst", "question": "lintai \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043B\u044C\u043D\u043E offline-first?", "answer": "\u0414\u0430. \u0411\u0430\u0437\u043E\u0432\u044B\u0439 repo-scan workflow \u0440\u0430\u0441\u0441\u0447\u0438\u0442\u0430\u043D \u043D\u0430 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u043F\u0440\u043E\u0433\u043E\u043D\u044B \u0438 CI \u0431\u0435\u0437 live network lookup \u0432\u043E \u0432\u0440\u0435\u043C\u044F scan. \u0414\u0430\u0436\u0435 advisory lane \u043F\u043E \u0443\u043C\u043E\u043B\u0447\u0430\u043D\u0438\u044E \u0438\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u0442 bundled offline snapshot, \u0435\u0441\u043B\u0438 \u0432\u044B \u044F\u0432\u043D\u043E \u043D\u0435 \u043F\u043E\u0434\u0441\u0442\u0430\u0432\u0438\u043B\u0438 \u0434\u0440\u0443\u0433\u043E\u0439 normalized dataset." }, { "id": "stablePreview", "question": "\u0412 \u0447\u0451\u043C \u0440\u0430\u0437\u043D\u0438\u0446\u0430 \u043C\u0435\u0436\u0434\u0443 Stable \u0438 Preview findings?", "answer": "<code>Stable</code> findings - \u044D\u0442\u043E release-quality baseline. <code>Preview</code> findings \u0442\u043E\u0436\u0435 \u043F\u043E\u043B\u0435\u0437\u043D\u044B, \u043D\u043E \u043F\u043E\u043A\u0430 \u043D\u0435 \u044F\u0432\u043B\u044F\u044E\u0442\u0441\u044F \u0434\u0435\u0444\u043E\u043B\u0442\u043D\u043E\u0439 \u043F\u043B\u0430\u043D\u043A\u043E\u0439 \u0434\u043E\u0432\u0435\u0440\u0438\u044F \u0438 \u0434\u043E\u043B\u0436\u043D\u044B \u0447\u0438\u0442\u0430\u0442\u044C\u0441\u044F \u043A\u0430\u043A \u0431\u043E\u043B\u0435\u0435 \u0433\u043B\u0443\u0431\u043E\u043A\u0430\u044F guidance, \u0430 \u043D\u0435 \u043A\u0430\u043A \u043E\u0441\u043D\u043E\u0432\u043D\u043E\u0439 gating signal." }, { "id": "fastestStart", "question": "\u041A\u0430\u043A \u0431\u044B\u0441\u0442\u0440\u0435\u0435 \u0432\u0441\u0435\u0433\u043E \u043F\u043E\u043F\u0440\u043E\u0431\u043E\u0432\u0430\u0442\u044C lintai?", "answer": "\u0423\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 public beta CLI \u0438\u0437 GitHub Releases, \u0437\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 <code>lintai scan .</code> \u043D\u0430 \u0440\u0435\u043F\u043E\u0437\u0438\u0442\u043E\u0440\u0438\u0438, \u0433\u0434\u0435 \u0443\u0436\u0435 \u0435\u0441\u0442\u044C \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u044B\u0435 AI-native \u0444\u0430\u0439\u043B\u044B, \u0430 \u0437\u0430\u0442\u0435\u043C \u0440\u0430\u0437\u0431\u0435\u0440\u0438\u0442\u0435 \u043E\u0442\u0434\u0435\u043B\u044C\u043D\u043E <code>Stable</code> \u0438 <code>Preview</code> findings \u043F\u0435\u0440\u0435\u0434 \u0442\u0435\u043C, \u043A\u0430\u043A \u0436\u0451\u0441\u0442\u043A\u043E \u0437\u0430\u0432\u043E\u0434\u0438\u0442\u044C lintai \u0432 CI." }, { "id": "cloudVsLintai", "question": "\u0417\u0430\u043C\u0435\u043D\u044F\u0435\u0442 \u043B\u0438 lintai cloud scanners \u0438\u043B\u0438 \u0448\u0438\u0440\u043E\u043A\u0438\u0435 supply-chain \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u044B?", "answer": "\u041D\u0435\u0442. \u0422\u0435\u043A\u0443\u0449\u0430\u044F beta \u043D\u0430\u043C\u0435\u0440\u0435\u043D\u043D\u043E \u0443\u0436\u0435. \u0415\u0433\u043E \u043B\u0443\u0447\u0448\u0435 \u043F\u043E\u043D\u0438\u043C\u0430\u0442\u044C \u043A\u0430\u043A focused repo-local linter \u0434\u043B\u044F agent trust surfaces, \u0430 \u043D\u0435 \u043A\u0430\u043A hosted platform \u0434\u043B\u044F registry reputation, broad ecosystem crawling \u0438\u043B\u0438 \u0432\u0441\u0435\u0445 \u0432\u043E\u0437\u043C\u043E\u0436\u043D\u044B\u0445 AI security \u0437\u0430\u0434\u0430\u0447." }];
const download = { "title": "\u0421\u0442\u0430\u0440\u0442", "note": "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 install path, \u043E\u0442\u043A\u0440\u043E\u0439\u0442\u0435 docs \u0438 \u043D\u0430\u0447\u043D\u0438\u0442\u0435 \u0441 \u0431\u044B\u0441\u0442\u0440\u043E\u0433\u043E repo-local scan." };
const installChannels = [{ "id": "script", "title": "\u041F\u0440\u043E\u0432\u0435\u0440\u044F\u0435\u043C\u044B\u0439 shell installer", "description": "\u0420\u0435\u043A\u043E\u043C\u0435\u043D\u0434\u0443\u0435\u043C\u044B\u0439 beta install path \u0434\u043B\u044F Unix-like \u0441\u0438\u0441\u0442\u0435\u043C. \u0418\u043D\u0441\u0442\u0430\u043B\u043B\u0435\u0440 \u0441\u043A\u0430\u0447\u0438\u0432\u0430\u0435\u0442 tagged archive \u043F\u043B\u044E\u0441 SHA256SUMS \u0438 \u043F\u0440\u043E\u0432\u0435\u0440\u044F\u0435\u0442 checksum.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh", "note": "\u041B\u0443\u0447\u0448\u0438\u0439 \u0434\u0435\u0444\u043E\u043B\u0442 \u043D\u0430 macOS \u0438 Linux, \u0435\u0441\u043B\u0438 \u043D\u0443\u0436\u0435\u043D \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u044B\u0439 beta flow.", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh", "recommended": true }, { "id": "powershell", "title": "PowerShell installer", "description": "\u041F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u044B\u0439 Windows path \u0434\u043B\u044F beta. \u0421\u043A\u0430\u0447\u0438\u0432\u0430\u0435\u0442 tagged archive \u043F\u043B\u044E\u0441 SHA256SUMS \u0438 \u0441\u0442\u0430\u0432\u0438\u0442 \u0431\u0438\u043D\u0430\u0440\u044C \u0432 user-level bin directory.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1", "note": "\u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 \u043D\u0430 Windows, \u0435\u0441\u043B\u0438 \u0445\u043E\u0442\u0438\u0442\u0435 \u0442\u043E\u0442 \u0436\u0435 release-asset flow, \u0447\u0442\u043E \u0438 \u0443 Unix installer.", "command": "Invoke-WebRequest -Uri https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1 -OutFile .\\lintai-installer.ps1\npowershell -ExecutionPolicy Bypass -File .\\lintai-installer.ps1" }, { "id": "archive", "title": "Direct archive + verify", "description": "\u0420\u0443\u0447\u043D\u043E\u0439 path, \u0435\u0441\u043B\u0438 \u0432\u0430\u043C \u043D\u0443\u0436\u043D\u044B raw release assets \u0438 checksum verification \u0431\u0435\u0437 convenience installer.", "href": "https://github.com/777genius/lintai/releases", "note": "\u041F\u043E\u0434\u0445\u043E\u0434\u0438\u0442, \u0435\u0441\u043B\u0438 \u0432\u044B \u0445\u043E\u0442\u0438\u0442\u0435 \u043D\u0430\u043F\u0440\u044F\u043C\u0443\u044E \u0440\u0430\u0431\u043E\u0442\u0430\u0442\u044C \u0441 release artifacts \u0438 \u0441\u0430\u043C\u0438 \u043F\u0440\u043E\u0432\u0435\u0441\u0442\u0438 verification.", "command": "TAG=v0.1.0-beta.1\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/lintai-$TAG-x86_64-unknown-linux-gnu.tar.gz\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/SHA256SUMS" }, { "id": "releases", "title": "GitHub Releases", "description": "\u0421\u043C\u043E\u0442\u0440\u0438\u0442\u0435 release notes, \u0430\u0440\u0442\u0435\u0444\u0430\u043A\u0442\u044B \u0438 \u0438\u0441\u0442\u043E\u0440\u0438\u044E \u0432\u0435\u0440\u0441\u0438\u0439 \u043D\u0430\u043F\u0440\u044F\u043C\u0443\u044E.", "href": "https://github.com/777genius/lintai/releases", "note": "\u042D\u0442\u043E\u0442 \u043F\u0443\u0442\u044C \u043D\u0443\u0436\u0435\u043D, \u043A\u043E\u0433\u0434\u0430 \u0432\u044B \u0445\u043E\u0442\u0438\u0442\u0435 raw release surface.", "command": "https://github.com/777genius/lintai/releases" }, { "id": "docs", "title": "Docs index", "description": "\u041E\u0442\u043A\u0440\u044B\u0442\u044C rules, presets \u0438 project docs, \u043E\u043F\u0443\u0431\u043B\u0438\u043A\u043E\u0432\u0430\u043D\u043D\u044B\u0435 \u0447\u0435\u0440\u0435\u0437 GitHub Pages.", "href": "https://777genius.github.io/lintai/docs/", "note": "\u041B\u0443\u0447\u0448\u0438\u0439 \u0441\u043B\u0435\u0434\u0443\u044E\u0449\u0438\u0439 \u0448\u0430\u0433 \u043F\u043E\u0441\u043B\u0435 \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438 CLI.", "command": "https://777genius.github.io/lintai/docs/" }];
const quickstartSteps = [{ "id": "install", "title": "\u0423\u0441\u0442\u0430\u043D\u043E\u0432\u0438\u0442\u0435 CLI", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh\nlintai version", "note": "\u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 install channel, \u043A\u043E\u0442\u043E\u0440\u044B\u0439 \u043F\u043E\u0434\u0445\u043E\u0434\u0438\u0442 \u0432\u0430\u0448\u0435\u0439 \u043C\u0430\u0448\u0438\u043D\u0435, \u0430 \u0437\u0430\u0442\u0435\u043C \u043F\u0440\u043E\u0432\u0435\u0440\u044C\u0442\u0435, \u0447\u0442\u043E CLI \u0432\u0438\u0434\u0435\u043D \u0432 PATH." }, { "id": "scan", "title": "\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u043F\u0435\u0440\u0432\u044B\u0439 repo scan", "command": "lintai scan .", "note": "\u041B\u0443\u0447\u0448\u0435 \u043D\u0430\u0447\u0438\u043D\u0430\u0442\u044C \u043D\u0430 \u0440\u0435\u043F\u043E\u0437\u0438\u0442\u043E\u0440\u0438\u0438, \u0433\u0434\u0435 \u0443\u0436\u0435 \u0435\u0441\u0442\u044C \u043F\u043E\u0434\u0434\u0435\u0440\u0436\u0438\u0432\u0430\u0435\u043C\u044B\u0435 AI-native \u0444\u0430\u0439\u043B\u044B, \u0447\u0442\u043E\u0431\u044B \u043F\u0435\u0440\u0432\u044B\u0439 \u043F\u0440\u043E\u0433\u043E\u043D \u0431\u044B\u043B \u043F\u043E\u043A\u0430\u0437\u0430\u0442\u0435\u043B\u044C\u043D\u044B\u043C." }, { "id": "sarif", "title": "\u0412\u044B\u0433\u0440\u0443\u0437\u0438\u0442\u0435 SARIF \u0434\u043B\u044F CI \u0438\u043B\u0438 code scanning", "command": "lintai scan . --format sarif", "note": "\u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0439\u0442\u0435 SARIF, \u0435\u0441\u043B\u0438 \u0445\u043E\u0442\u0438\u0442\u0435 \u0442\u043E\u0442 \u0436\u0435 scan \u0432\u0441\u0442\u0440\u043E\u0438\u0442\u044C \u0432 CI \u0438 downstream tooling." }, { "id": "explain", "title": "\u0420\u0430\u0437\u0431\u0435\u0440\u0438\u0442\u0435 resolved policy \u043F\u043E\u0441\u043B\u0435 \u0434\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u0438\u044F config", "command": "lintai explain-config lintai.toml", "note": "\u041F\u043E\u043B\u0435\u0437\u043D\u043E, \u043A\u043E\u0433\u0434\u0430 \u0432 target repo \u0443\u0436\u0435 \u043F\u043E\u044F\u0432\u0438\u043B\u0441\u044F \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0439 lintai policy file \u0438 \u0432\u044B \u0445\u043E\u0442\u0438\u0442\u0435 \u043F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C \u0430\u043A\u0442\u0438\u0432\u043D\u044B\u0439 preset \u0438 rule posture." }];
const supportLanes = [{ "id": "repo-scan", "name": "Repository-local scan surface", "status": "Public beta", "note": "\u0422\u0435\u043A\u0443\u0449\u0430\u044F \u043F\u0440\u043E\u0434\u0443\u043A\u0442\u043E\u0432\u0430\u044F \u0438\u0441\u0442\u043E\u0440\u0438\u044F \u0441\u0442\u0440\u043E\u0438\u0442\u0441\u044F \u0432\u043E\u043A\u0440\u0443\u0433 repo-local scan path \u0434\u043B\u044F AI-native \u0444\u0430\u0439\u043B\u043E\u0432 \u0432\u0440\u043E\u0434\u0435 skills, MCP configs, hooks \u0438 plugin surfaces." }, { "id": "signal-policy", "name": "Stable vs Preview policy", "status": "\u0423\u0436\u0435 \u0437\u0430\u0434\u043E\u043A\u0443\u043C\u0435\u043D\u0442\u0438\u0440\u043E\u0432\u0430\u043D\u043E", "note": "Stable findings - release-quality baseline. Preview \u043E\u0441\u0442\u0430\u0451\u0442\u0441\u044F \u043F\u043E\u043B\u0435\u0437\u043D\u044B\u043C, \u043D\u043E \u044F\u0432\u043D\u043E \u043D\u0435-\u0431\u0430\u0437\u043E\u0432\u044B\u043C \u0438 \u0431\u043E\u043B\u0435\u0435 context-sensitive \u0441\u043B\u043E\u0435\u043C." }, { "id": "advisory", "name": "Offline advisory lane", "status": "Opt-in", "note": "Dependency advisory matching \u0441\u0434\u0435\u043B\u0430\u043D \u043D\u0430\u043C\u0435\u0440\u0435\u043D\u043D\u043E opt-in \u0438 \u043E\u0433\u0440\u0430\u043D\u0438\u0447\u0435\u043D committed npm lockfiles \u043F\u0440\u043E\u0442\u0438\u0432 \u0430\u043A\u0442\u0438\u0432\u043D\u043E\u0433\u043E offline snapshot." }, { "id": "installed-audit", "name": "Installed artifact audit", "status": "\u0423\u0436\u0435 \u0434\u043E\u0441\u0442\u0443\u043F\u043D\u043E", "note": "scan-known, inventory-os \u0438 policy-os \u0440\u0430\u0441\u0448\u0438\u0440\u044F\u044E\u0442 lintai \u0437\u0430 \u043F\u0440\u0435\u0434\u0435\u043B\u044B repo scans, \u043A\u043E\u0433\u0434\u0430 \u043D\u0443\u0436\u043D\u043E \u043F\u0440\u043E\u0432\u0435\u0440\u0438\u0442\u044C, \u0447\u0442\u043E \u0443\u0436\u0435 \u043D\u0430\u0441\u0442\u0440\u043E\u0435\u043D\u043E \u0432 \u043B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0445 AI clients." }];
const ru = {
  hero,
  features,
  featuredRules,
  comparisonRows,
  faq,
  download,
  installChannels,
  quickstartSteps,
  supportLanes
};
const contentByLocale = {
  en: enContent,
  ru
};
const getContent = (locale) => {
  var _a;
  return (_a = contentByLocale[locale]) != null ? _a : contentByLocale.en;
};
const useLandingContent = () => {
  const { locale } = useI18n();
  const content = computed(() => getContent(locale.value));
  return { content };
};
const emptyVariant = { url: null, platformKey: null, version: null };
function emptyDownloadsResponse() {
  return {
    ok: false,
    source: "github-releases",
    fetchedAt: (/* @__PURE__ */ new Date()).toISOString(),
    version: null,
    pubDate: null,
    variants: {
      installers: {
        shell: { ...emptyVariant },
        powershell: { ...emptyVariant }
      },
      macos: {
        arm64: { ...emptyVariant }
      },
      windows: {
        x64: { ...emptyVariant }
      },
      linux: {
        x64: { ...emptyVariant },
        muslX64: { ...emptyVariant }
      }
    }
  };
}
function readCache() {
  {
    return null;
  }
}
function writeCache(data) {
  {
    return;
  }
}
const useReleaseDownloads = () => {
  const config = useRuntimeConfig();
  const githubRepo = config.public.githubRepo || "777genius/lintai";
  const fallbackUrl = config.public.githubReleasesUrl || `https://github.com/${githubRepo}/releases`;
  const { data, pending, error } = useAsyncData(
    "lintai-releases",
    async () => {
      const cached = readCache();
      if (cached) {
        return cached;
      }
      try {
        const parsed = await $fetch("/api/releases/latest");
        writeCache(parsed);
        return parsed;
      } catch {
        return emptyDownloadsResponse();
      }
    },
    {
      server: true,
      lazy: false,
      default: () => emptyDownloadsResponse()
    }
  );
  const resolve = (os, arch) => {
    const api = data.value;
    if (!api.ok) {
      return null;
    }
    if (os === "windows") {
      const variant = api.variants.windows.x64;
      return variant.url ? { url: variant.url, version: variant.version || api.version } : null;
    }
    if (os === "linux") {
      const variant = api.variants.linux.x64.url ? api.variants.linux.x64 : api.variants.linux.muslX64;
      return variant.url ? { url: variant.url, version: variant.version || api.version } : null;
    }
    if (os === "macos") {
      if (arch === "x64") {
        return null;
      }
      const byArch = api.variants.macos.arm64;
      if (byArch.url) {
        return { url: byArch.url, version: byArch.version || api.version };
      }
      return null;
    }
    return null;
  };
  const resolveUrlOrFallback = (os, arch) => {
    var _a;
    return ((_a = resolve(os, arch)) == null ? void 0 : _a.url) || fallbackUrl;
  };
  return { data, pending, error, fallbackUrl, resolve, resolveUrlOrFallback };
};
const formatReleaseDate = (value, locale) => new Intl.DateTimeFormat(locale, {
  year: "numeric",
  month: "short",
  day: "numeric",
  timeZone: "UTC"
}).format(new Date(value));
const usePageSeo = (titleSource, descriptionSource, options = {}) => {
  const { t, locale } = useI18n();
  const route = useRoute$1();
  const config = useRuntimeConfig();
  const switchLocale = useSwitchLocalePath();
  const { docsUrl } = useDocsLinks();
  const siteUrl = config.public.siteUrl || "https://777genius.github.io/lintai";
  const siteName = "lintai";
  const githubUrl = `https://github.com/${config.public.githubRepo}`;
  const shouldTranslate = options.translate !== false;
  const title = computed(() => shouldTranslate ? t(toValue(titleSource)) : toValue(titleSource));
  const description = computed(
    () => shouldTranslate ? t(toValue(descriptionSource)) : toValue(descriptionSource)
  );
  const canonicalPath = computed(() => route.path);
  const canonicalUrl = computed(() => `${siteUrl}${canonicalPath.value}`);
  const resolveSiteAssetUrl = (assetPath) => {
    if (assetPath.startsWith("http")) {
      return assetPath;
    }
    const normalizedSiteUrl = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
    return new URL(assetPath.replace(/^\/+/, ""), normalizedSiteUrl).toString();
  };
  const resolvedImage = computed(() => {
    if (options.image) {
      return options.image;
    }
    return {
      url: "/og-image.png",
      width: 1200,
      height: 630,
      type: "image/png",
      alt: "lintai - fast offline security checks for AI agent artifacts"
    };
  });
  const resolvedImageUrl = computed(() => {
    return resolveSiteAssetUrl(resolvedImage.value.url);
  });
  useSeoMeta({
    title,
    description,
    ogTitle: title,
    ogDescription: description,
    ogType: options.type || "website",
    ogSiteName: siteName,
    ogUrl: canonicalUrl,
    ogImage: resolvedImageUrl,
    ogImageType: computed(() => resolvedImage.value.type),
    ogImageWidth: computed(
      () => resolvedImage.value.width ? String(resolvedImage.value.width) : void 0
    ),
    ogImageHeight: computed(
      () => resolvedImage.value.height ? String(resolvedImage.value.height) : void 0
    ),
    ogImageAlt: computed(() => resolvedImage.value.alt),
    twitterCard: "summary_large_image",
    twitterTitle: title,
    twitterDescription: description,
    twitterImage: resolvedImageUrl,
    twitterImageAlt: computed(() => resolvedImage.value.alt),
    robots: options.robots || "index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1"
  });
  useHead(() => {
    const links = supportedLocales.map(
      (item) => {
        const path = switchLocale(item.code) || canonicalPath.value;
        return {
          rel: "alternate",
          hreflang: item.code,
          href: `${siteUrl}${path}`
        };
      }
    );
    const defaultPath = switchLocale(defaultLocale) || canonicalPath.value;
    links.push({
      rel: "alternate",
      hreflang: "x-default",
      href: `${siteUrl}${defaultPath}`
    });
    links.push({ rel: "canonical", href: canonicalUrl.value });
    const jsonLd = [
      {
        "@context": "https://schema.org",
        "@type": "WebSite",
        name: siteName,
        url: siteUrl,
        inLanguage: supportedLocales.map((item) => item.code),
        description: description.value
      },
      {
        "@context": "https://schema.org",
        "@type": "Organization",
        name: siteName,
        url: siteUrl,
        logo: resolveSiteAssetUrl("/icon.svg"),
        sameAs: [githubUrl]
      }
    ];
    const isDownload = canonicalPath.value.endsWith("/download");
    const isHome = canonicalPath.value === "/" || canonicalPath.value === "/ru";
    if (isHome || isDownload) {
      jsonLd.push({
        "@context": "https://schema.org",
        "@type": "SoftwareApplication",
        name: "lintai",
        applicationCategory: "DeveloperApplication",
        operatingSystem: "macOS, Linux, Windows",
        description: description.value,
        url: canonicalUrl.value,
        downloadUrl: config.public.githubReleasesUrl || `${githubUrl}/releases`,
        softwareHelp: docsUrl.value
      });
    }
    if (isHome) {
      const content = getContent(locale.value);
      if (content.faq.length > 0) {
        jsonLd.push({
          "@context": "https://schema.org",
          "@type": "FAQPage",
          mainEntity: content.faq.map((item) => ({
            "@type": "Question",
            name: item.question,
            acceptedAnswer: {
              "@type": "Answer",
              text: item.answer.replace(/<[^>]*>/g, "")
            }
          }))
        });
      }
    }
    return {
      htmlAttrs: {
        lang: locale.value || "en"
      },
      link: links,
      meta: [
        { name: "author", content: "lintai" },
        { name: "application-name", content: siteName },
        { name: "apple-mobile-web-app-title", content: siteName },
        { name: "format-detection", content: "telephone=no" },
        { name: "theme-color", content: "#00f0ff" },
        {
          name: "keywords",
          content: "lintai, AI agent security, MCP configs, skills, hooks, plugin manifests, SARIF, repo-local scanner"
        }
      ],
      script: jsonLd.map((item) => ({
        type: "application/ld+json",
        children: JSON.stringify(item)
      }))
    };
  });
};

export { useLandingContent as a, useReleaseDownloads as b, formatReleaseDate as f, usePageSeo as u };
//# sourceMappingURL=usePageSeo-Ba4JSXZC.mjs.map
