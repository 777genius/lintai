import { hasInjectionContext, inject, computed, toValue, getCurrentInstance, onServerPrefetch, ref, shallowRef, nextTick, unref, toRef } from "vue";
import { t as tryUseNuxtApp, f as useNuxtApp, h as asyncDataDefaults, i as createError, u as useI18n, e as useRuntimeConfig, j as useRoute, k as useSwitchLocalePath } from "../server.mjs";
import { debounce } from "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/perfect-debounce@2.1.0/node_modules/perfect-debounce/dist/index.mjs";
import { u as useDocsLinks, s as supportedLocales, d as defaultLocale } from "./i18n-B_nLlkZy.js";
import { useSeoMeta as useSeoMeta$1, useHead as useHead$1, headSymbol } from "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/@unhead+vue@2.1.12_vue@3.5.31/node_modules/@unhead/vue/dist/index.mjs";
function injectHead(nuxtApp) {
  const nuxt = nuxtApp || tryUseNuxtApp();
  return nuxt?.ssrContext?.head || nuxt?.runWithContext(() => {
    if (hasInjectionContext()) {
      return inject(headSymbol);
    }
  });
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
  options.server ??= true;
  options.default ??= getDefault;
  options.getCachedData ??= getDefaultCachedData;
  options.lazy ??= false;
  options.immediate ??= true;
  options.deep ??= asyncDataDefaults.deep;
  options.dedupe ??= "cancel";
  options._functionName || "useAsyncData";
  nuxtApp._asyncData[key.value];
  function createInitialFetch() {
    const initialFetchOptions = { cause: "initial", dedupe: options.dedupe };
    if (!nuxtApp._asyncData[key.value]?._init) {
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
    data: writableComputedRef(() => nuxtApp._asyncData[key.value]?.data),
    pending: writableComputedRef(() => nuxtApp._asyncData[key.value]?.pending),
    status: writableComputedRef(() => nuxtApp._asyncData[key.value]?.status),
    error: writableComputedRef(() => nuxtApp._asyncData[key.value]?.error),
    refresh: (...args2) => {
      if (!nuxtApp._asyncData[key.value]?._init) {
        const initialFetch2 = createInitialFetch();
        return initialFetch2();
      }
      return nuxtApp._asyncData[key.value].execute(...args2);
    },
    execute: (...args2) => asyncReturn.refresh(...args2),
    clear: () => {
      const entry = nuxtApp._asyncData[key.value];
      if (entry?._abortController) {
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
      return getter()?.value;
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
  nuxtApp.payload._errors[key] ??= asyncDataDefaults.errorValue;
  const hasCustomGetCachedData = options.getCachedData !== getDefaultCachedData;
  const handler = !import.meta.prerender || !nuxtApp.ssrContext?.["~sharedPrerenderCache"] ? _handler : (nuxtApp2, options2) => {
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
      const [_opts, newValue = void 0] = args;
      const opts = _opts && newValue === void 0 && typeof _opts === "object" ? _opts : {};
      if (nuxtApp._asyncDataPromises[key]) {
        if (isDefer(opts.dedupe ?? options.dedupe)) {
          return nuxtApp._asyncDataPromises[key];
        }
      }
      if (opts.cause === "initial" || nuxtApp.isHydrating) {
        const cachedData = "cachedData" in opts ? opts.cachedData : options.getCachedData(key, nuxtApp, { cause: opts.cause ?? "refresh:manual" });
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
          try {
            const timeout = opts.timeout ?? options.timeout;
            const mergedSignal = mergeAbortSignals([asyncData._abortController?.signal, opts?.signal], cleanupController.signal, timeout);
            if (mergedSignal.aborted) {
              const reason = mergedSignal.reason;
              reject(reason instanceof Error ? reason : new DOMException(String(reason ?? "Aborted"), "AbortError"));
              return;
            }
            mergedSignal.addEventListener("abort", () => {
              const reason = mergedSignal.reason;
              reject(reason instanceof Error ? reason : new DOMException(String(reason ?? "Aborted"), "AbortError"));
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
        if (nuxtApp._asyncDataPromises[key] && nuxtApp._asyncDataPromises[key] !== promise) {
          return nuxtApp._asyncDataPromises[key];
        }
        if (asyncData._abortController?.signal.aborted) {
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
      unsubRefreshAsyncData();
      if (nuxtApp._asyncData[key]?._init) {
        nuxtApp._asyncData[key]._init = false;
      }
      if (!hasCustomGetCachedData) {
        nextTick(() => {
          if (!nuxtApp._asyncData[key]?._init) {
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
  const list = signals.filter((s) => !!s);
  if (typeof timeout === "number" && timeout >= 0) {
    const timeoutSignal = AbortSignal.timeout?.(timeout);
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
      const reason = sig.reason ?? new DOMException("Aborted", "AbortError");
      try {
        controller.abort(reason);
      } catch {
        controller.abort();
      }
      return controller.signal;
    }
  }
  const onAbort = () => {
    const abortedSignal = list.find((s) => s.aborted);
    const reason = abortedSignal?.reason ?? new DOMException("Aborted", "AbortError");
    try {
      controller.abort(reason);
    } catch {
      controller.abort();
    }
  };
  for (const sig of list) {
    sig.addEventListener?.("abort", onAbort, { once: true, signal: cleanupSignal });
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
const hero = { "title": "lintai", "subtitle": "Быстрые offline security checks для AI agent artifacts в вашем репозитории. lintai помогает проверять skills, MCP-конфиги, agent rules, hooks и plugin manifests до того, как им начнут доверять в локальном workflow или CI." };
const features = [{ "id": "offlineFirst", "title": "Offline-first по умолчанию", "description": "lintai рассчитан на локальные прогоны, CI-gate и приватные репозитории, где не нужен cloud upload только ради review agent artifacts." }, { "id": "deterministic", "title": "Детерминированные finding'и с evidence", "description": "Stable rule id, структурированное evidence и предсказуемые exit code делают lintai удобнее для повторяемого локального и CI workflow." }, { "id": "repoSurfaces", "title": "Целится в файлы, которые реально управляют агентом", "description": "Skills, MCP configs, agent rules, hooks, Cursor Plugin surfaces и соседние repository-local файлы составляют основной scope текущей beta." }, { "id": "ciReady", "title": "Сразу готов для CI и SARIF", "description": "Text, JSON и SARIF output позволяют заводить lintai в обычный DevSecOps workflow, а не строить отдельный review-процесс вокруг новых tooling." }, { "id": "honestBoundary", "title": "Честная граница Stable vs Preview", "description": "lintai не делает вид, что все сигналы одинаково зрелые. Stable findings - базовая планка доверия, а Preview остаётся полезным, но явно не-базовым слоем." }, { "id": "installedAudit", "title": "Не только repo scans, когда нужно больше", "description": "scan-known, inventory-os и policy-os помогают проверять, что уже настроено в локальных AI clients, не ломая основной repo-scan story." }];
const featuredRules = [{ "id": "sec352", "eyebrow": "Ключевое правило", "code": "SEC352", "title": "Unscoped Bash grant в AI-native frontmatter", "description": "Ловит shared AI-native markdown frontmatter, где tool grant даёт слишком широкую Bash-власть без более узкого reviewed scope.", "whyItMatters": "Сейчас это самый сильный skills-markdown rule для обычных community repos, потому что он ловит реально опасный shell blast radius без расплывчатых prose-эвристик.", "evidence": "Лучший signal/noise по последнему external validation pass.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec352.html" }, { "id": "sec347", "eyebrow": "Ключевое правило", "code": "SEC347", "title": "Mutable MCP launcher в markdown setup docs", "description": "Ловит setup-style markdown, где для MCP tooling предлагаются mutable package launcher path вместо reproducible install flow или pinned path.", "whyItMatters": "Это один из самых понятных operational risks в markdown-heavy agent repos, потому что copy-paste setup легко начинает quietly drift'ить у пользователей.", "evidence": "Один из лучших operational docs rules для MCP setup surfaces.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec347.html" }, { "id": "sec340", "eyebrow": "Ключевое правило", "code": "SEC340", "title": "Mutable package launcher в committed Claude hook settings", "description": "Ловит committed Claude settings, где hook-команды запускают mutable package tooling вместо reviewed и reproducible executable path.", "whyItMatters": "Committed hook settings - это исполняемая policy-поверхность. Mutable launcher там защищается как реальный operational smell лучше, чем многие более широкие markdown-эвристики.", "evidence": "Один из самых сильных committed-config rules в текущем beta-наборе.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec340.html" }, { "id": "sec329", "eyebrow": "Ключевое правило", "code": "SEC329", "title": "Mutable package launcher в committed mcp.json", "description": "Ловит committed MCP client config, где package tooling запускается через mutable execution path вместо reviewed install surface.", "whyItMatters": "Это один из самых чистых config-level rules в продукте, потому что он совпадает с реальным executable trust decision, а не только с языком документации.", "evidence": "High-confidence committed-config rule для MCP wiring.", "href": "https://777genius.github.io/lintai/docs/rules/lintai-ai-security/sec329.html" }];
const comparisonRows = [{ "id": "offline", "feature": "Offline-first локальный workflow", "lintai": { "status": "yes", "note": "Сделан под локальные и CI-прогоны" }, "manualReview": { "status": "partial", "note": "Зависит от дисциплины reviewer'а" }, "scripts": { "status": "partial", "note": "Возможно, но обычно неполно" }, "cloudScanners": { "status": "no", "note": "Часто требуют upload или hosted state" } }, { "id": "signal", "feature": "Детерминированные finding'и с evidence", "lintai": { "status": "yes", "note": "Stable rule id и структурированное evidence" }, "manualReview": { "status": "partial", "note": "Качество review плавает от человека к человеку" }, "scripts": { "status": "partial", "note": "Трудно держать консистентно по репозиториям" }, "cloudScanners": { "status": "partial", "note": "Могут быть шире, но не всегда объяснимы" } }, { "id": "scope", "feature": "Бьёт прямо по AI-native repo surfaces", "lintai": { "status": "yes", "note": "Skills, MCP, hooks, plugins, agent policy files" }, "manualReview": { "status": "partial", "note": "Не-кодовые файлы легко пропустить" }, "scripts": { "status": "partial", "note": "Обычно закрывают только одно семейство файлов" }, "cloudScanners": { "status": "partial", "note": "Часто шире, чем нужно этой нише" } }, { "id": "ci", "feature": "CI и SARIF integration", "lintai": { "status": "yes", "note": "Text, JSON и SARIF - first-class output" }, "manualReview": { "status": "no", "note": "Нет machine-readable контракта по умолчанию" }, "scripts": { "status": "partial", "note": "Обычно требуют custom glue на каждый repo" }, "cloudScanners": { "status": "yes", "note": "Часто сильны здесь, но не repo-local по дефолту" } }, { "id": "boundary", "feature": "Честная граница Stable vs Preview", "lintai": { "status": "yes", "note": "Задокументирована в shipped product posture" }, "manualReview": { "status": "no", "note": "Обычно живёт как tribal knowledge" }, "scripts": { "status": "no", "note": "Редко разделяются по maturity lanes" }, "cloudScanners": { "status": "partial", "note": "Могут быть широкими, но не всегда честны про noise" } }, { "id": "installed", "feature": "Аудит уже установленного локального state", "lintai": { "status": "yes", "note": "scan-known и inventory-os встроены" }, "manualReview": { "status": "no", "note": "Скучно и неполно" }, "scripts": { "status": "partial", "note": "Возможно, но сильно platform-specific" }, "cloudScanners": { "status": "no", "note": "Обычно не рассчитаны на local client state" } }];
const faq = [{ "id": "whatIsIt", "question": "Что такое lintai?", "answer": "lintai - это offline-first и precision-first security linter для repository-local AI agent artifacts: skills, MCP configs, agent rules, hooks и связанных plugin surfaces." }, { "id": "whatDoesItScan", "question": "Что lintai сканирует в текущей beta?", "answer": "Текущая beta сфокусирована на repository-local trust surfaces вроде <code>SKILL.md</code>, <code>CLAUDE.md</code>, Cursor rules, MCP configs, hooks, Cursor Plugin files и opt-in advisory lane для committed npm lockfiles." }, { "id": "offlineFirst", "question": "lintai действительно offline-first?", "answer": "Да. Базовый repo-scan workflow рассчитан на локальные прогоны и CI без live network lookup во время scan. Даже advisory lane по умолчанию использует bundled offline snapshot, если вы явно не подставили другой normalized dataset." }, { "id": "stablePreview", "question": "В чём разница между Stable и Preview findings?", "answer": "<code>Stable</code> findings - это release-quality baseline. <code>Preview</code> findings тоже полезны, но пока не являются дефолтной планкой доверия и должны читаться как более глубокая guidance, а не как основной gating signal." }, { "id": "fastestStart", "question": "Как быстрее всего попробовать lintai?", "answer": "Установите public beta CLI из GitHub Releases, запустите <code>lintai scan .</code> на репозитории, где уже есть поддерживаемые AI-native файлы, а затем разберите отдельно <code>Stable</code> и <code>Preview</code> findings перед тем, как жёстко заводить lintai в CI." }, { "id": "cloudVsLintai", "question": "Заменяет ли lintai cloud scanners или широкие supply-chain платформы?", "answer": "Нет. Текущая beta намеренно уже. Его лучше понимать как focused repo-local linter для agent trust surfaces, а не как hosted platform для registry reputation, broad ecosystem crawling или всех возможных AI security задач." }];
const download = { "title": "Старт", "note": "Выберите install path, откройте docs и начните с быстрого repo-local scan." };
const installChannels = [{ "id": "script", "title": "Проверяемый shell installer", "description": "Рекомендуемый beta install path для Unix-like систем. Инсталлер скачивает tagged archive плюс SHA256SUMS и проверяет checksum.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh", "note": "Лучший дефолт на macOS и Linux, если нужен поддерживаемый beta flow.", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh", "recommended": true }, { "id": "powershell", "title": "PowerShell installer", "description": "Поддерживаемый Windows path для beta. Скачивает tagged archive плюс SHA256SUMS и ставит бинарь в user-level bin directory.", "href": "https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1", "note": "Используйте на Windows, если хотите тот же release-asset flow, что и у Unix installer.", "command": "Invoke-WebRequest -Uri https://github.com/777genius/lintai/releases/latest/download/lintai-installer.ps1 -OutFile .\\lintai-installer.ps1\npowershell -ExecutionPolicy Bypass -File .\\lintai-installer.ps1" }, { "id": "archive", "title": "Direct archive + verify", "description": "Ручной path, если вам нужны raw release assets и checksum verification без convenience installer.", "href": "https://github.com/777genius/lintai/releases", "note": "Подходит, если вы хотите напрямую работать с release artifacts и сами провести verification.", "command": "TAG=v0.1.0-beta.1\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/lintai-$TAG-x86_64-unknown-linux-gnu.tar.gz\ncurl -fsSLO https://github.com/777genius/lintai/releases/download/$TAG/SHA256SUMS" }, { "id": "releases", "title": "GitHub Releases", "description": "Смотрите release notes, артефакты и историю версий напрямую.", "href": "https://github.com/777genius/lintai/releases", "note": "Этот путь нужен, когда вы хотите raw release surface.", "command": "https://github.com/777genius/lintai/releases" }, { "id": "docs", "title": "Docs index", "description": "Открыть rules, presets и project docs, опубликованные через GitHub Pages.", "href": "https://777genius.github.io/lintai/docs/", "note": "Лучший следующий шаг после установки CLI.", "command": "https://777genius.github.io/lintai/docs/" }];
const quickstartSteps = [{ "id": "install", "title": "Установите CLI", "command": "curl -fsSLO https://github.com/777genius/lintai/releases/latest/download/lintai-installer.sh\nsh ./lintai-installer.sh\nlintai version", "note": "Используйте install channel, который подходит вашей машине, а затем проверьте, что CLI виден в PATH." }, { "id": "scan", "title": "Запустите первый repo scan", "command": "lintai scan .", "note": "Лучше начинать на репозитории, где уже есть поддерживаемые AI-native файлы, чтобы первый прогон был показательным." }, { "id": "sarif", "title": "Выгрузите SARIF для CI или code scanning", "command": "lintai scan . --format sarif", "note": "Используйте SARIF, если хотите тот же scan встроить в CI и downstream tooling." }, { "id": "explain", "title": "Разберите resolved policy после добавления config", "command": "lintai explain-config lintai.toml", "note": "Полезно, когда в target repo уже появился локальный lintai policy file и вы хотите проверить активный preset и rule posture." }];
const supportLanes = [{ "id": "repo-scan", "name": "Repository-local scan surface", "status": "Public beta", "note": "Текущая продуктовая история строится вокруг repo-local scan path для AI-native файлов вроде skills, MCP configs, hooks и plugin surfaces." }, { "id": "signal-policy", "name": "Stable vs Preview policy", "status": "Уже задокументировано", "note": "Stable findings - release-quality baseline. Preview остаётся полезным, но явно не-базовым и более context-sensitive слоем." }, { "id": "advisory", "name": "Offline advisory lane", "status": "Opt-in", "note": "Dependency advisory matching сделан намеренно opt-in и ограничен committed npm lockfiles против активного offline snapshot." }, { "id": "installed-audit", "name": "Installed artifact audit", "status": "Уже доступно", "note": "scan-known, inventory-os и policy-os расширяют lintai за пределы repo scans, когда нужно проверить, что уже настроено в локальных AI clients." }];
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
  return contentByLocale[locale] ?? contentByLocale.en;
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
  const resolveUrlOrFallback = (os, arch) => resolve(os, arch)?.url || fallbackUrl;
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
  const route = useRoute();
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
export {
  useReleaseDownloads as a,
  usePageSeo as b,
  formatReleaseDate as f,
  useLandingContent as u
};
//# sourceMappingURL=usePageSeo-Ba4JSXZC.js.map
