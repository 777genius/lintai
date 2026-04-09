import "vue";
import { klona } from "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/klona@2.0.6/node_modules/klona/dist/index.mjs";
import { f as useNuxtApp } from "../server.mjs";
import "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/hookable@5.5.3/node_modules/hookable/dist/index.mjs";
import { defuFn } from "/Users/belief/dev/projects/lintai/landing/node_modules/.pnpm/defu@6.1.6/node_modules/defu/dist/defu.mjs";
const inlineConfig = {
  "nuxt": {}
};
const __appConfig = /* @__PURE__ */ defuFn(inlineConfig);
function useAppConfig() {
  const nuxtApp = useNuxtApp();
  nuxtApp._appConfig ||= klona(__appConfig);
  return nuxtApp._appConfig;
}
const iconCollections = ["fluent-emoji-high-contrast", "streamline-ultimate-color", "streamline-freehand-color", "streamline-kameleon-color", "streamline-stickies-color", "material-symbols-light", "streamline-plump-color", "streamline-sharp-color", "streamline-cyber-color", "streamline-flex-color", "cryptocurrency-color", "streamline-ultimate", "streamline-freehand", "material-icon-theme", "icon-park-outline", "icon-park-twotone", "fluent-emoji-flat", "emojione-monotone", "streamline-emojis", "heroicons-outline", "simple-line-icons", "material-symbols", "streamline-plump", "streamline-sharp", "streamline-cyber", "streamline-pixel", "streamline-block", "qlementine-icons", "streamline-color", "streamline-logos", "flat-color-icons", "icon-park-solid", "pepicons-pencil", "streamline-flex", "heroicons-solid", "pepicons-print", "cryptocurrency", "pixelarticons", "bitcoin-icons", "system-uicons", "sidekickicons", "devicon-plain", "entypo-social", "token-branded", "grommet-icons", "meteor-icons", "svg-spinners", "pepicons-pop", "dinkie-icons", "fluent-color", "vscode-icons", "simple-icons", "circle-flags", "medical-icon", "icomoon-free", "fluent-emoji", "majesticons", "humbleicons", "rivet-icons", "glyphs-poly", "radix-icons", "fa7-regular", "skill-icons", "emojione-v1", "academicons", "healthicons", "fa6-regular", "fluent-mdl2", "lucide-lab", "akar-icons", "lets-icons", "ant-design", "gravity-ui", "teenyicons", "streamline", "file-icons", "catppuccin", "fa7-brands", "game-icons", "foundation", "fa6-brands", "fa-regular", "mono-icons", "mdi-light", "iconamoon", "eos-icons", "gridicons", "duo-icons", "hugeicons", "lineicons", "wordpress", "zondicons", "heroicons", "fa7-solid", "icon-park", "arcticons", "meteocons", "dashicons", "fa6-solid", "fa-brands", "websymbol", "fontelico", "boxicons", "mingcute", "flowbite", "proicons", "guidance", "famicons", "roentgen", "bytesize", "marketeq", "nonicons", "brandico", "openmoji", "emojione", "flagpack", "fa-solid", "fontisto", "si-glyph", "pepicons", "line-md", "iconoir", "tdesign", "formkit", "clarity", "octicon", "pajamas", "codicon", "devicon", "twemoji", "noto-v1", "fxemoji", "raphael", "flat-ui", "topcoat", "feather", "tabler", "mynaui", "lucide", "circum", "carbon", "lsicon", "nimbus", "fluent", "glyphs", "memory", "garden", "temaki", "entypo", "icons8", "subway", "vaadin", "solar", "basil", "pixel", "typcn", "prime", "cuida", "stash", "charm", "quill", "codex", "picon", "logos", "token", "covid", "weui", "mage", "ooui", "maki", "unjs", "noto", "flag", "iwwa", "gala", "zmdi", "bpmn", "mdi", "uil", "uim", "uit", "uis", "jam", "ion", "cil", "uiw", "oui", "nrk", "gcp", "cib", "bxl", "cbi", "cif", "gis", "map", "geo", "fad", "eva", "bxs", "wpf", "whh", "ic", "ri", "si", "gg", "ci", "fe", "mi", "ep", "bi", "ph", "ix", "ei", "f7", "wi", "la", "bx", "fa", "oi", "et", "el", "ls", "vs", "il", "ps"];
function resolveIconName(name = "") {
  let prefix;
  let provider = "";
  if (name[0] === "@" && name.includes(":")) {
    provider = name.split(":")[0].slice(1);
    name = name.split(":").slice(1).join(":");
  }
  if (name.startsWith("i-")) {
    name = name.replace(/^i-/, "");
    for (const collectionName of iconCollections) {
      if (name.startsWith(collectionName)) {
        prefix = collectionName;
        name = name.slice(collectionName.length + 1);
        break;
      }
    }
  } else if (name.includes(":")) {
    const [_prefix, _name] = name.split(":");
    prefix = _prefix;
    name = _name;
  }
  return {
    provider,
    prefix: prefix || "",
    name: name || ""
  };
}
export {
  resolveIconName as r,
  useAppConfig as u
};
//# sourceMappingURL=index-7WrDIlZh.js.map
