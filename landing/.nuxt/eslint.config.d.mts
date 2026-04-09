import type { FlatConfigComposer } from "../node_modules/.pnpm/eslint-flat-config-utils@3.1.0/node_modules/eslint-flat-config-utils/dist/index.mjs"
import { defineFlatConfigs } from "../node_modules/.pnpm/@nuxt+eslint-config@1.15.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_typescript@6.0.2/node_modules/@nuxt/eslint-config/dist/flat.mjs"
import type { NuxtESLintConfigOptionsResolved } from "../node_modules/.pnpm/@nuxt+eslint-config@1.15.2_@vue+compiler-sfc@3.5.31_eslint@9.39.4_typescript@6.0.2/node_modules/@nuxt/eslint-config/dist/flat.mjs"

declare const configs: FlatConfigComposer
declare const options: NuxtESLintConfigOptionsResolved
declare const withNuxt: typeof defineFlatConfigs
export default withNuxt
export { withNuxt, defineFlatConfigs, configs, options }