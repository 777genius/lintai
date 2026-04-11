#!/usr/bin/env node

import { ensureInstalled } from '../lib/install.js';

if (process.env.LINTAI_NPM_SKIP_DOWNLOAD === '1') {
  process.exit(0);
}

try {
  await ensureInstalled();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[lintai-cli] ${message}`);
  process.exit(1);
}
