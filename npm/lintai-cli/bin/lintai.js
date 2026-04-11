#!/usr/bin/env node

import { ensureInstalled, runLintai } from '../lib/install.js';

try {
  const binaryPath = await ensureInstalled();
  const exitCode = await runLintai(binaryPath, process.argv.slice(2));
  process.exit(exitCode);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[lintai-cli] ${message}`);
  process.exit(1);
}
