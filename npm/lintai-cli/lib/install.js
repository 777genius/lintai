import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(moduleDir, '..');
const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));

export function getReleaseTag(version = packageJson.version) {
  return process.env.LINTAI_NPM_RELEASE_TAG || `v${version}`;
}

export function isMuslLinux(report = process.report?.getReport?.()) {
  if (process.platform !== 'linux') {
    return false;
  }

  return !report?.header?.glibcVersionRuntime;
}

export function resolvePlatformAsset(platform = process.platform, arch = process.arch) {
  if (platform === 'darwin' && arch === 'arm64') {
    return {
      target: 'aarch64-apple-darwin',
      archiveExt: 'tar.gz',
      binaryName: 'lintai',
    };
  }

  if (platform === 'win32' && arch === 'x64') {
    return {
      target: 'x86_64-pc-windows-msvc',
      archiveExt: 'zip',
      binaryName: 'lintai.exe',
    };
  }

  if (platform === 'linux' && arch === 'x64') {
    return {
      target: isMuslLinux() ? 'x86_64-unknown-linux-musl' : 'x86_64-unknown-linux-gnu',
      archiveExt: 'tar.gz',
      binaryName: 'lintai',
    };
  }

  throw new Error(`unsupported platform for lintai-cli npm wrapper: ${platform}/${arch}`);
}

export function getAssetFileName(tag, target, archiveExt) {
  return `lintai-${tag}-${target}.${archiveExt}`;
}

export function getReleaseBaseUrl(tag = getReleaseTag()) {
  if (process.env.LINTAI_NPM_BASE_URL) {
    return process.env.LINTAI_NPM_BASE_URL;
  }

  return `https://github.com/777genius/lintai/releases/download/${tag}`;
}

export function getCacheRoot() {
  if (process.env.LINTAI_NPM_CACHE_DIR) {
    return process.env.LINTAI_NPM_CACHE_DIR;
  }

  if (process.platform === 'win32' && process.env.LOCALAPPDATA) {
    return path.join(process.env.LOCALAPPDATA, 'lintai-cli');
  }

  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Caches', 'lintai-cli');
  }

  return path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'lintai-cli');
}

export function parseChecksumManifest(text) {
  const entries = new Map();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }

    const match = line.match(/^([a-f0-9]{64})\s+\*?(.+)$/i);
    if (!match) {
      continue;
    }

    entries.set(match[2], match[1].toLowerCase());
  }

  return entries;
}

async function downloadToFile(url, destinationPath) {
  let response;

  try {
    response = await fetch(url, {
      headers: {
        'user-agent': 'lintai-cli-npm-wrapper',
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`failed to download ${url} - ${message}`);
  }

  if (!response.ok || !response.body) {
    throw new Error(`failed to download ${url} - ${response.status} ${response.statusText}`);
  }

  await pipeline(Readable.fromWeb(response.body), fs.createWriteStream(destinationPath));
}

async function hashFile(filePath) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filePath);

  for await (const chunk of stream) {
    hash.update(chunk);
  }

  return hash.digest('hex');
}

async function runCommand(command, args) {
  await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
    });

    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(new Error(`${command} exited with code ${code ?? 'unknown'}`));
    });
  });
}

async function extractArchive(archivePath, archiveExt, destinationPath) {
  await fsp.mkdir(destinationPath, { recursive: true });

  if (archiveExt === 'zip') {
    await runCommand('powershell', [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      `Expand-Archive -Path '${archivePath.replace(/'/g, "''")}' -DestinationPath '${destinationPath.replace(/'/g, "''")}' -Force`,
    ]);
    return;
  }

  await runCommand('tar', ['-xzf', archivePath, '-C', destinationPath]);
}

async function installBinary() {
  const tag = getReleaseTag();
  const { target, archiveExt, binaryName } = resolvePlatformAsset();
  const assetFileName = getAssetFileName(tag, target, archiveExt);
  const installRoot = path.join(getCacheRoot(), packageJson.version, target);
  const binaryPath = path.join(installRoot, binaryName);

  if (fs.existsSync(binaryPath)) {
    return binaryPath;
  }

  const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'lintai-cli-'));

  try {
    const archivePath = path.join(tempRoot, assetFileName);
    const checksumPath = path.join(tempRoot, 'SHA256SUMS');
    const extractPath = path.join(tempRoot, 'extract');
    const baseUrl = getReleaseBaseUrl(tag);

    await downloadToFile(`${baseUrl}/${assetFileName}`, archivePath);
    await downloadToFile(`${baseUrl}/SHA256SUMS`, checksumPath);

    const checksums = parseChecksumManifest(await fsp.readFile(checksumPath, 'utf8'));
    const expectedHash = checksums.get(assetFileName);
    if (!expectedHash) {
      throw new Error(`SHA256SUMS does not contain ${assetFileName}`);
    }

    const actualHash = await hashFile(archivePath);
    if (actualHash !== expectedHash) {
      throw new Error(`checksum mismatch for ${assetFileName}`);
    }

    await extractArchive(archivePath, archiveExt, extractPath);

    const extractedBinaryPath = path.join(
      extractPath,
      `lintai-${tag}-${target}`,
      binaryName,
    );

    if (!fs.existsSync(extractedBinaryPath)) {
      throw new Error(`release archive did not contain ${binaryName}`);
    }

    await fsp.mkdir(installRoot, { recursive: true });
    await fsp.copyFile(extractedBinaryPath, binaryPath);

    if (process.platform !== 'win32') {
      await fsp.chmod(binaryPath, 0o755);
    }

    return binaryPath;
  } finally {
    await fsp.rm(tempRoot, { recursive: true, force: true });
  }
}

export async function ensureInstalled() {
  return installBinary();
}

export async function runLintai(binaryPath, args) {
  return await new Promise((resolve, reject) => {
    const child = spawn(binaryPath, args, {
      stdio: 'inherit',
      env: process.env,
    });

    child.on('error', reject);
    child.on('exit', (code, signal) => {
      if (signal) {
        reject(new Error(`lintai terminated by signal ${signal}`));
        return;
      }

      resolve(code ?? 1);
    });
  });
}
