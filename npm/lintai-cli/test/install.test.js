import test from 'node:test';
import assert from 'node:assert/strict';
import {
  getAssetFileName,
  getReleaseTag,
  parseChecksumManifest,
  resolvePlatformAsset,
} from '../lib/install.js';

test('resolvePlatformAsset maps macOS arm64', () => {
  assert.deepEqual(resolvePlatformAsset('darwin', 'arm64'), {
    target: 'aarch64-apple-darwin',
    archiveExt: 'tar.gz',
    binaryName: 'lintai',
  });
});

test('resolvePlatformAsset maps macOS x64', () => {
  assert.deepEqual(resolvePlatformAsset('darwin', 'x64'), {
    target: 'x86_64-apple-darwin',
    archiveExt: 'tar.gz',
    binaryName: 'lintai',
  });
});

test('resolvePlatformAsset maps windows x64', () => {
  assert.deepEqual(resolvePlatformAsset('win32', 'x64'), {
    target: 'x86_64-pc-windows-msvc',
    archiveExt: 'zip',
    binaryName: 'lintai.exe',
  });
});

test('resolvePlatformAsset maps windows arm64', () => {
  assert.deepEqual(resolvePlatformAsset('win32', 'arm64'), {
    target: 'aarch64-pc-windows-msvc',
    archiveExt: 'zip',
    binaryName: 'lintai.exe',
  });
});

test('resolvePlatformAsset maps Linux arm64 glibc', () => {
  assert.deepEqual(resolvePlatformAsset('linux', 'arm64'), {
    target: 'aarch64-unknown-linux-gnu',
    archiveExt: 'tar.gz',
    binaryName: 'lintai',
  });
});

test('getReleaseTag prefixes package version', () => {
  assert.equal(getReleaseTag('0.1.0'), 'v0.1.0');
});

test('getAssetFileName composes release asset path', () => {
  assert.equal(
    getAssetFileName('v0.1.0', 'x86_64-unknown-linux-gnu', 'tar.gz'),
    'lintai-v0.1.0-x86_64-unknown-linux-gnu.tar.gz',
  );
});

test('parseChecksumManifest parses sha256sum output', () => {
  const checksums = parseChecksumManifest(
    [
      '1111111111111111111111111111111111111111111111111111111111111111  lintai-v0.1.0-x86_64-unknown-linux-gnu.tar.gz',
      '2222222222222222222222222222222222222222222222222222222222222222 *lintai-v0.1.0-x86_64-pc-windows-msvc.zip',
    ].join('\n'),
  );

  assert.equal(
    checksums.get('lintai-v0.1.0-x86_64-unknown-linux-gnu.tar.gz'),
    '1111111111111111111111111111111111111111111111111111111111111111',
  );
  assert.equal(
    checksums.get('lintai-v0.1.0-x86_64-pc-windows-msvc.zip'),
    '2222222222222222222222222222222222222222222222222222222222222222',
  );
});
