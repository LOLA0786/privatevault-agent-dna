const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');
const { test } = require('node:test');

test('nanoid zero-size generators terminate without hanging the caller', () => {
  const run = spawnSync(process.execPath, ['--experimental-vm-modules', '--input-type=module', '-e', `
    import assert from 'node:assert/strict';
    import { randomBytes } from 'node:crypto';
    import { readFileSync } from 'node:fs';
    import { createRequire } from 'node:module';
    import { dirname, join } from 'node:path';
    import { SourceTextModule, SyntheticModule } from 'node:vm';
    import { customAlphabet, customRandom } from 'nanoid';
    import { urlAlphabet } from 'nanoid/url-alphabet';

    const random = size => new Uint8Array(size).fill(1);
    for (const make of [
      size => customAlphabet('abc', size),
      size => customRandom('abc', size, random),
    ]) {
      assert.equal(make(0)(), '');
      assert.equal(make(8)(0), '');
      assert.equal(make(8)().length, 8);
    }

    // 3.3.17 left the native async adapter vulnerable. Supply Node entropy
    // for its Expo import while evaluating the installed generator unchanged.
    const require = createRequire(import.meta.url);
    const path = join(dirname(require.resolve('nanoid/package.json')), 'async/index.native.js');
    const native = new SourceTextModule(readFileSync(path, 'utf8'));
    await native.link(name => {
      if (name === 'expo-random') return new SyntheticModule(['getRandomBytesAsync'], function () {
        this.setExport('getRandomBytesAsync', size => Promise.resolve(randomBytes(size)));
      });
      if (name === '../url-alphabet/index.js') return new SyntheticModule(['urlAlphabet'], function () {
        this.setExport('urlAlphabet', urlAlphabet);
      });
      throw new Error('Unexpected native dependency: ' + name);
    });
    await native.evaluate();
    const make = native.namespace.customAlphabet;
    assert.equal(await make('abc', 0)(), '');
    assert.equal(await make('abc', 8)(0), '');
    assert.equal((await make('abc', 8)()).length, 8);
  `], { cwd: resolve(__dirname, '..'), encoding: 'utf8', timeout: 5000 });
  assert.equal(run.error, undefined, run.error?.message);
  assert.equal(run.status, 0, run.stderr);
});
