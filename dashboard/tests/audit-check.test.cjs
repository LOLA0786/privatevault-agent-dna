const assert = require('node:assert/strict');
const { test } = require('node:test');
const { evaluate } = require('../scripts/audit-check.cjs');

const advisory = (id, severity = 'high', name = 'picomatch') => ({
  source: 1, name, title: 't', severity, url: `https://github.com/advisories/${id}`,
});
const report = (...vias) => ({
  vulnerabilities: {
    picomatch: { via: vias },
    vite: { via: ['picomatch', 'tinyglobby'] }, // transitive: names only
  },
});
const ok = { id: 'GHSA-aaaa-bbbb-cccc', package: 'picomatch', reason: 'build tool only; patterns are ours', expires: '2026-12-18' };

test('a listed, unexpired advisory passes; transitive entries do not count twice', () => {
  const r = evaluate(report(advisory(ok.id)), [ok], '2026-11-18');
  assert.deepEqual(r.problems, []);
  assert.equal(r.accepted.length, 1);
  assert.equal(r.found, 1);
});

test('an unlisted high or critical advisory fails; moderate does not', () => {
  assert.equal(evaluate(report(advisory('GHSA-dddd-eeee-ffff')), [], '2026-11-18').problems.length, 1);
  assert.equal(evaluate(report(advisory('GHSA-dddd-eeee-ffff', 'critical')), [], '2026-11-18').problems.length, 1);
  assert.deepEqual(evaluate(report(advisory('GHSA-dddd-eeee-ffff', 'moderate')), [], '2026-11-18').problems, []);
});

test('an exception stops covering a different advisory in the same package', () => {
  const r = evaluate(report(advisory(ok.id), advisory('GHSA-dddd-eeee-ffff')), [ok], '2026-11-18');
  assert.equal(r.problems.length, 1);
  assert.match(r.problems[0], /GHSA-dddd-eeee-ffff/);
});

test('an expired, undated or unexplained exception fails', () => {
  assert.match(evaluate(report(advisory(ok.id)), [ok], '2026-12-19').problems[0], /expired/);
  assert.equal(evaluate(report(advisory(ok.id)), [ok], '2026-12-18').problems.length, 0);
  assert.match(evaluate(report(advisory(ok.id)), [{ ...ok, expires: 'soon' }], '2026-11-18').problems[0], /expires/);
  assert.match(evaluate(report(advisory(ok.id)), [{ ...ok, reason: '' }], '2026-11-18').problems[0], /reason/);
});

test('an exception that no longer matches anything fails, so it gets removed', () => {
  assert.match(evaluate({ vulnerabilities: {} }, [ok], '2026-11-18').problems[0], /no longer reported/);
});

test('the shipped exceptions file is well formed', () => {
  const { exceptions } = require('../audit-exceptions.json');
  assert.ok(exceptions.length >= 1);
  for (const e of exceptions) {
    assert.match(e.id, /^GHSA-/);
    assert.match(e.expires, /^\d{4}-\d{2}-\d{2}$/);
    assert.ok(e.reason.length >= 20);
  }
});
