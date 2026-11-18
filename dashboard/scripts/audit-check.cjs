// npm audit --audit-level=high, with named, dated exceptions.
//
//   node scripts/audit-check.cjs            runs npm audit --json
//   node scripts/audit-check.cjs FILE.json  checks a saved report (tests)
//
// Fails on any high or critical advisory not listed in audit-exceptions.json,
// on any listed exception past its expiry date, and on any listed exception
// that no longer matches a reported advisory (so a fixed one gets removed).
'use strict';

const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const FAILING = new Set(['high', 'critical']);

function advisoryId(via) {
  const match = String(via.url || '').match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
  return match ? match[0] : `npm-${via.source}`;
}

function evaluate(report, exceptions, today) {
  const found = new Map();
  for (const vuln of Object.values(report.vulnerabilities || {})) {
    for (const via of vuln.via || []) {
      if (via && typeof via === 'object' && FAILING.has(via.severity)) {
        found.set(advisoryId(via), { package: via.name, title: via.title, severity: via.severity });
      }
    }
  }
  const problems = [];
  const accepted = [];
  const listed = new Map(exceptions.map(e => [e.id, e]));
  for (const [id, adv] of found) {
    const entry = listed.get(id);
    if (!entry) {
      problems.push(`${adv.severity} ${id} in ${adv.package}: ${adv.title} (not in audit-exceptions.json)`);
    } else if (!/^\d{4}-\d{2}-\d{2}$/.test(String(entry.expires || ''))) {
      problems.push(`${id}: exception has no valid expires date (YYYY-MM-DD)`);
    } else if (entry.expires < today) {
      problems.push(`${id}: exception expired on ${entry.expires}; re-check the advisory and fix, or renew with a reason`);
    } else if (!entry.reason || String(entry.reason).trim().length < 20) {
      problems.push(`${id}: exception needs a reason`);
    } else {
      accepted.push(`${id} in ${adv.package} accepted until ${entry.expires}`);
    }
  }
  for (const id of listed.keys()) {
    if (!found.has(id)) problems.push(`${id}: listed in audit-exceptions.json but no longer reported; remove it`);
  }
  return { problems, accepted, found: found.size };
}

function main(argv) {
  const root = resolve(__dirname, '..');
  let raw;
  if (argv[0]) {
    raw = readFileSync(argv[0], 'utf8');
  } else {
    const run = spawnSync('npm', ['audit', '--json'], { cwd: root, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    if (run.error) throw run.error;
    raw = run.stdout;
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    console.error('audit-check: npm audit did not return JSON; failing closed');
    return 1;
  }
  if (report.error) {
    console.error(`audit-check: npm audit failed: ${JSON.stringify(report.error)}; failing closed`);
    return 1;
  }
  const { exceptions } = JSON.parse(readFileSync(resolve(root, 'audit-exceptions.json'), 'utf8'));
  const today = new Date().toISOString().slice(0, 10);
  const { problems, accepted, found } = evaluate(report, exceptions, today);
  for (const line of accepted) console.log(`accepted: ${line}`);
  for (const line of problems) console.error(`FAIL: ${line}`);
  console.log(`audit-check: ${found} high/critical advisories, ${accepted.length} accepted, ${problems.length} problems`);
  return problems.length ? 1 : 0;
}

module.exports = { evaluate, advisoryId };
if (require.main === module) process.exitCode = main(process.argv.slice(2));
