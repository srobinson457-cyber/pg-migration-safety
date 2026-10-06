#!/usr/bin/env node
// mutation-check.mjs
//
// Checks that the self-test actually guards each rule. For every mutant below,
// a temp copy of the scanner is broken in one place and its --self-test is run.
// The self-test must FAIL on every mutant. A mutant that passes ("survives")
// means a rule could be deleted or broken without any test noticing.
//
//   Usage:  node scripts/mutation-check.mjs
//   exit 0  -> every mutant was killed
//   exit 1  -> a mutant survived, a mutant no longer applies, or the
//              unmutated scanner fails its own self-test
//
// No dependencies.

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'check-migration-safety.mjs');
// Normalized to LF so the multi-line finds below match on a CRLF checkout too.
const source = readFileSync(SRC, 'utf8').replace(/\r\n/g, '\n');

// One mutant per STMT_RULES entry, generated so a newly added rule is covered
// without editing this file.
const stmtRuleMutants = () => {
  const block = /const STMT_RULES = \[\n([\s\S]*?)\n\];/.exec(source);
  if (!block) throw new Error('could not find the STMT_RULES block');
  const lines = block[1].split('\n').filter((l) => /^\s*\['/.test(l));
  if (lines.length === 0) throw new Error('found no entries in STMT_RULES');
  return lines.map((line) => [`remove STMT_RULES entry ${/\['([^']*)'/.exec(line)[1]}`, line + '\n', '']);
};

// [description, exact text to find (must occur exactly once), replacement]
const MUTANTS = [
  ...stmtRuleMutants(),
  ['DROP POLICY: never exempt a same-file recreate',
    'if (!createdPolicies.has(policyKey(m[1], m[2]))) {', 'if (true) {'],
  ['DROP POLICY: always exempt',
    'if (!createdPolicies.has(policyKey(m[1], m[2]))) {', 'if (false) {'],
  ['remove the unrecognized DROP POLICY branch',
    "findings.add('DROP POLICY (unrecognized form)');", ''],
  ['remove ADD COLUMN ... NOT NULL rule',
    "findings.add('ADD COLUMN ... NOT NULL without DEFAULT (fails on existing rows)');", ''],
  ['ADD COLUMN ... NOT NULL: ignore DEFAULT',
    ' && !/\\bdefault\\b/i.test(s)', ''],
  ['remove unqualified DELETE rule',
    "findings.add('unqualified DELETE (no WHERE)');", ''],
  ['DELETE: ignore WHERE',
    'delRe.exec(s)); ) {\n      if (!hasTopLevelWhere(groupSpan(s, m.index))) {',
    'delRe.exec(s)); ) {\n      if (true) {'],
  ['remove unqualified UPDATE rule',
    "findings.add('unqualified UPDATE (no WHERE)');", ''],
  ['UPDATE: ignore WHERE',
    'updRe.exec(s)); ) {\n      if (!hasTopLevelWhere(groupSpan(s, m.index))) {',
    'updRe.exec(s)); ) {\n      if (true) {'],
  ['groupSpan: never stop at an enclosing )',
    'if (depth === 0) return s.slice(idx, i);', 'if (depth === 0) continue;'],
  ['groupSpan: stop at the first )',
    'if (depth === 0) return s.slice(idx, i);', 'return s.slice(idx, i);'],
  ['hasTopLevelWhere: count a WHERE nested in a subquery',
    "top += depth === 0 && c !== ')' ? c : ' ';", 'top += c;'],
  ['remove non-CONCURRENT CREATE INDEX rule',
    'findings.add(`non-CONCURRENT CREATE INDEX on existing table "${tbl}" (locks prod)`);', ''],
  ['CREATE INDEX: ignore CONCURRENTLY',
    ' && !/\\bconcurrently\\b/i.test(s)', ''],
  ['CREATE INDEX: ignore tables created in the same file',
    'if (!created.has(tbl)) {', 'if (true) {'],
  ['ALTER ... TYPE: require the COLUMN keyword',
    '|\\balter\\s+(?:"[^"]+"|[a-z0-9_]+)\\s+(?:set\\s+data\\s+)?type\\b', ''],
  ['UPDATE: no alias allowed before SET',
    '(?:\\s+(?:as\\s+)?[a-z0-9_"]+)?\\s+set\\b', '\\s+set\\b'],
  ['scanSql: do not strip comments',
    'const sql = stripComments(rawSql);', 'const sql = rawSql;'],
];

const countOf = (haystack, needle) => haystack.split(needle).length - 1;

const runSelfTest = (dir, text) => {
  const file = join(dir, 'check-migration-safety.mjs');
  writeFileSync(file, text);
  return spawnSync(process.execPath, [file, '--self-test'], { encoding: 'utf8' });
};

const dir = mkdtempSync(join(tmpdir(), 'pg-migration-safety-mutants-'));
let problems = 0;
try {
  // A self-test that already fails would "kill" every mutant and prove nothing.
  const base = runSelfTest(dir, source);
  if (base.status !== 0) {
    console.error('mutation-check: the unmutated scanner fails its own self-test:');
    console.error((base.stdout || '') + (base.stderr || ''));
    process.exit(1);
  }

  for (const [desc, find, replace] of MUTANTS) {
    const n = countOf(source, find);
    if (n !== 1) {
      problems++;
      console.error(`  DID NOT APPLY (${n} matches): ${desc}`);
      continue;
    }
    const r = runSelfTest(dir, source.replace(find, () => replace));
    if (r.status === 0) {
      problems++;
      console.error(`  SURVIVED: ${desc}`);
    } else {
      console.log(`  killed: ${desc}`);
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}

if (problems) {
  console.error(`mutation-check: ${problems}/${MUTANTS.length} mutant(s) not killed`);
  process.exit(1);
}
console.log(`mutation-check: all ${MUTANTS.length} mutants killed.`);
