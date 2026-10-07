#!/usr/bin/env node
// mutation-check.mjs
//
// Checks that the self-test actually guards each rule. For every mutant below,
// a temp copy of the scanner is broken in one place and its --self-test is run.
// The self-test must FAIL on every mutant. A mutant that passes ("survives")
// means a rule could be deleted or broken without any test noticing.
//
// A mutant counts as killed only when the self-test exits 1 AND prints its
// "N/M case(s) FAILED" summary, meaning a test case caught it. Any other exit
// (a syntax error from a mutant that broke the file, a crash) proves nothing
// about the tests, so it is reported as a problem rather than a kill.
//
//   Usage:  node scripts/mutation-check.mjs
//   exit 0  -> every mutant was killed by a failing self-test case
//   exit 1  -> a mutant survived, a mutant no longer applies, a mutant broke
//              the self-test without failing a case, or the unmutated
//              scanner fails its own self-test
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
  ['ALTER ... TYPE without COLUMN: no quoted column name',
    '|\\balter\\s+(?:"[^"]+"|[a-z0-9_]+)', '|\\balter\\s+(?:[a-z0-9_]+)'],
  ['UPDATE: no alias allowed before SET',
    '(?:\\s+(?:as\\s+)?[a-z0-9_"]+)?\\s+set\\b', '\\s+set\\b'],
  ['UPDATE: no quoted alias',
    '(?:as\\s+)?[a-z0-9_"]+)?', '(?:as\\s+)?[a-z0-9_]+)?'],
  ['UPDATE: no * inheritance marker',
    '(?:\\s*\\*)?', ''],
  ['UPDATE: quoted table name cannot contain spaces',
    '(?:"[^"]*"|[a-z0-9_.])+', '[a-z0-9_."]+'],
  ['scanSql: do not strip comments',
    'const sql = stripComments(rawSql);', 'const sql = rawSql;'],
  // stripComments: one mutant per lexer branch.
  ['line comments: not stripped',
    "if (sql.startsWith('--', i)) {", 'if (false) {'],
  ['block comments: not stripped',
    "} else if (sql.startsWith('/*', i)) {", '} else if (false) {'],
  ['block comments: do not nest',
    "else if (sql.startsWith('/*', i)) { depth++; i += 2; }", 'else if (false) { depth++; i += 2; }'],
  ['single quotes: not a string',
    '} else if (c === "\'") {', '} else if (false) {'],
  ['strings: comments inside are kept',
    "out += `'${stripComments(body)}'`;", "out += `'${body}'`;"],
  ["E'' strings: backslash escapes nothing",
    'const re = isE ? E_BODY : PLAIN_BODY;', 'const re = PLAIN_BODY;'],
  ["E'' strings: a doubled '' ends them",
    "|''|", '|'],
  ["E'' strings: also after a word ending in e",
    " && !IDENT_CHAR.test(sql[i - 2] ?? '')", ''],
  ['double quotes: not an identifier',
    "} else if (c === '\"') {", '} else if (false) {'],
  ['dollar quotes: not recognized',
    "const dollar = c === '$' && DOLLAR_QUOTE.exec(sql);", 'const dollar = false;'],
  ['dollar quotes: $$ only, no $tag$',
    '(?:(?:[a-z_]|[^\\x00-\\x7f])(?:\\w|[^\\x00-\\x7f])*)?', ''],
  ['dollar-quoted bodies: comments inside are kept',
    'out += tag + stripComments(body) + tag;', 'out += tag + body + tag;'],
];

// The summary line the self-test prints to stderr when any case fails.
const SELF_TEST_FAILED = /^check-migration-safety --self-test: \d+\/\d+ case\(s\) FAILED$/m;

const countOf = (haystack, needle) => haystack.split(needle).length - 1;

const runSelfTest = (dir, text) => {
  const file = join(dir, 'check-migration-safety.mjs');
  writeFileSync(file, text);
  return spawnSync(process.execPath, [file, '--self-test'], { encoding: 'utf8' });
};

// First line of stderr that names an error (e.g. "SyntaxError: ..."), for the report.
const errorLine = (stderr) =>
  (stderr || '').split('\n').find((l) => /^\w*Error\b/.test(l)) || '(no error line on stderr)';

const dir = mkdtempSync(join(tmpdir(), 'pg-migration-safety-mutants-'));
let baselineFails = false;
let problems = 0;
try {
  // A self-test that already fails would "kill" every mutant and prove nothing.
  const base = runSelfTest(dir, source);
  baselineFails = base.status !== 0;
  if (baselineFails) {
    console.error('mutation-check: the unmutated scanner fails its own self-test:');
    console.error((base.stdout || '') + (base.stderr || ''));
  } else {
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
      } else if (r.status === 1 && SELF_TEST_FAILED.test(r.stderr || '')) {
        console.log(`  killed: ${desc}`);
      } else {
        // Not a kill: the self-test reported no failing case, so this proves nothing.
        problems++;
        console.error(`  NO FAILING CASE (exit ${r.status ?? r.signal}): ${desc}: ${errorLine(r.stderr)}`);
      }
    }
  }
} finally {
  // Runs on every path, including a failing baseline, so the temp dir never leaks.
  rmSync(dir, { recursive: true, force: true });
}

if (baselineFails) process.exit(1);
if (problems) {
  console.error(`mutation-check: ${problems}/${MUTANTS.length} mutant(s) not killed`);
  process.exit(1);
}
console.log(`mutation-check: all ${MUTANTS.length} mutants killed.`);
