#!/usr/bin/env node
// check-migration-safety.mjs
//
// A required pre-merge CI check. Scans the given migration SQL files for
// DESTRUCTIVE / prod-data-dangerous statements that a from-empty CI replay
// CANNOT catch.
//
// THE HOLE THIS EXISTS TO CLOSE, because it is not obvious and it is common:
// a migration test job replays migrations against an EMPTY database. So a DROP,
// TRUNCATE, type change or unqualified DELETE that destroys or rewrites REAL
// production rows passes that job GREEN. The test suite is structurally
// incapable of seeing the class of bug that actually costs you data, because
// there is no data in the database it runs against.
//
// If any file trips a rule, exit non-zero so the pull request routes to human
// review and the CI check goes red. A reviewer can still merge a deliberate,
// reviewed destructive migration; the point is that nobody does it by accident.
//
// Additive migrations (CREATE TABLE, ADD COLUMN nullable or with DEFAULT, new
// function/policy/trigger, CREATE INDEX on a table created in the SAME
// migration) pass clean.
//
//   Usage:  node check-migration-safety.mjs <file1.sql> [file2.sql ...]
//           node check-migration-safety.mjs --self-test
//   exit 0  -> all clean, or no .sql files given
//   exit 1  -> at least one destructive/risky pattern (route to human)
//
// Also importable: `import { scanSql } from './check-migration-safety.mjs'`.
// Importing has no side effects: the CLI below runs only when this file is
// the entry point, so it never calls process.exit inside your process.
//
// Detection notes (hardened 2026-07-03):
//   - Rules are UNANCHORED: DELETE/UPDATE inside DO $$ bodies, PL/pgSQL branches,
//     CTEs (`WITH d AS (DELETE FROM ...)`) and EXECUTE format('...') strings are
//     all caught. The old `^`-anchored rules missed every one of these.
//   - The WHERE check for DELETE/UPDATE is paren-depth aware: the statement span
//     ends only at a `)` that closes an ENCLOSING group, so `SET a = now() WHERE`
//     is not truncated at `now()` (no false flag), while a WHERE-less
//     `WITH d AS (DELETE FROM x)` still trips.
//   - Only a WHERE at depth 0 of that span counts. A WHERE nested inside a
//     subquery belongs to the subquery, so
//     `UPDATE a SET b = (SELECT c FROM d WHERE e = 1)` still flags.
//   - Added verbs: DROP CONSTRAINT / RENAME COLUMN|CONSTRAINT|TO / ADD COLUMN
//     ... NOT NULL without DEFAULT / DROP POLICY (exempt when the same policy on
//     the same table is recreated in the SAME single-transaction file, which is
//     the dominant legitimate alter-policy pattern; a naked drop still flags).
//
// Bias: FALSE POSITIVES are SAFE (they just route to a human). FALSE NEGATIVES
// are the danger, so the rules deliberately over-flag rather than under-flag,
// e.g. a 'DROP TABLE' inside a string literal still flags.
// No dependencies.

import { readFileSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Drop SQL comments so a comment mentioning "DROP TABLE" can't false-flag.
const stripComments = (sql) =>
  sql.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/--[^\n]*/g, ' ');

// Per-statement rules (statements are split on ';'). Unanchored on purpose.
const STMT_RULES = [
  ['DROP TABLE', /\bdrop\s+table\b/i],
  ['DROP SCHEMA', /\bdrop\s+schema\b/i],
  ['DROP DATABASE', /\bdrop\s+database\b/i],
  ['DROP COLUMN', /\bdrop\s+column\b/i],
  ['DROP CONSTRAINT', /\bdrop\s+constraint\b/i],
  ['RENAME column/constraint/table (breaks live clients)', /\brename\s+(?:column|constraint|to)\b/i],
  ['TRUNCATE', /\btruncate\b/i],
  ['ALTER COLUMN ... TYPE (table rewrite)', /\balter\s+column\b[\s\S]*?\btype\b/i],
  ['SET NOT NULL (can fail/lock on existing rows)', /\bset\s+not\s+null\b/i],
];

// From `idx`, the span of the current SQL group: stops at a `)` that closes an
// ENCLOSING paren group (a CTE/subquery wrapper), but skips over balanced pairs
// opened after `idx`, so `WHERE f(a) = 1` and `SET a = now() WHERE ...` keep
// their WHERE inside the span.
const groupSpan = (s, idx) => {
  let depth = 0;
  for (let i = idx; i < s.length; i++) {
    const c = s[i];
    if (c === '(') depth++;
    else if (c === ')') {
      if (depth === 0) return s.slice(idx, i);
      depth--;
    }
  }
  return s.slice(idx);
};

// True when `span` has a WHERE at paren depth 0. Text inside nested parens is
// blanked first, so the WHERE of a subquery such as
// `SET b = (SELECT c FROM d WHERE e = 1)` does not count as the statement's own.
const hasTopLevelWhere = (span) => {
  let depth = 0;
  let top = '';
  for (const c of span) {
    if (c === '(') depth++;
    else if (c === ')') depth = Math.max(0, depth - 1);
    top += depth === 0 && c !== ')' ? c : ' ';
  }
  return /\bwhere\b/i.test(top);
};

// Scan one comment-stripped SQL text; returns finding names (deduped).
export const scanSql = (sql) => {
  const findings = new Set();

  // Tables created in THIS migration: an index/constraint on one of them is safe
  // (the table is empty when the migration runs).
  const created = new Set();
  const ctRe = /\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:"?public"?\.)?"?([a-z0-9_]+)"?/gi;
  for (let m; (m = ctRe.exec(sql)); ) created.add(m[1].toLowerCase());

  // Policies (re)created in THIS migration. Where the runner applies each migration
  // file in a single transaction (most do), DROP POLICY + CREATE POLICY of the SAME
  // policy on the SAME table in one file leaves no window without row-level security,
  // and that is the dominant legitimate way to alter a policy. A naked DROP POLICY
  // with no same-file recreate still flags.
  //
  // If your runner does NOT wrap each file in a transaction, delete this exemption:
  // the gap it assumes away becomes real.
  const policyKey = (name, tbl) =>
    `${name.replace(/"/g, '').trim().toLowerCase()}|${tbl.replace(/"/g, '').replace(/^public\./i, '').trim().toLowerCase()}`;
  const createdPolicies = new Set();
  const cpRe = /\bcreate\s+policy\s+("[^"]+"|[a-z0-9_]+)\s+on\s+((?:"?[a-z0-9_]+"?\.)?"?[a-z0-9_]+"?)/gi;
  for (let m; (m = cpRe.exec(sql)); ) createdPolicies.add(policyKey(m[1], m[2]));

  for (const stmt of sql.split(';')) {
    const s = stmt.trim();
    if (!s) continue;

    for (const [name, re] of STMT_RULES) {
      if (re.test(s)) findings.add(name);
    }

    // DROP POLICY: exempt only when the same policy on the same table is
    // recreated later in this same (single-transaction) migration file.
    const dpRe = /\bdrop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[a-z0-9_]+)\s+on\s+((?:"?[a-z0-9_]+"?\.)?"?[a-z0-9_]+"?)/gi;
    for (let m; (m = dpRe.exec(s)); ) {
      if (!createdPolicies.has(policyKey(m[1], m[2]))) {
        findings.add('DROP POLICY without same-file recreate (RLS gap / permission loss)');
      }
    }
    if (/\bdrop\s+policy\b/i.test(s) && !/\bdrop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|[a-z0-9_]+)\s+on\s+/i.test(s)) {
      // Unparseable DROP POLICY shape: over-flag rather than guess.
      findings.add('DROP POLICY (unrecognized form)');
    }

    // ADD COLUMN ... NOT NULL without a DEFAULT fails outright on a non-empty
    // prod table (and with GENERATED/complex defaults may rewrite). DEFAULT
    // anywhere in the statement passes; over-flagging multi-column adds is fine.
    if (/\badd\s+column\b[\s\S]*?\bnot\s+null\b/i.test(s) && !/\bdefault\b/i.test(s)) {
      findings.add('ADD COLUMN ... NOT NULL without DEFAULT (fails on existing rows)');
    }

    // Unqualified DELETE / UPDATE: per occurrence, a WHERE is required at depth 0
    // of the occurrence's own paren group (catches DO-block bodies and CTEs, and
    // ignores a WHERE that belongs to a nested subquery).
    const delRe = /\bdelete\s+from\b/gi;
    for (let m; (m = delRe.exec(s)); ) {
      if (!hasTopLevelWhere(groupSpan(s, m.index))) {
        findings.add('unqualified DELETE (no WHERE)');
      }
    }
    const updRe = /\bupdate\s+(?:only\s+)?[a-z0-9_."]+\s+set\b/gi;
    for (let m; (m = updRe.exec(s)); ) {
      if (!hasTopLevelWhere(groupSpan(s, m.index))) {
        findings.add('unqualified UPDATE (no WHERE)');
      }
    }

    const idxRe = /\bcreate\s+(?:unique\s+)?index\b/i;
    if (idxRe.test(s) && !/\bconcurrently\b/i.test(s)) {
      const on = /\bon\s+(?:"?public"?\.)?"?([a-z0-9_]+)"?/i.exec(s);
      const tbl = on ? on[1].toLowerCase() : '(unknown)';
      if (!created.has(tbl)) {
        findings.add(`non-CONCURRENT CREATE INDEX on existing table "${tbl}" (locks prod)`);
      }
    }
  }
  return [...findings];
};

// ---------------------------------------------------------------------------
// Self-test: `node src/check-migration-safety.mjs --self-test`
// Run by CI before the gate so a regression in the gate itself cannot merge.
// ---------------------------------------------------------------------------
const SELF_TEST_CASES = [
  // [description, sql, expected finding-count > 0]
  ['DELETE without WHERE inside DO block', `do $$ begin if true then delete from public.stars; end if; end $$`, true],
  ['DELETE with WHERE inside DO block', `do $$ begin delete from stars where family_id = fid; end $$`, false],
  ['DELETE without WHERE inside CTE', `with dead as (delete from stars returning id) select count(*) from dead`, true],
  ['DELETE with WHERE inside CTE', `with dead as (delete from stars where created_at < now() - interval '30 days') select 1`, false],
  ['UPDATE with function-call value and WHERE', `update families set updated_at = now() where id = '1'`, false],
  ['UPDATE without WHERE', `update families set premium_override = false`, true],
  ['UPDATE without WHERE inside DO block', `do $$ begin update families set x = 1; end $$`, true],
  ['UPDATE whose only WHERE is inside a subquery value', `update a set b = (select c from d where e = 1)`, true],
  ['UPDATE with a subquery value and its own WHERE', `update a set b = (select c from d where e = 1) where id = 2`, false],
  ['DELETE whose only WHERE is inside a USING subquery', `delete from a using (select id from b where x = 1) s`, true],
  ['EXECUTE format dynamic DELETE without WHERE', `do $$ begin execute format('delete from %I', t); end $$`, true],
  ['naked DROP POLICY (no recreate)', `drop policy "families_select" on public.families`, true],
  ['DROP POLICY + same-file recreate (single-txn, no gap)', `drop policy "families_select" on public.families;\ncreate policy "families_select" on public.families for select using (family_id = get_user_family_id())`, false],
  ['DROP POLICY recreated under a DIFFERENT name', `drop policy "families_select" on public.families;\ncreate policy "families_read" on public.families for select using (true)`, true],
  ['DROP POLICY IF EXISTS + recreate', `drop policy if exists families_select on families;\ncreate policy families_select on families for select using (true)`, false],
  ['DROP CONSTRAINT', `alter table families drop constraint families_pkey`, true],
  ['RENAME COLUMN', `alter table families rename column name to family_name`, true],
  ['RENAME TO (table rename)', `alter table families rename to households`, true],
  ['ADD COLUMN NOT NULL without DEFAULT', `alter table families add column tier text not null`, true],
  ['ADD COLUMN NOT NULL with DEFAULT', `alter table families add column tier text not null default 'free'`, false],
  ['ADD COLUMN nullable', `alter table families add column note text`, false],
  ['DROP TABLE mentioned only in a comment', `-- we deliberately do NOT drop table stars\ncreate table foo (id uuid primary key)`, false],
  ['plain additive migration', `create table foo (id uuid primary key);\ncreate index foo_idx on foo (id);\ncreate policy p on foo for select using (true)`, false],
  ['non-concurrent index on pre-existing table', `create index stars_idx on public.stars (family_id)`, true],
  ['SET NOT NULL', `alter table families alter column name set not null`, true],
  ['ALTER COLUMN TYPE', `alter table families alter column id type bigint`, true],
  ['TRUNCATE inside DO block', `do $$ begin truncate public.stars; end $$`, true],
];

// Importing the module must not run the CLI. A fresh Node process imports it
// and reports what it got; if the import had called process.exit, the marker
// line never prints.
const checkImportHasNoSideEffects = () => {
  const code = `const m = await import(${JSON.stringify(import.meta.url)}); console.log('import-ok:' + typeof m.scanSql);`;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  const out = (r.stdout || '').trim();
  return r.status === 0 && out === 'import-ok:function'
    ? null
    : `exit ${r.status}, stdout ${JSON.stringify(out)}`;
};

const runSelfTest = () => {
  const total = SELF_TEST_CASES.length + 1;
  let failed = 0;
  for (const [desc, sql, shouldFlag] of SELF_TEST_CASES) {
    const found = scanSql(stripComments(sql));
    const flagged = found.length > 0;
    if (flagged !== shouldFlag) {
      failed++;
      console.error(`  FAIL: ${desc}: expected ${shouldFlag ? 'flagged' : 'clean'}, got ${flagged ? `flagged (${found.join('; ')})` : 'clean'}`);
    }
  }
  const importProblem = checkImportHasNoSideEffects();
  if (importProblem) {
    failed++;
    console.error(`  FAIL: importing the module must not run the CLI: got ${importProblem}`);
  }
  if (failed) {
    console.error(`check-migration-safety --self-test: ${failed}/${total} case(s) FAILED`);
    process.exit(1);
  }
  console.log(`check-migration-safety --self-test: ${total} cases passed.`);
  process.exit(0);
};

// ---------------------------------------------------------------------------
// CLI: runs only when this file is the entry point (directly, or through the
// npm bin link, hence realpath), never when it is imported.
// ---------------------------------------------------------------------------
const isEntryPoint = () => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
};

const main = () => {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) runSelfTest();

  const files = argv.filter((f) => f.endsWith('.sql'));
  if (files.length === 0) {
    console.log('check-migration-safety: no .sql files to check, clean.');
    process.exit(0);
  }

  const findings = new Set();
  for (const file of files) {
    let raw;
    try {
      raw = readFileSync(file, 'utf8');
    } catch (e) {
      console.error(`check-migration-safety: cannot read ${file}: ${e.message}`);
      process.exit(1);
    }
    for (const name of scanSql(stripComments(raw))) findings.add(`${file}: ${name}`);
  }

  if (findings.size) {
    console.error('check-migration-safety: DESTRUCTIVE/risky patterns found, routing to human review:');
    for (const f of findings) console.error('  - ' + f);
    process.exit(1);
  }
  console.log(`check-migration-safety: ${files.length} migration file(s) clean.`);
  process.exit(0);
};

if (isEntryPoint()) main();
