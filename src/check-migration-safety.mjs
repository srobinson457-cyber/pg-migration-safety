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
//           node check-migration-safety.mjs --json <file1.sql> [...]
//           node check-migration-safety.mjs --self-test
//   --json  -> print {"<file>": [sorted rule names]} instead of text; same exit codes
//   exit 0  -> all clean, or no .sql files given
//   exit 1  -> at least one destructive/risky pattern (route to human)
//
// Also importable: `import { scanSql } from './check-migration-safety.mjs'`.
// scanSql takes raw SQL text and strips comments itself.
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
//   - Comment stripping is quote-aware (2026-10): a '/*' or '--' inside a
//     string, an E'' string, a quoted identifier or a dollar-quoted body is
//     text, so it cannot hide the statements after it. Block comments nest, as
//     in Postgres. `UPDATE t * SET` and quoted table names containing spaces
//     reach the WHERE check.
//
// Bias: FALSE POSITIVES are SAFE (they just route to a human). FALSE NEGATIVES
// are the danger, so the rules deliberately over-flag rather than under-flag,
// e.g. a 'DROP TABLE' inside a string literal still flags.
// No dependencies.

import { readFileSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Postgres identifier characters: ASCII letters, digits, _ and $, and any
// non-ASCII character. A dollar-quote tag is the same without $ and never
// starts with a digit, so $1 is a parameter, not a quote.
const IDENT_CHAR = /[\w$]|[^\x00-\x7f]/;
const DOLLAR_QUOTE = /\$(?:(?:[a-z_]|[^\x00-\x7f])(?:\w|[^\x00-\x7f])*)?\$/iy;
// String contents up to the closing quote. A doubled '' needs no case of its
// own in a plain string: 'it''s' scans as two adjacent strings with the same
// boundaries. In an E'' string, \ escapes the next character, and '' must not
// end it either, or the second half would scan as a plain string.
const PLAIN_BODY = /[^']*/y;
const E_BODY = /(?:\\[\s\S]|''|[^\\'])*/y;

// Index of `needle` in `s` at or after `from`, or the end of `s` if absent.
const indexOrEnd = (s, needle, from) => {
  const j = s.indexOf(needle, from);
  return j < 0 ? s.length : j;
};

// Drop SQL comments so a comment mentioning "DROP TABLE" can't false-flag and a
// WHERE in a comment can't count. Comments are found the way Postgres's lexer
// finds them: a '/*' or '--' inside a string, a quoted identifier or a
// dollar-quoted body is text, so it can never swallow the statements after it.
// String and dollar-quoted contents are kept, since they can be code that runs
// (function and DO bodies, EXECUTE strings), and comments inside them are
// stripped too, but only up to their own closing quote. A comment or quote left
// open runs to the end of the text. Assumes standard_conforming_strings = on
// (the Postgres default since 9.1), so a backslash escapes only in E'' strings.
const stripComments = (sql) => {
  let out = '';
  for (let i = 0; i < sql.length; ) {
    const c = sql[i];
    DOLLAR_QUOTE.lastIndex = i;
    const dollar = c === '$' && DOLLAR_QUOTE.exec(sql);
    if (sql.startsWith('--', i)) {
      i = indexOrEnd(sql, '\n', i);
      out += ' ';
    } else if (sql.startsWith('/*', i)) {
      // Block comments nest: /* a /* b */ c */ is one comment.
      let depth = 1;
      for (i += 2; depth > 0 && i < sql.length; ) {
        if (sql.startsWith('*/', i)) { depth--; i += 2; }
        else if (sql.startsWith('/*', i)) { depth++; i += 2; }
        else i++;
      }
      out += ' ';
    } else if (c === "'") {
      // E'' only when the E starts a word: in `like ... escape'\'` the e ends
      // a keyword, and '\' is a plain one-character string.
      const isE = /e/i.test(sql[i - 1] ?? '') && !IDENT_CHAR.test(sql[i - 2] ?? '');
      const re = isE ? E_BODY : PLAIN_BODY;
      re.lastIndex = i + 1;
      const body = re.exec(sql)[0];
      out += `'${stripComments(body)}'`;
      i += body.length + 2;
    } else if (c === '"') {
      // A quoted identifier is a name, not code: kept as is.
      const end = indexOrEnd(sql, '"', i + 1) + 1;
      out += sql.slice(i, end);
      i = end;
    } else if (dollar) {
      // $$...$$ or $tag$...$tag$: the body ends only at the same tag.
      const tag = dollar[0];
      const body = sql.slice(i + tag.length, indexOrEnd(sql, tag, i + tag.length));
      out += tag + stripComments(body) + tag;
      i += body.length + tag.length * 2;
    } else {
      out += c;
      i++;
    }
  }
  return out;
};

// Per-statement rules (statements are split on ';'). Unanchored on purpose.
const STMT_RULES = [
  ['DROP TABLE', /\bdrop\s+table\b/i],
  ['DROP SCHEMA', /\bdrop\s+schema\b/i],
  ['DROP DATABASE', /\bdrop\s+database\b/i],
  ['DROP COLUMN', /\bdrop\s+column\b/i],
  ['DROP CONSTRAINT', /\bdrop\s+constraint\b/i],
  ['RENAME column/constraint/table (breaks live clients)', /\brename\s+(?:column|constraint|to)\b/i],
  ['TRUNCATE', /\btruncate\b/i],
  // COLUMN is optional in Postgres: ALTER [ COLUMN ] name [ SET DATA ] TYPE.
  ['ALTER COLUMN ... TYPE (table rewrite)', /\balter\s+column\b[\s\S]*?\btype\b|\balter\s+(?:"[^"]+"|[a-z0-9_]+)\s+(?:set\s+data\s+)?type\b/i],
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

// Scan one SQL text (raw file contents are fine); returns finding names (deduped).
// Comments are stripped here so library callers get the same result as the CLI.
export const scanSql = (rawSql) => {
  const sql = stripComments(rawSql);
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
    // The table may carry an alias, with or without AS, before SET. A quoted
    // name part may contain spaces, and `UPDATE t * SET` (the explicit
    // inheritance marker) is the same statement as `UPDATE t SET`.
    const updRe = /\bupdate\s+(?:only\s+)?(?:"[^"]*"|[a-z0-9_.])+(?:\s*\*)?(?:\s+(?:as\s+)?[a-z0-9_"]+)?\s+set\b/gi;
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
// scripts/mutation-check.mjs breaks each rule in turn and requires this
// self-test to fail, so every rule needs a case that names it.
// ---------------------------------------------------------------------------
// Rule names exactly as scanSql reports them. Spelled out here rather than
// shared with the rules above, so renaming a rule also fails the self-test.
const DEL = 'unqualified DELETE (no WHERE)';
const UPD = 'unqualified UPDATE (no WHERE)';
const DROP_POLICY = 'DROP POLICY without same-file recreate (RLS gap / permission loss)';
const RENAME = 'RENAME column/constraint/table (breaks live clients)';
const ADD_NOT_NULL = 'ADD COLUMN ... NOT NULL without DEFAULT (fails on existing rows)';
const ALTER_TYPE = 'ALTER COLUMN ... TYPE (table rewrite)';

const SELF_TEST_CASES = [
  // [description, sql, exact rule names expected ([] means clean)]
  ['DELETE without WHERE inside DO block', `do $$ begin if true then delete from public.stars; end if; end $$`, [DEL]],
  ['DELETE with WHERE inside DO block', `do $$ begin delete from stars where family_id = fid; end $$`, []],
  ['DELETE without WHERE inside CTE', `with dead as (delete from stars returning id) select count(*) from dead`, [DEL]],
  ['DELETE without WHERE inside CTE, outer query has a WHERE', `with d as (delete from public.sessions returning id) select * from d where id > 0`, [DEL]],
  ['DELETE with WHERE inside CTE', `with dead as (delete from stars where created_at < now() - interval '30 days') select 1`, []],
  ['UPDATE with function-call value and WHERE', `update families set updated_at = now() where id = '1'`, []],
  ['UPDATE without WHERE', `update families set premium_override = false`, [UPD]],
  ['UPDATE without WHERE inside DO block', `do $$ begin update families set x = 1; end $$`, [UPD]],
  ['UPDATE whose only WHERE is inside a subquery value', `update a set b = (select c from d where e = 1)`, [UPD]],
  ['UPDATE with a subquery value and its own WHERE', `update a set b = (select c from d where e = 1) where id = 2`, []],
  ['UPDATE with a table alias, no WHERE', `update public.accounts a set tier = 1`, [UPD]],
  ['UPDATE with an AS alias, no WHERE', `update public.accounts as a set tier = 1`, [UPD]],
  ['UPDATE with a quoted alias, no WHERE', `update public.accounts "A" set tier = 1`, [UPD]],
  ['UPDATE with a table alias and WHERE', `update public.accounts a set tier = 1 where a.id = 2`, []],
  ['UPDATE t * (explicit inheritance marker), no WHERE', `update public.accounts * set tier = 1`, [UPD]],
  ['UPDATE on a quoted table name containing a space, with an alias, no WHERE', `update public."audit log" a set archived = true`, [UPD]],
  ['DELETE whose only "where" is in a trailing comment', `delete from public.audit_log -- purge everything where possible`, [DEL]],
  ['DELETE whose only WHERE is inside a USING subquery', `delete from a using (select id from b where x = 1) s`, [DEL]],
  ['EXECUTE format dynamic DELETE without WHERE', `do $$ begin execute format('delete from %I', t); end $$`, [DEL]],
  ['naked DROP POLICY (no recreate)', `drop policy "families_select" on public.families`, [DROP_POLICY]],
  ['DROP POLICY + same-file recreate (single-txn, no gap)', `drop policy "families_select" on public.families;\ncreate policy "families_select" on public.families for select using (family_id = get_user_family_id())`, []],
  ['DROP POLICY recreated under a DIFFERENT name', `drop policy "families_select" on public.families;\ncreate policy "families_read" on public.families for select using (true)`, [DROP_POLICY]],
  ['DROP POLICY IF EXISTS + recreate', `drop policy if exists families_select on families;\ncreate policy families_select on families for select using (true)`, []],
  ['DROP POLICY in a form the parser does not recognize', `drop policy families_select`, ['DROP POLICY (unrecognized form)']],
  ['DROP TABLE', `drop table public.legacy_imports`, ['DROP TABLE']],
  ['DROP SCHEMA', `drop schema reporting cascade`, ['DROP SCHEMA']],
  ['DROP DATABASE', `drop database analytics`, ['DROP DATABASE']],
  ['DROP COLUMN', `alter table families drop column legacy_code`, ['DROP COLUMN']],
  ['DROP CONSTRAINT', `alter table families drop constraint families_pkey`, ['DROP CONSTRAINT']],
  ['RENAME COLUMN', `alter table families rename column name to family_name`, [RENAME]],
  ['RENAME TO (table rename)', `alter table families rename to households`, [RENAME]],
  ['ADD COLUMN NOT NULL without DEFAULT', `alter table families add column tier text not null`, [ADD_NOT_NULL]],
  ['ADD COLUMN NOT NULL with DEFAULT', `alter table families add column tier text not null default 'free'`, []],
  ['ADD COLUMN nullable', `alter table families add column note text`, []],
  ['DROP TABLE mentioned only in a line comment', `-- we deliberately do NOT drop table stars\ncreate table foo (id uuid primary key)`, []],
  ['DROP TABLE mentioned only in a block comment', `/* drop table public.accounts was considered and rejected */\ncreate table foo (id uuid primary key)`, []],
  // A comment marker inside quotes is text, not a comment, and must not hide
  // the statements after it.
  ["DELETE after a string containing /* and a doubled '' quote", `insert into public.notes (body) values ('it''s /* not a comment'); delete from public.stars; /* tidy up */`, [DEL]],
  ['DELETE after a string containing --', `insert into public.notes (body) values ('--'); delete from public.stars`, [DEL]],
  ['DELETE after an E-string with a backslash-escaped quote and /*', `insert into public.notes (body) values (E'it\\'s /* not a comment'); delete from public.stars; /* tidy up */`, [DEL]],
  ["DELETE after an E-string using both '' and backslash quote escapes", `insert into public.notes (body) values (E'O''Brien\\'s /* draft'); delete from public.stars; /* tidy up */`, [DEL]],
  ["a keyword ending in e before a quote (escape'...') does not start an E-string", `select 1 where 'a' like 'a' escape'\\'; insert into public.notes (body) values ('-- cleared'); delete from public.stars`, [DEL]],
  ['DELETE after a quoted identifier containing /*', `insert into public."odd /* name" (id) values (1); delete from public.stars; /* tidy up */`, [DEL]],
  ['DROP TABLE after a dollar-quoted function body containing /*', `create function public.strip_c_comment(src text) returns text language plpython3u as $$\n# keep only the text before the first /*\nreturn src.split('/*')[0]\n$$;\ndrop table public.legacy_imports;\n/* end of migration */`, ['DROP TABLE']],
  ['DROP TABLE after a $tag$ body ending in a -- comment', `create function public.noop() returns void language sql as $fn$ select 1 -- placeholder $fn$; drop table public.legacy_imports`, ['DROP TABLE']],
  // Quoted contents can be code that runs, so their own comments still go.
  ['commented-out WHERE inside a DO body does not count', `do $$ begin delete from public.audit_log /* where id < 100 */; end $$`, [DEL]],
  ['commented-out WHERE inside a single-quoted function body does not count', `create function public.purge() returns void language sql as 'delete from public.audit_log /* where id < 100 */'`, [DEL]],
  // Block comments nest in Postgres, and a /* inside a line comment opens nothing.
  ['DELETE inside a nested block comment', `/* disabled for now:\n   /* original: */ delete from public.audit_log;\n*/\nselect 1`, []],
  ['WHERE inside a nested block comment does not count', `delete from public.audit_log /* outer /* inner */ where id = 1 */`, [DEL]],
  ['a /* inside a line comment opens no block comment', `-- a /* in a line comment opens nothing\ndelete from public.stars;\n/* end of migration */`, [DEL]],
  ['plain additive migration', `create table foo (id uuid primary key);\ncreate index foo_idx on foo (id);\ncreate policy p on foo for select using (true)`, []],
  ['non-concurrent index on pre-existing table', `create index stars_idx on public.stars (family_id)`, ['non-CONCURRENT CREATE INDEX on existing table "stars" (locks prod)']],
  ['CONCURRENT index on pre-existing table', `create index concurrently i on public.existing (c)`, []],
  ['SET NOT NULL', `alter table families alter column name set not null`, ['SET NOT NULL (can fail/lock on existing rows)']],
  ['ALTER COLUMN TYPE', `alter table families alter column id type bigint`, [ALTER_TYPE]],
  ['ALTER ... TYPE without the optional COLUMN keyword', `alter table public.accounts alter amount_cents type bigint`, [ALTER_TYPE]],
  ['ALTER ... SET DATA TYPE without COLUMN', `alter table public.accounts alter amount_cents set data type bigint`, [ALTER_TYPE]],
  ['ALTER ... TYPE on a quoted column without COLUMN', `alter table public.accounts alter "Amount" type bigint`, [ALTER_TYPE]],
  ['TRUNCATE inside DO block', `do $$ begin truncate public.stars; end $$`, ['TRUNCATE']],
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
  const show = (names) => (names.length ? names.join('; ') : 'clean');
  for (const [desc, sql, expectedNames] of SELF_TEST_CASES) {
    // Raw text on purpose: this is the documented library call.
    const found = [...scanSql(sql)].sort();
    const expected = [...expectedNames].sort();
    if (found.join('\n') !== expected.join('\n')) {
      failed++;
      console.error(`  FAIL: ${desc}: expected ${show(expected)}, got ${show(found)}`);
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

  const json = argv.includes('--json');
  const files = argv.filter((f) => f.endsWith('.sql'));
  if (files.length === 0) {
    console.log(json ? '{}' : 'check-migration-safety: no .sql files to check, clean.');
    process.exit(0);
  }

  const findings = new Set();
  const byFile = {};
  for (const file of files) {
    let raw;
    try {
      raw = readFileSync(file, 'utf8');
    } catch (e) {
      console.error(`check-migration-safety: cannot read ${file}: ${e.message}`);
      process.exit(1);
    }
    const names = scanSql(raw);
    byFile[file] = [...names].sort();
    for (const name of names) findings.add(`${file}: ${name}`);
  }

  // Sorted, stable output so CI can diff it against a checked-in list.
  if (json) {
    console.log(JSON.stringify(byFile, null, 2));
    process.exitCode = findings.size ? 1 : 0;
    return;
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
