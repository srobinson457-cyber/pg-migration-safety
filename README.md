# pg-migration-safety

A CI gate that catches destructive SQL migrations **your migration tests cannot see**.

Zero dependencies. One file. 42 self-tests, and a mutation check that removes each rule in turn
and requires a test to fail.

Extracted in September 2026 from private code I run in production, built agent-first with Claude Code; the history stays private because it contains private data.

```bash
node src/check-migration-safety.mjs migrations/*.sql
```

---

## The hole this closes

Most projects test migrations by replaying them against an empty database. That is a good
test, and it catches syntax errors, ordering problems and broken references.

It is also **structurally incapable of catching the class of bug that actually costs you
data**, because there is no data in the database it runs against.

Consider a migration containing:

```sql
delete from public.audit_log;
alter table public.accounts alter column amount_cents type bigint;
```

Against an empty CI database, both statements succeed instantly and the job goes green. The
first deletes nothing because there is nothing to delete. The second rewrites nothing because
there are no rows.

Against production, the first destroys the audit log and the second takes an `ACCESS EXCLUSIVE`
lock while it rewrites every row in the table.

**Your test suite reported success on the exact statement that took the site down.** That is not
a gap in coverage you can close by writing more tests of the same kind. It needs a different
kind of check, applied to the SQL text itself.

---

## What it flags

| Pattern | Why |
|---|---|
| `DELETE` / `UPDATE` with no `WHERE` | Destroys or rewrites the whole table |
| `DROP TABLE` / `DROP COLUMN` | Irreversible data loss |
| `TRUNCATE` | Same, and it does not fire row triggers |
| `ALTER [COLUMN] ... [SET DATA] TYPE` | Full table rewrite under an exclusive lock |
| `RENAME` column / constraint / table | Breaks deployed clients still using the old name |
| `ADD COLUMN ... NOT NULL` without `DEFAULT` | Fails outright on a table with existing rows |
| Non-`CONCURRENT` `CREATE INDEX` on a pre-existing table | Blocks writes for the duration of the build |
| `DROP CONSTRAINT` | Silently removes an invariant the application still assumes |
| `DROP POLICY` not recreated in the same file | Leaves a window with no row-level security |

Purely additive migrations pass clean: `CREATE TABLE`, nullable `ADD COLUMN`, `ADD COLUMN` with
a `DEFAULT`, new functions, policies and triggers, and `CREATE INDEX` on a table created in the
same migration, which has no rows to lock.

---

## What makes the detection non-trivial

The naive version of this tool is a handful of anchored regexes, and it misses most real
destructive migrations. Three things it has to get right:

**Rules are unanchored.** A `DELETE` is dangerous wherever it appears, and in real migrations it
usually does not appear at the start of a line:

```sql
-- all three are caught
do $$ begin delete from public.stars; end $$;
with doomed as (delete from public.sessions returning id)
  insert into public.archive (id) select id from doomed;
execute format('delete from %I', tbl);
```

**The `WHERE` check is paren-depth aware.** Deciding whether a `DELETE` or `UPDATE` has a
`WHERE` means knowing where the statement ends. Stopping at the first `)` gets this wrong in
both directions:

```sql
-- must NOT flag: the WHERE is real, the ) belongs to now()
update public.accounts set updated_at = now() where id = $1;

-- must flag: the ) closes the CTE wrapper, and there is no WHERE
with d as (delete from public.sessions) select 1;

-- must flag: the only WHERE belongs to the subquery, so every row is updated
update public.accounts set tier = (select tier from public.plans where id = 1);
```

The scan walks balanced pairs and stops only at a `)` that closes an *enclosing* group. Within
that span, only a `WHERE` at the top level counts; a `WHERE` nested inside a subquery is the
subquery's, not the statement's.

**Comments are stripped first**, inside `scanSql` itself, so a comment mentioning `DROP TABLE`
cannot false-flag and a `where` in a comment cannot satisfy the `WHERE` check, while a
`DROP TABLE` inside a string literal still flags.

---

## Bias: false positives are safe, false negatives are not

A false positive costs a reviewer thirty seconds. A false negative costs you the table.

So the rules deliberately over-flag. A `DROP TABLE` inside a string literal flags. A
`CREATE INDEX` flags unless the tool can see the table was created in the same migration. When
a rule is arguable, it fires.

A flagged migration is not blocked, it is **routed to a human**. Merging a deliberate,
reviewed destructive migration is a normal thing to do. Doing it by accident is not.

---

## Use it

**As a CI check.** Exits non-zero on any finding.

```yaml
# .github/workflows/migration-safety.yml
name: migration safety
on: pull_request

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-node@v4
        with:
          node-version: 20

      # Guard the guard: if the tool itself regresses, fail before trusting it.
      - run: node src/check-migration-safety.mjs --self-test

      - name: Scan migrations changed in this PR
        run: |
          CHANGED=$(git diff --name-only --diff-filter=d \
            origin/${{ github.base_ref }}...HEAD -- '*.sql')
          [ -z "$CHANGED" ] && echo "no SQL changed" && exit 0
          node src/check-migration-safety.mjs $CHANGED
```

Running `--self-test` before the gate is not ceremony. A gate whose own logic has silently
regressed is worse than no gate, because you will trust it.

Each self-test case asserts the exact rule names it expects, and `scripts/mutation-check.mjs`
deletes or breaks each rule in turn and requires a self-test case to fail. A rule that could
be removed without a failing test is a rule nobody is guarding.

Pass `--json` to get `{"<file>": [sorted rule names]}` on stdout instead of text, with the same
exit codes. This repo's CI diffs that output for the destructive example against
`examples/20260101000001_destructive.expected.json`.

**As a library.**

```js
import { scanSql } from './src/check-migration-safety.mjs';

const findings = scanSql(sqlText);   // raw file contents; comments are stripped for you
if (findings.length) { /* ... */ }   // => array of rule names, deduped
```

Importing has no side effects. The CLI runs only when the file is the entry point, so it never
calls `process.exit` inside your process.

**Try it.**

```bash
npm run test          # 42 self-test cases
npm run test:mutation # breaks each rule in turn; every break must fail the self-test
npm run demo:safe     # exits 0
npm run demo:unsafe   # exits 1, lists six findings
```

---

## Scope, honestly

This is a text scanner, not a Postgres parser. It does not connect to a database, it does not
know your schema, and it cannot tell you whether a given table actually has rows in production.

It is a tripwire on the statements that are dangerous regardless of schema. That is a narrow
job, and it is a job nothing else in a normal migration pipeline is doing.

Written for Postgres, and the rules assume Postgres syntax. Most of them transfer to any SQL
dialect; the `DROP POLICY` and `CREATE INDEX CONCURRENTLY` rules do not.

---

## License

MIT. See [LICENSE](LICENSE).
