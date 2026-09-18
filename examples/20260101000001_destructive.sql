-- DANGEROUS: every statement here passes a from-empty CI replay green,
-- and every one of them destroys or rewrites real production data.

-- No rows exist in CI, so nothing is lost there. In production this is the table.
delete from public.audit_log;

-- Rewrites every row and takes an ACCESS EXCLUSIVE lock for the duration.
alter table public.accounts alter column amount_cents type bigint;

-- Hidden inside a CTE. An anchored regex misses this entirely.
with doomed as (delete from public.sessions returning id)
insert into public.session_archive (id) select id from doomed;

-- Renaming breaks any deployed client still referring to the old name.
alter table public.invoices rename column amount_cents to amount;

-- On a table with existing rows this fails, or blocks writes while it validates.
alter table public.accounts add column tier text not null;

-- Non-concurrent index on a pre-existing table: blocks writes for the build.
create index accounts_email_idx on public.accounts (billing_email);

drop table public.legacy_imports;
