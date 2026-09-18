-- SAFE: purely additive. A from-empty CI replay and a production apply agree.
create table if not exists public.invoices (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid not null references public.accounts (id),
  amount_cents integer not null check (amount_cents >= 0),
  created_at  timestamptz not null default now()
);

-- Nullable, so existing rows need no backfill and no table rewrite.
alter table public.accounts add column billing_email text;

-- Index created on a table defined in THIS migration, so there are no rows to lock.
create index invoices_account_id_idx on public.invoices (account_id);

create policy invoices_select on public.invoices
  for select using (account_id = auth_account_id());
