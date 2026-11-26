-- ============================================================================
-- GSO Custodian Inventory System — Supabase Postgres Schema & Security (RLS)
-- ============================================================================
-- Run this script in your Supabase Dashboard -> SQL Editor.
-- Also in Supabase Dashboard -> Authentication -> Providers -> Email:
--   Disable "Allow new users to sign up" (or manage users strictly via Admin).
-- ============================================================================

create extension if not exists pgcrypto;

-- Private schema for internal helper functions (never exposed via Data API)
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated;

-- ============================================================================
-- 1. PROFILES TABLE
-- ============================================================================
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  full_name text not null check (char_length(trim(full_name)) between 1 and 120),
  role text not null default 'custodian' check (role in ('admin', 'custodian')),
  is_active boolean not null default true,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_profiles_active on public.profiles(is_active);

-- ============================================================================
-- 2. SECURITY HELPER FUNCTIONS
-- ============================================================================
-- Authorization uses app_metadata (server-controlled), NEVER user_metadata.
create or replace function private.is_admin()
returns boolean
language sql
stable
security invoker
set search_path = ''
as $$
  select (
    (select auth.uid()) is not null
    and coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
    and exists (
      select 1
      from public.profiles p
      where p.id = (select auth.uid())
        and p.role = 'admin'
        and p.is_active = true
    )
  );
$$;

create or replace function private.is_active_staff()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (
    (select auth.uid()) is not null
    and exists (
      select 1
      from public.profiles p
      where p.id = (select auth.uid())
        and p.is_active = true
    )
  );
$$;

revoke all on function private.is_admin() from public;
grant execute on function private.is_admin() to authenticated;

revoke all on function private.is_active_staff() from public;
grant execute on function private.is_active_staff() to authenticated;

grant execute on all functions in schema private to authenticated;

-- Updated_at trigger helper
create or replace function private.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

-- Sync new auth.users rows into public.profiles automatically
create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  assigned_role text;
  display_name text;
begin
  assigned_role := coalesce(new.raw_app_meta_data ->> 'role', 'custodian');
  if assigned_role not in ('admin', 'custodian') then
    assigned_role := 'custodian';
  end if;

  display_name := coalesce(
    nullif(trim(new.raw_user_meta_data ->> 'full_name'), ''),
    split_part(coalesce(new.email, 'custodian'), '@', 1)
  );

  insert into public.profiles (id, email, full_name, role, is_active)
  values (new.id, coalesce(new.email, ''), left(display_name, 120), assigned_role, true)
  on conflict (id) do update
    set email = excluded.email,
        full_name = excluded.full_name,
        role = excluded.role,
        updated_at = now();

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function private.handle_new_user();

drop trigger if exists trg_profiles_updated_at on public.profiles;
create trigger trg_profiles_updated_at
  before update on public.profiles
  for each row execute function private.set_updated_at();

-- ============================================================================
-- 3. DOCUMENT NUMBER SEQUENCES (ATOMIC ICS & PAR NUMBERING)
-- ============================================================================
create table if not exists private.doc_sequences (
  doc_type text not null check (doc_type in ('ics', 'par')),
  year_suffix text not null check (year_suffix ~ '^\d{2}$'),
  next_seq integer not null default 0 check (next_seq >= 0 and next_seq <= 1000000),
  primary key (doc_type, year_suffix)
);

create or replace function private.allocate_doc_no(p_doc_type text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_year text := to_char(now() at time zone 'Asia/Manila', 'YY');
  v_seq integer;
begin
  if (select auth.uid()) is null or not private.is_active_staff() then
    raise exception 'Unauthorized';
  end if;

  insert into private.doc_sequences (doc_type, year_suffix, next_seq)
  values (p_doc_type, v_year, 1)
  on conflict (doc_type, year_suffix)
  do update set next_seq = private.doc_sequences.next_seq + 1
  returning next_seq - 1 into v_seq;

  if v_seq > 999999 then
    raise exception 'Document sequence limit reached for year %', v_year;
  end if;

  return lpad(v_seq::text, 6, '0') || '-' || v_year;
end;
$$;

-- ============================================================================
-- 4. ICS RECORDS TABLE
-- ============================================================================
create table if not exists public.ics_records (
  id uuid primary key default gen_random_uuid(),
  ics_no text not null unique,
  qty integer not null check (qty >= 1 and qty <= 1000000),
  unit text not null check (char_length(trim(unit)) between 1 and 50),
  description text not null check (char_length(trim(description)) between 1 and 500),
  item_no text not null check (char_length(trim(item_no)) between 1 and 100),
  estimated_useful_life text not null check (char_length(trim(estimated_useful_life)) between 1 and 100),
  price numeric(14, 2) not null check (price >= 0),
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_ics_records_created_at on public.ics_records(created_at desc);
create index if not exists idx_ics_records_created_by on public.ics_records(created_by);

create or replace function private.before_insert_ics()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.ics_no is null or trim(new.ics_no) = '' then
    new.ics_no := private.allocate_doc_no('ics');
  end if;
  new.created_by := (select auth.uid());
  new.updated_by := (select auth.uid());
  return new;
end;
$$;

create or replace function private.before_update_ics()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.ics_no := old.ics_no;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
  new.updated_by := (select auth.uid());
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists trg_ics_before_insert on public.ics_records;
create trigger trg_ics_before_insert
  before insert on public.ics_records
  for each row execute function private.before_insert_ics();

drop trigger if exists trg_ics_before_update on public.ics_records;
create trigger trg_ics_before_update
  before update on public.ics_records
  for each row execute function private.before_update_ics();

-- ============================================================================
-- 5. PAR RECORDS TABLE
-- ============================================================================
create table if not exists public.par_records (
  id uuid primary key default gen_random_uuid(),
  par_no text not null unique,
  qty integer not null check (qty >= 1 and qty <= 1000000),
  unit text not null check (char_length(trim(unit)) between 1 and 50),
  description text not null check (char_length(trim(description)) between 1 and 500),
  property_number text not null check (char_length(trim(property_number)) between 1 and 100),
  date_acquired date not null,
  amount numeric(14, 2) not null check (amount >= 0),
  created_by uuid not null default auth.uid() references auth.users(id) on delete restrict,
  updated_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_par_records_created_at on public.par_records(created_at desc);
create index if not exists idx_par_records_created_by on public.par_records(created_by);

create or replace function private.before_insert_par()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.par_no is null or trim(new.par_no) = '' then
    new.par_no := private.allocate_doc_no('par');
  end if;
  new.created_by := (select auth.uid());
  new.updated_by := (select auth.uid());
  return new;
end;
$$;

create or replace function private.before_update_par()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  new.par_no := old.par_no;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
  new.updated_by := (select auth.uid());
  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists trg_par_before_insert on public.par_records;
create trigger trg_par_before_insert
  before insert on public.par_records
  for each row execute function private.before_insert_par();

drop trigger if exists trg_par_before_update on public.par_records;
create trigger trg_par_before_update
  before update on public.par_records
  for each row execute function private.before_update_par();

-- ============================================================================
-- 6. IMMUTABLE AUDIT LOGS TABLE
-- ============================================================================
create table if not exists public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null check (action in ('INSERT', 'UPDATE', 'DELETE', 'ADMIN_CREATE_USER', 'ADMIN_UPDATE_USER')),
  table_name text not null,
  record_id text,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_audit_logs_created_at on public.audit_logs(created_at desc);
create index if not exists idx_audit_logs_actor_id on public.audit_logs(actor_id);

create or replace function private.write_audit_log()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_record_id text;
  v_details jsonb;
begin
  if (tg_op = 'DELETE') then
    v_record_id := old.id::text;
    v_details := to_jsonb(old);
  elsif (tg_op = 'UPDATE') then
    v_record_id := new.id::text;
    v_details := jsonb_build_object('before', to_jsonb(old), 'after', to_jsonb(new));
  else
    v_record_id := new.id::text;
    v_details := to_jsonb(new);
  end if;

  insert into public.audit_logs (actor_id, action, table_name, record_id, details)
  values ((select auth.uid()), tg_op, tg_table_name, v_record_id, v_details);

  return coalesce(new, old);
end;
$$;

drop trigger if exists trg_ics_audit on public.ics_records;
create trigger trg_ics_audit
  after insert or update or delete on public.ics_records
  for each row execute function private.write_audit_log();

drop trigger if exists trg_par_audit on public.par_records;
create trigger trg_par_audit
  after insert or update or delete on public.par_records
  for each row execute function private.write_audit_log();

-- ============================================================================
-- 7. ROW LEVEL SECURITY (MANDATORY ON EVERY TABLE)
-- ============================================================================
alter table public.profiles enable row level security;
alter table public.ics_records enable row level security;
alter table public.par_records enable row level security;
alter table public.audit_logs enable row level security;

-- Revoke anonymous access explicitly (defense in depth)
revoke all on public.profiles from anon;
revoke all on public.ics_records from anon;
revoke all on public.par_records from anon;
revoke all on public.audit_logs from anon;

grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.ics_records to authenticated;
grant select, insert, update, delete on public.par_records to authenticated;
grant select on public.audit_logs to authenticated;

grant usage on schema public to service_role;
grant all on public.profiles to service_role;
grant all on public.ics_records to service_role;
grant all on public.par_records to service_role;
grant all on public.audit_logs to service_role;
grant usage, select on all sequences in schema public to service_role;
grant usage on schema private to service_role;
grant execute on all functions in schema private to service_role;

-- PROFILES POLICIES
drop policy if exists "Users see own profile or admin sees all" on public.profiles;
create policy "Users see own profile or admin sees all"
  on public.profiles for select
  to authenticated
  using ((select auth.uid()) = id or private.is_admin());

drop policy if exists "Users update own name only" on public.profiles;
create policy "Users update own name only"
  on public.profiles for update
  to authenticated
  using ((select auth.uid()) = id and is_active = true)
  with check (
    (select auth.uid()) = id
    and role = (select p.role from public.profiles p where p.id = (select auth.uid()))
    and is_active = (select p.is_active from public.profiles p where p.id = (select auth.uid()))
    and email = (select p.email from public.profiles p where p.id = (select auth.uid()))
  );

-- ICS POLICIES
drop policy if exists "Active staff read ICS records" on public.ics_records;
create policy "Active staff read ICS records"
  on public.ics_records for select
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff());

drop policy if exists "Active staff insert ICS records" on public.ics_records;
create policy "Active staff insert ICS records"
  on public.ics_records for insert
  to authenticated
  with check (
    (select auth.uid()) = created_by
    and private.is_active_staff()
  );

drop policy if exists "Active staff update ICS records" on public.ics_records;
create policy "Active staff update ICS records"
  on public.ics_records for update
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff())
  with check (
    (select auth.uid()) = updated_by
    and private.is_active_staff()
  );

drop policy if exists "Active staff delete ICS records" on public.ics_records;
create policy "Active staff delete ICS records"
  on public.ics_records for delete
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff());

-- PAR POLICIES
drop policy if exists "Active staff read PAR records" on public.par_records;
create policy "Active staff read PAR records"
  on public.par_records for select
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff());

drop policy if exists "Active staff insert PAR records" on public.par_records;
create policy "Active staff insert PAR records"
  on public.par_records for insert
  to authenticated
  with check (
    (select auth.uid()) = created_by
    and private.is_active_staff()
  );

drop policy if exists "Active staff update PAR records" on public.par_records;
create policy "Active staff update PAR records"
  on public.par_records for update
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff())
  with check (
    (select auth.uid()) = updated_by
    and private.is_active_staff()
  );

drop policy if exists "Active staff delete PAR records" on public.par_records;
create policy "Active staff delete PAR records"
  on public.par_records for delete
  to authenticated
  using ((select auth.uid()) is not null and private.is_active_staff());

-- AUDIT LOG POLICIES (Admin read-only; immutable from client)
drop policy if exists "Admins read audit logs" on public.audit_logs;
create policy "Admins read audit logs"
  on public.audit_logs for select
  to authenticated
  using ((select auth.uid()) is not null and private.is_admin());

-- ============================================================================
-- 8. BOOTSTRAP FIRST ADMIN (RUN AFTER CREATING FIRST USER IN AUTH DASHBOARD)
-- ============================================================================
-- Example:
-- update auth.users
-- set raw_app_meta_data = coalesce(raw_app_meta_data, '{}'::jsonb) || '{"role":"admin"}'::jsonb
-- where email = 'admin@gso.gov';
--
-- update public.profiles
-- set role = 'admin', is_active = true
-- where email = 'admin@gso.gov';
