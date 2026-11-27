-- ============================================================================
-- Migration 002: Automatically renumber ICS No. and PAR No. on record deletion
-- ============================================================================
-- Example: If 000003-26, 000004-26, 000005-26 exist and 000004-26 is deleted,
-- 000005-26 is automatically renumbered to 000004-26 and the next created
-- record receives 000005-26.
-- ============================================================================

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

  if p_doc_type not in ('ics', 'par') then
    raise exception 'Invalid document type';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_doc_type || '_' || v_year));

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

create or replace function private.before_update_ics()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if coalesce(current_setting('gso.allow_doc_renumber', true), 'false') <> 'true' then
    new.ics_no := old.ics_no;
    new.updated_by := (select auth.uid());
    new.updated_at := now();
  end if;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
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
  if coalesce(current_setting('gso.allow_doc_renumber', true), 'false') <> 'true' then
    new.par_no := old.par_no;
    new.updated_by := (select auth.uid());
    new.updated_at := now();
  end if;
  new.created_by := old.created_by;
  new.created_at := old.created_at;
  return new;
end;
$$;

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
  if tg_op = 'UPDATE' and coalesce(current_setting('gso.allow_doc_renumber', true), 'false') = 'true' then
    return new;
  end if;

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

create or replace function private.renumber_doc_year(p_doc_type text, p_year text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_idx integer := 0;
  v_expected text;
  v_row record;
begin
  if p_doc_type not in ('ics', 'par') or p_year !~ '^\d{2}$' then
    return;
  end if;

  perform pg_advisory_xact_lock(hashtext(p_doc_type || '_' || p_year));
  perform set_config('gso.allow_doc_renumber', 'true', true);

  if p_doc_type = 'ics' then
    for v_row in
      select id, ics_no
      from public.ics_records
      where ics_no ~ ('^\d+-' || p_year || '$')
      order by (substring(ics_no from '^(\d+)-')::integer) asc, created_at asc, id asc
    loop
      v_expected := lpad(v_idx::text, 6, '0') || '-' || p_year;
      if v_row.ics_no <> v_expected then
        update public.ics_records
        set ics_no = v_expected
        where id = v_row.id;
      end if;
      v_idx := v_idx + 1;
    end loop;
  else
    for v_row in
      select id, par_no
      from public.par_records
      where par_no ~ ('^\d+-' || p_year || '$')
      order by (substring(par_no from '^(\d+)-')::integer) asc, created_at asc, id asc
    loop
      v_expected := lpad(v_idx::text, 6, '0') || '-' || p_year;
      if v_row.par_no <> v_expected then
        update public.par_records
        set par_no = v_expected
        where id = v_row.id;
      end if;
      v_idx := v_idx + 1;
    end loop;
  end if;

  insert into private.doc_sequences (doc_type, year_suffix, next_seq)
  values (p_doc_type, p_year, v_idx)
  on conflict (doc_type, year_suffix)
  do update set next_seq = excluded.next_seq;

  perform set_config('gso.allow_doc_renumber', 'false', true);
end;
$$;

create or replace function private.after_delete_doc()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_doc_no text;
  v_year text;
  v_doc_type text;
begin
  if tg_table_name = 'ics_records' then
    v_doc_type := 'ics';
    v_doc_no := old.ics_no;
  elsif tg_table_name = 'par_records' then
    v_doc_type := 'par';
    v_doc_no := old.par_no;
  else
    return old;
  end if;

  v_year := substring(coalesce(v_doc_no, '') from '^\d+-(\d{2})$');
  if v_year is not null then
    perform private.renumber_doc_year(v_doc_type, v_year);
  end if;

  return old;
end;
$$;

drop trigger if exists trg_ics_after_delete on public.ics_records;
create trigger trg_ics_after_delete
  after delete on public.ics_records
  for each row execute function private.after_delete_doc();

drop trigger if exists trg_par_after_delete on public.par_records;
create trigger trg_par_after_delete
  after delete on public.par_records
  for each row execute function private.after_delete_doc();

revoke all on function private.renumber_doc_year(text, text) from public;
revoke all on function private.after_delete_doc() from public;
grant execute on function private.after_delete_doc() to authenticated, service_role;
