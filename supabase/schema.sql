-- Performance Management V4.1 (fresh install)
create extension if not exists "pgcrypto";

-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.profiles') is null then
    create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique,
  name text not null default '',
  department text,
  position text,
  role text not null default 'manager' check (role in ('manager','admin')),
  account_status text not null default 'pending' check (account_status in ('pending','active','inactive')),
  employment_status text not null default '재직' check (employment_status in ('재직','휴직','퇴직')),
  joined_date date,
  manager_id uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
    alter table public.profiles enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.profiles from public, anon, authenticated, service_role;
    grant select, update on table public.profiles to authenticated;
  end if;
end;
$table_setup$;

-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.employees') is null then
    create table public.employees (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  department text,
  position text,
  employment_status text not null default '재직' check (employment_status in ('재직','휴직','퇴직')),
  joined_date date,
  manager_id uuid not null references public.profiles(id) on delete restrict,
  memo text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
    alter table public.employees enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.employees from public, anon, authenticated, service_role;
    grant select, insert, update, delete on table public.employees to authenticated;
  end if;
end;
$table_setup$;

-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.goals') is null then
    create table public.goals (
  id uuid primary key default gen_random_uuid(), title text not null, description text,
  owner_id uuid not null references public.employees(id) on delete cascade,
  created_by uuid references public.profiles(id) on delete set null,
  period text not null default '연간', category text, target_value text, current_value text,
  weight int not null default 0 check (weight between 0 and 100), due_date date,
  progress int not null default 0 check (progress between 0 and 100),
  status text not null default '진행중' check (status in ('미진행','진행중','완료','보류')),
  evidence text, manager_feedback text, last_progress_at timestamptz not null default now(),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
    alter table public.goals enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.goals from public, anon, authenticated, service_role;
    grant select, insert, update, delete on table public.goals to authenticated;
  end if;
end;
$table_setup$;

-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.interviews') is null then
    create table public.interviews (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  manager_id uuid not null references public.profiles(id) on delete cascade,
  interview_date date not null, interview_type text not null default '정기면담', mood text,
  summary text not null, strengths text, concerns text, action_items text,
  employee_commitment text, manager_support text, next_date date,
  visibility text not null default 'participants' check (visibility in ('participants','manager_only')),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
    alter table public.interviews enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.interviews from public, anon, authenticated, service_role;
    grant select, insert, update, delete on table public.interviews to authenticated;
  end if;
end;
$table_setup$;

-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.audit_logs') is null then
    create table public.audit_logs (
  id bigint generated by default as identity primary key,
  actor_id uuid references public.profiles(id) on delete set null,
  action text not null, target_type text not null, target_id text,
  details jsonb not null default '{}'::jsonb, created_at timestamptz not null default now()
);
    alter table public.audit_logs enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.audit_logs from public, anon, authenticated, service_role;
    grant select, insert on table public.audit_logs to authenticated;
  end if;
end;
$table_setup$;

create or replace function public.set_updated_at() returns trigger language plpgsql as $$ begin new.updated_at=now(); return new; end; $$;
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into public.profiles(id,email,name,role,account_status) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'name',''),'manager','pending') on conflict(id) do nothing; return new; end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

do $$ begin
  drop trigger if exists profiles_updated_at on public.profiles;
  create trigger profiles_updated_at before update on public.profiles for each row execute procedure public.set_updated_at();
  drop trigger if exists employees_updated_at on public.employees;
  create trigger employees_updated_at before update on public.employees for each row execute procedure public.set_updated_at();
  drop trigger if exists goals_updated_at on public.goals;
  create trigger goals_updated_at before update on public.goals for each row execute procedure public.set_updated_at();
  drop trigger if exists interviews_updated_at on public.interviews;
  create trigger interviews_updated_at before update on public.interviews for each row execute procedure public.set_updated_at();
end $$;

create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin' and account_status='active'); $$;
create or replace function public.is_manager() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.profiles where id=auth.uid() and role in ('manager','admin') and account_status='active'); $$;
create or replace function public.is_active() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.profiles where id=auth.uid() and account_status='active'); $$;
create or replace function public.manages_employee(target uuid) returns boolean language sql stable security definer set search_path=public as $$ select public.is_admin() or exists(select 1 from public.employees where id=target and manager_id=auth.uid()); $$;

alter table public.profiles enable row level security;
alter table public.employees enable row level security;
alter table public.goals enable row level security;
alter table public.interviews enable row level security;
alter table public.audit_logs enable row level security;

create policy "profiles self or admin read" on public.profiles for select to authenticated using (id=auth.uid() or public.is_admin());
create policy "profiles admin update" on public.profiles for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "employees scoped read" on public.employees for select to authenticated using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped insert" on public.employees for insert to authenticated with check (public.is_active() and public.is_manager() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped update" on public.employees for update to authenticated using (public.is_active() and (public.is_admin() or manager_id=auth.uid())) with check (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped delete" on public.employees for delete to authenticated using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "goals read scoped" on public.goals for select to authenticated using (public.is_active() and public.manages_employee(owner_id));
create policy "goals insert scoped" on public.goals for insert to authenticated with check (public.is_active() and public.manages_employee(owner_id) and created_by=auth.uid());
create policy "goals update scoped" on public.goals for update to authenticated using (public.is_active() and public.manages_employee(owner_id)) with check (public.is_active() and public.manages_employee(owner_id));
create policy "goals delete scoped" on public.goals for delete to authenticated using (public.is_active() and public.manages_employee(owner_id));
create policy "interviews read scoped" on public.interviews for select to authenticated using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "interviews insert manager" on public.interviews for insert to authenticated with check (public.is_active() and public.is_manager() and public.manages_employee(employee_id) and (manager_id=auth.uid() or public.is_admin()));
create policy "interviews update manager" on public.interviews for update to authenticated using (public.is_active() and (manager_id=auth.uid() or public.is_admin())) with check (public.is_active() and public.manages_employee(employee_id) and (manager_id=auth.uid() or public.is_admin()));
create policy "interviews delete manager" on public.interviews for delete to authenticated using (public.is_active() and (manager_id=auth.uid() or public.is_admin()));
create policy "audit admin read" on public.audit_logs for select to authenticated using (public.is_admin());
create policy "audit authenticated insert" on public.audit_logs for insert to authenticated with check (actor_id=auth.uid());

create index if not exists employees_manager_idx on public.employees(manager_id);
create index if not exists goals_owner_idx on public.goals(owner_id);
create index if not exists goals_due_idx on public.goals(due_date);
create index if not exists interviews_employee_idx on public.interviews(employee_id);
create index if not exists interviews_date_idx on public.interviews(interview_date);


-- Required by the existing authenticated RLS policies (no anon grant).
grant execute on function public.is_admin() to authenticated;
grant execute on function public.is_manager() to authenticated;
grant execute on function public.is_active() to authenticated;
grant execute on function public.manages_employee(uuid) to authenticated;
