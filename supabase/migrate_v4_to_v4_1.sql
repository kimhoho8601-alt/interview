-- V4 -> V4.1 migration
-- 관리자/팀장만 로그인하고, 일반 팀원은 employees 테이블에서 관리합니다.

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

drop trigger if exists employees_updated_at on public.employees;
create trigger employees_updated_at before update on public.employees for each row execute procedure public.set_updated_at();

-- 신규 가입자는 팀장 승인대기 계정으로 생성
alter table public.profiles alter column role set default 'manager';
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin
  insert into public.profiles (id,email,name,role,account_status)
  values (new.id,new.email,coalesce(new.raw_user_meta_data->>'name',''),'manager','pending')
  on conflict (id) do nothing;
  return new;
end; $$;

-- 초기 구축 단계용: 목표/면담이 이미 있다면 먼저 백업하세요.
-- 기존 목표/면담은 로그인 계정이 아니라 employees를 참조하도록 전환합니다.
delete from public.goals;
delete from public.interviews;

alter table public.goals drop constraint if exists goals_owner_id_fkey;
alter table public.goals add constraint goals_owner_id_fkey foreign key (owner_id) references public.employees(id) on delete cascade;

alter table public.interviews drop constraint if exists interviews_employee_id_fkey;
alter table public.interviews add constraint interviews_employee_id_fkey foreign key (employee_id) references public.employees(id) on delete cascade;

alter table public.employees enable row level security;

drop policy if exists "profiles read scoped" on public.profiles;
drop policy if exists "profile admin update" on public.profiles;
create policy "profiles self or admin read" on public.profiles for select to authenticated
using (id=auth.uid() or public.is_admin());
create policy "profiles admin update" on public.profiles for update to authenticated
using (public.is_admin()) with check (public.is_admin());

drop policy if exists "employees scoped read" on public.employees;
drop policy if exists "employees scoped insert" on public.employees;
drop policy if exists "employees scoped update" on public.employees;
drop policy if exists "employees scoped delete" on public.employees;
create policy "employees scoped read" on public.employees for select to authenticated
using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped insert" on public.employees for insert to authenticated
with check (public.is_active() and public.is_manager() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped update" on public.employees for update to authenticated
using (public.is_active() and (public.is_admin() or manager_id=auth.uid()))
with check (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "employees scoped delete" on public.employees for delete to authenticated
using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));

create or replace function public.manages_employee(target uuid) returns boolean language sql stable security definer set search_path=public as $$
  select public.is_admin() or exists(select 1 from public.employees where id=target and manager_id=auth.uid());
$$;

drop policy if exists "goals read scoped" on public.goals;
drop policy if exists "goals insert scoped" on public.goals;
drop policy if exists "goals update scoped" on public.goals;
drop policy if exists "goals delete scoped" on public.goals;
create policy "goals read scoped" on public.goals for select to authenticated
using (public.is_active() and public.manages_employee(owner_id));
create policy "goals insert scoped" on public.goals for insert to authenticated
with check (public.is_active() and public.manages_employee(owner_id) and created_by=auth.uid());
create policy "goals update scoped" on public.goals for update to authenticated
using (public.is_active() and public.manages_employee(owner_id))
with check (public.is_active() and public.manages_employee(owner_id));
create policy "goals delete scoped" on public.goals for delete to authenticated
using (public.is_active() and public.manages_employee(owner_id));

drop policy if exists "interviews read scoped" on public.interviews;
drop policy if exists "interviews insert manager" on public.interviews;
drop policy if exists "interviews update manager" on public.interviews;
drop policy if exists "interviews delete manager" on public.interviews;
create policy "interviews read scoped" on public.interviews for select to authenticated
using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));
create policy "interviews insert manager" on public.interviews for insert to authenticated
with check (public.is_active() and public.is_manager() and public.manages_employee(employee_id) and (manager_id=auth.uid() or public.is_admin()));
create policy "interviews update manager" on public.interviews for update to authenticated
using (public.is_active() and (manager_id=auth.uid() or public.is_admin()))
with check (public.is_active() and public.manages_employee(employee_id) and (manager_id=auth.uid() or public.is_admin()));
create policy "interviews delete manager" on public.interviews for delete to authenticated
using (public.is_active() and (manager_id=auth.uid() or public.is_admin()));

create index if not exists employees_manager_idx on public.employees(manager_id);
create index if not exists employees_status_idx on public.employees(employment_status);


-- Required by the existing authenticated RLS policies (no anon grant).
grant execute on function public.manages_employee(uuid) to authenticated;
