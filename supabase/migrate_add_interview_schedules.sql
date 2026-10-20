-- Add calendar-based interview scheduling without mixing planned schedules with completed interview records.
-- Explicit API privileges apply only when this statement creates the table.
-- Existing table ACLs are intentionally left unchanged.
do $table_setup$
begin
  if to_regclass('public.interview_schedules') is null then
    create table public.interview_schedules (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.employees(id) on delete cascade,
  manager_id uuid not null references public.profiles(id) on delete cascade,
  scheduled_date date not null,
  scheduled_time time,
  interview_type text not null default '정기 1:1',
  topic text,
  status text not null default '예정' check (status in ('예정','완료','취소','미실시')),
  linked_interview_id uuid references public.interviews(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
    alter table public.interview_schedules enable row level security;
    -- Also safe on projects that still have the old automatic default grants.
    revoke all on table public.interview_schedules from public, anon, authenticated, service_role;
    grant select, insert, update, delete on table public.interview_schedules to authenticated;
  end if;
end;
$table_setup$;

drop trigger if exists interview_schedules_updated_at on public.interview_schedules;
create trigger interview_schedules_updated_at
before update on public.interview_schedules
for each row execute procedure public.set_updated_at();

alter table public.interview_schedules enable row level security;

drop policy if exists "interview schedules read scoped" on public.interview_schedules;
drop policy if exists "interview schedules insert manager" on public.interview_schedules;
drop policy if exists "interview schedules update manager" on public.interview_schedules;
drop policy if exists "interview schedules delete manager" on public.interview_schedules;

create policy "interview schedules read scoped" on public.interview_schedules
for select to authenticated
using (public.is_active() and (public.is_admin() or manager_id=auth.uid()));

create policy "interview schedules insert manager" on public.interview_schedules
for insert to authenticated
with check (
  public.is_active()
  and public.is_manager()
  and public.manages_employee(employee_id)
  and (manager_id=auth.uid() or public.is_admin())
);

create policy "interview schedules update manager" on public.interview_schedules
for update to authenticated
using (public.is_active() and (manager_id=auth.uid() or public.is_admin()))
with check (
  public.is_active()
  and public.manages_employee(employee_id)
  and (manager_id=auth.uid() or public.is_admin())
);

create policy "interview schedules delete manager" on public.interview_schedules
for delete to authenticated
using (public.is_active() and (manager_id=auth.uid() or public.is_admin()));

create index if not exists interview_schedules_employee_idx on public.interview_schedules(employee_id);
create index if not exists interview_schedules_manager_idx on public.interview_schedules(manager_id);
create index if not exists interview_schedules_date_idx on public.interview_schedules(scheduled_date);
create index if not exists interview_schedules_status_idx on public.interview_schedules(status);

