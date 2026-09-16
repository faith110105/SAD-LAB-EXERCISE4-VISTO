-- ============================================================
-- Laboratory 4 - Section B
-- Role-Based Facility Reservation and Approval System
-- Supabase (PostgreSQL) Schema
-- ============================================================

-- ------------------------------------------------------------
-- 1. ENUM TYPES
-- ------------------------------------------------------------
create type user_role as enum ('admin', 'staff', 'requester');

create type facility_status as enum ('active', 'maintenance', 'inactive');

create type reservation_status as enum (
  'pending', 'approved', 'rejected', 'scheduled',
  'in_use', 'completed', 'cancelled'
);

-- ------------------------------------------------------------
-- 2. PROFILES TABLE  (extends Supabase auth.users with a role)
-- ------------------------------------------------------------
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  email text not null unique,
  role user_role not null default 'requester',
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 3. FACILITIES TABLE
-- ------------------------------------------------------------
create table facilities (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  location text,
  capacity int,
  status facility_status not null default 'active',
  created_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 4. RESERVATIONS TABLE
-- ------------------------------------------------------------
create table reservations (
  id uuid primary key default gen_random_uuid(),
  facility_id uuid not null references facilities(id),
  requester_id uuid not null references profiles(id),
  purpose text not null,
  start_time timestamptz not null,
  end_time timestamptz not null,
  status reservation_status not null default 'pending',
  reviewed_by uuid references profiles(id),
  reviewed_at timestamptz,
  remarks text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- BR-B4-02: start must precede end
  constraint chk_time_order check (start_time < end_time)
);

-- ------------------------------------------------------------
-- 5. SERVICE REQUESTS TABLE (Facility Staff -> Administrator)
-- ------------------------------------------------------------
create table service_requests (
  id uuid primary key default gen_random_uuid(),
  facility_id uuid not null references facilities(id),
  raised_by uuid not null references profiles(id),
  concern text not null,
  status text not null default 'open', -- open, in_progress, resolved
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 6. AUDIT LOGS TABLE
-- ------------------------------------------------------------
create table audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references profiles(id),
  action text not null,           -- e.g. 'RESERVATION_SUBMITTED'
  entity_type text not null,      -- e.g. 'reservation', 'facility'
  entity_id uuid,
  details jsonb,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------
-- 7. HELPER FUNCTION: current user's role
-- ------------------------------------------------------------
create or replace function current_role_name()
returns user_role
language sql stable
as $$
  select role from profiles where id = auth.uid();
$$;

-- ------------------------------------------------------------
-- 8. TRIGGER FUNCTION: generic audit logger
-- ------------------------------------------------------------
create or replace function log_audit()
returns trigger
language plpgsql
security definer
as $$
begin
  if (tg_op = 'INSERT') then
    insert into audit_logs(actor_id, action, entity_type, entity_id, details)
    values (auth.uid(), tg_argv[0], tg_table_name, new.id, to_jsonb(new));
    return new;
  elsif (tg_op = 'UPDATE') then
    insert into audit_logs(actor_id, action, entity_type, entity_id, details)
    values (auth.uid(), tg_argv[0], tg_table_name, new.id,
            jsonb_build_object('old_status', to_jsonb(old), 'new_status', to_jsonb(new)));
    return new;
  end if;
  return null;
end;
$$;

create trigger trg_reservation_insert
  after insert on reservations
  for each row execute function log_audit('RESERVATION_SUBMITTED');

create trigger trg_reservation_update
  after update of status on reservations
  for each row execute function log_audit('RESERVATION_STATUS_CHANGED');

create trigger trg_facility_update
  after update on facilities
  for each row execute function log_audit('FACILITY_UPDATED');

-- ------------------------------------------------------------
-- 9. BUSINESS-RULE ENFORCEMENT: overlap + facility status checks
--    (BR-B4-01, BR-B4-03, BR-B4-08)
-- ------------------------------------------------------------
create or replace function check_reservation_rules()
returns trigger
language plpgsql
as $$
declare
  f_status facility_status;
  overlap_count int;
begin
  select status into f_status from facilities where id = new.facility_id;

  -- BR-B4-01 / BR-B4-08: only active facilities may be reserved
  if f_status <> 'active' then
    raise exception 'Facility is not active (status: %). Reservation blocked.', f_status;
  end if;

  -- BR-B4-03: no overlapping approved / scheduled / in_use reservations
  if new.status in ('approved', 'scheduled', 'in_use') then
    select count(*) into overlap_count
    from reservations
    where facility_id = new.facility_id
      and id <> coalesce(new.id, '00000000-0000-0000-0000-000000000000')
      and status in ('approved', 'scheduled', 'in_use')
      and (new.start_time, new.end_time) overlaps (start_time, end_time);

    if overlap_count > 0 then
      raise exception 'Schedule conflict: overlapping reservation exists for this facility.';
    end if;
  end if;

  -- BR-B4-05: rejected reservations cannot become scheduled
  if tg_op = 'UPDATE' and old.status = 'rejected' and new.status = 'scheduled' then
    raise exception 'Rejected reservations cannot be scheduled.';
  end if;

  -- BR-B4-07: completed reservations cannot be edited
  if tg_op = 'UPDATE' and old.status = 'completed' then
    raise exception 'Completed reservations cannot be edited.';
  end if;

  return new;
end;
$$;

create trigger trg_check_reservation_rules
  before insert or update on reservations
  for each row execute function check_reservation_rules();

-- ------------------------------------------------------------
-- 10. ROW-LEVEL SECURITY
-- ------------------------------------------------------------
alter table profiles enable row level security;
alter table facilities enable row level security;
alter table reservations enable row level security;
alter table service_requests enable row level security;
alter table audit_logs enable row level security;

-- Profiles: everyone can read their own row; admin can read all
create policy "profiles_select_own_or_admin" on profiles
  for select using (id = auth.uid() or current_role_name() = 'admin');

create policy "profiles_update_own" on profiles
  for update using (id = auth.uid());

-- Facilities: everyone (any authenticated role) can view
create policy "facilities_select_all" on facilities
  for select using (auth.role() = 'authenticated');

-- Facilities: only Administrator manages (insert/update/delete)
create policy "facilities_admin_write" on facilities
  for all using (current_role_name() = 'admin')
  with check (current_role_name() = 'admin');

-- Facilities: Facility Staff may update condition/status only (handled at app layer;
-- DB-level narrows to admin+staff for update)
create policy "facilities_staff_update" on facilities
  for update using (current_role_name() in ('admin', 'staff'));

-- Reservations: Requesters see their own; Staff/Admin see all
create policy "reservations_select" on reservations
  for select using (
    requester_id = auth.uid()
    or current_role_name() in ('admin', 'staff')
  );

-- Reservations: Requesters create their own reservations
create policy "reservations_insert_requester" on reservations
  for insert with check (requester_id = auth.uid());

-- Reservations: BR-B4-04 approve/reject only by Administrator;
-- BR-B4-09 requester may edit only own Pending requests;
-- Staff may update to in_use/completed
create policy "reservations_update" on reservations
  for update using (
    current_role_name() = 'admin'
    or (current_role_name() = 'staff')
    or (requester_id = auth.uid() and status = 'pending')
  );

-- Service requests: Staff create, Admin + Staff view
create policy "service_requests_select" on service_requests
  for select using (current_role_name() in ('admin', 'staff'));

create policy "service_requests_insert_staff" on service_requests
  for insert with check (current_role_name() in ('admin', 'staff'));

-- Audit logs: Administrator only (BR: auditability restricted to admin)
create policy "audit_logs_admin_only" on audit_logs
  for select using (current_role_name() = 'admin');

-- ------------------------------------------------------------
-- 11. SEED DATA (sample facilities for testing)
-- ------------------------------------------------------------
insert into facilities (name, location, capacity, status) values
  ('Conference Room A', 'Main Building, 2nd Floor', 20, 'active'),
  ('Gymnasium', 'Sports Complex', 200, 'active'),
  ('Computer Laboratory 1', 'IT Building, 1st Floor', 40, 'maintenance'),
  ('Audio-Visual Room', 'Library Building', 60, 'active');
