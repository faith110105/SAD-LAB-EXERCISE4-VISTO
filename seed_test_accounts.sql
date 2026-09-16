-- ============================================================
-- Laboratory 4 - Section B
-- OPTIONAL: Seed 3 ready-to-use test accounts
-- ============================================================
-- Run this AFTER schema.sql has already been run successfully.
-- Creates one login for each role so you can test right away
-- without manually registering and editing profiles.role.
--
-- Test accounts created (password is the same for all three):
--   Administrator : admin@lab4.test      / Lab4Password!
--   Facility Staff: staff@lab4.test      / Lab4Password!
--   Requester     : requester@lab4.test  / Lab4Password!
--
-- IMPORTANT: These are for testing/demo only. Change or delete
-- them before using the system for anything real.
-- ============================================================

-- pgcrypto is needed to hash the password the same way Supabase Auth does
create extension if not exists pgcrypto;

do $$
declare
  admin_id      uuid := gen_random_uuid();
  staff_id      uuid := gen_random_uuid();
  requester_id  uuid := gen_random_uuid();
  test_password text := 'Lab4Password!';
begin

  -- ---------- Administrator ----------
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at, confirmation_token, email_change,
    email_change_token_new, recovery_token
  ) values (
    '00000000-0000-0000-0000-000000000000', admin_id, 'authenticated', 'authenticated',
    'admin@lab4.test', crypt(test_password, gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}',
    now(), now(), '', '', '', ''
  );

  insert into public.profiles (id, full_name, email, role)
  values (admin_id, 'Test Administrator', 'admin@lab4.test', 'admin');

  insert into auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    gen_random_uuid(), admin_id, admin_id::text,
    jsonb_build_object('sub', admin_id::text, 'email', 'admin@lab4.test'),
    'email', now(), now(), now()
  );

  -- ---------- Facility Staff ----------
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at, confirmation_token, email_change,
    email_change_token_new, recovery_token
  ) values (
    '00000000-0000-0000-0000-000000000000', staff_id, 'authenticated', 'authenticated',
    'staff@lab4.test', crypt(test_password, gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}',
    now(), now(), '', '', '', ''
  );

  insert into public.profiles (id, full_name, email, role)
  values (staff_id, 'Test Facility Staff', 'staff@lab4.test', 'staff');

  insert into auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    gen_random_uuid(), staff_id, staff_id::text,
    jsonb_build_object('sub', staff_id::text, 'email', 'staff@lab4.test'),
    'email', now(), now(), now()
  );

  -- ---------- Requester ----------
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at, confirmation_token, email_change,
    email_change_token_new, recovery_token
  ) values (
    '00000000-0000-0000-0000-000000000000', requester_id, 'authenticated', 'authenticated',
    'requester@lab4.test', crypt(test_password, gen_salt('bf')),
    now(), '{"provider":"email","providers":["email"]}', '{}',
    now(), now(), '', '', '', ''
  );

  insert into public.profiles (id, full_name, email, role)
  values (requester_id, 'Test Requester', 'requester@lab4.test', 'requester');

  insert into auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    gen_random_uuid(), requester_id, requester_id::text,
    jsonb_build_object('sub', requester_id::text, 'email', 'requester@lab4.test'),
    'email', now(), now(), now()
  );

end $$;

-- Quick check
select email, role from public.profiles where email like '%@lab4.test' order by role;
