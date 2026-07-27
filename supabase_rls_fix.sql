-- ============================================================
--  SECURITY FIX — run once in Supabase → SQL Editor
--
--  Problem: the policy "Users can update own profile" let ANY logged-in
--  user PATCH their own row through the public REST API — including
--  license_active / expires_at / key_type / banned. In practice that means
--  a user could grant themselves a lifetime license for free, or unban
--  themselves.
--
--  Fix: users may no longer UPDATE profiles at all. Only the backend
--  (which connects with the direct Postgres string and bypasses RLS)
--  can change license state. Users keep read access to their own row,
--  which is all the site needs.
-- ============================================================

drop policy if exists "Users can update own profile" on profiles;

-- keep: read-only access to your own profile (site shows key + status)
drop policy if exists "Users can view own profile" on profiles;
create policy "Users can view own profile"
    on profiles for select
    using (auth.uid() = id);

-- service role keeps full access (admin panel / launcher backend)
drop policy if exists "Service role full access" on profiles;
create policy "Service role full access"
    on profiles for all
    using (auth.role() = 'service_role');

-- Telemetry: clients may only INSERT their reports, never read others'.
alter table telemetry_logs enable row level security;
drop policy if exists "Anyone can insert telemetry" on telemetry_logs;
create policy "Anyone can insert telemetry"
    on telemetry_logs for insert
    with check (true);
drop policy if exists "Service role reads telemetry" on telemetry_logs;
create policy "Service role reads telemetry"
    on telemetry_logs for select
    using (auth.role() = 'service_role');

-- Admin activity log must never be readable/writable from the browser.
alter table activity_logs enable row level security;
drop policy if exists "Service role only" on activity_logs;
create policy "Service role only"
    on activity_logs for all
    using (auth.role() = 'service_role');
