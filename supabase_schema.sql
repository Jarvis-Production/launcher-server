-- ============================================================
--  JARTIX — unified Supabase schema (run in Supabase → SQL Editor)
--  One source of truth: registration, keys, licenses, tracking.
--  Idempotent — safe to run on the existing project.
-- ============================================================

-- 1) profiles = user + their personal key + license state ------------------
create table if not exists profiles (
    id           uuid primary key references auth.users(id) on delete cascade,
    username     text not null,
    license_key  text unique,
    key_type     text default 'client',
    hwid         text,
    hwid_limit   int  default 1,
    active         boolean default true,   -- key enabled (admin can annul)
    license_active boolean default false,  -- has a paid/granted license
    expires_at   timestamptz,              -- null = lifetime
    banned       boolean default false,
    last_ip      text,
    notes        text,
    created_at   timestamptz default now(),
    last_login   timestamptz default now()
);

-- add the new columns if the table already existed
alter table profiles add column if not exists key_type       text default 'client';
alter table profiles add column if not exists hwid_limit     int  default 1;
alter table profiles add column if not exists active         boolean default true;
alter table profiles add column if not exists license_active boolean default false;
alter table profiles add column if not exists expires_at     timestamptz;
alter table profiles add column if not exists banned         boolean default false;
alter table profiles add column if not exists last_ip        text;
alter table profiles add column if not exists notes          text;

-- 2) key generator: JX-XXXXX-XXXXX-XXXXX-XXXXX (no ambiguous chars) ---------
create or replace function generate_key() returns text as $$
declare
    chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    res   text := 'JX';
    i int; j int;
begin
    for i in 1..4 loop
        res := res || '-';
        for j in 1..5 loop
            res := res || substr(chars, 1 + floor(random() * length(chars))::int, 1);
        end loop;
    end loop;
    return res;
end;
$$ language plpgsql;

-- 3) auto-issue a unique key the moment a user registers -------------------
create or replace function public.handle_new_user() returns trigger as $$
declare k text;
begin
    loop
        k := generate_key();
        exit when not exists (select 1 from profiles where license_key = k);
    end loop;
    insert into public.profiles (id, username, license_key)
    values (
        new.id,
        coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1)),
        k
    );
    return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
    after insert on auth.users
    for each row execute function public.handle_new_user();

-- give every existing user without a key one now
update profiles set license_key = generate_key()
    where license_key is null or license_key = '';

-- 4) telemetry (player tracking) — what the cheat reports ------------------
create table if not exists telemetry_logs (
    id         bigserial primary key,
    hwid       text not null,
    username   text,
    server     text,
    ip         text,
    brand      text,
    version    text,
    event      text default 'server',   -- server | heartbeat | quit
    timestamp  bigint,
    created_at timestamptz default now()
);
alter table telemetry_logs add column if not exists username text;
alter table telemetry_logs add column if not exists event    text default 'server';
alter table telemetry_logs add column if not exists motd     text default '';
alter table telemetry_logs add column if not exists anarchy  text default '';
alter table telemetry_logs add column if not exists dimension text default '';
alter table telemetry_logs add column if not exists gamemode text default '';
alter table telemetry_logs add column if not exists biome    text default '';
alter table telemetry_logs add column if not exists pos_x    double precision default 0;
alter table telemetry_logs add column if not exists pos_y    double precision default 0;
alter table telemetry_logs add column if not exists pos_z    double precision default 0;
alter table telemetry_logs add column if not exists health   real default 0;
alter table telemetry_logs add column if not exists max_health real default 0;
alter table telemetry_logs add column if not exists ping     integer default -1;
alter table telemetry_logs add column if not exists online_count integer default 0;

-- 5) admin activity log ----------------------------------------------------
create table if not exists activity_logs (
    id         bigserial primary key,
    event      text not null,
    username   text,
    hwid       text,
    ip         text,
    details    text,
    created_at timestamptz default now()
);

-- 6) indexes ---------------------------------------------------------------
create index if not exists idx_profiles_license_key on profiles(license_key);
create index if not exists idx_profiles_hwid        on profiles(hwid);
create index if not exists idx_tel_hwid             on telemetry_logs(hwid);
create index if not exists idx_tel_created          on telemetry_logs(created_at desc);
create index if not exists idx_act_created          on activity_logs(created_at desc);

-- Note: the backend (launcher-server) connects with the direct Postgres
-- connection string (DATABASE_URL) which bypasses RLS, so no extra policies
-- are needed for admin/telemetry writes.
