-- ============================================================
--  JARTIX — ВАЖНЫЙ фикс безопасности (выполнить в Supabase → SQL Editor)
--
--  Проблема: политика "Users can update own profile" разрешала юзеру
--  менять ЛЮБЫЕ поля своей строки — включая license_active, expires_at,
--  key_type, banned и license_key. Т.е. любой мог выдать себе лицензию
--  навсегда через обычный REST-запрос с anon-ключом.
--
--  Решение: убрать право UPDATE у пользователей полностью.
--  Все изменения лицензий/ключей делает бэкенд (launcher-server),
--  который подключается по DATABASE_URL и обходит RLS.
--  Читать свой профиль юзер по-прежнему может (нужно для кабинета).
-- ============================================================

-- 1) Убираем опасную политику записи
drop policy if exists "Users can update own profile" on profiles;

-- 2) Оставляем только чтение своего профиля
drop policy if exists "Users can view own profile" on profiles;
create policy "Users can view own profile"
    on profiles for select
    using (auth.uid() = id);

-- 3) RLS обязательно включён
alter table profiles enable row level security;

-- 4) Телеметрия: чит пишет анонимно, читать — только сервер
alter table telemetry_logs enable row level security;
drop policy if exists "Anyone can insert telemetry" on telemetry_logs;
create policy "Anyone can insert telemetry"
    on telemetry_logs for insert with check (true);
drop policy if exists "No public read telemetry" on telemetry_logs;

-- 5) Журнал админ-действий: полностью закрыт для публики
alter table activity_logs enable row level security;

-- 6) Проверка: что осталось из политик
-- select tablename, policyname, cmd from pg_policies
--   where tablename in ('profiles','telemetry_logs','activity_logs');
