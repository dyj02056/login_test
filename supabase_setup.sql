-- ============================================================
-- login_test — Supabase 전체 스키마 / 함수 정의
-- Supabase 대시보드 > SQL Editor > New query 에 붙여넣고 Run 하세요.
-- 여러 번 실행해도 안전합니다 (idempotent).
-- ============================================================

create extension if not exists pgcrypto with schema extensions;


-- ============================================================
-- 1. 테이블
-- ============================================================

create table if not exists public.users (
    id bigint generated always as identity primary key,
    username text unique not null,
    password_hash text not null,
    created_at timestamptz not null default now()
);

-- 기존 설치본에도 새 컬럼을 안전하게 추가
alter table public.users add column if not exists email text;
alter table public.users add column if not exists is_active boolean not null default true;
alter table public.users add column if not exists is_admin boolean not null default false;

-- 로그인 시도 기록 (무차별 대입 차단 + 감사 로그)
create table if not exists public.login_attempts (
    id bigint generated always as identity primary key,
    username text not null,
    ip text,
    success boolean not null,
    attempted_at timestamptz not null default now()
);

create index if not exists login_attempts_username_time_idx
    on public.login_attempts (username, attempted_at desc);
create index if not exists login_attempts_time_idx
    on public.login_attempts (attempted_at desc);

-- 비밀번호 재설정 토큰 (원문은 저장하지 않고 해시만 보관)
create table if not exists public.password_resets (
    id bigint generated always as identity primary key,
    user_id bigint not null references public.users(id) on delete cascade,
    token_hash text not null,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists password_resets_user_idx on public.password_resets (user_id);

-- 앱 전역 설정 (단일 행)
create table if not exists public.app_settings (
    id boolean primary key default true,
    signup_enabled boolean not null default true,
    constraint app_settings_singleton check (id = true)
);

insert into public.app_settings (id, signup_enabled)
values (true, true)
on conflict (id) do nothing;

-- 서버(Flask)만 알고 있어야 하는 RPC 호출용 비밀키.
-- publishable 키가 유출되어도 이 값이 없으면 아래 함수들을 호출할 수 없습니다.
alter table public.app_settings add column if not exists rpc_secret text;
update public.app_settings
   set rpc_secret = extensions.gen_random_uuid()::text
 where rpc_secret is null;
alter table public.app_settings alter column rpc_secret set not null;

-- 모든 테이블 RLS 활성화 + 정책 없음 => anon 키로 직접 접근 불가.
-- 오직 아래 security definer 함수들을 통해서만 데이터에 접근합니다.
alter table public.users enable row level security;
alter table public.login_attempts enable row level security;
alter table public.password_resets enable row level security;
alter table public.app_settings enable row level security;


-- ============================================================
-- 2. 내부 헬퍼 (anon 에게 권한을 주지 않음)
-- ============================================================

create or replace function public.check_secret(p_secret text)
returns boolean
language sql
security definer
set search_path = public
as $$
    select exists (
        select 1 from public.app_settings
        where id = true and rpc_secret = p_secret
    );
$$;

revoke all on function public.check_secret(text) from public, anon, authenticated;


-- 이전 버전의 함수 시그니처 제거 (인자가 바뀌었으므로)
drop function if exists public.signup_user(text, text);
drop function if exists public.login_user(text, text);
drop function if exists public.get_signup_enabled();
drop function if exists public.set_signup_enabled(boolean);


-- ============================================================
-- 3. 인증 (회원가입 / 로그인)
-- ============================================================

create or replace function public.signup_user(
    p_secret text,
    p_username text,
    p_password text,
    p_email text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_id bigint;
    v_enabled boolean;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    select signup_enabled into v_enabled from public.app_settings where id = true;
    if not v_enabled then
        return jsonb_build_object('success', false, 'error', '현재 회원가입이 중단되었습니다.');
    end if;

    if length(p_username) < 3 then
        return jsonb_build_object('success', false, 'error', '아이디는 3자 이상이어야 합니다.');
    end if;
    if length(p_password) < 6 then
        return jsonb_build_object('success', false, 'error', '비밀번호는 6자 이상이어야 합니다.');
    end if;
    if exists (select 1 from public.users where username = p_username) then
        return jsonb_build_object('success', false, 'error', '이미 사용 중인 아이디입니다.');
    end if;

    insert into public.users (username, password_hash, email)
    values (
        p_username,
        extensions.crypt(p_password, extensions.gen_salt('bf')),
        nullif(trim(coalesce(p_email, '')), '')
    )
    returning id into v_id;

    return jsonb_build_object('success', true, 'id', v_id);
end;
$$;


-- 로그인: 15분 내 5회 실패 시 계정 잠금, 모든 시도를 기록
create or replace function public.login_user(
    p_secret text,
    p_username text,
    p_password text,
    p_ip text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
    v_fails int;
    v_ok boolean := false;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'reason', 'secret');
    end if;

    select count(*) into v_fails
      from public.login_attempts
     where username = p_username
       and success = false
       and attempted_at > now() - interval '15 minutes';

    if v_fails >= 5 then
        insert into public.login_attempts (username, ip, success)
        values (p_username, p_ip, false);
        return jsonb_build_object('success', false, 'reason', 'locked');
    end if;

    select id, username, password_hash, is_active, is_admin
      into v_user
      from public.users
     where username = p_username;

    if v_user.id is not null
       and v_user.password_hash = extensions.crypt(p_password, v_user.password_hash) then
        v_ok := true;
    end if;

    insert into public.login_attempts (username, ip, success)
    values (p_username, p_ip, v_ok);

    if not v_ok then
        return jsonb_build_object('success', false, 'reason', 'credentials');
    end if;

    if not v_user.is_active then
        return jsonb_build_object('success', false, 'reason', 'inactive');
    end if;

    return jsonb_build_object(
        'success', true,
        'id', v_user.id,
        'username', v_user.username,
        'is_admin', v_user.is_admin
    );
end;
$$;


-- ============================================================
-- 4. 내 계정 관리 (비밀번호 변경 / 탈퇴)
-- ============================================================

create or replace function public.change_password(
    p_secret text,
    p_user_id bigint,
    p_old_password text,
    p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    if length(p_new_password) < 6 then
        return jsonb_build_object('success', false, 'error', '새 비밀번호는 6자 이상이어야 합니다.');
    end if;

    select id, password_hash into v_user from public.users where id = p_user_id;

    if v_user.id is null
       or v_user.password_hash <> extensions.crypt(p_old_password, v_user.password_hash) then
        return jsonb_build_object('success', false, 'error', '현재 비밀번호가 올바르지 않습니다.');
    end if;

    update public.users
       set password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf'))
     where id = p_user_id;

    return jsonb_build_object('success', true);
end;
$$;


create or replace function public.delete_own_account(
    p_secret text,
    p_user_id bigint,
    p_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    select id, password_hash into v_user from public.users where id = p_user_id;

    if v_user.id is null
       or v_user.password_hash <> extensions.crypt(p_password, v_user.password_hash) then
        return jsonb_build_object('success', false, 'error', '비밀번호가 올바르지 않습니다.');
    end if;

    delete from public.users where id = p_user_id;
    return jsonb_build_object('success', true);
end;
$$;


-- ============================================================
-- 5. 비밀번호 재설정 (토큰 방식)
-- ============================================================

-- 토큰 원문은 이 함수의 반환값으로 딱 한 번만 나가고, DB 에는 해시만 남습니다.
create or replace function public.create_password_reset(
    p_secret text,
    p_username text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
    v_token text;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    select id, username, email into v_user from public.users where username = p_username;

    -- 존재하지 않는 아이디여도 동일하게 성공을 반환 (계정 존재 여부 노출 방지)
    if v_user.id is null then
        return jsonb_build_object('success', true, 'issued', false);
    end if;

    v_token := encode(extensions.gen_random_bytes(24), 'hex');

    insert into public.password_resets (user_id, token_hash, expires_at)
    values (
        v_user.id,
        encode(extensions.digest(v_token, 'sha256'), 'hex'),
        now() + interval '1 hour'
    );

    return jsonb_build_object(
        'success', true,
        'issued', true,
        'token', v_token,
        'username', v_user.username,
        'email', v_user.email
    );
end;
$$;


create or replace function public.reset_password_with_token(
    p_secret text,
    p_token text,
    p_new_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_reset record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    if length(p_new_password) < 6 then
        return jsonb_build_object('success', false, 'error', '비밀번호는 6자 이상이어야 합니다.');
    end if;

    select id, user_id into v_reset
      from public.password_resets
     where token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
       and used_at is null
       and expires_at > now();

    if v_reset.id is null then
        return jsonb_build_object('success', false, 'error', '링크가 만료되었거나 이미 사용되었습니다.');
    end if;

    update public.users
       set password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf'))
     where id = v_reset.user_id;

    update public.password_resets set used_at = now() where id = v_reset.id;

    -- 비밀번호를 되찾았으므로 기존 실패 기록으로 인한 잠금을 해제
    delete from public.login_attempts
     where success = false
       and username = (select username from public.users where id = v_reset.user_id);

    return jsonb_build_object('success', true);
end;
$$;


-- 관리자 화면에서 "아직 사용되지 않은 재설정 요청" 목록을 보여주기 위한 함수
create or replace function public.list_pending_resets(p_secret text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_result jsonb;
begin
    if not public.check_secret(p_secret) then
        return '[]'::jsonb;
    end if;

    select coalesce(jsonb_agg(t order by t.created_at desc), '[]'::jsonb) into v_result
      from (
        select r.id, u.username, r.created_at, r.expires_at
          from public.password_resets r
          join public.users u on u.id = r.user_id
         where r.used_at is null and r.expires_at > now()
      ) t;

    return v_result;
end;
$$;


-- ============================================================
-- 6. 관리자 기능
-- ============================================================

create or replace function public.get_signup_enabled(p_secret text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return true;
    end if;
    return (select signup_enabled from public.app_settings where id = true);
end;
$$;


create or replace function public.set_signup_enabled(p_secret text, p_enabled boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    update public.app_settings set signup_enabled = p_enabled where id = true;
    return jsonb_build_object('success', true, 'signup_enabled', p_enabled);
end;
$$;


-- 회원 목록 (검색 + 페이지네이션)
create or replace function public.list_users(
    p_secret text,
    p_limit int default 20,
    p_offset int default 0,
    p_search text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_rows jsonb;
    v_total int;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('total', 0, 'users', '[]'::jsonb);
    end if;

    select count(*) into v_total
      from public.users
     where p_search is null or p_search = '' or username ilike '%' || p_search || '%';

    select coalesce(jsonb_agg(t order by t.id desc), '[]'::jsonb) into v_rows
      from (
        select id, username, email, is_active, is_admin, created_at
          from public.users
         where p_search is null or p_search = '' or username ilike '%' || p_search || '%'
         order by id desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object('total', v_total, 'users', v_rows);
end;
$$;


create or replace function public.set_user_active(
    p_secret text, p_user_id bigint, p_active boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    update public.users set is_active = p_active where id = p_user_id;
    return jsonb_build_object('success', true);
end;
$$;


create or replace function public.set_user_admin(
    p_secret text, p_user_id bigint, p_is_admin boolean
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    update public.users set is_admin = p_is_admin where id = p_user_id;
    return jsonb_build_object('success', true);
end;
$$;


create or replace function public.admin_delete_user(p_secret text, p_user_id bigint)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    delete from public.users where id = p_user_id;
    return jsonb_build_object('success', true);
end;
$$;


-- 로그인 기록 (감사 로그)
create or replace function public.get_login_attempts(
    p_secret text,
    p_limit int default 50,
    p_offset int default 0
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_rows jsonb;
    v_total int;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('total', 0, 'attempts', '[]'::jsonb);
    end if;

    select count(*) into v_total from public.login_attempts;

    select coalesce(jsonb_agg(t order by t.attempted_at desc), '[]'::jsonb) into v_rows
      from (
        select id, username, ip, success, attempted_at
          from public.login_attempts
         order by attempted_at desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object('total', v_total, 'attempts', v_rows);
end;
$$;


-- 잠긴 계정 수동 해제
create or replace function public.clear_login_attempts(p_secret text, p_username text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    delete from public.login_attempts where username = p_username and success = false;
    return jsonb_build_object('success', true);
end;
$$;


-- 가입 통계 (최근 N일)
create or replace function public.get_signup_stats(p_secret text, p_days int default 14)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_rows jsonb;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('daily', '[]'::jsonb);
    end if;

    select coalesce(jsonb_agg(t order by t.day), '[]'::jsonb) into v_rows
      from (
        select d::date as day,
               (select count(*) from public.users u
                 where u.created_at::date = d::date) as count
          from generate_series(
                 (now() - (p_days - 1) * interval '1 day')::date,
                 now()::date,
                 interval '1 day'
               ) d
      ) t;

    return jsonb_build_object(
        'daily', v_rows,
        'total_users', (select count(*) from public.users),
        'active_users', (select count(*) from public.users where is_active),
        'admin_users', (select count(*) from public.users where is_admin),
        'logins_24h', (select count(*) from public.login_attempts
                        where success and attempted_at > now() - interval '24 hours'),
        'failed_24h', (select count(*) from public.login_attempts
                        where not success and attempted_at > now() - interval '24 hours')
    );
end;
$$;


-- ============================================================
-- 7. 권한 부여 (anon = publishable 키로 호출 가능한 함수 목록)
--    모든 함수가 p_secret 을 요구하므로 실제 실행은 서버만 가능합니다.
-- ============================================================

grant execute on function public.signup_user(text, text, text, text) to anon, authenticated;
grant execute on function public.login_user(text, text, text, text) to anon, authenticated;
grant execute on function public.change_password(text, bigint, text, text) to anon, authenticated;
grant execute on function public.delete_own_account(text, bigint, text) to anon, authenticated;
grant execute on function public.create_password_reset(text, text) to anon, authenticated;
grant execute on function public.reset_password_with_token(text, text, text) to anon, authenticated;
grant execute on function public.list_pending_resets(text) to anon, authenticated;
grant execute on function public.get_signup_enabled(text) to anon, authenticated;
grant execute on function public.set_signup_enabled(text, boolean) to anon, authenticated;
grant execute on function public.list_users(text, int, int, text) to anon, authenticated;
grant execute on function public.set_user_active(text, bigint, boolean) to anon, authenticated;
grant execute on function public.set_user_admin(text, bigint, boolean) to anon, authenticated;
grant execute on function public.admin_delete_user(text, bigint) to anon, authenticated;
grant execute on function public.get_login_attempts(text, int, int) to anon, authenticated;
grant execute on function public.clear_login_attempts(text, text) to anon, authenticated;
grant execute on function public.get_signup_stats(text, int) to anon, authenticated;


-- ============================================================
-- 8. 마지막으로 이 값을 복사해서 환경변수 SUPABASE_RPC_SECRET 에 넣으세요.
--    (.env 와 Vercel > Settings > Environment Variables 양쪽 모두)
-- ============================================================

select rpc_secret as "이_값을_SUPABASE_RPC_SECRET_에_넣으세요"
  from public.app_settings where id = true;
