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

-- 세션 무효화용 버전. 비밀번호 변경·계정 정지·권한 변경 시 1 증가시켜
-- 이전에 발급된 세션 쿠키를 즉시 무효로 만듭니다.
alter table public.users add column if not exists session_version int not null default 1;

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
-- 잠금 판정이 (아이디, IP) 와 IP 단독 조건을 모두 조회하므로 함께 걸어 둡니다.
create index if not exists login_attempts_user_ip_time_idx
    on public.login_attempts (username, ip, attempted_at desc);
create index if not exists login_attempts_ip_time_idx
    on public.login_attempts (ip, attempted_at desc);

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

-- 관리자 행위 감사 로그.
-- 대상 아이디를 함께 저장해 두므로 회원이 삭제된 뒤에도 누가 무엇을 지웠는지 남습니다.
create table if not exists public.admin_actions (
    id bigint generated always as identity primary key,
    actor text not null,
    action text not null,
    target_user_id bigint,
    target_username text,
    detail text,
    ip text,
    created_at timestamptz not null default now()
);

create index if not exists admin_actions_time_idx
    on public.admin_actions (created_at desc);


-- 앱 전역 설정 (단일 행)
create table if not exists public.app_settings (
    id boolean primary key default true,
    signup_enabled boolean not null default true,
    constraint app_settings_singleton check (id = true)
);

-- 서버(Flask)만 알고 있어야 하는 RPC 호출용 비밀키.
-- publishable 키가 유출되어도 이 값이 없으면 아래 함수들을 호출할 수 없습니다.
--
-- 컬럼 준비를 아래 INSERT 보다 반드시 먼저 해야 합니다. PostgreSQL 은 ON CONFLICT 로
-- 넘어가기 전에 NOT NULL 을 먼저 검사하므로, 순서가 뒤바뀌면 재실행 시
-- "null value in column rpc_secret" 오류가 납니다.
alter table public.app_settings add column if not exists rpc_secret text;
alter table public.app_settings
    alter column rpc_secret set default extensions.gen_random_uuid()::text;

-- 설정 행이 없을 때만 생성 (이미 있으면 아무 것도 하지 않음)
insert into public.app_settings (id, signup_enabled)
select true, true
where not exists (select 1 from public.app_settings where id = true);

-- 기존 설치본에 비밀키가 없으면 채움. 이미 있으면 값을 유지합니다.
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
alter table public.admin_actions enable row level security;

-- 오래된 기록을 언제 마지막으로 정리했는지 (자동 정리 주기 판단용)
alter table public.app_settings add column if not exists last_pruned_at timestamptz;


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


-- 로그인 잠금 판정. login_user 와 check_login_lock 이 공유하는 단일 기준점이므로
-- 잠금 정책을 바꿀 때는 이 함수 하나만 고치면 됩니다.
--
-- 아이디만으로 판정하면 누구나 남의 아이디로 5번 틀려서 그 사람을 로그인 불가로
-- 만들 수 있으므로(서비스 거부), (아이디 + IP) 조합을 기준으로 삼습니다.
-- 공격자 IP 에서 실패가 쌓여도 피해자 IP 에서의 로그인은 막히지 않습니다.
create or replace function public.is_login_locked(p_username text, p_ip text)
returns boolean
language sql
security definer
set search_path = public
as $$
    select case
        -- IP 를 알 수 없으면 아이디 기준으로만 판정 (임계값을 올려 오탐을 줄임)
        when coalesce(p_ip, '') = '' then
            (select count(*) from public.login_attempts
              where username = p_username
                and not success
                and attempted_at > now() - interval '15 minutes') >= 10
        else
            -- 같은 (아이디, IP) 에서 5회 실패 → 해당 계정 대입 차단
            (select count(*) from public.login_attempts
              where username = p_username
                and ip = p_ip
                and not success
                and attempted_at > now() - interval '15 minutes') >= 5
            or
            -- 같은 IP 에서 아이디 불문 20회 실패 → 여러 계정을 훑는 공격 차단
            (select count(*) from public.login_attempts
              where ip = p_ip
                and not success
                and attempted_at > now() - interval '15 minutes') >= 20
    end;
$$;

revoke all on function public.is_login_locked(text, text) from public, anon, authenticated;


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
    v_ok boolean := false;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'reason', 'secret');
    end if;

    if public.is_login_locked(p_username, p_ip) then
        insert into public.login_attempts (username, ip, success)
        values (p_username, p_ip, false);
        return jsonb_build_object('success', false, 'reason', 'locked');
    end if;

    select id, username, password_hash, is_active, is_admin, session_version
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
        'is_admin', v_user.is_admin,
        'session_version', v_user.session_version
    );
end;
$$;


-- 로그인 전 잠금 여부만 확인. 환경변수 관리자처럼 DB 를 거치지 않는 로그인 경로도
-- 동일한 제한을 받도록 하기 위해 분리했습니다.
create or replace function public.check_login_lock(
    p_secret text,
    p_username text,
    p_ip text default null
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    -- 비밀키가 틀리면 잠기지 않은 것으로 봅니다. 비밀키 오류로 DB 경로가 전부 막힌
    -- 상황에서 환경변수 관리자는 유일한 복구 통로여야 하기 때문입니다.
    if not public.check_secret(p_secret) then
        return jsonb_build_object('locked', false, 'ok', false);
    end if;

    return jsonb_build_object(
        'locked', public.is_login_locked(p_username, p_ip),
        'ok', true
    );
end;
$$;


-- 로그인 시도 기록. DB 를 거치지 않는 로그인 경로에서 직접 호출합니다.
create or replace function public.record_login_attempt(
    p_secret text,
    p_username text,
    p_ip text,
    p_success boolean
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

    insert into public.login_attempts (username, ip, success)
    values (p_username, p_ip, p_success);

    return jsonb_build_object('success', true);
end;
$$;


-- 살아 있는 세션이 여전히 유효한지 확인하기 위한 조회.
-- found=false 는 계정이 삭제되었다는 뜻이므로 세션을 파기해야 합니다.
create or replace function public.get_user_session_state(
    p_secret text,
    p_user_id bigint
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('found', false, 'ok', false);
    end if;

    select is_active, is_admin, session_version into v
      from public.users
     where id = p_user_id;

    if v is null then
        return jsonb_build_object('found', false, 'ok', true);
    end if;

    return jsonb_build_object(
        'found', true,
        'ok', true,
        'is_active', v.is_active,
        'is_admin', v.is_admin,
        'session_version', v.session_version
    );
end;
$$;


-- 관리자가 특정 회원의 모든 세션을 즉시 종료
create or replace function public.force_logout_user(p_secret text, p_user_id bigint)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;

    update public.users
       set session_version = session_version + 1
     where id = p_user_id;

    return jsonb_build_object('success', true);
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
    v_new_version int;
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

    -- 비밀번호를 바꾸면 다른 기기의 세션은 모두 무효화됩니다.
    -- 새 버전을 돌려주므로 요청을 보낸 본인의 세션만 이어서 유지할 수 있습니다.
    update public.users
       set password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf')),
           session_version = session_version + 1
     where id = p_user_id
    returning session_version into v_new_version;

    return jsonb_build_object('success', true, 'session_version', v_new_version);
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

    -- 재설정은 계정 탈취 대응 수단이므로 기존 세션을 전부 무효화합니다.
    update public.users
       set password_hash = extensions.crypt(p_new_password, extensions.gen_salt('bf')),
           session_version = session_version + 1
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
    -- 정지시킬 때는 살아 있는 세션도 함께 끊습니다.
    update public.users
       set is_active = p_active,
           session_version = case when p_active then session_version
                                  else session_version + 1 end
     where id = p_user_id;
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
    -- 권한을 "해제"할 때만 세션을 끊습니다. 부여할 때는 세션 검사가 60초 안에
    -- is_admin 을 자동으로 따라가므로 굳이 재로그인시킬 필요가 없습니다.
    update public.users
       set is_admin = p_is_admin,
           session_version = case when p_is_admin then session_version
                                  else session_version + 1 end
     where id = p_user_id;
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


-- 관리자 행위 기록
create or replace function public.log_admin_action(
    p_secret text,
    p_actor text,
    p_action text,
    p_target_user_id bigint default null,
    p_target_username text default null,
    p_detail text default null,
    p_ip text default null
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

    insert into public.admin_actions
        (actor, action, target_user_id, target_username, detail, ip)
    values
        (p_actor, p_action, p_target_user_id, p_target_username, p_detail, p_ip);

    return jsonb_build_object('success', true);
end;
$$;


create or replace function public.get_admin_actions(
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
        return jsonb_build_object('total', 0, 'actions', '[]'::jsonb);
    end if;

    select count(*) into v_total from public.admin_actions;

    select coalesce(jsonb_agg(t order by t.created_at desc), '[]'::jsonb) into v_rows
      from (
        select id, actor, action, target_user_id, target_username,
               detail, ip, created_at
          from public.admin_actions
         order by created_at desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object('total', v_total, 'actions', v_rows);
end;
$$;


-- 오래된 기록 정리.
-- login_attempts 는 로그인마다 1행씩 쌓이고 잠금 판정이 매번 이 테이블을 읽으므로
-- 방치하면 로그인이 점점 느려집니다.
--
-- p_force = false 이면 마지막 정리 후 하루가 지났을 때만 실제로 동작합니다.
-- 관리자 화면 진입 시 호출해도 부담이 없도록 하기 위한 장치입니다.
create or replace function public.prune_old_records(
    p_secret text,
    p_days int default 90,
    p_force boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_last timestamptz;
    v_attempts int;
    v_resets int;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'ran', false);
    end if;

    select last_pruned_at into v_last from public.app_settings where id = true;

    if not p_force and v_last is not null and v_last > now() - interval '1 day' then
        return jsonb_build_object('success', true, 'ran', false);
    end if;

    delete from public.login_attempts
     where attempted_at < now() - (p_days || ' days')::interval;
    get diagnostics v_attempts = row_count;

    -- 이미 쓰였거나 만료된 재설정 토큰은 보관할 이유가 없습니다.
    delete from public.password_resets
     where used_at is not null or expires_at < now() - interval '7 days';
    get diagnostics v_resets = row_count;

    -- 감사 로그는 더 오래 (1년) 보관합니다.
    delete from public.admin_actions
     where created_at < now() - interval '365 days';

    update public.app_settings set last_pruned_at = now() where id = true;

    return jsonb_build_object(
        'success', true, 'ran', true,
        'deleted_attempts', v_attempts,
        'deleted_resets', v_resets
    );
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
grant execute on function public.check_login_lock(text, text, text) to anon, authenticated;
grant execute on function public.record_login_attempt(text, text, text, boolean) to anon, authenticated;
grant execute on function public.get_user_session_state(text, bigint) to anon, authenticated;
grant execute on function public.force_logout_user(text, bigint) to anon, authenticated;
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
grant execute on function public.log_admin_action(text, text, text, bigint, text, text, text) to anon, authenticated;
grant execute on function public.get_admin_actions(text, int, int) to anon, authenticated;
grant execute on function public.prune_old_records(text, int, boolean) to anon, authenticated;


-- ============================================================
-- 8. 마지막으로 이 값을 복사해서 환경변수 SUPABASE_RPC_SECRET 에 넣으세요.
--    (.env 와 Vercel > Settings > Environment Variables 양쪽 모두)
-- ============================================================

select rpc_secret as "이_값을_SUPABASE_RPC_SECRET_에_넣으세요"
  from public.app_settings where id = true;
