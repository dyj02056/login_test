-- Supabase SQL Editor에서 이 스크립트를 한 번 실행하세요.
-- (Dashboard > SQL Editor > New query > 붙여넣기 > Run)

-- 비밀번호 해싱을 위한 확장 기능 (Supabase는 extensions 스키마에 설치함)
create extension if not exists pgcrypto with schema extensions;

-- 사용자 테이블
create table if not exists public.users (
    id bigint generated always as identity primary key,
    username text unique not null,
    password_hash text not null,
    created_at timestamptz not null default now()
);

-- RLS 활성화 + 정책을 하나도 만들지 않음
-- => anon 키로는 이 테이블을 직접 select/insert 할 수 없음 (아래 함수를 통해서만 접근 가능)
alter table public.users enable row level security;

-- 회원가입 함수: 검증 + 비밀번호 해싱 + 저장을 DB 안에서 안전하게 처리
create or replace function public.signup_user(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_id bigint;
begin
    if length(p_username) < 3 then
        return jsonb_build_object('success', false, 'error', '아이디는 3자 이상이어야 합니다.');
    end if;
    if length(p_password) < 6 then
        return jsonb_build_object('success', false, 'error', '비밀번호는 6자 이상이어야 합니다.');
    end if;
    if exists (select 1 from public.users where username = p_username) then
        return jsonb_build_object('success', false, 'error', '이미 사용 중인 아이디입니다.');
    end if;

    insert into public.users (username, password_hash)
    values (p_username, extensions.crypt(p_password, extensions.gen_salt('bf')))
    returning id into v_id;

    return jsonb_build_object('success', true, 'id', v_id);
end;
$$;

-- 로그인 함수: 비밀번호 해시는 함수 밖으로 절대 나가지 않음
create or replace function public.login_user(p_username text, p_password text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
begin
    select id, username, password_hash into v_user
    from public.users
    where username = p_username;

    if v_user is null or v_user.password_hash <> extensions.crypt(p_password, v_user.password_hash) then
        return jsonb_build_object('success', false);
    end if;

    return jsonb_build_object('success', true, 'id', v_user.id, 'username', v_user.username);
end;
$$;

-- publishable(anon) 키로 위 두 함수만 호출할 수 있도록 권한 부여
grant execute on function public.signup_user(text, text) to anon, authenticated;
grant execute on function public.login_user(text, text) to anon, authenticated;

-- ── 관리자용: 회원가입 on/off 설정 ──────────────────────────────
-- 배포 환경(Vercel)은 서버리스라 서버 메모리에 상태를 못 두므로 Supabase에 저장합니다.
create table if not exists public.app_settings (
    id boolean primary key default true,
    signup_enabled boolean not null default true,
    constraint app_settings_singleton check (id = true)
);

insert into public.app_settings (id, signup_enabled)
values (true, true)
on conflict (id) do nothing;

alter table public.app_settings enable row level security;

-- 현재 회원가입 가능 여부 조회 (누구나 호출 가능해야 /signup 페이지가 동작함)
create or replace function public.get_signup_enabled()
returns boolean
language sql
security definer
set search_path = public
as $$
    select signup_enabled from public.app_settings where id = true;
$$;

-- 회원가입 on/off 전환 (Flask 쪽에서 관리자 로그인 확인 후에만 호출함)
create or replace function public.set_signup_enabled(p_enabled boolean)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    update public.app_settings set signup_enabled = p_enabled where id = true;
    return jsonb_build_object('success', true, 'signup_enabled', p_enabled);
end;
$$;

grant execute on function public.get_signup_enabled() to anon, authenticated;
grant execute on function public.set_signup_enabled(boolean) to anon, authenticated;
