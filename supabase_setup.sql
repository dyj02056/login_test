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

-- 이메일 인증 여부. 현재 로그인 조건은 아니며 상태 표시용입니다.
alter table public.users add column if not exists email_verified boolean not null default false;

-- 로그인 시도 기록 (무차별 대입 차단 + 감사 로그)
create table if not exists public.login_attempts (
    id bigint generated always as identity primary key,
    username text not null,
    ip text,
    success boolean not null,
    attempted_at timestamptz not null default now()
);

-- 침입 탐지를 위한 부가 정보. 규칙을 만들기 전에 먼저 쌓아 두어야
-- 임계값을 추측이 아니라 실제 데이터로 정할 수 있습니다.
alter table public.login_attempts add column if not exists user_agent text;
alter table public.login_attempts add column if not exists country text;
alter table public.login_attempts add column if not exists city text;
alter table public.login_attempts add column if not exists lat numeric;
alter table public.login_attempts add column if not exists lon numeric;
-- 존재하지 않는 아이디만 시도하는 정찰(reconnaissance) 탐지에 씁니다.
alter table public.login_attempts add column if not exists user_existed boolean;

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

-- IP 평판. 로그인 잠금(15분)과 달리 누적 관리되며, 아이디를 바꿔가며
-- 시도하는 공격을 IP 단위로 승격해 차단합니다.
create table if not exists public.ip_reputation (
    ip text primary key,
    score int not null default 0,              -- 0~100, 높을수록 위험
    blocked_until timestamptz,                 -- 이 시각까지 전면 차단
    manual_override text,                      -- 'allow' | 'block' | null (관리자 판단 우선)
    reasons jsonb not null default '[]'::jsonb,-- 점수가 오른 근거 누적
    first_seen timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    constraint ip_reputation_override_check
        check (manual_override is null or manual_override in ('allow', 'block'))
);

create index if not exists ip_reputation_blocked_idx
    on public.ip_reputation (blocked_until desc) where blocked_until is not null;
create index if not exists ip_reputation_score_idx
    on public.ip_reputation (score desc);


-- 회원별 "평소 로그인 모습". 성공한 로그인만 반영해 정상 패턴을 학습하고,
-- 이후 로그인이 이 패턴에서 얼마나 벗어나는지로 위험도를 판단합니다.
create table if not exists public.user_login_profile (
    user_id bigint primary key references public.users(id) on delete cascade,
    known_ips jsonb not null default '[]'::jsonb,
    known_countries jsonb not null default '[]'::jsonb,
    known_agents jsonb not null default '[]'::jsonb,   -- User-Agent 해시
    typical_hours int[] not null default '{}',         -- 주로 로그인하는 시(0~23)
    last_lat numeric,
    last_lon numeric,
    last_login_at timestamptz,
    login_count int not null default 0,
    updated_at timestamptz not null default now()
);


-- 위험도가 매겨진 로그인 기록. 차단 여부와 무관하게 남겨서
-- 임계값을 실제 데이터로 정할 수 있게 합니다(섀도 모드).
create table if not exists public.login_risk_events (
    id bigint generated always as identity primary key,
    user_id bigint,
    username text,
    ip text,
    country text,
    city text,
    score int not null,
    reasons jsonb not null default '[]'::jsonb,
    action text not null,          -- 'allowed' | 'flagged' | 'blocked'
    created_at timestamptz not null default now()
);

create index if not exists login_risk_events_time_idx
    on public.login_risk_events (created_at desc);
create index if not exists login_risk_events_score_idx
    on public.login_risk_events (score desc, created_at desc);


-- 가입·재설정 남용을 막기 위한 사건 기록.
-- 로그인 잠금과 성격이 달라(계정이 아니라 IP 남용을 봄) 별도 테이블로 둡니다.
create table if not exists public.rate_events (
    id bigint generated always as identity primary key,
    kind text not null,          -- 'signup' | 'password_reset'
    ip text,
    subject text,                -- 대상 아이디 (재설정에서 사용)
    created_at timestamptz not null default now()
);

create index if not exists rate_events_kind_ip_time_idx
    on public.rate_events (kind, ip, created_at desc);
create index if not exists rate_events_kind_subject_time_idx
    on public.rate_events (kind, subject, created_at desc);


-- 이메일 인증 토큰. 비밀번호 재설정과 동일하게 원문은 저장하지 않고 해시만 보관합니다.
create table if not exists public.email_verifications (
    id bigint generated always as identity primary key,
    user_id bigint not null references public.users(id) on delete cascade,
    token_hash text not null,
    expires_at timestamptz not null,
    used_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists email_verifications_user_idx
    on public.email_verifications (user_id);


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
alter table public.rate_events enable row level security;
alter table public.email_verifications enable row level security;
alter table public.ip_reputation enable row level security;
alter table public.user_login_profile enable row level security;
alter table public.login_risk_events enable row level security;

-- 위험 점수가 이 값 이상이면 로그인을 차단합니다.
-- 기본 101 = 아무것도 차단하지 않음(섀도 모드). 실제 데이터로 오탐이 없음을
-- 확인한 뒤 관리자 화면에서 86 등으로 낮추는 것을 전제로 합니다.
alter table public.app_settings
    add column if not exists risk_block_threshold int not null default 101;

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
    -- ① IP 평판에 의한 차단이 최우선. 아이디를 바꿔가며 시도하는 공격은
    --    계정 단위 잠금으로는 막히지 않으므로 IP 단위 차단이 필요하다.
    select coalesce((
        select case
            when manual_override = 'allow' then false
            when manual_override = 'block' then true
            else blocked_until is not null and blocked_until > now()
        end
        from public.ip_reputation where ip = p_ip
    ), false)
    or
    -- ② 계정 단위 잠금 (기존 규칙)
    case
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


-- 가입·재설정 남용 판정. IP 를 알 수 없으면 제한하지 않습니다
-- (IP 없이 아이디만으로 막으면 남을 방해하는 수단이 되기 때문).
create or replace function public.is_rate_limited(
    p_kind text,
    p_ip text,
    p_subject text,
    p_ip_limit int,
    p_subject_limit int,
    p_minutes int
)
returns boolean
language sql
security definer
set search_path = public
as $$
    select
        (
            coalesce(p_ip, '') <> ''
            and (select count(*) from public.rate_events
                  where kind = p_kind and ip = p_ip
                    and created_at > now() - (p_minutes || ' minutes')::interval
                ) >= p_ip_limit
        )
        or
        (
            p_subject_limit is not null
            and coalesce(p_subject, '') <> ''
            and (select count(*) from public.rate_events
                  where kind = p_kind and subject = p_subject
                    and created_at > now() - (p_minutes || ' minutes')::interval
                ) >= p_subject_limit
        );
$$;

revoke all on function public.is_rate_limited(text, text, text, int, int, int)
    from public, anon, authenticated;


-- 로그인 시도 1건을 기록하는 내부 헬퍼.
-- 기록 지점이 여러 곳(일반 로그인 / 환경변수 관리자)이라 한 곳에 모아 둡니다.
-- p_context 예: {"ua":"...", "country":"KR", "city":"Seoul", "lat":"37.5", "lon":"127.0"}
create or replace function public.record_attempt_internal(
    p_username text,
    p_ip text,
    p_success boolean,
    p_context jsonb,
    p_user_existed boolean
)
returns void
language sql
security definer
set search_path = public
as $$
    insert into public.login_attempts
        (username, ip, success, user_agent, country, city, lat, lon, user_existed)
    values (
        p_username,
        p_ip,
        p_success,
        nullif(p_context->>'ua', ''),
        nullif(p_context->>'country', ''),
        nullif(p_context->>'city', ''),
        nullif(p_context->>'lat', '')::numeric,
        nullif(p_context->>'lon', '')::numeric,
        p_user_existed
    );
$$;

revoke all on function public.record_attempt_internal(text, text, boolean, jsonb, boolean)
    from public, anon, authenticated;


-- ============================================================
-- 2-2. 침입 탐지 (IP 평판)
-- ============================================================

-- 최근 행동을 근거로 IP 위험 점수를 계산한다.
-- 순수 조회 함수이므로 부작용이 없고, 규칙을 바꿀 때는 여기만 고치면 된다.
--
-- 반환: {score, reasons[]}
create or replace function public.assess_ip(p_ip text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_score int := 0;
    v_reasons text[] := '{}';
    v_fails int;
    v_distinct_users int;
    v_total int;
    v_success int;
    v_ghost int;
    v_bot int;
    v_burst int;
begin
    if coalesce(p_ip, '') = '' then
        return jsonb_build_object('score', 0, 'reasons', '[]'::jsonb);
    end if;

    -- 최근 30분 집계를 한 번에 계산
    select
        count(*) filter (where not success),
        count(distinct username) filter (where not success),
        count(*),
        count(*) filter (where success),
        count(*) filter (where not success and user_existed is false),
        count(*) filter (where user_agent is null
                            or user_agent ~* '(curl|wget|python-requests|go-http|libwww|scrapy|httpclient)'),
        count(*) filter (where attempted_at > now() - interval '1 minute')
      into v_fails, v_distinct_users, v_total, v_success, v_ghost, v_bot, v_burst
      from public.login_attempts
     where ip = p_ip
       and attempted_at > now() - interval '30 minutes';

    -- 한 계정 무차별 대입
    if v_fails >= 10 then
        v_score := v_score + 40;
        v_reasons := v_reasons || format('30분 내 로그인 실패 %s회', v_fails);
    elsif v_fails >= 5 then
        v_score := v_score + 20;
        v_reasons := v_reasons || format('30분 내 로그인 실패 %s회', v_fails);
    end if;

    -- 아이디 스프레이 (가장 흔한 봇 패턴)
    if v_distinct_users >= 8 then
        v_score := v_score + 50;
        v_reasons := v_reasons || format('서로 다른 아이디 %s개 시도(스프레이)', v_distinct_users);
    elsif v_distinct_users >= 4 then
        v_score := v_score + 25;
        v_reasons := v_reasons || format('서로 다른 아이디 %s개 시도', v_distinct_users);
    end if;

    -- 크리덴셜 스터핑: 시도는 많은데 성공률이 극히 낮음
    if v_total >= 30 and v_success::numeric / greatest(v_total, 1) < 0.05 then
        v_score := v_score + 30;
        v_reasons := v_reasons || format('시도 %s회 중 성공 %s회(스터핑 의심)', v_total, v_success);
    end if;

    -- 정찰: 존재하지 않는 계정만 훑음
    if v_ghost >= 5 and v_ghost::numeric / greatest(v_fails, 1) > 0.8 then
        v_score := v_score + 35;
        v_reasons := v_reasons || format('없는 계정 위주로 %s회 시도(정찰)', v_ghost);
    end if;

    -- 자동화 도구 흔적
    -- 타입을 명시하지 않으면 PostgreSQL 이 배열||배열로 해석해
    -- "malformed array literal" 오류가 납니다. ::text 를 반드시 붙일 것.
    if v_bot >= 3 then
        v_score := v_score + 25;
        v_reasons := v_reasons || '자동화 도구 User-Agent'::text;
    end if;

    -- 비인간 속도
    if v_burst >= 10 then
        v_score := v_score + 30;
        v_reasons := v_reasons || format('1분 내 %s회 요청', v_burst);
    end if;

    return jsonb_build_object(
        'score', least(v_score, 100),
        'reasons', to_jsonb(v_reasons)
    );
end;
$$;

revoke all on function public.assess_ip(text) from public, anon, authenticated;


-- 평가 결과를 ip_reputation 에 반영하고, 임계값을 넘으면 차단 시각을 찍는다.
-- 점수가 높을수록 차단 시간이 길어진다.
create or replace function public.update_ip_reputation(p_ip text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_assess jsonb;
    v_score int;
    v_block_minutes int := 0;
    v_existing record;
begin
    if coalesce(p_ip, '') = '' then
        return jsonb_build_object('blocked', false, 'score', 0);
    end if;

    v_assess := public.assess_ip(p_ip);
    v_score := (v_assess->>'score')::int;

    select manual_override into v_existing from public.ip_reputation where ip = p_ip;

    -- 관리자가 직접 허용한 IP 는 점수와 무관하게 차단하지 않는다.
    -- 회사·학교처럼 여러 사람이 한 IP 를 쓰는 경우의 오탐 안전장치.
    if v_existing.manual_override = 'allow' then
        insert into public.ip_reputation (ip, score, last_seen)
        values (p_ip, v_score, now())
        on conflict (ip) do update
            set score = excluded.score, last_seen = now(),
                reasons = v_assess->'reasons';
        return jsonb_build_object('blocked', false, 'score', v_score, 'override', 'allow');
    end if;

    if v_score >= 90 then
        v_block_minutes := 360;   -- 6시간
    elsif v_score >= 70 then
        v_block_minutes := 60;
    elsif v_score >= 50 then
        v_block_minutes := 15;
    end if;

    insert into public.ip_reputation (ip, score, reasons, last_seen, blocked_until)
    values (
        p_ip, v_score, v_assess->'reasons', now(),
        case when v_block_minutes > 0
             then now() + (v_block_minutes || ' minutes')::interval end
    )
    on conflict (ip) do update
        set score = excluded.score,
            reasons = excluded.reasons,
            last_seen = now(),
            -- 이미 걸린 차단은 줄이지 않고 더 긴 쪽을 유지한다
            blocked_until = greatest(
                public.ip_reputation.blocked_until,
                excluded.blocked_until
            );

    return jsonb_build_object(
        'blocked', v_block_minutes > 0,
        'score', v_score,
        'block_minutes', v_block_minutes,
        'reasons', v_assess->'reasons'
    );
end;
$$;

revoke all on function public.update_ip_reputation(text) from public, anon, authenticated;


-- ============================================================
-- 2-3. 로그인 위험 평가 (계정 도용 탐지)
-- ============================================================

-- 두 좌표 사이 거리(km). 하버사인 공식.
create or replace function public.geo_distance_km(
    lat1 numeric, lon1 numeric, lat2 numeric, lon2 numeric
)
returns numeric
language sql
immutable
as $$
    select 2 * 6371 * asin(sqrt(
        power(sin(radians(lat2 - lat1) / 2), 2)
        + cos(radians(lat1)) * cos(radians(lat2))
        * power(sin(radians(lon2 - lon1) / 2), 2)
    ));
$$;


-- 비밀번호가 맞은 로그인이 "정말 본인인지" 평가한다.
-- 평소 패턴에서 벗어난 정도를 점수로 매기고, 프로필을 갱신한다.
create or replace function public.assess_login_risk(
    p_user_id bigint,
    p_username text,
    p_ip text,
    p_context jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_p record;
    v_score int := 0;
    v_reasons text[] := '{}';
    v_ua_hash text;
    v_country text;
    v_lat numeric;
    v_lon numeric;
    v_hour int := extract(hour from now())::int;
    v_km numeric;
    v_hours numeric;
    v_speed numeric;
    v_other_fails int;
    v_own_fails int;
    v_threshold int;
    v_action text;
begin
    v_country := nullif(p_context->>'country', '');
    v_lat := nullif(p_context->>'lat', '')::numeric;
    v_lon := nullif(p_context->>'lon', '')::numeric;
    v_ua_hash := md5(coalesce(p_context->>'ua', ''));

    select * into v_p from public.user_login_profile where user_id = p_user_id;

    -- 첫 로그인은 비교 대상이 없으므로 점수를 매기지 않고 프로필만 만든다.
    if v_p.user_id is null or v_p.login_count < 1 then
        insert into public.user_login_profile
            (user_id, known_ips, known_countries, known_agents, typical_hours,
             last_lat, last_lon, last_login_at, login_count)
        values (
            p_user_id,
            jsonb_build_array(p_ip),
            case when v_country is null then '[]'::jsonb else jsonb_build_array(v_country) end,
            jsonb_build_array(v_ua_hash),
            array[v_hour],
            v_lat, v_lon, now(), 1
        )
        on conflict (user_id) do update
            set known_ips = jsonb_build_array(p_ip),
                known_countries = case when v_country is null then '[]'::jsonb
                                       else jsonb_build_array(v_country) end,
                known_agents = jsonb_build_array(v_ua_hash),
                typical_hours = array[v_hour],
                last_lat = v_lat, last_lon = v_lon,
                last_login_at = now(),
                login_count = public.user_login_profile.login_count + 1,
                updated_at = now();

        return jsonb_build_object('score', 0, 'reasons', '[]'::jsonb,
                                  'action', 'allowed', 'first_login', true);
    end if;

    -- ① 처음 보는 IP
    if not (v_p.known_ips ? p_ip) then
        v_score := v_score + 15;
        v_reasons := v_reasons || '처음 보는 IP'::text;
    end if;

    -- ② 처음 보는 국가 (IP 변경보다 훨씬 강한 신호)
    if v_country is not null and not (v_p.known_countries ? v_country) then
        v_score := v_score + 35;
        v_reasons := v_reasons || format('처음 보는 국가(%s)', v_country);
    end if;

    -- ③ 처음 보는 기기
    if not (v_p.known_agents ? v_ua_hash) then
        v_score := v_score + 15;
        v_reasons := v_reasons || '처음 보는 기기'::text;
    end if;

    -- ④ 평소와 다른 시간대 (표본이 쌓인 뒤에만 판단)
    if v_p.login_count >= 5 and not (v_hour = any(v_p.typical_hours)) then
        v_score := v_score + 10;
        v_reasons := v_reasons || format('평소와 다른 시간대(%s시)', v_hour);
    end if;

    -- ⑤ 불가능한 이동 — 가장 강한 신호
    if v_lat is not null and v_p.last_lat is not null and v_p.last_login_at is not null then
        v_km := public.geo_distance_km(v_p.last_lat, v_p.last_lon, v_lat, v_lon);
        v_hours := greatest(
            extract(epoch from (now() - v_p.last_login_at)) / 3600.0,
            0.01
        );
        v_speed := v_km / v_hours;
        -- 여객기 순항속도(약 900km/h)를 크게 넘으면 물리적으로 불가능하다.
        if v_km > 500 and v_speed > 1000 then
            v_score := v_score + 60;
            v_reasons := v_reasons || format(
                '불가능한 이동: %s분 만에 %skm (필요속도 %skm/h)',
                round(v_hours * 60), round(v_km), round(v_speed)
            );
        end if;
    end if;

    -- ⑥ 이 IP 가 최근 다른 계정을 공격했다면 성공 로그인도 의심스럽다
    select count(*) into v_other_fails
      from public.login_attempts
     where ip = p_ip and not success
       and username <> p_username
       and attempted_at > now() - interval '1 hour';
    if v_other_fails >= 5 then
        v_score := v_score + 40;
        v_reasons := v_reasons || format('같은 IP 가 다른 계정 %s회 실패시킴', v_other_fails);
    end if;

    -- ⑦ 이 계정이 직전에 집중적으로 시도당했다면 대입 끝에 뚫렸을 수 있다
    select count(*) into v_own_fails
      from public.login_attempts
     where username = p_username and not success
       and attempted_at > now() - interval '1 hour';
    if v_own_fails >= 10 then
        v_score := v_score + 25;
        v_reasons := v_reasons || format('직전 1시간 이 계정 실패 %s회', v_own_fails);
    end if;

    v_score := least(v_score, 100);

    select risk_block_threshold into v_threshold from public.app_settings where id = true;
    if v_score >= coalesce(v_threshold, 101) then
        v_action := 'blocked';
    elsif v_score >= 61 then
        v_action := 'flagged';
    else
        v_action := 'allowed';
    end if;

    -- 정상으로 판정된 로그인만 학습한다.
    -- 의심스러운 로그인(flagged)까지 학습하면, 공격자가 한 번 통과하는 순간
    -- 그 위치·기기가 "평소 패턴"이 되어 이후 탐지가 무력화된다.
    -- 대가로 실제 해외 출장자는 매번 주의로 표시되는데, 이는 본인 확인 수단
    -- (이메일 코드)이 붙는 다음 단계에서 "본인 맞음"을 눌러 해소할 부분이다.
    if v_action = 'allowed' then
        update public.user_login_profile
           set known_ips = case when known_ips ? p_ip then known_ips
                                else (
                                    -- 최근 10개만 유지
                                    select jsonb_agg(v) from (
                                        select v from jsonb_array_elements(
                                            jsonb_build_array(p_ip) || known_ips
                                        ) v limit 10
                                    ) t
                                ) end,
               known_countries = case
                    when v_country is null or known_countries ? v_country then known_countries
                    else known_countries || jsonb_build_array(v_country) end,
               known_agents = case when known_agents ? v_ua_hash then known_agents
                                   else (
                                       select jsonb_agg(v) from (
                                           select v from jsonb_array_elements(
                                               jsonb_build_array(v_ua_hash) || known_agents
                                           ) v limit 5
                                       ) t
                                   ) end,
               typical_hours = case when v_hour = any(typical_hours) then typical_hours
                                    else typical_hours || v_hour end,
               last_lat = coalesce(v_lat, last_lat),
               last_lon = coalesce(v_lon, last_lon),
               last_login_at = now(),
               login_count = login_count + 1,
               updated_at = now()
         where user_id = p_user_id;
    end if;

    if v_score > 0 then
        insert into public.login_risk_events
            (user_id, username, ip, country, city, score, reasons, action)
        values (
            p_user_id, p_username, p_ip, v_country,
            nullif(p_context->>'city', ''), v_score, to_jsonb(v_reasons), v_action
        );
    end if;

    return jsonb_build_object(
        'score', v_score,
        'reasons', to_jsonb(v_reasons),
        'action', v_action
    );
end;
$$;

revoke all on function public.assess_login_risk(bigint, text, text, jsonb)
    from public, anon, authenticated;


-- 이전 버전의 함수 시그니처 제거 (인자가 바뀌었으므로)
drop function if exists public.signup_user(text, text);
drop function if exists public.login_user(text, text);
drop function if exists public.get_signup_enabled();
drop function if exists public.set_signup_enabled(boolean);

-- p_context 를 추가하면서 인자 수가 바뀌므로 이전 시그니처를 제거합니다.
-- 새 함수는 p_context 에 기본값이 있어 구버전의 4인자 호출도 그대로 동작합니다.
drop function if exists public.login_user(text, text, text, text);
drop function if exists public.record_login_attempt(text, text, text, boolean);


-- ============================================================
-- 3. 인증 (회원가입 / 로그인)
-- ============================================================

create or replace function public.signup_user(
    p_secret text,
    p_username text,
    p_password text,
    p_email text,
    p_ip text
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

    -- 한 IP 가 계정을 대량 생성하는 것을 막습니다. 성공한 가입만 세므로
    -- 비밀번호 오타 같은 실패는 정상 사용자를 막지 않습니다.
    if public.is_rate_limited('signup', p_ip, null, 5, null, 60) then
        return jsonb_build_object(
            'success', false,
            'error', '가입 시도가 너무 많습니다. 잠시 후 다시 시도해 주세요.'
        );
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

    insert into public.rate_events (kind, ip, subject)
    values ('signup', p_ip, p_username);

    return jsonb_build_object('success', true, 'id', v_id);
end;
$$;


-- 구버전 코드(4인자) 호환용 래퍼.
-- 이것이 없으면 SQL 을 먼저 실행하는 순간부터 새 코드가 배포되기 전까지
-- 운영 사이트의 회원가입이 죽습니다.
create or replace function public.signup_user(
    p_secret text,
    p_username text,
    p_password text,
    p_email text default null
)
returns jsonb
language sql
security definer
set search_path = public
as $$
    select public.signup_user(p_secret, p_username, p_password, p_email, null);
$$;


-- 로그인: 15분 내 5회 실패 시 계정 잠금, 모든 시도를 기록
create or replace function public.login_user(
    p_secret text,
    p_username text,
    p_password text,
    p_ip text default null,
    p_context jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_user record;
    v_ok boolean := false;
    v_existed boolean;
    v_risk jsonb;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'reason', 'secret');
    end if;

    if public.is_login_locked(p_username, p_ip) then
        perform public.record_attempt_internal(
            p_username, p_ip, false, p_context,
            exists (select 1 from public.users where username = p_username)
        );
        return jsonb_build_object('success', false, 'reason', 'locked');
    end if;

    select id, username, password_hash, is_active, is_admin, session_version
      into v_user
      from public.users
     where username = p_username;

    v_existed := v_user.id is not null;

    if v_existed
       and v_user.password_hash = extensions.crypt(p_password, v_user.password_hash) then
        v_ok := true;
    end if;

    perform public.record_attempt_internal(
        p_username, p_ip, v_ok, p_context, v_existed
    );

    -- 실패했을 때만 평판을 다시 계산한다. 성공은 위험 신호가 아니고,
    -- 매번 계산하면 정상 로그인에도 집계 쿼리가 붙는다.
    if not v_ok then
        perform public.update_ip_reputation(p_ip);
    end if;

    if not v_ok then
        return jsonb_build_object('success', false, 'reason', 'credentials');
    end if;

    if not v_user.is_active then
        return jsonb_build_object('success', false, 'reason', 'inactive');
    end if;

    -- 비밀번호는 맞았다. 이제 "정말 본인인가"를 평소 패턴과 비교해 판단한다.
    v_risk := public.assess_login_risk(
        v_user.id, v_user.username, p_ip, p_context
    );

    if v_risk->>'action' = 'blocked' then
        return jsonb_build_object(
            'success', false,
            'reason', 'risk',
            'risk_score', (v_risk->>'score')::int,
            'risk_reasons', v_risk->'reasons'
        );
    end if;

    return jsonb_build_object(
        'success', true,
        'id', v_user.id,
        'username', v_user.username,
        'is_admin', v_user.is_admin,
        'session_version', v_user.session_version,
        'risk_score', (v_risk->>'score')::int,
        'risk_action', v_risk->>'action',
        'risk_reasons', v_risk->'reasons'
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
    p_success boolean,
    p_context jsonb default '{}'::jsonb
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

    -- 환경변수 관리자는 DB 계정이 아니므로 user_existed 는 null(해당 없음)입니다.
    -- false 로 두면 "없는 계정을 시도했다"는 뜻이 되어, 존재하지 않는 아이디만
    -- 훑는 정찰 공격 탐지 통계를 정상 관리자 로그인이 오염시킵니다.
    perform public.record_attempt_internal(
        p_username, p_ip, p_success, p_context, null
    );

    if not p_success then
        perform public.update_ip_reputation(p_ip);
    end if;

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

    select is_active, is_admin, session_version, email, email_verified into v
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
        'session_version', v.session_version,
        'has_email', coalesce(v.email, '') <> '',
        'email_verified', v.email_verified
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
    p_username text,
    p_ip text
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

    -- IP 기준 5회, 아이디 기준 3회. 아이디 제한은 특정인의 메일함을
    -- 재설정 메일로 도배하는 것을 막기 위한 것입니다.
    if public.is_rate_limited('password_reset', p_ip, p_username, 5, 3, 60) then
        return jsonb_build_object(
            'success', false,
            'error', '재설정 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.'
        );
    end if;

    -- 존재 여부와 무관하게 기록합니다. 없는 아이디로 훑는 것도 제한 대상입니다.
    insert into public.rate_events (kind, ip, subject)
    values ('password_reset', p_ip, p_username);

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


-- 구버전 코드(2인자) 호환용 래퍼. signup_user 와 같은 이유로 남겨 둡니다.
create or replace function public.create_password_reset(
    p_secret text,
    p_username text
)
returns jsonb
language sql
security definer
set search_path = public
as $$
    select public.create_password_reset(p_secret, p_username, null);
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


-- ── 이메일 인증 ────────────────────────────────────────────
-- 재설정과 같은 토큰 방식. 현재 로그인 조건은 아니며 상태 표시용입니다.
-- 이메일이 선택 입력이고 메일 발송이 아직 꺼져 있어, 인증을 강제하면
-- 기존 회원이 모두 잠기기 때문입니다.
create or replace function public.create_email_verification(
    p_secret text,
    p_user_id bigint
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
        return jsonb_build_object('success', false);
    end if;

    select id, username, email, email_verified into v_user
      from public.users where id = p_user_id;

    if v_user.id is null or coalesce(v_user.email, '') = '' then
        return jsonb_build_object('success', true, 'issued', false, 'reason', 'no_email');
    end if;

    if v_user.email_verified then
        return jsonb_build_object('success', true, 'issued', false, 'reason', 'already');
    end if;

    v_token := encode(extensions.gen_random_bytes(24), 'hex');

    insert into public.email_verifications (user_id, token_hash, expires_at)
    values (
        v_user.id,
        encode(extensions.digest(v_token, 'sha256'), 'hex'),
        now() + interval '24 hours'
    );

    return jsonb_build_object(
        'success', true, 'issued', true,
        'token', v_token,
        'username', v_user.username,
        'email', v_user.email
    );
end;
$$;


create or replace function public.verify_email_with_token(
    p_secret text,
    p_token text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    v_row record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false, 'error', '서버 인증에 실패했습니다.');
    end if;

    select id, user_id into v_row
      from public.email_verifications
     where token_hash = encode(extensions.digest(p_token, 'sha256'), 'hex')
       and used_at is null
       and expires_at > now();

    if v_row.id is null then
        return jsonb_build_object('success', false,
            'error', '링크가 만료되었거나 이미 사용되었습니다.');
    end if;

    update public.users set email_verified = true where id = v_row.user_id;
    update public.email_verifications set used_at = now() where id = v_row.id;

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
        select id, username, email, email_verified, is_active, is_admin, created_at
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
        select id, username, ip, success, attempted_at,
               user_agent, country, city, user_existed
          from public.login_attempts
         order by attempted_at desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object('total', v_total, 'attempts', v_rows);
end;
$$;


-- ── 침입 탐지: 관리자 조회·조작 ──────────────────────────
create or replace function public.list_ip_reputation(
    p_secret text,
    p_limit int default 50,
    p_offset int default 0,
    p_only_flagged boolean default true
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
    v_rows jsonb;
    v_total int;
    v_blocked int;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('total', 0, 'items', '[]'::jsonb);
    end if;

    select count(*) into v_total
      from public.ip_reputation
     where not p_only_flagged or score > 0 or manual_override is not null;

    select count(*) into v_blocked
      from public.ip_reputation
     where (blocked_until is not null and blocked_until > now())
        or manual_override = 'block';

    select coalesce(jsonb_agg(t order by t.sort_key desc, t.score desc), '[]'::jsonb)
      into v_rows
      from (
        select ip, score, blocked_until, manual_override, reasons,
               first_seen, last_seen,
               (blocked_until is not null and blocked_until > now()) as is_blocked,
               extract(epoch from last_seen) as sort_key
          from public.ip_reputation
         where not p_only_flagged or score > 0 or manual_override is not null
         order by last_seen desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object('total', v_total, 'blocked', v_blocked, 'items', v_rows);
end;
$$;


-- 관리자 수동 판단. 'allow' 는 오탐 구제(회사·학교 공용 IP 등),
-- 'block' 은 영구 차단, null 은 자동 판정으로 되돌림.
create or replace function public.set_ip_override(
    p_secret text,
    p_ip text,
    p_override text          -- 'allow' | 'block' | null
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

    if p_override is not null and p_override not in ('allow', 'block') then
        return jsonb_build_object('success', false, 'error', 'invalid override');
    end if;

    insert into public.ip_reputation (ip, manual_override, blocked_until, last_seen)
    values (
        p_ip, p_override,
        case when p_override = 'block' then now() + interval '100 years' end,
        now()
    )
    on conflict (ip) do update
        set manual_override = p_override,
            -- allow 로 구제하면 걸려 있던 자동 차단도 함께 푼다
            blocked_until = case
                when p_override = 'allow' then null
                when p_override = 'block' then now() + interval '100 years'
                else public.ip_reputation.blocked_until
            end,
            last_seen = now();

    return jsonb_build_object('success', true);
end;
$$;


-- 위험도가 매겨진 로그인 목록 (관리자 화면)
create or replace function public.list_risk_events(
    p_secret text,
    p_limit int default 30,
    p_offset int default 0,
    p_min_score int default 1
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
        return jsonb_build_object('total', 0, 'events', '[]'::jsonb);
    end if;

    select count(*) into v_total
      from public.login_risk_events where score >= p_min_score;

    select coalesce(jsonb_agg(t order by t.created_at desc), '[]'::jsonb) into v_rows
      from (
        select id, username, ip, country, city, score, reasons, action, created_at
          from public.login_risk_events
         where score >= p_min_score
         order by created_at desc
         limit p_limit offset p_offset
      ) t;

    return jsonb_build_object(
        'total', v_total,
        'events', v_rows,
        'threshold', (select risk_block_threshold from public.app_settings where id = true)
    );
end;
$$;


-- 차단 임계값 조정. 101 이면 아무것도 차단하지 않는 섀도 모드.
create or replace function public.set_risk_threshold(p_secret text, p_threshold int)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;
    if p_threshold < 1 or p_threshold > 101 then
        return jsonb_build_object('success', false, 'error', '1~101 사이여야 합니다.');
    end if;
    update public.app_settings set risk_block_threshold = p_threshold where id = true;
    return jsonb_build_object('success', true, 'threshold', p_threshold);
end;
$$;


-- 자동 차단 즉시 해제 (점수는 남기되 차단만 품)
create or replace function public.unblock_ip(p_secret text, p_ip text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('success', false);
    end if;

    update public.ip_reputation
       set blocked_until = null, score = 0, reasons = '[]'::jsonb
     where ip = p_ip;

    -- 계정 단위 잠금 판정에 쓰이는 실패 기록도 함께 지워야 즉시 풀린다
    delete from public.login_attempts
     where ip = p_ip and not success
       and attempted_at > now() - interval '30 minutes';

    return jsonb_build_object('success', true);
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

    delete from public.email_verifications
     where used_at is not null or expires_at < now() - interval '7 days';

    -- 속도 제한 판정은 최근 60분만 보므로 하루치만 남겨도 충분합니다.
    delete from public.rate_events
     where created_at < now() - interval '1 day';

    -- 위험 로그인 기록은 감사 로그와 같은 기준(1년)으로 보관합니다.
    delete from public.login_risk_events
     where created_at < now() - interval '365 days';

    -- 오래 조용한 IP 는 평판을 지웁니다. 관리자가 직접 지정한 항목은 남깁니다.
    delete from public.ip_reputation
     where manual_override is null
       and last_seen < now() - interval '30 days'
       and (blocked_until is null or blocked_until < now());

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

grant execute on function public.signup_user(text, text, text, text, text) to anon, authenticated;
grant execute on function public.signup_user(text, text, text, text) to anon, authenticated;
grant execute on function public.create_password_reset(text, text, text) to anon, authenticated;
grant execute on function public.create_email_verification(text, bigint) to anon, authenticated;
grant execute on function public.verify_email_with_token(text, text) to anon, authenticated;
grant execute on function public.login_user(text, text, text, text, jsonb) to anon, authenticated;
grant execute on function public.check_login_lock(text, text, text) to anon, authenticated;
grant execute on function public.record_login_attempt(text, text, text, boolean, jsonb) to anon, authenticated;
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
grant execute on function public.list_ip_reputation(text, int, int, boolean) to anon, authenticated;
grant execute on function public.set_ip_override(text, text, text) to anon, authenticated;
grant execute on function public.unblock_ip(text, text) to anon, authenticated;
grant execute on function public.list_risk_events(text, int, int, int) to anon, authenticated;
grant execute on function public.set_risk_threshold(text, int) to anon, authenticated;
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
