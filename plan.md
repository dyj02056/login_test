# login_test — 보안 수정 실행 계획

작성일: 2026-08-16
근거 문서: `research.md`
대상: 위험 ① (관리자 로그인 제한 우회) → ③ (세션 무효화) → ④ (계정 잠금 DoS)
      → 4단계(② ⑥ ⑦ ⑨) → 5단계(⑤) → 6단계(⑧)

> **진행 상황 — 전 단계 완료**
> 1~4단계 `16ebea0` `b2924d9` `7d9343c` `16fb665` `493b9c7` (배포 확인 완료)
> 5·6단계 `1cd18ea`
> ⑩(운영 주의)은 코드 변경 대상이 아니라 문서로만 남겼습니다.

---

## 0. 전체 개요

### 왜 이 순서인가

| 순서 | 항목 | 이유 |
|---|---|---|
| 1 | ① 관리자 제한 우회 | **재현 확인된 실제 구멍.** 전체 회원 삭제 권한을 가진 계정이 무제한 대입 시도에 노출됨. 수정 비용이 가장 낮고 효과가 가장 큼 |
| 2 | ③ 세션 무효화 | 정지·권한해제·비밀번호 변경이 **무효**해지는 문제. ①을 고쳐도 이게 남으면 사고 후 대응이 불가능 |
| 3 | ④ 잠금 DoS | ①③보다 영향은 작지만, ①을 고치면서 잠금 로직을 건드리므로 **같이 처리하는 것이 효율적** |

③과 ④는 모두 `login_user`를 수정합니다. ①→④를 먼저 묶고 ③을 나중에 할 수도 있지만,
③이 가장 복잡하고 위험하므로 **①(간단) → ③(복잡) → ④(간단)** 순으로 진행해
중간에 문제가 생겨도 되돌리기 쉽게 합니다.

### 예상 소요

| 단계 | 작업 | 검증 | 합계 |
|---|---|---|---|
| 1단계 ① | 1시간 | 30분 | 1.5시간 |
| 2단계 ③ | 2.5시간 | 1시간 | 3.5시간 |
| 3단계 ④ | 1시간 | 30분 | 1.5시간 |
| 배포·확인 | — | 30분 | 0.5시간 |
| | | | **약 7시간** |

### 배포 순서 원칙 (중요)

이번 SQL 변경은 **모두 하위 호환**입니다.

- 컬럼 추가는 `add column if not exists`
- `login_user`는 시그니처 그대로, 반환 JSON에 필드만 추가 → 구버전 `app.py`는 무시
- 신규 함수는 구버전이 호출하지 않음

따라서 **SQL을 먼저 적용해도 현재 배포된 사이트는 그대로 동작**합니다.
반대로 새 `app.py`를 먼저 올리면 없는 함수를 호출해 즉시 장애가 납니다.

> **반드시 SQL → 로컬 검증 → 코드 배포 순서로 진행합니다.**

---

## 1단계 — ① 관리자 로그인 제한 우회 차단

### 문제 (재현 확인됨)

`app.py:184-193`의 환경변수 관리자 검사가 `rpc("login_user")`보다 먼저 실행되어,
이 경로는 DB를 아예 거치지 않습니다. 결과:

- 잠금 판정이 적용되지 않음 → **비밀번호 무제한 대입 가능**
- `login_attempts`에 기록되지 않음 → `/admin/logs`에 흔적 없음

### 설계

관리자 경로에도 **잠금 판정과 기록을 명시적으로 적용**합니다.
`login_user` 안에 있는 잠금 로직을 밖에서도 쓸 수 있게 내부 함수로 분리합니다.

```
POST /login
  │
  ├─[신규] rpc("check_login_lock")  ← 아이디 무관하게 최우선 판정
  │        잠김이면 즉시 거부 (관리자 아이디도 예외 없음)
  │
  ├─[1] 환경변수 관리자 검사
  │     ├─ 성공 → rpc("record_login_attempt", success=true) 후 로그인
  │     └─ 아이디만 일치하고 비번 틀림
  │          → rpc("record_login_attempt", success=false) 후 거부
  │            (login_user로 넘기지 않음 — 이중 기록 방지)
  │
  └─[2] rpc("login_user")  ← 내부에서 자체 기록 (기존과 동일)
```

### 변경 내용

**`supabase_setup.sql`** — 함수 3개 추가

```sql
-- 내부 전용: 잠금 판정 로직을 한 곳에 모음 (anon 권한 부여하지 않음)
create or replace function public.is_login_locked(p_username text, p_ip text)
returns boolean
language sql
security definer
set search_path = public
as $$
    select (select count(*) from public.login_attempts
             where username = p_username and not success
               and attempted_at > now() - interval '15 minutes') >= 5;
$$;

revoke all on function public.is_login_locked(text, text) from public, anon, authenticated;

-- 로그인 전 잠금 확인 (관리자 경로에서 사용)
create or replace function public.check_login_lock(
    p_secret text, p_username text, p_ip text default null
)
returns jsonb
language plpgsql security definer set search_path = public
as $$
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('locked', false, 'ok', false);
    end if;
    return jsonb_build_object(
        'locked', public.is_login_locked(p_username, p_ip), 'ok', true
    );
end;
$$;

-- 시도 기록 (관리자 경로에서 사용)
create or replace function public.record_login_attempt(
    p_secret text, p_username text, p_ip text, p_success boolean
)
returns jsonb
language plpgsql security definer set search_path = public
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

grant execute on function public.check_login_lock(text, text, text) to anon, authenticated;
grant execute on function public.record_login_attempt(text, text, text, boolean) to anon, authenticated;
```

`login_user` 내부의 인라인 집계도 `is_login_locked()` 호출로 교체합니다 (로직 일원화).

**`app.py:176-221`** — `login()` 재구성

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        ip = client_ip()

        # 아이디 종류와 무관하게 잠금을 먼저 판정
        if rpc("check_login_lock", {"p_username": username, "p_ip": ip}).get("locked"):
            flash("로그인 시도가 너무 많습니다. 15분 후 다시 시도해 주세요.", "error")
            return render_template("login.html", username=username)

        # 비상용 환경변수 관리자
        if ADMIN_USERNAME and hmac.compare_digest(username, ADMIN_USERNAME):
            if hmac.compare_digest(password, ADMIN_PASSWORD):
                rpc("record_login_attempt",
                    {"p_username": username, "p_ip": ip, "p_success": True})
                session.clear()
                session["is_admin"] = True
                session["username"] = username
                session.permanent = remember
                return redirect(url_for("admin_panel"))

            rpc("record_login_attempt",
                {"p_username": username, "p_ip": ip, "p_success": False})
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
            return render_template("login.html", username=username)

        result = rpc("login_user", {...})   # 이하 기존과 동일
```

### 주의할 점

- 관리자 아이디로 들어오면 **DB 로그인 경로로 넘기지 않습니다.** 현재도 환경변수 관리자가
  같은 이름의 DB 계정을 가리므로 동작 변화는 없지만, 이제 명시적으로 분기됩니다.
- `check_login_lock`은 비밀키가 틀리면 `locked: false`를 돌려줍니다.
  이는 의도적입니다 — 비밀키가 잘못되어 DB 경로가 전부 막힌 상황에서
  환경변수 관리자는 **복구 통로**여야 하기 때문입니다.
- 로그인 요청당 Supabase 호출이 1회 늘어납니다 (잠금 확인). 허용 범위로 판단합니다.

### 검증

```
1. 일반 계정 5회 실패 → 6회차 잠김                        (기존 동작 유지 확인)
2. 관리자 아이디로 5회 실패 → 6회차 잠김
3. 잠긴 상태에서 올바른 관리자 비밀번호 → 거부되어야 함    ★ 이번 수정의 핵심
4. /admin/logs 에 관리자 로그인 시도가 성공·실패 모두 기록되는지 확인
5. 잠금 해제 후 관리자 정상 로그인
```

3번은 현재 "로그인 성공"이 나옵니다. 수정 후 "잠김"으로 바뀌어야 합니다.

---

## 2단계 — ③ 권한·비밀번호 변경의 세션 즉시 반영

### 문제

`@login_required` / `@admin_required`가 세션 쿠키만 보고 DB를 조회하지 않습니다. 결과:

- 회원을 **정지**시켜도 이미 로그인해 있으면 계속 사용 가능
- **관리자 권한을 해제**해도 세션 만료까지 콘솔 사용 가능
- **비밀번호를 바꿔도 기존 세션 유지** → 계정 탈취 후 비번을 바꿔도 공격자 세션은 최대 7일 생존

### 설계

`users.session_version` 컬럼을 두고, 세션에 로그인 시점의 값을 담습니다.
무효화가 필요한 사건이 생기면 DB 값을 올려 세션과 어긋나게 만듭니다.

```
로그인 시    session["sv"] = users.session_version
매 요청 시   DB 값과 대조 → 다르면 세션 파기

session_version 을 올리는 사건:
  - 비밀번호 변경 (change_password)
  - 비밀번호 재설정 (reset_password_with_token)
  - 계정 정지 (set_user_active → false)
  - 관리자 권한 변경 (set_user_admin)
  - 관리자의 강제 로그아웃 (신규)
```

### 성능 문제와 절충

매 요청마다 Supabase를 호출하면 모든 페이지가 느려집니다.
**60초 캐시**를 둡니다 — 최대 60초의 지연을 허용하는 대신 호출량을 분당 1회로 제한합니다.

```python
SESSION_CHECK_INTERVAL = 60  # 초

def session_is_valid():
    """세션이 여전히 유효한지 확인. 최대 60초까지 오래된 판정을 허용."""
    user_id = session.get("user_id")
    if not user_id:
        return True   # 환경변수 관리자는 DB 계정이 없으므로 대상 외

    if time.time() - session.get("sv_checked_at", 0) < SESSION_CHECK_INTERVAL:
        return True

    try:
        state = rpc("get_user_session_state", {"p_user_id": user_id})
    except SupabaseError:
        return True   # DB 장애 시 기존 세션 유지 (아래 '결정 사항' 참고)

    if (not state.get("found")
            or not state.get("is_active")
            or state.get("session_version") != session.get("sv")):
        return False

    session["is_admin"] = bool(state.get("is_admin"))   # 권한 변경 즉시 반영
    session["sv_checked_at"] = time.time()
    return True
```

두 데코레이터에 삽입:

```python
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("로그인이 필요합니다.", "error"); return redirect(url_for("login"))
        if not session_is_valid():
            session.clear()
            flash("세션이 만료되었습니다. 다시 로그인해 주세요.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
```

`admin_required`도 동일하게 적용 (단, `user_id`가 없는 환경변수 관리자는 통과).

### 변경 내용

**`supabase_setup.sql`**

```sql
alter table public.users add column if not exists session_version int not null default 1;

create or replace function public.get_user_session_state(p_secret text, p_user_id bigint)
returns jsonb
language plpgsql security definer set search_path = public
as $$
declare v record;
begin
    if not public.check_secret(p_secret) then
        return jsonb_build_object('found', false);
    end if;
    select is_active, is_admin, session_version into v
      from public.users where id = p_user_id;
    if v is null then
        return jsonb_build_object('found', false);   -- 삭제된 계정
    end if;
    return jsonb_build_object('found', true, 'is_active', v.is_active,
                              'is_admin', v.is_admin,
                              'session_version', v.session_version);
end;
$$;

create or replace function public.force_logout_user(p_secret text, p_user_id bigint)
returns jsonb ...   -- session_version + 1
```

기존 함수 수정:

| 함수 | 변경 |
|---|---|
| `login_user` | 반환값에 `session_version` 추가 |
| `change_password` | `session_version = session_version + 1`, 새 값을 반환 |
| `reset_password_with_token` | `session_version + 1` |
| `set_user_active` | 정지시킬 때 `session_version + 1` |
| `set_user_admin` | 권한 변경 시 `session_version + 1` |

**`app.py`**

- `import time` 추가
- `login()`에서 `session["sv"] = result["session_version"]`, `session["sv_checked_at"] = time.time()`
- `change_password()` 성공 시 반환된 새 버전으로 세션 재동기화
  (**본인은 로그아웃되지 않고, 다른 기기만 로그아웃**)
- `session_is_valid()` 신설, 두 데코레이터에 적용
- `/admin/users/<id>/force-logout` 라우트 추가

**`templates/admin_users.html`** — 작업 열에 `강제 로그아웃` 버튼 1개 추가
(`button.mini` 클래스 재사용, 새 CSS 불필요)

### 결정 사항 (검토 필요)

1. **DB 장애 시 기존 세션을 유지(fail-open)** 합니다.
   보안 검사를 fail-open 하는 것은 일반적으로 나쁘지만, 이 검사는 *실효(revocation)* 확인이고
   Supabase 장애 시마다 전 사용자가 로그아웃되면 가용성 피해가 더 큽니다.
   대신 `sv_checked_at`을 갱신하지 않아 다음 요청에서 즉시 재시도합니다.
2. **최대 60초의 지연**을 허용합니다. 즉시 차단이 필요하면
   `SESSION_CHECK_INTERVAL = 0`으로 두면 되지만 모든 요청에 DB 호출이 붙습니다.
   관리자 경로만 0으로 두는 것도 방법입니다.
3. **환경변수 관리자 세션은 무효화할 수 없습니다** (DB 계정이 없음).
   이 계정을 차단하려면 Vercel 환경변수를 바꾸고 재배포해야 합니다. 의도된 한계입니다.

### 검증

```
1. A로 로그인 → 관리자가 A를 정지 → A가 페이지 이동 시 60초 내 로그아웃
2. A에게 관리자 권한 부여 → A의 화면에 관리자 메뉴가 나타남 (재로그인 없이)
3. A의 관리자 권한 해제 → 60초 내 /admin 접근 차단
4. 브라우저 2개로 A 로그인 → 한쪽에서 비밀번호 변경
   → 변경한 쪽은 유지, 다른 쪽은 로그아웃            ★ 핵심
5. 강제 로그아웃 버튼 → 해당 회원 세션 종료
6. 회원 삭제 → 그 회원의 살아있는 세션도 종료 (found=false)
7. 로그인 후 페이지를 여러 번 이동 → Supabase 호출이 분당 1회인지 확인
```

### 리스크

**이번 계획에서 가장 위험한 단계입니다.** 잘못 만들면 전원이 무한 로그아웃되거나
반대로 아무도 차단되지 않습니다. 반드시 로컬에서 7개 항목을 모두 확인한 뒤 배포합니다.

---

## 3단계 — ④ 계정 잠금 DoS 완화

### 문제

잠금 판정이 **아이디 기준**이라, 누구나 남의 아이디로 5번 틀리면
그 사람을 15분간 로그인 불가로 만들 수 있습니다.

### 설계

판정 기준을 **(아이디 + IP)** 로 바꾸고, **IP 단위 총량 제한**을 별도로 둡니다.

| 조건 | 임계값 | 목적 |
|---|---|---|
| 같은 (아이디, IP)에서 15분 내 실패 | 5회 | 특정 계정 무차별 대입 차단 |
| 같은 IP에서 15분 내 실패 (아이디 무관) | 20회 | 여러 계정을 훑는 공격 차단 |
| IP를 알 수 없을 때 아이디 기준 실패 | 10회 | 대체 수단 (임계값 상향) |

공격자 IP에서 실패를 쌓아도 **피해자 IP에서의 로그인은 막히지 않습니다.**

1단계에서 만든 `is_login_locked()` 하나만 고치면 `login_user`와 `check_login_lock`에
동시에 반영됩니다 — 1단계에서 로직을 일원화해 둔 이유입니다.

```sql
create or replace function public.is_login_locked(p_username text, p_ip text)
returns boolean
language sql security definer set search_path = public
as $$
    select case
        when coalesce(p_ip, '') = '' then
            (select count(*) from public.login_attempts
              where username = p_username and not success
                and attempted_at > now() - interval '15 minutes') >= 10
        else
            (select count(*) from public.login_attempts
              where username = p_username and ip = p_ip and not success
                and attempted_at > now() - interval '15 minutes') >= 5
            or
            (select count(*) from public.login_attempts
              where ip = p_ip and not success
                and attempted_at > now() - interval '15 minutes') >= 20
    end;
$$;
```

인덱스 추가 (IP 조건 조회가 늘어나므로):

```sql
create index if not exists login_attempts_ip_time_idx
    on public.login_attempts (ip, attempted_at desc);
```

### 남는 한계 (문서화)

- 서로 다른 IP를 여럿 가진 공격자(봇넷)는 여전히 한 계정을 천천히 대입할 수 있습니다.
  완전 차단에는 CAPTCHA나 2FA가 필요하며 이번 범위 밖입니다.
- 회사·학교처럼 **여러 사람이 한 IP를 공유**하면 IP 임계값 20회에 걸릴 수 있습니다.
  운영 중 오탐이 보이면 임계값을 올립니다.
- `X-Forwarded-For`는 위조 가능성이 있습니다(`app.py:77`).
  Vercel이 값을 설정하지만, 엄밀히 하려면 마지막 값을 쓰거나 Vercel 전용 헤더를 씁니다.
  → 이번 범위 밖, `research.md` ⑩에 기록해 둠.

### 검증

```
1. IP-A에서 계정 X로 5회 실패 → IP-A에서 X 로그인 잠김
2. 같은 시점에 IP-B에서 계정 X로 올바른 비번 → 로그인 성공해야 함   ★ 핵심
3. IP-A에서 서로 다른 20개 아이디로 실패 → IP-A 전체 차단
4. 관리자 잠금 해제가 여전히 동작하는지 확인
```

2번이 현재는 실패(잠김)합니다. 수정 후 성공해야 합니다.
로컬에서는 IP가 모두 `127.0.0.1`이므로 `X-Forwarded-For` 헤더를 직접 넣어 시험합니다.

---

## 4단계 — 남은 저비용 항목 ✅ 완료

| 항목 | 작업 | 커밋 |
|---|---|---|
| ② Referer 리다이렉트 | `safe_redirect()` 도입 → 6곳 치환 | `16fb665` |
| ⑨ 보안 헤더 | CSP·X-Frame-Options·nosniff·Referrer-Policy·HSTS | `16fb665` |
| ⑦ 관리자 감사 로그 | `admin_actions` 테이블 + `/admin/audit` | `493b9c7` |
| ⑥ 기록 정리 | `prune_old_records()` (하루 1회 자체 제한) | `493b9c7` |

⑨를 하면서 인라인 스크립트·스타일 2곳을 `static/app.js` 로 옮겨
`'unsafe-inline'` 없는 엄격한 CSP 를 적용할 수 있었습니다.

---

## 5단계 — ⑤ 가입·재설정 속도 제한 ✅ 완료 (`1cd18ea`)

### 문제

`/signup` 과 `/forgot-password` 에는 아무 제한이 없습니다.
스크립트로 계정을 무한 생성하거나, 특정 회원에게 재설정 메일을 계속 보내
괴롭히거나, `password_resets` 행을 무한 적재할 수 있습니다.

### 설계

로그인 잠금과 성격이 다릅니다. 로그인은 "이 계정이 공격받는가"를 보지만,
가입·재설정은 "이 IP 가 남용하는가"를 봐야 합니다. 따라서 별도의 사건 기록
테이블을 두고 종류(kind)별로 세는 방식으로 만듭니다.

```sql
rate_events(id, kind, ip, subject, created_at)
  kind = 'signup' | 'password_reset'
  subject = 대상 아이디 (재설정에서 사용)
```

| 제한 | 임계값 | 기록 시점 | 이유 |
|---|---|---|---|
| 가입 (IP 기준) | 60분에 5회 | **성공했을 때만** | 오타로 인한 실패까지 세면 정상 사용자가 막힘 |
| 재설정 (IP 기준) | 60분에 5회 | **모든 요청** | 존재하지 않는 아이디로 훑는 것도 막아야 함 |
| 재설정 (아이디 기준) | 60분에 3회 | 모든 요청 | 특정인 메일함 폭탄 방지 |

### 하위 호환 (중요)

`signup_user` 와 `create_password_reset` 에 `p_ip` 인자가 추가되므로
**시그니처가 바뀝니다.** 기존 함수를 `drop` 하면 SQL 실행 시점부터
새 코드가 배포되기 전까지 운영 사이트의 가입 기능이 죽습니다.

→ **기존 시그니처를 삭제하지 않고 호환용 래퍼로 남깁니다.**
PostgreSQL 은 오버로딩을 허용하고 PostgREST 는 보낸 인자 이름으로 함수를
고르므로, 구버전 코드(4인자)와 신버전 코드(5인자)가 동시에 동작합니다.

```sql
-- 구버전 호출을 새 구현으로 넘겨주는 래퍼 (p_ip 없이)
create or replace function public.signup_user(
    p_secret text, p_username text, p_password text, p_email text default null
) returns jsonb ... as $$
    select public.signup_user(p_secret, p_username, p_password, p_email, null);
$$;
```

덕분에 이 단계도 **SQL 을 먼저 적용해도 운영에 영향이 없습니다.**

### 변경 내용

| 파일 | 변경 |
|---|---|
| `supabase_setup.sql` | `rate_events` 테이블·인덱스, `is_rate_limited()`, `record_rate_event()`,<br>`signup_user`/`create_password_reset` 에 `p_ip` 추가 + 호환 래퍼,<br>`prune_old_records` 에 `rate_events` 정리 추가 |
| `app.py` | 두 호출부에 `p_ip: client_ip()` 전달, 제한 시 안내 메시지 |

### 검증

```
1. 한 IP 에서 6번째 가입 시도 → 차단                        PASS
2. 다른 IP 에서는 정상 가입                                 PASS
3. 가입 실패(비밀번호 불일치)를 여러 번 → 카운트 안 됨       PASS
4. 한 IP 에서 재설정 6회 요청 → 차단                        PASS
5. 같은 아이디로 4회 재설정 요청 → 3회 후 차단              PASS
6. 기존 회원가입·재설정 흐름이 그대로 동작                  PASS
```

구버전 래퍼도 함께 확인했습니다. 4인자 `signup_user` 와 2인자
`create_password_reset` 를 직접 호출해 정상 응답을 받았으므로,
SQL 을 먼저 적용해도 배포된 사이트가 깨지지 않습니다.

---

## 6단계 — ⑧ 이메일 인증 ✅ 완료 (`1cd18ea`)

### 문제

가입 시 이메일을 그대로 저장할 뿐 검증하지 않습니다(`signup_user`).
오타가 있으면 재설정 메일이 영영 도착하지 않고, 남의 이메일을 적어도 막히지 않습니다.

### 범위 결정 — 로그인을 막지 않습니다

이메일 인증을 로그인 조건으로 걸면:

- 이메일이 **선택 입력**이라 이메일 없는 기존 회원이 전부 잠깁니다.
- `RESEND_API_KEY` 가 비어 있어 **메일을 보낼 수단이 아직 없습니다.**

따라서 이번 단계는 **인증 상태를 만들고 보이게 하는 데까지**만 합니다.
로그인 차단은 메일 발송이 켜지고 이메일을 필수로 바꾼 뒤에 검토합니다.

### 설계

비밀번호 재설정과 같은 토큰 방식을 재사용합니다 (원문 미저장, 해시만 보관).

```
가입 시 이메일 입력 → 인증 토큰 발급 (24시간)
   ├─ RESEND_API_KEY 있음 → 메일 발송
   └─ 없음 → 관리자가 회원 관리에서 인증 링크를 만들어 전달

/verify-email/<token> → email_verified = true
```

### 변경 내용

| 파일 | 변경 |
|---|---|
| `supabase_setup.sql` | `users.email_verified`, `email_verifications` 테이블,<br>`create_email_verification()`, `verify_email_with_token()`,<br>`list_users`/`get_user_session_state` 반환값에 인증 여부 추가 |
| `app.py` | `/verify-email/<token>`, 가입 시 토큰 발급,<br>`/admin/users/<id>/verify-link` |
| `templates/dashboard.html` | 미인증 안내 배너 |
| `templates/admin_users.html` | 이메일 옆 인증 배지 + 인증 링크 버튼 |

### 검증

```
1. 이메일을 넣고 가입 → 미인증 상태로 생성                  PASS
2. 대시보드에 미인증 안내가 보임                            PASS
3. 관리자 화면에서 인증 링크 발급 → 접속 → 인증됨           PASS
4. 같은 링크 재사용 → 거부                                  PASS
5. 만료된 링크 → 거부                        (토큰 검증 로직 4와 동일 경로)
6. 이메일 없이 가입 → 인증 안내가 뜨지 않음                 PASS
7. 인증 여부와 무관하게 로그인은 정상 동작                  PASS
추가. 인증 완료 후 대시보드 안내가 사라짐                   PASS
```

---

## ⑩ 운영 주의 — 코드 변경 없음

`research.md` ⑩ 은 코드 결함이 아니라 운영 습관에 대한 것이라 수정 대상이 아닙니다.
다만 아래는 계속 유효한 주의사항이라 문서로만 남깁니다.

- `.env` 가 **OneDrive 동기화 경로**에 있어 파일 자체가 클라우드에 업로드됩니다.
  git 에는 제외되지만 OneDrive 에는 올라갑니다.
- `X-Forwarded-For` 는 위조 가능성이 있습니다. Vercel 이 값을 설정하지만
  엄밀히 하려면 마지막 값을 쓰거나 Vercel 전용 헤더를 씁니다.
- `is_signup_enabled()` 는 DB 장애 시 True 를 반환합니다(fail-open).
  실제 가입은 `signup_user` 가 다시 막으므로 화면만 잠깐 열립니다.

---

## 5. 배포 절차

각 단계마다 아래를 반복합니다.

```
1. supabase_setup.sql 수정
2. Supabase SQL Editor 에서 전체 실행          ← 하위 호환이므로 운영 무영향
3. app.py / 템플릿 수정
4. 로컬에서 해당 단계의 검증 항목 전부 통과
5. git commit (단계별로 나눠서 — 되돌리기 쉽게)
6. git push → Vercel 자동 배포
7. 배포된 사이트에서 핵심 항목 1~2개 재확인
```

### 되돌리기

- **SQL**: 모든 변경이 `create or replace` / `add column if not exists` 이므로
  이전 버전 스크립트를 다시 실행하면 복구됩니다. 단 `session_version` 컬럼은 남습니다(무해).
- **코드**: `git revert <커밋>` 후 push.
- 단계별로 커밋을 나누므로 2단계만 문제가 생기면 2단계만 되돌릴 수 있습니다.

---

## 6. 선행 조건

**이 계획을 시작하기 전에 Vercel 환경변수 4개가 등록되어야 합니다.**
현재 배포된 사이트는 `SUPABASE_URL`, `SUPABASE_KEY`, `SUPABASE_RPC_SECRET`, `SECRET_KEY`가
없어 500 상태입니다. 수정 결과를 실제 사이트에서 확인할 수 없으므로 먼저 해결이 필요합니다.

로컬 검증만으로 진행할 수는 있으나, 배포 확인 없이 커밋이 쌓이는 상태가 됩니다.

---

## 7. 체크리스트

### 1단계 ①
- [ ] `is_login_locked` / `check_login_lock` / `record_login_attempt` 추가 + grant
- [ ] `login_user` 내부 집계를 `is_login_locked()` 호출로 교체
- [ ] `login()` 재구성 (잠금 선판정 → 관리자 분기 → DB 로그인)
- [ ] 검증 5항목 통과 (특히 "잠긴 상태 + 올바른 관리자 비번 → 거부")

### 2단계 ③
- [ ] `users.session_version` 컬럼 추가
- [ ] `get_user_session_state` / `force_logout_user` 추가 + grant
- [ ] `login_user` 반환값에 `session_version` 추가
- [ ] `change_password` / `reset_password_with_token` / `set_user_active` / `set_user_admin` 버전 증가
- [ ] `session_is_valid()` + 두 데코레이터 적용
- [ ] 강제 로그아웃 라우트 + 버튼
- [ ] 검증 7항목 통과 (특히 "비번 변경 시 본인 유지 / 타 기기 로그아웃")

### 3단계 ④
- [ ] `is_login_locked` 판정식 교체 (아이디+IP, IP 총량)
- [ ] `login_attempts_ip_time_idx` 인덱스 추가
- [ ] 검증 4항목 통과 (특히 "다른 IP에서는 정상 로그인")

### 마무리
- [ ] `features_guide.pdf` 갱신 (보안 절의 잠금 설명이 바뀜)
- [ ] `research.md`의 ①③④ 항목에 해결 표시
- [ ] 배포 후 실제 사이트에서 재확인
