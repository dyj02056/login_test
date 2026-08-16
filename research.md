# login_test — 코드베이스 분석 및 개선 제안

분석일: 2026-08-16
대상 커밋: `9e4e254` (main)
분석 방법: 전체 소스 정독 + 로컬 서버 기동 후 실제 요청으로 취약점 재현 검증

> **진행 상황 (2026-08-16 갱신)**
> `plan.md` 에 따라 ① ③ ④ 를 수정하고 각각 검증을 마쳤습니다.
> 커밋: `16ebea0`(①) · `b2924d9`(③) · `7d9343c`(④)
> 남은 항목: ② ⑤ ⑥ ⑦ ⑧ ⑨ ⑩

---

## 1. 관련 파일 / 폴더

```
login_test/
├── app.py                  526줄  Flask 서버 — 라우트 19개, 전체 로직의 유일한 진입점
├── supabase_setup.sql      660줄  DB 스키마 4개 + RPC 함수 16개 (비즈니스 로직의 절반이 여기 있음)
├── requirements.txt          4줄  Flask, Flask-WTF, requests, python-dotenv
├── .env                          실제 비밀값 (git 제외됨)
├── .env.example                  환경변수 템플릿
├── .gitignore                    __pycache__, *.pyc, users.db, *.log, .env, venv/
├── features_guide.pdf            기능 설명서 (6페이지)
├── static/
│   └── style.css           449줄  전체 스타일 (프레임워크 없음)
└── templates/              14개   Jinja2 템플릿
    ├── base.html                 공통 레이아웃 + 관리자 네비 + flash 메시지 출력
    ├── login/signup/dashboard    일반 회원 화면
    ├── change_password / delete_account / forgot_password / reset_password
    ├── admin / admin_users / admin_logs / admin_stats
    └── error.html                404 / 500 / 503 공용
```

### 구조상 특징

- **`vercel.json`이 없습니다.** Vercel의 Flask 자동 감지에 의존하고 있습니다. 현재는 동작하지만
  런타임 버전·리전·함수 타임아웃을 명시적으로 고정할 수 없습니다.
- **테스트 코드가 전혀 없습니다.** `tests/` 디렉터리 자체가 없습니다.
- **로직이 두 곳에 분산**되어 있습니다. 검증 규칙이 `app.py`와 `supabase_setup.sql` 양쪽에
  중복 존재합니다 (아래 2절 참고).

---

## 2. 유사 기능 존재 여부

새 기능을 넣기 전에 **이미 있는 것과 겹치지 않는지** 확인한 결과입니다.

| 넣으려는 기능 | 이미 있는가 | 판단 |
|---|---|---|
| 로그인 기록 조회 | **있음** — `get_login_attempts` + `/admin/logs` | 신규 불필요. 필터(성공/실패, 아이디별)만 추가하면 됨 |
| 계정 잠금 해제 | **있음** — `clear_login_attempts` + `/admin/unlock` | 신규 불필요 |
| 비밀번호 재설정 | **있음** — 토큰 방식 완비 | 이메일 발송만 미연결 (`RESEND_API_KEY` 비어 있음) |
| 회원 검색 | **있음** — `list_users(p_search)`, `username ilike` | 이메일 검색은 미지원 → 확장 여지 |
| 관리자 권한 관리 | **있음** — `set_user_admin` + DB `is_admin` | 신규 불필요 |
| 가입 통계 | **있음** — `get_signup_stats` (일별 + 요약 5종) | 로그인 통계는 없음 → 확장 여지 |
| 세션 관리 / 강제 로그아웃 | **없음** | 신규 필요 (5절 위험 ③과 직결) |
| 이메일 인증 | **없음** — 이메일 컬럼만 있고 검증 없음 | 신규 필요 |
| 감사 로그(관리자 행위) | **없음** — 로그인 시도만 기록, 삭제·정지는 흔적 없음 | 신규 필요 |
| 2단계 인증(2FA) | **없음** | 신규 |
| 소셜 로그인 | **없음** | 신규 (규모 큼) |

### 중복 로직 발견

**같은 검증이 Flask와 DB 양쪽에 각각 구현되어 있습니다.**

| 검증 | Flask | Postgres |
|---|---|---|
| 아이디 3자 이상 | `app.py:151` | `supabase_setup.sql` `signup_user` |
| 비밀번호 6자 이상 | `app.py:153` | `signup_user`, `change_password`, `reset_password_with_token` |
| 회원가입 on/off | `app.py:141` | `signup_user` 내부 재확인 |

이는 **의도된 이중 방어**입니다 (Flask를 우회한 직접 호출도 DB가 막음). 다만 규칙을 바꿀 때
**두 곳을 모두 고쳐야 한다는 점**이 문서화되어 있지 않아, 한쪽만 고치면 조용히 어긋납니다.
→ 향후 규칙 변경 시 반드시 짝으로 수정.

---

## 3. 주요 함수 / 데이터 흐름

### 3-1. 모든 DB 접근의 단일 통로 — `rpc()` (`app.py:56`)

```
호출부 → rpc("함수명", {인자})
          └─ body에 p_secret 자동 주입          app.py:58
          └─ POST {SUPABASE_URL}rpc/{함수명}
             헤더: apikey + Authorization (publishable 키)
          └─ raise_for_status() 실패 시 SupabaseError
                                                app.py:74
```

DB 접근이 이 함수 하나로 모이므로, **재시도·로깅·캐싱을 넣는다면 여기 한 곳**이면 됩니다.

### 3-2. 로그인 흐름 (가장 복잡하고, 가장 위험한 경로)

```
POST /login                                     app.py:176
  │
  ├─[1] 환경변수 관리자 검사                     app.py:184-193
  │     hmac.compare_digest 로 상수시간 비교
  │     ★ 일치하면 여기서 즉시 로그인 — DB를 아예 거치지 않음
  │        └─ 로그인 기록도 남지 않고, 잠금도 적용되지 않음  ← 5절 위험 ①
  │
  └─[2] rpc("login_user")                       app.py:195
        └─ Postgres login_user()
           ├─ 최근 15분 실패 횟수 집계
           ├─ 5회 이상 → login_attempts에 실패 기록 후 {reason:"locked"}
           ├─ bcrypt 비교 (crypt(입력, 저장된해시) == 저장된해시)
           ├─ 성공/실패 무관하게 login_attempts INSERT   ← 감사 로그의 원천
           ├─ is_active=false → {reason:"inactive"}
           └─ 성공 → {id, username, is_admin}
                     │
                     └─ session.clear() 후 재설정     app.py:211-215
                        user_id / username / is_admin
                        session.permanent = remember (7일)
```

**핵심**: 비밀번호는 Flask를 통과만 하고 검증은 전부 Postgres 안에서 일어납니다.
해시값은 어떤 경로로도 함수 밖으로 나오지 않습니다.

### 3-3. 비밀번호 재설정 흐름

```
POST /forgot-password                           app.py:318
  └─ rpc("create_password_reset")
     └─ Postgres: gen_random_bytes(24) → hex 토큰 생성
        ├─ DB에는 sha256 해시만 저장 (원문 미저장)
        ├─ 만료 1시간
        └─ 원문 토큰을 응답으로 1회만 반환
           │
           ├─ RESEND_API_KEY 있음 → 메일 발송      app.py:291
           └─ 없음 → 관리자가 /admin/users에서 링크 발급해 수동 전달

POST /reset-password/<token>                    app.py:347
  └─ rpc("reset_password_with_token")
     ├─ 해시 대조 + used_at IS NULL + 미만료 확인
     ├─ 비밀번호 갱신 + used_at 기록 (재사용 차단)
     └─ 해당 계정의 실패 기록 삭제 → 잠금 자동 해제
```

### 3-4. 권한 판정 흐름

```
session["is_admin"] ─┬─ 환경변수 관리자 로그인 시 True    app.py:190
                     └─ DB users.is_admin = true 일 때 True  app.py:214
                              │
        @admin_required ──────┘                        app.py:106
        (세션만 확인, DB 재조회 없음)  ← 5절 위험 ③
```

---

## 4. 기존 API / 컴포넌트 목록

### 4-1. Flask 라우트 (19개)

| 경로 | 메서드 | 보호 | 호출하는 RPC |
|---|---|---|---|
| `/` | GET | — | — |
| `/signup` | GET/POST | — | `get_signup_enabled`, `signup_user` |
| `/login` | GET/POST | — | `login_user` |
| `/logout` | GET | — | — |
| `/dashboard` | GET | `@login_required` | — |
| `/change-password` | GET/POST | `@login_required` | `change_password` |
| `/delete-account` | GET/POST | `@login_required` | `delete_own_account` |
| `/forgot-password` | GET/POST | — | `create_password_reset` |
| `/reset-password/<token>` | GET/POST | — | `reset_password_with_token` |
| `/admin` | GET | `@admin_required` | `get_signup_stats`, `list_pending_resets`, `get_signup_enabled` |
| `/admin/toggle-signup` | POST | `@admin_required` | `set_signup_enabled` |
| `/admin/users` | GET | `@admin_required` | `list_users` |
| `/admin/users/<id>/toggle-active` | POST | `@admin_required` | `set_user_active` |
| `/admin/users/<id>/toggle-admin` | POST | `@admin_required` | `set_user_admin` |
| `/admin/users/<id>/delete` | POST | `@admin_required` | `admin_delete_user` |
| `/admin/users/<id>/reset-link` | POST | `@admin_required` | `create_password_reset` |
| `/admin/logs` | GET | `@admin_required` | `get_login_attempts` |
| `/admin/unlock` | POST | `@admin_required` | `clear_login_attempts` |
| `/admin/stats` | GET | `@admin_required` | `get_signup_stats` |

### 4-2. Postgres RPC 함수 (16개)

전부 `security definer` + 첫 인자 `p_secret` 필수. `check_secret()`은 anon 권한 미부여.

| 함수 | 용도 |
|---|---|
| `check_secret` | 내부 전용 — 비밀키 검증 |
| `signup_user` | 가입 (길이·중복·가입허용 재검증 + bcrypt) |
| `login_user` | 로그인 (잠금 판정 + 검증 + 기록) |
| `change_password` | 기존 비번 확인 후 변경 |
| `delete_own_account` | 비번 확인 후 삭제 |
| `create_password_reset` | 토큰 발급 (해시 저장) |
| `reset_password_with_token` | 토큰 검증 후 재설정 |
| `list_pending_resets` | 미사용 재설정 요청 목록 |
| `get_signup_enabled` / `set_signup_enabled` | 가입 on/off |
| `list_users` | 목록 (검색 + 페이지네이션 + total) |
| `set_user_active` / `set_user_admin` / `admin_delete_user` | 회원 상태 조작 |
| `get_login_attempts` / `clear_login_attempts` | 감사 로그 조회 / 잠금 해제 |
| `get_signup_stats` | 일별 가입 + 요약 지표 |

### 4-3. 외부 의존

| 대상 | 위치 | 상태 |
|---|---|---|
| Supabase REST | `app.py:62` | 사용 중 |
| Resend (메일) | `app.py:295` | **코드는 있으나 미활성** (`RESEND_API_KEY` 공백) |

### 4-4. 재사용 가능한 프론트엔드 컴포넌트 (`style.css`)

`.card` / `.card.wide`, `.notice.error|.success`, `.badge.ok|.danger|.admin`,
`.stat-grid`+`.stat`, `.table-scroll`+`table`, `.pagination`, `.chart`+`.bar`,
`.nav`, `.menu`, `button.mini|.inline|.danger`
→ **새 관리자 화면을 만들 때 CSS를 새로 짤 필요가 거의 없습니다.**

---

## 5. 위험한 부분

실제로 로컬 서버를 띄워 요청을 보내 **재현 확인한 것**과, 코드 검토로만 판단한 것을 구분했습니다.

### ① 환경변수 관리자가 로그인 시도 제한을 완전히 우회 — **높음 · 재현 확인됨** → ✅ **해결됨 (`16ebea0`)**

> 잠금 판정을 `is_login_locked()` 로 분리해 자격 증명 검사보다 먼저 실행하고,
> 관리자 경로의 시도도 `record_login_attempt()` 로 기록하도록 했습니다.
> 재검증: 잠긴 상태에서 올바른 관리자 비밀번호를 넣어도 거부됨을 확인.

`app.py:184-193`의 환경변수 관리자 검사가 `rpc("login_user")`보다 **먼저** 실행됩니다.
이 경로는 DB를 거치지 않으므로 잠금 판정도, 기록도 적용되지 않습니다.

재현 결과:

```
dyj02056 계정으로 6회 실패 → 상태: "잠김"
잠긴 상태에서 올바른 관리자 비밀번호 입력 → 로그인 성공 (제한 우회)
```

즉 **관리자 비밀번호는 무제한으로 대입 시도할 수 있습니다.** 현재 관리자 비밀번호는 8자이며,
이 계정은 전체 회원 삭제 권한을 가집니다. 일반 회원은 5회로 막히는데 정작 가장 강력한 계정이
안 막히는 역전 상태입니다.

또한 이 경로의 로그인은 `/admin/logs`에 **아무 흔적도 남지 않습니다.**

> 조치: 환경변수 관리자 검사를 `login_user` 호출 **뒤로** 옮기거나, 별도의
> 시도 횟수 카운터를 두고 성공/실패 모두 `login_attempts`에 기록.

### ② 검증되지 않은 Referer 리다이렉트 — **중간 · 재현 확인됨**

`app.py:429, 441, 449, 462, 491` — 5곳이 `redirect(request.referrer or ...)`.

재현 결과:

```
POST /admin/unlock  (Referer: https://evil.example.com/phish)
→ 302 Location: https://evil.example.com/phish
```

CSRF 토큰이 외부 사이트발 요청을 막아주므로 **실제 악용 난이도는 높습니다.**
다만 리다이렉트 대상을 검증하지 않는 구조 자체가 위험하며, 향후 CSRF가 면제되는
엔드포인트(API 등)가 추가되면 곧바로 피싱 경로가 됩니다.

> 조치: 내부 경로인지 확인 후 리다이렉트하는 `safe_redirect()` 헬퍼 도입.

### ③ 권한 변경이 기존 세션에 즉시 반영되지 않음 — **중간 · 코드 검토** → ✅ **해결됨 (`b2924d9`)**

> `users.session_version` 을 도입해 로그인 시 세션에 담고 접근 데코레이터에서 대조합니다.
> 정지·권한해제·비밀번호 변경·재설정·강제 로그아웃이 이 값을 올려 기존 세션을 끊습니다.
> 재확인 주기는 `SESSION_CHECK_INTERVAL`(기본 60초)로 조절합니다.
> 구현 중 `admin_required` 에서 권한 검사가 세션 갱신보다 먼저 실행되는 버그를 발견해
> 순서를 바로잡았습니다.

`@admin_required`(`app.py:106`)는 세션 쿠키만 확인하고 DB를 재조회하지 않습니다. 따라서:

- 관리자가 어떤 회원을 **정지**시켜도, 그 회원이 이미 로그인해 있다면 **계속 사용 가능**합니다.
  (`is_active` 검사는 로그인 시점에만 일어납니다 — `login_user`)
- **관리자 권한을 해제**해도 그 사람은 세션이 만료될 때까지 관리자 콘솔을 계속 씁니다.
- **비밀번호를 변경/재설정해도 기존 세션이 유지**됩니다. 계정을 탈취당해 비밀번호를 바꿔도
  공격자의 세션은 살아 있습니다. "로그인 상태 유지"를 켰다면 최대 7일입니다.

> 조치: 세션에 `session_version`을 넣고 users 테이블에도 같은 값을 두어,
> 비밀번호 변경·정지·권한해제 시 증가시키는 방식. 매 요청 DB 조회가 부담이면
> 관리자 경로에만 우선 적용.

### ④ 계정 잠금을 이용한 서비스 거부 — **중간 · 코드 검토** → ✅ **해결됨 (`7d9343c`)**

> 판정 기준을 (아이디 + IP) 로 바꾸고 IP 단위 총량 제한(20회)을 추가했습니다.
> 재검증: 공격자 IP 에서 5회 실패로 잠긴 상태에서도 피해자가 자기 IP 에서
> 정상 로그인됨을 확인. 봇넷을 이용한 분산 대입은 여전히 가능하며,
> 완전 차단에는 CAPTCHA·2FA 가 필요합니다.

잠금 판정이 **아이디 기준**입니다 (`login_user`, IP는 기록만 함).
누구나 남의 아이디로 5번 틀리면 그 사람을 15분간 로그인 못 하게 만들 수 있습니다.
아이디는 공개 정보나 다름없으므로 표적 공격이 쉽습니다.

> 조치: (아이디 + IP) 조합으로 카운트하거나, 아이디 기준 잠금은 더 완만하게 하고
> IP 기준 제한을 별도로 추가.

### ⑤ 가입·재설정 요청에 속도 제한 없음 — **중간 · 코드 검토**

`/signup`과 `/forgot-password`에는 아무 제한이 없습니다.
스크립트로 계정을 무한 생성하거나 `password_resets` 행을 무한 적재할 수 있습니다.

### ⑥ 테이블 무한 증가 — **낮음(운영) · 코드 검토**

`login_attempts`와 `password_resets`는 **삭제 로직이 없습니다.**
`login_attempts`는 모든 로그인 시도마다 1행씩 쌓이며, 잠금 판정 쿼리가 매 로그인마다
이 테이블을 조회하므로 시간이 지날수록 로그인이 느려집니다.

> 조치: `attempted_at < now() - interval '90 days'` 정리 + Supabase cron.

### ⑦ 관리자 행위에 감사 기록이 없음 — **중간 · 코드 검토**

회원 삭제·정지·권한부여는 **아무 흔적도 남지 않습니다.** 관리자가 여럿이 되면
(현재 `set_user_admin`으로 늘릴 수 있음) 누가 무엇을 지웠는지 추적이 불가능합니다.
특히 `admin_delete_user`는 되돌릴 수 없습니다.

### ⑧ 이메일이 검증되지 않음 — **낮음 · 코드 검토**

가입 시 이메일을 그대로 저장합니다(`signup_user`). 오타가 있으면 재설정 메일이
영영 도착하지 않고, 남의 이메일을 적어도 막히지 않습니다.
현재는 메일 발송이 비활성이라 영향이 적지만, Resend를 켜는 순간 문제가 됩니다.

### ⑨ 보안 헤더 부재 — **낮음 · 코드 검토**

CSP, X-Frame-Options, HSTS가 없습니다. 관리자 콘솔이 iframe에 삽입될 수 있어
클릭재킹으로 "삭제" 버튼을 누르게 만들 여지가 있습니다.

### ⑩ 운영상 주의 — **정보**

- `.env`에 실제 비밀키가 들어 있고, 이 폴더는 **OneDrive 동기화 경로**에 있습니다.
  파일 자체가 클라우드에 업로드됩니다. git에는 제외되지만 OneDrive에는 올라갑니다.
- `is_signup_enabled()`는 DB 장애 시 **True를 반환**합니다(`app.py:88`).
  가입을 꺼둔 상태에서 DB가 불안정하면 가입이 잠시 열립니다.
  다만 `signup_user`가 다시 확인하므로 실제 가입은 막힙니다 — 화면만 잠깐 열립니다.
- `admin_reset_link`는 URL의 `user_id`를 무시하고 폼의 `username`을 씁니다(`app.py:454-456`).
  현재는 관리자만 호출하므로 문제없지만 일관성이 깨져 있습니다.
- `/logout`이 GET이라 외부 사이트가 사용자를 임의로 로그아웃시킬 수 있습니다(경미).

---

## 6. 새 기능을 넣을 위치

### 우선순위 A — 위 위험의 직접 해소

| 작업 | 수정 위치 | 규모 |
|---|---|---|
| 관리자 로그인 제한 우회 차단 (①) | `app.py:184-193` 순서 조정 + `login_attempts` 기록 추가 | 1시간 |
| `safe_redirect()` 도입 (②) | `app.py` 헬퍼 신설 → 5개 라우트 치환 | 1시간 |
| 세션 무효화 (③) | SQL: `users.session_version` 컬럼 + `login_user` 반환값<br>`app.py`: `login_required`/`admin_required`에서 대조 | 3시간 |
| 잠금 기준에 IP 추가 (④) | `supabase_setup.sql` `login_user` 집계 조건 | 1시간 |
| 오래된 로그 정리 (⑥) | `supabase_setup.sql`에 `prune_old_records()` + Supabase cron | 1시간 |
| 보안 헤더 (⑨) | `app.py`에 `@app.after_request` 1개 | 30분 |

### 우선순위 B — 새 기능

| 기능 | 신규 파일 | 기존 파일 수정 |
|---|---|---|
| **관리자 행위 감사 로그** (⑦) | `templates/admin_audit.html` | SQL: `admin_actions` 테이블 + `log_admin_action()`,<br>`set_user_*`/`admin_delete_user`에 기록 삽입<br>`app.py`: `/admin/audit` 라우트<br>`base.html`: 네비 항목 |
| **이메일 인증** (⑧) | `templates/verify_email.html` | SQL: `users.email_verified` + `email_verifications` 테이블<br>`app.py`: `/verify-email/<token>`<br>`signup()`에서 발송 |
| **가입/재설정 속도 제한** (⑤) | — | SQL: `signup_user`/`create_password_reset`에<br>IP 기준 카운트 (인자 `p_ip` 추가 필요) |
| **로그인 통계** | — | SQL: `get_signup_stats`에 일별 로그인 수 추가<br>`admin_stats.html`에 그래프 1개 (`.chart` 재사용) |
| **회원 상세 페이지** | `templates/admin_user_detail.html` | `app.py`: `/admin/users/<id>`<br>해당 회원의 로그인 이력 + 조작 버튼 모음 |
| **테스트 코드** | `tests/test_auth.py` 등 | `requirements-dev.txt` 신설 |
| **`vercel.json`** | `vercel.json` | 런타임·리전·타임아웃 고정 |

### 새 기능 추가 시 지켜야 할 규칙

1. **DB 접근은 반드시 `rpc()`를 통해서** (`app.py:56`). 직접 `requests.post`를 쓰면
   `p_secret` 주입이 빠져 실패합니다.
2. **새 RPC 함수는 반드시 `p_secret`을 첫 인자로 받고 `check_secret()`으로 검증**한 뒤
   `grant execute ... to anon`을 추가해야 합니다. 빠뜨리면 호출 자체가 실패합니다.
3. **검증 규칙은 Flask와 Postgres 양쪽에 넣습니다** (2절 참고). DB 쪽이 최종 방어선입니다.
4. **모든 POST 폼에 `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`**.
   빠지면 400으로 거부됩니다.
5. **관리자 화면은 `{% block card_class %}wide{% endblock %}`** 을 넣고
   기존 `.stat-grid` / `table` / `.pagination` 클래스를 재사용합니다.
6. **RPC 함수 시그니처를 바꿀 때는 `drop function if exists` 를 먼저** 넣어야 합니다.
   `create or replace`는 인자가 다르면 덮어쓰지 않고 오버로드를 만듭니다.

---

## 7. 요약

전체적으로 **구조는 견고합니다.** 비밀번호가 DB 밖으로 나오지 않고, RLS와 비밀키로
이중 잠금이 걸려 있으며, DB 기반 잠금은 서버리스 환경에서도 정확히 동작합니다.

다만 **가장 강력한 계정(환경변수 관리자)이 가장 약하게 보호되고 있다는 역전**이
가장 시급한 문제입니다(①, 재현 확인됨). 그다음은 권한·비밀번호 변경이 기존 세션에
반영되지 않는 문제(③)입니다.

새 기능보다 **①③④를 먼저 처리하시기를 권합니다.** 합쳐서 반나절 정도면 끝나고,
그 뒤에 감사 로그(⑦)와 이메일 인증(⑧)을 얹는 순서가 자연스럽습니다.

### 갱신 (2026-08-16)

①③④ 수정을 완료했습니다. 각 항목의 검증 결과는 위 5절에 표시해 두었습니다.

다음 우선순위는 **⑦ 관리자 행위 감사 로그**입니다. ③을 구현하면서 관리자가
회원 세션을 강제 종료할 수 있게 되어 관리자 권한이 더 강해졌는데, 정작 그 행위가
아무 기록도 남기지 않기 때문입니다. 그다음은 ② · ⑥ · ⑨ (각각 1시간 이내) 입니다.
