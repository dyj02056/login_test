import hmac
import os
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/") + "/"
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
SUPABASE_RPC_SECRET = os.environ["SUPABASE_RPC_SECRET"]

# 환경변수로 지정하는 비상용 관리자. DB 의 is_admin 계정과 별개로 항상 로그인할 수 있어
# 관리자 계정을 잃어버려도 잠기지 않습니다.
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# 이메일 발송(선택). 없으면 재설정 링크를 관리자 화면에서 직접 전달합니다.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM = os.environ.get("RESEND_FROM", "onboarding@resend.dev")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL") is not None,
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

csrf = CSRFProtect(app)


@app.after_request
def set_security_headers(response):
    """브라우저 쪽 방어선. 인라인 스크립트·스타일을 쓰지 않으므로
    'unsafe-inline' 없이 엄격한 정책을 적용할 수 있습니다."""
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "object-src 'none'",
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if os.environ.get("VERCEL"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# ----------------------------------------------------------------------
# Supabase 호출
# ----------------------------------------------------------------------

class SupabaseError(RuntimeError):
    pass


def rpc(function_name, payload=None):
    """Supabase RPC 호출. 모든 함수는 서버 전용 비밀키를 요구합니다."""
    body = {"p_secret": SUPABASE_RPC_SECRET}
    body.update(payload or {})
    try:
        response = requests.post(
            f"{SUPABASE_URL}rpc/{function_name}",
            json=body,
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        raise SupabaseError(str(exc)) from exc


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def safe_redirect(fallback_endpoint):
    """직전 페이지로 돌아가되, 외부 주소로는 절대 보내지 않는다.

    Referer 는 요청자가 조종할 수 있으므로 그대로 믿고 리다이렉트하면
    피싱 사이트로 유도하는 통로가 된다.
    """
    target = request.referrer
    if target:
        parsed = urlparse(target)
        if not parsed.netloc or parsed.netloc == urlparse(request.host_url).netloc:
            return redirect(target)
    return redirect(url_for(fallback_endpoint))


def is_signup_enabled():
    try:
        return bool(rpc("get_signup_enabled"))
    except SupabaseError:
        return True


def log_admin(action, target_user_id=None, target_username=None, detail=None):
    """관리자 행위를 감사 로그에 남긴다.

    기록에 실패해도 이미 수행된 작업을 되돌릴 수는 없으므로, 요청을 실패시키는
    대신 관리자에게 경고를 띄워 기록이 누락되었음을 알린다.
    """
    try:
        rpc(
            "log_admin_action",
            {
                "p_actor": session.get("username") or "(unknown)",
                "p_action": action,
                "p_target_user_id": target_user_id,
                "p_target_username": target_username,
                "p_detail": detail,
                "p_ip": client_ip(),
            },
        )
    except SupabaseError:
        flash("작업은 완료되었지만 감사 로그 기록에 실패했습니다.", "error")


# ----------------------------------------------------------------------
# 접근 제어 데코레이터
# ----------------------------------------------------------------------

# 세션 유효성을 다시 확인하기까지 허용하는 최대 시간(초).
# 0 으로 두면 매 요청마다 확인하지만 모든 페이지에 DB 왕복이 붙습니다.
SESSION_CHECK_INTERVAL = int(os.environ.get("SESSION_CHECK_INTERVAL", "60"))


def session_is_valid():
    """세션이 아직 살아 있는지 확인하고, 권한 변경을 세션에 반영한다.

    최대 SESSION_CHECK_INTERVAL 초만큼 오래된 판정을 허용한다.
    """
    user_id = session.get("user_id")
    if not user_id:
        # 환경변수 관리자는 DB 계정이 없으므로 이 검사의 대상이 아니다.
        return True

    if time.time() - session.get("sv_checked_at", 0) < SESSION_CHECK_INTERVAL:
        return True

    try:
        state = rpc("get_user_session_state", {"p_user_id": user_id})
    except SupabaseError:
        # DB 장애 때 전 사용자를 로그아웃시키는 것은 피해가 더 크다.
        # sv_checked_at 을 갱신하지 않으므로 다음 요청에서 곧바로 다시 시도한다.
        return True

    if (
        not state.get("found")
        or not state.get("is_active")
        or state.get("session_version") != session.get("sv")
    ):
        return False

    session["is_admin"] = bool(state.get("is_admin"))
    session["sv_checked_at"] = time.time()
    return True


def _reject_stale_session():
    session.clear()
    flash("세션이 만료되었습니다. 다시 로그인해 주세요.", "error")
    return redirect(url_for("login"))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("로그인이 필요합니다.", "error")
            return redirect(url_for("login"))
        if not session_is_valid():
            return _reject_stale_session()
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # 권한 판정보다 세션 갱신이 먼저여야 한다. 순서가 뒤바뀌면 방금 부여된
        # 관리자 권한이 반영되기 전에 차단되어 재로그인해야만 들어올 수 있다.
        if session.get("user_id") and not session_is_valid():
            return _reject_stale_session()
        if not session.get("is_admin"):
            flash("관리자만 접근할 수 있습니다.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    return {
        "current_username": session.get("username"),
        "current_is_admin": bool(session.get("is_admin")),
        "logged_in": bool(session.get("user_id") or session.get("is_admin")),
    }


# ----------------------------------------------------------------------
# 기본 라우트
# ----------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("is_admin"):
        return redirect(url_for("admin_panel"))
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if not is_signup_enabled():
        return render_template("signup.html", disabled=True, username="", email="")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = None
        if len(username) < 3:
            error = "아이디는 3자 이상이어야 합니다."
        elif len(password) < 6:
            error = "비밀번호는 6자 이상이어야 합니다."
        elif password != confirm:
            error = "비밀번호가 일치하지 않습니다."

        if error is None:
            result = rpc(
                "signup_user",
                {"p_username": username, "p_password": password, "p_email": email},
            )
            if result.get("success"):
                flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
                return redirect(url_for("login"))
            error = result.get("error", "회원가입에 실패했습니다.")

        flash(error, "error")
        return render_template(
            "signup.html", disabled=False, username=username, email=email
        )

    return render_template("signup.html", disabled=False, username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"
        ip = client_ip()

        # 아이디 종류와 무관하게 잠금을 가장 먼저 판정합니다.
        # 환경변수 관리자도 이 검사를 통과해야만 다음으로 넘어갑니다.
        if rpc("check_login_lock", {"p_username": username, "p_ip": ip}).get("locked"):
            flash("로그인 시도가 너무 많습니다. 15분 후 다시 시도해 주세요.", "error")
            return render_template("login.html", username=username)

        # 비상용 환경변수 관리자. DB 를 거치지 않으므로 기록도 직접 남깁니다.
        if ADMIN_USERNAME and hmac.compare_digest(username, ADMIN_USERNAME):
            success = hmac.compare_digest(password, ADMIN_PASSWORD)
            rpc(
                "record_login_attempt",
                {"p_username": username, "p_ip": ip, "p_success": success},
            )
            if not success:
                flash("아이디 또는 비밀번호가 올바르지 않습니다.", "error")
                return render_template("login.html", username=username)

            session.clear()
            session["is_admin"] = True
            session["username"] = username
            session.permanent = remember
            return redirect(url_for("admin_panel"))

        result = rpc(
            "login_user",
            {"p_username": username, "p_password": password, "p_ip": ip},
        )

        if not result.get("success"):
            reason = result.get("reason")
            if reason == "locked":
                message = "로그인 시도가 너무 많습니다. 15분 후 다시 시도해 주세요."
            elif reason == "inactive":
                message = "정지된 계정입니다. 관리자에게 문의해 주세요."
            else:
                message = "아이디 또는 비밀번호가 올바르지 않습니다."
            flash(message, "error")
            return render_template("login.html", username=username)

        session.clear()
        session["user_id"] = result["id"]
        session["username"] = result["username"]
        session["is_admin"] = bool(result.get("is_admin"))
        session["sv"] = result.get("session_version")
        session["sv_checked_at"] = time.time()
        session.permanent = remember

        if session["is_admin"]:
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))

    return render_template("login.html", username="")


@app.route("/logout")
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ----------------------------------------------------------------------
# 내 계정 관리
# ----------------------------------------------------------------------

@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm = request.form.get("confirm", "")

        if new_password != confirm:
            flash("새 비밀번호가 일치하지 않습니다.", "error")
            return render_template("change_password.html")

        result = rpc(
            "change_password",
            {
                "p_user_id": session["user_id"],
                "p_old_password": old_password,
                "p_new_password": new_password,
            },
        )
        if result.get("success"):
            # 다른 기기의 세션은 끊기고, 요청을 보낸 본인만 그대로 이어간다.
            session["sv"] = result.get("session_version")
            session["sv_checked_at"] = time.time()
            flash("비밀번호가 변경되었습니다. 다른 기기에서는 다시 로그인해야 합니다.", "success")
            return redirect(url_for("dashboard"))
        flash(result.get("error", "비밀번호 변경에 실패했습니다."), "error")

    return render_template("change_password.html")


@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        password = request.form.get("password", "")
        result = rpc(
            "delete_own_account",
            {"p_user_id": session["user_id"], "p_password": password},
        )
        if result.get("success"):
            session.clear()
            flash("회원 탈퇴가 완료되었습니다.", "success")
            return redirect(url_for("login"))
        flash(result.get("error", "탈퇴에 실패했습니다."), "error")

    return render_template("delete_account.html")


# ----------------------------------------------------------------------
# 비밀번호 재설정
# ----------------------------------------------------------------------

def send_reset_email(to_email, reset_url):
    if not RESEND_API_KEY or not to_email:
        return False
    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": RESEND_FROM,
                "to": [to_email],
                "subject": "비밀번호 재설정 안내",
                "html": (
                    "<p>아래 링크에서 비밀번호를 재설정해 주세요. "
                    "링크는 1시간 후 만료됩니다.</p>"
                    f'<p><a href="{reset_url}">{reset_url}</a></p>'
                ),
            },
            timeout=10,
        )
        return response.ok
    except requests.RequestException:
        return False


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        result = rpc("create_password_reset", {"p_username": username})

        if result.get("issued"):
            reset_url = url_for(
                "reset_password", token=result["token"], _external=True
            )
            sent = send_reset_email(result.get("email"), reset_url)
            if sent:
                flash("가입하신 이메일로 재설정 링크를 보냈습니다.", "success")
            else:
                flash(
                    "재설정 요청이 접수되었습니다. 관리자가 확인 후 링크를 전달해 드립니다.",
                    "success",
                )
        else:
            # 계정이 없어도 동일한 메시지 (존재 여부 노출 방지)
            flash(
                "재설정 요청이 접수되었습니다. 관리자가 확인 후 링크를 전달해 드립니다.",
                "success",
            )
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if password != confirm:
            flash("비밀번호가 일치하지 않습니다.", "error")
            return render_template("reset_password.html", token=token)

        result = rpc(
            "reset_password_with_token",
            {"p_token": token, "p_new_password": password},
        )
        if result.get("success"):
            flash("비밀번호가 재설정되었습니다. 로그인해 주세요.", "success")
            return redirect(url_for("login"))
        flash(result.get("error", "재설정에 실패했습니다."), "error")

    return render_template("reset_password.html", token=token)


# ----------------------------------------------------------------------
# 관리자
# ----------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_panel():
    # 오래된 기록 정리. 함수 안에서 하루에 한 번만 실제로 동작하므로
    # 관리자가 화면에 들어올 때마다 불러도 부담이 없습니다.
    try:
        rpc("prune_old_records", {"p_days": 90})
    except SupabaseError:
        pass

    stats = rpc("get_signup_stats", {"p_days": 14})
    return render_template(
        "admin.html",
        signup_enabled=is_signup_enabled(),
        stats=stats,
        pending_resets=rpc("list_pending_resets"),
    )


@app.route("/admin/toggle-signup", methods=["POST"])
@admin_required
def admin_toggle_signup():
    new_state = not is_signup_enabled()
    rpc("set_signup_enabled", {"p_enabled": new_state})
    log_admin("signup_enabled" if new_state else "signup_disabled")
    flash(
        "회원가입을 켰습니다." if new_state else "회원가입을 껐습니다.",
        "success",
    )
    return redirect(url_for("admin_panel"))


@app.route("/admin/users")
@admin_required
def admin_users():
    page = max(1, request.args.get("page", 1, type=int))
    search = request.args.get("q", "").strip()
    per_page = 20

    data = rpc(
        "list_users",
        {
            "p_limit": per_page,
            "p_offset": (page - 1) * per_page,
            "p_search": search or None,
        },
    )
    total = data.get("total", 0)
    return render_template(
        "admin_users.html",
        users=data.get("users", []),
        total=total,
        page=page,
        pages=max(1, (total + per_page - 1) // per_page),
        search=search,
    )


@app.route("/admin/users/<int:user_id>/toggle-active", methods=["POST"])
@admin_required
def admin_toggle_active(user_id):
    active = request.form.get("active") == "1"
    rpc("set_user_active", {"p_user_id": user_id, "p_active": active})
    log_admin(
        "activate_user" if active else "suspend_user",
        target_user_id=user_id,
        target_username=request.form.get("username"),
    )
    flash("계정을 활성화했습니다." if active else "계정을 정지했습니다.", "success")
    return safe_redirect("admin_users")


@app.route("/admin/users/<int:user_id>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(user_id):
    make_admin = request.form.get("is_admin") == "1"
    rpc("set_user_admin", {"p_user_id": user_id, "p_is_admin": make_admin})
    log_admin(
        "grant_admin" if make_admin else "revoke_admin",
        target_user_id=user_id,
        target_username=request.form.get("username"),
    )
    flash(
        "관리자 권한을 부여했습니다." if make_admin else "관리자 권한을 해제했습니다.",
        "success",
    )
    return safe_redirect("admin_users")


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    rpc("admin_delete_user", {"p_user_id": user_id})
    log_admin(
        "delete_user",
        target_user_id=user_id,
        target_username=request.form.get("username"),
    )
    flash("회원을 삭제했습니다.", "success")
    return safe_redirect("admin_users")


@app.route("/admin/users/<int:user_id>/force-logout", methods=["POST"])
@admin_required
def admin_force_logout(user_id):
    rpc("force_logout_user", {"p_user_id": user_id})
    log_admin(
        "force_logout",
        target_user_id=user_id,
        target_username=request.form.get("username"),
    )
    flash("해당 회원의 모든 세션을 종료했습니다.", "success")
    return safe_redirect("admin_users")


@app.route("/admin/users/<int:user_id>/reset-link", methods=["POST"])
@admin_required
def admin_reset_link(user_id):
    username = request.form.get("username", "")
    result = rpc("create_password_reset", {"p_username": username})
    if result.get("issued"):
        link = url_for("reset_password", token=result["token"], _external=True)
        log_admin("issue_reset_link", target_user_id=user_id, target_username=username)
        flash(f"재설정 링크(1시간 유효): {link}", "success")
    else:
        flash("링크 생성에 실패했습니다.", "error")
    return safe_redirect("admin_users")


@app.route("/admin/logs")
@admin_required
def admin_logs():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 50
    data = rpc(
        "get_login_attempts",
        {"p_limit": per_page, "p_offset": (page - 1) * per_page},
    )
    total = data.get("total", 0)
    return render_template(
        "admin_logs.html",
        attempts=data.get("attempts", []),
        total=total,
        page=page,
        pages=max(1, (total + per_page - 1) // per_page),
    )


@app.route("/admin/unlock", methods=["POST"])
@admin_required
def admin_unlock():
    username = request.form.get("username", "").strip()
    if username:
        rpc("clear_login_attempts", {"p_username": username})
        log_admin("unlock_account", target_username=username)
        flash(f"'{username}' 계정의 로그인 잠금을 해제했습니다.", "success")
    return safe_redirect("admin_logs")


@app.route("/admin/audit")
@admin_required
def admin_audit():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = 50
    data = rpc(
        "get_admin_actions",
        {"p_limit": per_page, "p_offset": (page - 1) * per_page},
    )
    total = data.get("total", 0)
    return render_template(
        "admin_audit.html",
        actions=data.get("actions", []),
        total=total,
        page=page,
        pages=max(1, (total + per_page - 1) // per_page),
    )


@app.route("/admin/stats")
@admin_required
def admin_stats():
    stats = rpc("get_signup_stats", {"p_days": 30})
    daily = stats.get("daily", [])
    peak = max((d["count"] for d in daily), default=0) or 1
    return render_template("admin_stats.html", stats=stats, daily=daily, peak=peak)


# ----------------------------------------------------------------------
# 오류 페이지
# ----------------------------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404,
                           message="페이지를 찾을 수 없습니다."), 404


@app.errorhandler(500)
def server_error(error):
    return render_template("error.html", code=500,
                           message="서버에서 오류가 발생했습니다."), 500


@app.errorhandler(SupabaseError)
def supabase_error(error):
    return render_template("error.html", code=503,
                           message="데이터베이스에 연결할 수 없습니다."), 503


if __name__ == "__main__":
    app.run(debug=True)
