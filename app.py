import hmac
import os
from pathlib import Path

import requests
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/") + "/"
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key-change-me"


def call_supabase_rpc(function_name, payload=None):
    response = requests.post(
        f"{SUPABASE_URL}rpc/{function_name}",
        json=payload or {},
        headers={
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def is_signup_enabled():
    try:
        return bool(call_supabase_rpc("get_signup_enabled"))
    except requests.RequestException:
        return True


def is_admin_login(username, password):
    return hmac.compare_digest(username, ADMIN_USERNAME) and hmac.compare_digest(
        password, ADMIN_PASSWORD
    )


@app.route("/")
def index():
    if session.get("is_admin"):
        return redirect(url_for("admin_panel"))
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    signup_enabled = is_signup_enabled()

    if not signup_enabled:
        return render_template("signup.html", error=None, username="", disabled=True)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
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
            result = call_supabase_rpc(
                "signup_user", {"p_username": username, "p_password": password}
            )
            if result.get("success"):
                return redirect(url_for("login", signup="success"))
            error = result.get("error", "회원가입에 실패했습니다.")

        return render_template(
            "signup.html", error=error, username=username, disabled=False
        )

    return render_template("signup.html", error=None, username="", disabled=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if is_admin_login(username, password):
            session.clear()
            session["is_admin"] = True
            session["username"] = username
            return redirect(url_for("admin_panel"))

        result = call_supabase_rpc(
            "login_user", {"p_username": username, "p_password": password}
        )

        if not result.get("success"):
            return render_template(
                "login.html", error="아이디 또는 비밀번호가 올바르지 않습니다.", username=username
            )

        session.clear()
        session["user_id"] = result["id"]
        session["username"] = result["username"]
        return redirect(url_for("dashboard"))

    signup_success = request.args.get("signup") == "success"
    return render_template(
        "login.html", error=None, username="", signup_success=signup_success
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/admin")
def admin_panel():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    return render_template(
        "admin.html", username=session.get("username"), signup_enabled=is_signup_enabled()
    )


@app.route("/admin/toggle-signup", methods=["POST"])
def admin_toggle_signup():
    if not session.get("is_admin"):
        return redirect(url_for("login"))
    call_supabase_rpc(
        "set_signup_enabled", {"p_enabled": not is_signup_enabled()}
    )
    return redirect(url_for("admin_panel"))


if __name__ == "__main__":
    app.run(debug=True)
