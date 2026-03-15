"""
Capsule Trust & Savings - Intentionally Vulnerable Banking Application
Target application for Project Argus. Run ONLY in local dev environments.
"""

import sqlite3
from datetime import datetime

from flask import Flask, jsonify, make_response, redirect, render_template, request

from database import DB_PATH, init_db

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login_page():
    return render_template("login.html")


@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()
    conn.close()

    if row:
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session_user", row["username"])
        return resp

    return render_template("login.html", error="Invalid username or password.")


@app.get("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session_user")
    return resp


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------


@app.get("/dashboard")
def dashboard():
    username = request.cookies.get("session_user")
    if not username:
        return redirect("/login")
    return render_template("dashboard.html",
                           username=username,
                           now=datetime.utcnow().strftime('%A, %d %B %Y'))


# ---------------------------------------------------------------------------
# VULN 1 - SQL Injection via legacy auth portal
# ---------------------------------------------------------------------------


@app.get("/corp/legacy-auth")
def legacy_auth_form():
    return render_template('legacy_auth.html')


@app.post("/corp/legacy-auth")
def legacy_auth():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = get_db()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as e:
        conn.close()
        return jsonify({
            "status": "error",
            "db_error": str(e),
            "hint": "Legacy schema v1.3 — contact DBA",
        }), 200

    conn.close()

    if row:
        return jsonify({
            "status": "authenticated",
            "INTERNAL_VAULT_KEY": "VLT-7F3A-ALPHA-9921",
            "CORE_BANKING_ACCESS_TOKEN": "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4iLCAic3ViIjoial9zdGVybGluZyJ9.",
            "message": "Legacy migration session established.",
        }), 200

    return jsonify({
        "status": "unauthorized",
        "message": "Credentials not found in legacy schema.",
    }), 401


# ---------------------------------------------------------------------------
# VULN 2 - IDOR on wire transfer receipts
# ---------------------------------------------------------------------------


@app.get("/api/v1/vault/receipt/<int:tx_id>")
def get_receipt(tx_id: int):
    session_user = request.cookies.get("session_user")
    if not session_user:
        return jsonify({"status": "unauthorized", "message": "Login required."}), 401

    conn = get_db()
    row = conn.execute(
        """
        SELECT t.*, u.username, u.email, u.ssn, u.salary
        FROM transactions t JOIN users u ON t.user_id = u.id
        WHERE t.tx_id = ?
        """,
        (tx_id,),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "not_found", "message": "Receipt not found."}), 404

    return jsonify({
        "tx_id": row["tx_id"],
        "amount": row["amount"],
        "recipient_account": row["recipient_account"],
        "routing_number": row["routing_number"],
        "is_private": row["is_private"],
        "owner": {
            "username": row["username"],
            "email": row["email"],
            "ssn": row["ssn"],
            "salary": row["salary"],
        },
    })


# ---------------------------------------------------------------------------
# VULN 3 - Reflected XSS in dispute search
# ---------------------------------------------------------------------------


@app.get("/admin/disputes/search")
def dispute_search():
    session_user = request.cookies.get("session_user")
    if not session_user:
        return redirect("/login")

    merchant = request.args.get("merchant", "")

    results = [
        {"id": "DSP-40221", "merchant": "ACME Retail", "amount": 2499, "status": "Under Review", "analyst": "s_miller"},
        {"id": "DSP-40222", "merchant": "GlobalPay Ltd", "amount": 18700, "status": "Escalated", "analyst": "s_miller"},
        {"id": "DSP-40223", "merchant": "NovaTech Inc", "amount": 530, "status": "Closed - Fraudulent", "analyst": "j_sterling"},
    ]

    return render_template("disputes.html",
                           username=session_user,
                           merchant=merchant,
                           results=results)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
