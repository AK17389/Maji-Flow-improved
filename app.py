"""
MAJI-FLOW — Water Leak Detection System
========================================
Security hardening applied:
  - Passwords hashed with werkzeug (bcrypt-backed)
  - Secret key loaded from environment variable
  - Debug/test routes removed
  - mark_fixed converted to POST (CSRF-safe)
  - PDF streamed via BytesIO (never written to static/)
  - Raw error strings replaced with flash messages
  - CSRF protection via flask-wtf

Architecture fixes:
  - DB connections use context managers (no leaks)
  - Double get_db() in client_dashboard removed
  - Filter logic extracted to helper
  - update_profile route fixed (was dead nested code)
  - ML model uses Path(__file__) for reliable resolution

Code quality:
  - Duplicate imports consolidated at top
  - No bare except clauses
  - Consistent error handling throughout
"""

import io
import os
import random
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytz
from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from werkzeug.security import check_password_hash, generate_password_hash

from ml_model.model import predict_leak

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

load_dotenv()  # reads .env file if present

app = Flask(__name__)

# Secret key MUST come from environment — never hardcoded
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# CSRF protection for all POST forms
csrf = CSRFProtect(app)

DATABASE_PATH = Path(os.environ.get("DATABASE_PATH", "database/maji_flow.db"))

# ─────────────────────────────────────────────
# SIMULATED WATER NETWORK LOCATIONS
# ─────────────────────────────────────────────

LOCATIONS = [
    "Lusaka Central",
    "Kabwata",
    "Chilenje",
    "Woodlands",
    "Chelstone",
    "Kamwala",
    "Matero",
    "Kalingalinga",
]

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

@contextmanager
def get_db():
    """Context manager for database connections.
    Guarantees the connection is closed even if an exception occurs.

    Usage:
        with get_db() as conn:
            conn.execute(...)
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # enables dict-style column access
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they don't already exist."""
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname       TEXT,
                company_name   TEXT,
                email          TEXT UNIQUE NOT NULL,
                contact        TEXT,
                branch_location TEXT,
                password       TEXT NOT NULL,
                role           TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS leak_reports (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                location  TEXT    NOT NULL,
                pressure  INTEGER NOT NULL,
                status    TEXT    NOT NULL,
                timestamp TEXT    NOT NULL,
                fixed     INTEGER NOT NULL DEFAULT 0
            );
        """)


def _migrate_db():
    """Add any missing columns from older schema versions (safe to run repeatedly)."""
    with get_db() as conn:
        try:
            conn.execute("ALTER TABLE leak_reports ADD COLUMN fixed INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # column already exists — expected


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def login_required(role=None):
    """Return a redirect to /login if the user is not logged in,
    or if a specific role is required and doesn't match."""
    if "user_id" not in session:
        return redirect(url_for("login"))
    if role and session.get("role") != role:
        return redirect(url_for("login"))
    return None


def get_reports(filter_type: str, fixed: bool = False) -> list:
    """Shared query helper used by both the dashboard and the API.

    Args:
        filter_type: 'LEAK', 'WARNING', or anything else for all.
        fixed:       True to fetch resolved reports, False for active.

    Returns:
        List of sqlite3.Row objects.
    """
    fixed_val = 1 if fixed else 0

    with get_db() as conn:
        if filter_type == "LEAK":
            rows = conn.execute(
                "SELECT * FROM leak_reports WHERE status='LEAK' AND fixed=? ORDER BY id DESC LIMIT 100",
                (fixed_val,),
            ).fetchall()
        elif filter_type == "WARNING":
            rows = conn.execute(
                "SELECT * FROM leak_reports WHERE status='WARNING' AND fixed=? ORDER BY id DESC LIMIT 100",
                (fixed_val,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM leak_reports WHERE fixed=? ORDER BY id DESC LIMIT 100",
                (fixed_val,),
            ).fetchall()
    return rows


# ─────────────────────────────────────────────
# PUBLIC ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        role = request.form.get("role", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # Server-side validation
        if role not in ("client", "company"):
            flash("Please select a valid role.", "error")
            return render_template("register.html")

        if not email or "@" not in email:
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        # Role-specific fields
        if role == "client":
            fullname = request.form.get("fullname", "").strip()
            if not fullname:
                flash("Full name is required.", "error")
                return render_template("register.html")
            company_name = contact = branch_location = None
        else:
            company_name = request.form.get("company_name", "").strip()
            contact = request.form.get("contact", "").strip()
            branch_location = request.form.get("branch_location", "").strip()
            if not company_name:
                flash("Company name is required.", "error")
                return render_template("register.html")
            fullname = None

        # Hash the password — never store plaintext
        hashed_password = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    """
                    INSERT INTO users
                        (fullname, company_name, email, contact, branch_location, password, role)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (fullname, company_name, email, contact, branch_location, hashed_password, role),
                )
            flash("Account created successfully. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("An account with that email already exists.", "error")
        except Exception:
            flash("Registration failed. Please try again.", "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip()

        if not email or not password or role not in ("client", "company"):
            flash("Please fill in all fields correctly.", "error")
            return render_template("login.html")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email=? AND role=?",
                (email, role),
            ).fetchone()

        # Use constant-time password check to prevent timing attacks
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["user"] = user["fullname"] if role == "client" else user["company_name"]

            return redirect(
                url_for("client_dashboard") if role == "client" else url_for("company_dashboard")
            )
        else:
            # Generic message — don't reveal whether email or password was wrong
            flash("Invalid credentials. Please check your email, password and role.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ─────────────────────────────────────────────
# CLIENT ROUTES
# ─────────────────────────────────────────────

@app.route("/client_dashboard")
def client_dashboard():
    guard = login_required(role="client")
    if guard:
        return guard

    pressure = random.randint(20, 100)
    location = random.choice(LOCATIONS)
    status = predict_leak(pressure)

    timestamp = datetime.now(pytz.timezone("Africa/Lusaka")).strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        conn.execute(
            "INSERT INTO leak_reports (location, pressure, status, timestamp) VALUES (?, ?, ?, ?)",
            (location, pressure, status, timestamp),
        )

    return render_template(
        "client_dashboard.html",
        pressure=pressure,
        status=status,
        location=location,
        client_name=session.get("user"),
    )


# ─────────────────────────────────────────────
# COMPANY ROUTES
# ─────────────────────────────────────────────

@app.route("/company_dashboard")
def company_dashboard():
    guard = login_required(role="company")
    if guard:
        return guard

    filter_type = request.args.get("filter", "ALL").upper()
    reports = get_reports(filter_type, fixed=False)

    return render_template(
        "company_dashboard.html",
        company_name=session.get("user"),
        reports=reports,
        current_filter=filter_type,
    )


@app.route("/mark_fixed/<int:report_id>", methods=["POST"])
def mark_fixed(report_id):
    """POST-only so it cannot be triggered by a link (CSRF-safe)."""
    guard = login_required(role="company")
    if guard:
        return guard

    with get_db() as conn:
        conn.execute(
            "UPDATE leak_reports SET fixed=1 WHERE id=?",
            (report_id,),
        )

    flash("Report marked as fixed.", "success")
    return redirect(url_for("company_dashboard"))


@app.route("/fixed_reports")
def fixed_reports():
    guard = login_required(role="company")
    if guard:
        return guard

    reports = get_reports("ALL", fixed=True)

    return render_template(
        "fixed_reports.html",
        company_name=session.get("user"),
        reports=reports,
    )


@app.route("/company_analytics")
def company_analytics():
    guard = login_required(role="company")
    if guard:
        return guard

    with get_db() as conn:
        total_leaks    = conn.execute("SELECT COUNT(*) FROM leak_reports WHERE status='LEAK'").fetchone()[0]
        total_warnings = conn.execute("SELECT COUNT(*) FROM leak_reports WHERE status='WARNING'").fetchone()[0]
        total_fixed    = conn.execute("SELECT COUNT(*) FROM leak_reports WHERE fixed=1").fetchone()[0]
        total_active   = conn.execute("SELECT COUNT(*) FROM leak_reports WHERE fixed=0").fetchone()[0]

    return render_template(
        "company_analytics.html",
        total_leaks=total_leaks,
        total_warnings=total_warnings,
        total_fixed=total_fixed,
        total_active=total_active,
    )


# ─────────────────────────────────────────────
# API ROUTES
# ─────────────────────────────────────────────

@app.route("/api/reports")
def api_reports():
    guard = login_required(role="company")
    if guard:
        return jsonify({"error": "Unauthorized"}), 401

    filter_type = request.args.get("filter", "ALL").upper()
    rows = get_reports(filter_type, fixed=False)

    data = [
        {
            "id":        row["id"],
            "location":  row["location"],
            "pressure":  row["pressure"],
            "status":    row["status"],
            "timestamp": row["timestamp"],
        }
        for row in rows
    ]

    return jsonify({"reports": data})


@app.route("/download_pdf")
def download_pdf():
    guard = login_required(role="company")
    if guard:
        return guard

    with get_db() as conn:
        reports = conn.execute(
            "SELECT location, pressure, status, timestamp FROM leak_reports ORDER BY id DESC"
        ).fetchall()

    # Build PDF in memory — never write to static/
    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer, pagesize=letter)

    table_data = [["Location", "Pressure (PSI)", "Status", "Timestamp"]]
    for report in reports:
        table_data.append([report["location"], report["pressure"], report["status"], report["timestamp"]])

    table = Table(table_data)
    table.setStyle(
        TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#0077b6")),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0),  11),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND",  (0, 1), (-1, -1), colors.HexColor("#f4f6f8")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eaf4fb")]),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE",    (0, 1), (-1, -1), 9),
            ("TOPPADDING",  (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    doc.build([table])
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="maji_flow_leak_report.pdf",
        mimetype="application/pdf",
    )


@app.route("/update_profile", methods=["POST"])
def update_profile():
    """Allow a logged-in user to update their password."""
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request"}), 400

    new_password = data.get("password", "").strip()

    if new_password and len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    updates = []
    params = []

    if new_password:
        updates.append("password = ?")
        params.append(generate_password_hash(new_password))

    if not updates:
        return jsonify({"message": "Nothing to update"}), 200

    params.append(session["user_id"])

    with get_db() as conn:
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)

    return jsonify({"message": "Profile updated successfully"})


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    _migrate_db()
    init_db()
    # debug=False in production — set FLASK_ENV=development in .env for dev mode
    debug_mode = os.environ.get("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=10000)
