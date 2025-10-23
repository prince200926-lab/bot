import os, time
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import firebase_admin
from firebase_admin import credentials, db, auth as admin_auth
import requests
from dotenv import load_dotenv

load_dotenv()

# --- Firebase Config --------------------------------------------------------
FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY")
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")
SERVICE_ACCOUNT_PATH = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "serviceAccountKey.json")

if not FIREBASE_API_KEY or not FIREBASE_DB_URL:
    raise RuntimeError("Set FIREBASE_API_KEY and FIREBASE_DB_URL in .env")

if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
    firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})

# --- Flask Setup ------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "super-secret-key")

# --- Firebase Helpers -------------------------------------------------------
def firebase_sign_in(email, password):
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_API_KEY}"
    payload = {"email": email, "password": password, "returnSecureToken": True}
    r = requests.post(url, json=payload)
    return r.json() if r.status_code == 200 else {"error": r.json()}

def get_user_metadata(uid):
    return db.reference(f"users/{uid}").get() or {}

def student_key_from_name(name):
    return "".join(ch if ch.isalnum() else "_" for ch in name.strip())

# --- Auth & Session ---------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    if session.get("idToken") and session.get("uid"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        if not email or not password:
            flash("Enter email and password", "warning")
            return redirect(url_for("login"))
        res = firebase_sign_in(email, password)
        if "error" in res:
            flash("Login failed: " + str(res["error"]), "danger")
            return redirect(url_for("login"))

        uid = res["localId"]
        id_token = res["idToken"]
        refresh_token = res.get("refreshToken")

        # Fetch role from Firebase DB
        meta = get_user_metadata(uid)
        if not meta:
            flash("User metadata not found. Contact admin.", "danger")
            return redirect(url_for("login"))

        # Store in session
        session.update({
            "uid": uid,
            "idToken": id_token,
            "refreshToken": refresh_token,
            "role": meta.get("role"),  # <-- detect role from Firebase
            "assignedClass": meta.get("assignedClass", ""),
            "assignedSection": meta.get("assignedSection", "")
        })

        flash(f"Signed in as {meta.get('role')}", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            flash("Please sign in", "warning")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

# --- Dashboards -------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")
    if role == "counselor":
        return redirect(url_for("counselor_dashboard"))
    else:
        return redirect(url_for("teacher_dashboard"))

# Teacher sees assigned class/section
@app.route("/teacher")
@login_required
def teacher_dashboard():
    if session.get("role") != "teacher":
        flash("Not authorized for teacher dashboard", "danger")
        return redirect(url_for("dashboard"))
    assigned_class = session.get("assignedClass")
    assigned_section = session.get("assignedSection")
    students = db.reference(f"Classes/{assigned_class}/{assigned_section}").get() or {}
    return render_template(
        "teacher_dashboard.html",
        students=students,
        assigned_class=assigned_class,
        assigned_section=assigned_section
    )

# Counselor sees all students
@app.route("/counselor")
@login_required
def counselor_dashboard():
    if session.get("role") != "counselor":
        flash("Not authorized for counselor dashboard", "danger")
        return redirect(url_for("dashboard"))

    # Fetch all classes from Firebase
    ref = db.reference("Classes")
    all_students = ref.get() or {}  # now it's a nested dict: Class -> Section -> Students

    return render_template("counselor_dashboard.html", all_students=all_students)

# --- Add/Edit Students ------------------------------------------------------
@app.route("/add_student", methods=["GET", "POST"])
@login_required
def add_student():
    if request.method == "POST":
        if session.get("role") == "teacher":
            target_class = session.get("assignedClass")
            target_section = session.get("assignedSection")
        else:
            target_class = request.form.get("class", "").strip()
            target_section = request.form.get("section", "").strip()
        name = request.form.get("name", "").strip()
        key = student_key_from_name(name)
        payload = {
            "name": name,
            "specialNeeds": request.form.get("specialNeeds", "").strip(),
            "progress": request.form.get("progress", "").strip(),
            "accommodations": request.form.get("accommodations", "").strip(),
            "notes": request.form.get("notes", "").strip(),
            "createdBy": session.get("uid"),
            "lastUpdated": int(time.time()*1000)
        }
        db.reference(f"Classes/{target_class}/{target_section}/{key}").set(payload)
        flash(f"Student {name} added to {target_class}/{target_section}", "success")
        return redirect(url_for("dashboard"))
    return render_template("add_edit_student.html", role=session.get("role"))

# --- Run App ---------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
