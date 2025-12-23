import streamlit as st
import sqlite3
from datetime import datetime

# ================= CONFIG =================
st.set_page_config(
    page_title="MAC Healthcare System",
    page_icon="🔐",
    layout="centered"
)

DB_NAME = "database.db"

# ================= DATABASE =================
def connect_db():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def init_db():
    conn = connect_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        clearance TEXT,
        active INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        timestamp TEXT
    )
    """)

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany("""
        INSERT INTO users (username, password, clearance, active)
        VALUES (?, ?, ?, ?)
        """, [
            ("admin", "admin123", "Top Secret", 1),
            ("doctor1", "doctor123", "Secret", 1),
            ("nurse1", "nurse123", "Confidential", 1),
            ("lab1", "lab123", "Restricted", 1)
        ])

    conn.commit()
    conn.close()

# ================= LOGGING =================
def log_action(user, action):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs (username, action, timestamp) VALUES (?, ?, ?)",
        (user, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_logs():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT username, action, timestamp FROM audit_logs ORDER BY id DESC")
    logs = cur.fetchall()
    conn.close()
    return logs

# ================= USERS =================
def authenticate(username, password):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, clearance, active
        FROM users WHERE username=? AND password=?
    """, (username, password))
    user = cur.fetchone()
    conn.close()
    return user

def get_users():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, clearance, active FROM users")
    users = cur.fetchall()
    conn.close()
    return users

def disable_user(uid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET active=0 WHERE id=?", (uid,))
    conn.commit()
    conn.close()

def enable_user(uid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET active=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()

def delete_user(uid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit()
    conn.close()

# ================= INIT =================
init_db()

if "user" not in st.session_state:
    st.session_state.user = None

if "confirm_delete" not in st.session_state:
    st.session_state.confirm_delete = None

# ================= LOGIN =================
if not st.session_state.user:
    st.markdown("## 🔐 MAC Healthcare Access System")
    st.caption("Mandatory Access Control — Academic Demonstration")

    u = st.text_input("Username")
    p = st.text_input("Password", type="password")

    if st.button("Login"):
        user = authenticate(u, p)
        if not user:
            st.error("Invalid credentials")
        else:
            uid, uname, clearance, active = user
            if not active:
                st.error("Account disabled")
                log_action(uname, "Login attempt while disabled")
            else:
                st.session_state.user = {
                    "id": uid,
                    "username": uname,
                    "clearance": clearance
                }
                log_action(uname, "Logged in")
                st.rerun()

# ================= APP =================
else:
    user = st.session_state.user

    st.sidebar.success(f"User: {user['username']}")
    st.sidebar.write(f"Clearance: {user['clearance']}")

    pages = ["Dashboard", "Logout"]
    if user["clearance"] == "Top Secret":
        pages.insert(1, "Admin Panel")
        pages.insert(2, "Audit Logs")

    page = st.sidebar.radio("Navigation", pages)

    # -------- DASHBOARD --------
    if page == "Dashboard":
        st.header("🏥 Healthcare Dashboard")
        st.info("Access enforced using Mandatory Access Control (MAC).")

        if user["clearance"] in ["Top Secret", "Secret"]:
            st.success("Access Granted: Medical Records")
        elif user["clearance"] == "Confidential":
            st.warning("Limited Access: Patient Info Only")
        else:
            st.error("Access Denied")

    # -------- ADMIN PANEL --------
    elif page == "Admin Panel":
        st.header("🛡️ Admin Panel")

        for uid, uname, clearance, active in get_users():
            c1, c2, c3, c4 = st.columns([3, 3, 2, 4])

            c1.write(f"**{uname}**")
            c2.write(clearance)
            c3.write("🟢 Active" if active else "🔴 Disabled")

            if uname == "admin":
                c4.write("🔒 Protected")
                continue

            if active:
                if c4.button("🚫 Disable", key=f"d_{uid}"):
                    disable_user(uid)
                    log_action("admin", f"Disabled {uname}")
                    st.rerun()
            else:
                if c4.button("✅ Enable", key=f"e_{uid}"):
                    enable_user(uid)
                    log_action("admin", f"Enabled {uname}")
                    st.rerun()

            if c4.button("🗑️ Delete", key=f"x_{uid}"):
                st.session_state.confirm_delete = (uid, uname)

        if st.session_state.confirm_delete:
            uid, uname = st.session_state.confirm_delete
            st.error(f"Confirm permanent deletion of **{uname}**?")
            a, b = st.columns(2)

            if a.button("Cancel"):
                st.session_state.confirm_delete = None
                st.rerun()

            if b.button("Yes, Delete"):
                delete_user(uid)
                log_action("admin", f"Deleted {uname}")
                st.session_state.confirm_delete = None
                st.rerun()

    # -------- AUDIT LOGS --------
    elif page == "Audit Logs":
        st.header("📜 Audit Logs")
        for u, a, t in get_logs():
            st.write(f"🕒 {t} | 👤 {u} | 🔐 {a}")

    # -------- LOGOUT --------
    elif page == "Logout":
        log_action(user["username"], "Logged out")
        st.session_state.user = None
        st.rerun()

