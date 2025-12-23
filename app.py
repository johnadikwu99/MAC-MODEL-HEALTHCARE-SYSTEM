import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, DateTime, inspect
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd

# ---------------- DATABASE SETUP ----------------
Base = declarative_base()
engine = create_engine("sqlite:///database.db", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
db_session = Session()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    role = Column(String)
    clearance = Column(Integer)
    active = Column(Integer, default=1)  # 1 = active, 0 = disabled

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Patient(Base):
    __tablename__ = "patients"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    diagnosis = Column(String)
    classification = Column(Integer)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    username = Column(String)
    patient_name = Column(String)
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.now)

# Create tables if missing
Base.metadata.create_all(engine)

# ---------------- SAFE SCHEMA UPDATE ----------------
inspector = inspect(engine)
columns = [col['name'] for col in inspector.get_columns('users')]
if 'active' not in columns:
    with engine.connect() as conn:
        conn.execute("ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1")
        conn.commit()

# ---------------- INITIAL DATA ----------------
def init_data():
    if not db_session.query(User).filter_by(username="admin").first():
        admin = User(username="admin", role="admin", clearance=3)
        admin.set_password("admin123")
        doctor = User(username="doctor1", role="doctor", clearance=3)
        doctor.set_password("doc123")
        nurse = User(username="nurse1", role="nurse", clearance=2)
        nurse.set_password("nurse123")
        staff = User(username="staff1", role="staff", clearance=1)
        staff.set_password("staff123")
        db_session.add_all([admin, doctor, nurse, staff])

        # Example patients
        p1 = Patient(name="John Doe", diagnosis="Cardiac Arrest", classification=3)
        p2 = Patient(name="Jane Smith", diagnosis="Diabetes", classification=2)
        p3 = Patient(name="Alex Brown", diagnosis="Flu", classification=1)
        db_session.add_all([p1, p2, p3])
        db_session.commit()

init_data()

# ---------------- STREAMLIT CSS (embedded) ----------------
st.markdown("""
<style>
body {background-color:#0b0c10; color:white; font-family:'Arial', sans-serif;}
.stButton>button {background-color:#1f6feb; color:white; border-radius:8px; height:40px; margin:5px; width:100%;}
.stButton>button:hover {background-color:#3aa0ff; transition:0.3s;}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION STATE ----------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user" not in st.session_state:
    st.session_state.user = None

# ---------------- LOGIN PAGE ----------------
def login_page():
    st.set_page_config(page_title="MAC Healthcare System", page_icon="🔒", layout="centered")
    st.markdown("<h1 style='text-align: center; color: #1f6feb;'>🔒 MAC Healthcare System</h1>", unsafe_allow_html=True)
    st.markdown("<h4 style='text-align: center; color: white;'>Secure Access Controlled Dashboard</h4>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h5 style='color:white; text-align:center;'>Login</h5>", unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            user = db_session.query(User).filter_by(username=username).first()
            if user and user.check_password(password):
                if user.active == 0:
                    st.error("Account disabled. Contact admin.")
                else:
                    st.session_state.logged_in = True
                    st.session_state.user = user
            else:
                st.error("Invalid credentials")

# ---------------- DASHBOARD ----------------
def dashboard_page(user):
    st.title(f"{user.username}'s Dashboard")
    st.write(f"Role: {user.role} | Clearance Level: {user.clearance}")
    st.sidebar.write(f"Logged in as {user.username}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"logged_in":False,"user":None}))
    st.subheader("Accessible Patients")

    search = st.text_input("Search patient by name")
    patients = db_session.query(Patient).filter(Patient.classification <= user.clearance)
    if search:
        patients = [p for p in patients if search.lower() in p.name.lower()]

    cols = st.columns(3)
    for idx, p in enumerate(patients):
        col = cols[idx % 3]
        with col:
            color = "#2ecc71" if p.classification==1 else "#f1c40f" if p.classification==2 else "#e63946"
            with st.container():
                st.markdown(f"<div style='background-color:#1f1f1f; padding:15px; border-left:5px solid {color}; border-radius:10px;'>", unsafe_allow_html=True)
                st.markdown(f"### {p.name}")
                st.markdown(f"Classification: {p.classification}")
                st.markdown(f"Diagnosis: {'***Hidden***' if user.clearance < p.classification else p.diagnosis}")
                st.markdown("</div>", unsafe_allow_html=True)
                if st.button(f"View {p.name}", key=f"view_{p.id}"):
                    if user.clearance >= p.classification:
                        db_session.add(AuditLog(username=user.username, patient_name=p.name, action="GRANTED"))
                        db_session.commit()
                        st.success(f"Access Granted to {p.name}. Check your email for details.")
                        st.info(f"Diagnosis: {p.diagnosis}")
                    else:
                        db_session.add(AuditLog(username=user.username, patient_name=p.name, action="DENIED"))
                        db_session.commit()
                        st.error("Access Denied: Insufficient clearance.")

# ---------------- ADMIN PANEL ----------------
def admin_panel(user):
    st.title("Admin Panel")
    st.sidebar.write(f"Admin: {user.username}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"logged_in":False,"user":None}))

    st.subheader("Users")
    users = db_session.query(User).all()

    # Session flag for safe rerun
    if "rerun_flag" not in st.session_state:
        st.session_state.rerun_flag = False

    for u in users:
        col1, col2, col3 = st.columns([4,2,2])
        with col1:
            status = "Active" if u.active else "Disabled"
            st.markdown(f"{u.username} ({u.role}) - Clearance: {u.clearance} - Status: {status}")
        with col2:
            if st.button(f"{'Disable' if u.active else 'Enable'} {u.username}", key=f"toggle_{u.id}"):
                u.active = 0 if u.active else 1
                db_session.commit()
                st.success(f"{u.username} has been {'disabled' if u.active == 0 else 'enabled'}.")
                st.session_state.rerun_flag = True
        with col3:
            if st.button(f"Delete {u.username}", key=f"delete_{u.id}"):
                db_session.delete(u)
                db_session.commit()
                st.success(f"{u.username} deleted permanently.")
                st.session_state.rerun_flag = True

    # Trigger rerun once after all changes
    if st.session_state.rerun_flag:
        st.session_state.rerun_flag = False
        st.experimental_rerun()

    # Add User Form
    with st.form("add_user_form"):
        st.write("Add New User")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["admin","doctor","nurse","staff"])
        new_clearance = st.slider("Clearance Level", 1, 3, 1)
        submitted = st.form_submit_button("Add User")
        if submitted:
            if db_session.query(User).filter_by(username=new_username).first():
                st.error("Username already exists.")
            else:
                new_user = User(username=new_username, role=new_role, clearance=new_clearance)
                new_user.set_password(new_password)
                db_session.add(new_user)
                db_session.commit()
                st.success(f"User {new_username} added successfully.")

# ---------------- MAIN ----------------
if not st.session_state.logged_in:
    login_page()
else:
    user = st.session_state.user
    if user.role == "admin":
        admin_panel(user)
    else:
        dashboard_page(user)
