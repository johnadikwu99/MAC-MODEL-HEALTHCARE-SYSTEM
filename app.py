import streamlit as st
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import os

# ---------------- ROLE → CLEARANCE MAP ----------------
ROLE_CLEARANCE = {
    "admin": 3,
    "doctor": 3,
    "nurse": 2,
    "staff": 1
}

# ---------------- DATABASE SETUP ----------------
Base = declarative_base()

# Streamlit Cloud friendly path
db_path = os.path.join(os.getcwd(), "database.db")
engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
Session = sessionmaker(bind=engine)
db_session = Session()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password_hash = Column(String)
    role = Column(String)
    clearance = Column(Integer)
    is_active = Column(Integer, default=1)

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

Base.metadata.create_all(engine)

# ---------------- INITIAL DATA ----------------
def init_data():
    if not db_session.query(User).first():
        admin = User(username="admin", role="admin", clearance=ROLE_CLEARANCE["admin"])
        admin.set_password("admin123")
        doctor = User(username="doctor1", role="doctor", clearance=ROLE_CLEARANCE["doctor"])
        doctor.set_password("doc123")
        nurse = User(username="nurse1", role="nurse", clearance=ROLE_CLEARANCE["nurse"])
        nurse.set_password("nurse123")
        staff = User(username="staff1", role="staff", clearance=ROLE_CLEARANCE["staff"])
        staff.set_password("staff123")
        db_session.add_all([admin, doctor, nurse, staff])

        # Example patients
        p1 = Patient(name="John Doe", diagnosis="Cardiac Arrest", classification=3)
        p2 = Patient(name="Jane Smith", diagnosis="Diabetes", classification=2)
        p3 = Patient(name="Alex Brown", diagnosis="Flu", classification=1)
        db_session.add_all([p1, p2, p3])
        db_session.commit()

init_data()

# ---------------- STREAMLIT CSS ----------------
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
    st.write("")  
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h5 style='color:white; text-align:center;'>Login</h5>", unsafe_allow_html=True)
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        st.write("")  
        if st.button("Login"):
            user = db_session.query(User).filter_by(username=username).first()
            if user and user.check_password(password) and user.is_active == 1:
                st.session_state.logged_in = True
                st.session_state.user = user
                st.success("Login successful!")
            elif user and user.is_active == 0:
                st.error("Account disabled. Contact admin.")
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

    # Users Section
    st.subheader("Users")
    users = db_session.query(User).all()
    for u in users:
        cols = st.columns([3,2,2,2])
        cols[0].write(f"**{u.username}**")
        cols[1].write(f"Role: {u.role}")
        cols[2].write("🟢 Active" if u.is_active else "🔴 Disabled")

        # Disable / Enable
        if u.username != user.username:
            if u.is_active:
                if cols[3].button("Disable", key=f"disable_{u.id}"):
                    u.is_active = 0
                    db_session.commit()
                    st.rerun()
            else:
                if cols[3].button("Enable", key=f"enable_{u.id}"):
                    u.is_active = 1
                    db_session.commit()
                    st.rerun()

        # Delete user
        if u.username != user.username:
            if st.button(f"❌ Delete {u.username}", key=f"delete_{u.id}"):
                db_session.delete(u)
                db_session.commit()
                st.success(f"{u.username} deleted")
                st.rerun()

    # Add New User
    with st.form("add_user_form"):
        st.write("Add New User")
        new_username = st.text_input("Username")
        new_password = st.text_input("Password", type="password")
        new_role = st.selectbox("Role", ["admin","doctor","nurse","staff"])
        submitted = st.form_submit_button("Add User")
        if submitted:
            if db_session.query(User).filter_by(username=new_username).first():
                st.error("Username already exists.")
            else:
                new_user = User(username=new_username, role=new_role, clearance=ROLE_CLEARANCE[new_role])
                new_user.set_password(new_password)
                db_session.add(new_user)
                db_session.commit()
                st.success(f"User {new_username} added successfully.")

    # Patients Table
    st.subheader("Patients")
    patients = db_session.query(Patient).all()
    patients_df = pd.DataFrame([{"Name": p.name, "Diagnosis": p.diagnosis, "Classification": p.classification} for p in patients])
    st.dataframe(patients_df.style.set_properties(**{'background-color': '#1e1e2e', 'color': 'white'}))

    # Add Patient Form
    with st.form("add_patient_form"):
        st.write("Add New Patient")
        patient_name = st.text_input("Patient Name")
        diagnosis = st.text_input("Diagnosis")
        classification = st.slider("Classification Level", 1, 3, 1)
        submitted = st.form_submit_button("Add Patient")
        if submitted:
            if db_session.query(Patient).filter_by(name=patient_name).first():
                st.error("Patient already exists.")
            else:
                new_patient = Patient(name=patient_name, diagnosis=diagnosis, classification=classification)
                db_session.add(new_patient)
                db_session.commit()
                st.success(f"Patient {patient_name} added successfully.")

    # Audit Logs
    st.subheader("Audit Logs")
    logs = db_session.query(AuditLog).order_by(AuditLog.timestamp.desc()).all()
    logs_df = pd.DataFrame([{"Time": l.timestamp, "User": l.username, "Patient": l.patient_name, "Action": l.action} for l in logs])
    st.dataframe(logs_df.style.set_properties(**{'background-color': '#1e1e2e', 'color': 'white'}))

# ---------------- MAIN ----------------
if not st.session_state.logged_in:
    login_page()
else:
    user = st.session_state.user
    if user.role == "admin":
        admin_panel(user)
    else:
        dashboard_page(user)

