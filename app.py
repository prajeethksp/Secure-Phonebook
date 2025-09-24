# Import necessary modules
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, validator
from sqlalchemy import create_engine, Column, Integer, String, text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timedelta
from typing import Optional
import jwt  # Install PyJWT if not already installed
import bcrypt
import re
import logging
import os


# Create the FastAPI app
app = FastAPI()

# Database setup
DATABASE_URL = "sqlite:///phonebook.db"
engine = create_engine(DATABASE_URL, echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)

# JWT settings
SECRET_KEY = "your_jwt_secret_key"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 settings
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User database model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # 'read' or 'read_write'

# PhoneBook database model
class PhoneBook(Base):
    __tablename__ = "phonebook"
    id = Column(Integer, primary_key=True, autoincrement=True)
    full_name = Column(String, nullable=False)
    phone_number = Column(String, unique=True, nullable=False)

# Create tables
Base.metadata.create_all(engine)

# Utility to hash passwords
def get_password_hash(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

# Ensure "role" column exists
def ensure_role_column():
    with engine.connect() as connection:
        result = connection.execute(text("PRAGMA table_info(users)"))
        columns = [row[1] for row in result]
        if "role" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN role TEXT"))

ensure_role_column()

# Add users
def add_users():
    session = Session()
    users = [
        {"username": "read_user", "password": "read_password", "role": "read"},
        {"username": "write_user", "password": "write_password", "role": "read_write"},
    ]
    for user in users:
        if not session.query(User).filter_by(username=user["username"]).first():
            hashed_password = get_password_hash(user["password"])
            new_user = User(username=user["username"], hashed_password=hashed_password, role=user["role"])
            session.add(new_user)
            print(f"User '{user['username']}' with role '{user['role']}' added.")
    session.commit()
    session.close()

add_users()

# JWT utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    

# Set up logging configuration
LOG_FILE = "phonebook_audit.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Utility function to log actions
def log_action(username: str, action: str, detail: str):
    logging.info(f"User: {username} | Action: {action} | Detail: {detail}")


# Endpoint to fetch phonebook audit logs
@app.get("/PhoneBook/auditLogs")
def get_audit_logs(current_user: str = Depends(get_current_user)):
    session = Session()
    user = session.query(User).filter_by(username=current_user).first()
    session.close()

    # Restrict access to admin or read_write users
    if user.role != "read_write":
        raise HTTPException(status_code=403, detail="Not authorized to access audit logs")

    # Check if the log file exists
    if not os.path.exists(LOG_FILE):
        raise HTTPException(status_code=404, detail="Audit log file not found")

    # Read the log file
    try:
        with open(LOG_FILE, "r") as log_file:
            logs = log_file.readlines()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read audit logs: {str(e)}")

    # Return the logs as a list of lines
    return {"logs": logs}


# Token endpoint
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    session = Session()
    user = session.query(User).filter_by(username=form_data.username).first()
    session.close()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires)
    log_action(user.username, "LOGIN", "User logged in successfully")
    return {"access_token": access_token, "token_type": "bearer"}

# Pydantic model for phonebook entries
class Person(BaseModel):
    full_name: str
    phone_number: Optional[str]

    @validator("full_name")
    def validate_full_name(cls, v):
        pattern = r"^(?:[A-Za-z]+(?:[ '\u2019-][A-Za-z]+)*,?\s+[A-Za-z]+(?:\s+[A-Z](?:[a-z]+|\.)?)?(?:\s+[A-Za-z]+(?:[ '\u2019-][A-Za-z]+)*)?|\b[A-Za-z]+\b)$"
        if not re.match(pattern, v):
            raise ValueError("Invalid name format.")
        return v.strip()

    @validator("phone_number")
    def validate_phone_number(cls, v):
        if v:
            pattern = r"^(?:(?:\+(?!0)|00|011)?\s*([1-9]\d{0,2})?\s*[-. (]*(?!0)(\d{2,4})[-. )]*\s*\d{3}[-. ]\d{4}|\d{5}|\d{5}[-. ]\d{5}|[1-9]\d{2}-\d{4})$"
            if not re.match(pattern, v):
                raise ValueError("Invalid phone number format.")
        return v

# List phonebook entries
@app.get("/PhoneBook/list")
def list_phonebook(current_user: str = Depends(get_current_user)):
    session = Session()
    phonebook_entries = session.query(PhoneBook).all()
    session.close()
    log_action(current_user, "LIST", "Retrieved all phonebook entries")
    return phonebook_entries

# Add phonebook entry
@app.post("/PhoneBook/add")
def add_person(person: Person, current_user: str = Depends(get_current_user)):
    session = Session()
    user = session.query(User).filter_by(username=current_user).first()
    if user.role != "read_write":
        session.close()
        raise HTTPException(status_code=403, detail="Not authorized to add entries")
    existing_person = session.query(PhoneBook).filter_by(phone_number=person.phone_number).first()
    if existing_person:
        session.close()
        raise HTTPException(status_code=400, detail="Person already exists in the database")
    new_person = PhoneBook(full_name=person.full_name, phone_number=person.phone_number)
    session.add(new_person)
    session.commit()
    session.close()
    log_action(current_user, "ADD", f"Added {person.full_name} with phone number {person.phone_number}")
    return {"message": "Person added successfully"}

# Delete by name
@app.put("/PhoneBook/deleteByName")
def delete_by_name(full_name: str = Query(...), current_user: str = Depends(get_current_user)):
    session = Session()
    user = session.query(User).filter_by(username=current_user).first()
    if user.role != "read_write":
        session.close()
        raise HTTPException(status_code=403, detail="Not authorized to delete entries")
    person = session.query(PhoneBook).filter_by(full_name=full_name).first()
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    session.delete(person)
    session.commit()
    session.close()
    log_action(current_user, "DELETE", f"Deleted person with full name {full_name}")
    return {"message": "Person deleted successfully"}

# Delete by phone number
@app.put("/PhoneBook/deleteByNumber")
def delete_by_number(phone_number: str = Query(...), current_user: str = Depends(get_current_user)):
    session = Session()
    user = session.query(User).filter_by(username=current_user).first()
    if user.role != "read_write":
        session.close()
        raise HTTPException(status_code=403, detail="Not authorized to delete entries")
    person = session.query(PhoneBook).filter_by(phone_number=phone_number).first()
    if not person:
        session.close()
        raise HTTPException(status_code=404, detail="Person not found in the database")
    session.delete(person)
    session.commit()
    session.close()
    log_action(current_user, "DELETE", f"Deleted person with phone number {phone_number}")
    return {"message": "Person deleted successfully"}
