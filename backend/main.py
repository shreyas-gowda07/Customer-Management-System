import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import psycopg2
from pwdlib import PasswordHash
from jose import jwt, JWTError
from datetime import datetime, timedelta
import secrets
import smtplib
from email.message import EmailMessage

load_dotenv()


# =========================================================
# JWT SETTINGS
# =========================================================

SECRET_KEY = os.getenv("Monkey-D-Luffy")
ALGORITHM = "HS256"


# =========================================================
# EMAIL SETTINGS
# =========================================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# Your Gmail address
SENDER_EMAIL = os.getenv("donotreply2725@gmail.com")

# IMPORTANT:
# Put your Gmail APP PASSWORD here.
# Do NOT put your normal Gmail password.
SENDER_PASSWORD = os.getenv("saxepzmipdzqecdj")


# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI()
app.mount(
    "/static",
    StaticFiles(directory="../frontend"),
    name="static"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)


# =========================================================
# PASSWORD HASHING
# =========================================================

password_hash = PasswordHash.recommended()


# =========================================================
# JWT SECURITY
# =========================================================

security = HTTPBearer()


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    return psycopg2.connect(
        host="localhost",
        database="postgres",
        user="postgres",
        password=os.getenv("luffy"),
        port="5432"
    )


# =========================================================
# PYDANTIC MODELS
# =========================================================

class CustomerCreate(BaseModel):
    customer_name: str
    country: str
    email: EmailStr
    password: str
    role: str = "user"


class CustomerUpdate(BaseModel):
    customer_name: str
    email: EmailStr
    country: str | None = None


class CustomerPatch(BaseModel):
    country: str


class RegisterUser(BaseModel):
    customer_name: str
    country: str
    email: EmailStr
    password: str


class LoginUser(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    role: str


class PermissionUpdate(BaseModel):
    can_delete: bool


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str


# =========================================================
# GET CURRENT USER FROM JWT
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        customer_id = payload.get("customer_id")
        email = payload.get("email")
        role = payload.get("role")
        can_delete = payload.get("can_delete")

        if customer_id is None or email is None or role is None:

            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        return {
            "customer_id": customer_id,
            "email": email,
            "role": role,
            "can_delete": can_delete
        }

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )


# =========================================================
# GET ALL CUSTOMERS
# =========================================================

@app.get("/customers")
def get_customers(
    current_user: dict = Depends(get_current_user)
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id,
               customer_name,
               country,
               email
        FROM customers
        ORDER BY customer_id
    """)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    customers = []

    for row in rows:

        customers.append({
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3]
        })

    return {
        "customers": customers
    }


# =========================================================
# GET ONE CUSTOMER
# =========================================================

@app.get("/customers/{customer_id}")
def get_customer(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id,
               customer_name,
               country,
               email
        FROM customers
        WHERE customer_id = %s
    """, (customer_id,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row is None:

        raise HTTPException(
            status_code=404,
            detail="Customer not found"
        )

    return {
        "customer_id": row[0],
        "customer_name": row[1],
        "country": row[2],
        "email": row[3]
    }


# =========================================================
# CREATE CUSTOMER
# =========================================================

@app.post("/customers")
def create_customer(
    customer: CustomerCreate,
    current_user: dict = Depends(get_current_user)
):

    if current_user["role"] not in ["admin", "super-admin"]:

        raise HTTPException(
            status_code=403,
            detail="Only Admin or Super-Admin can add users"
        )

    if customer.role not in ["user", "admin"]:

        raise HTTPException(
            status_code=400,
            detail="New users can only be User or Admin"
        )

    conn = get_connection()
    cur = conn.cursor()

    try:

        hashed_password = password_hash.hash(
            customer.password
        )

        cur.execute(
            """
            INSERT INTO customers
            (
                customer_name,
                country,
                email,
                password,
                role,
                can_delete
            )
            VALUES (%s, %s, %s, %s, %s, FALSE)
            RETURNING customer_id
            """,
            (
                customer.customer_name,
                customer.country,
                customer.email,
                hashed_password,
                customer.role
            )
        )

        customer_id = cur.fetchone()[0]

        conn.commit()

        return {
            "message": "Customer created successfully",
            "customer_id": customer_id,
            "role": customer.role
        }

    except psycopg2.errors.UniqueViolation:

        conn.rollback()

        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    finally:

        cur.close()
        conn.close()


# =========================================================
# UPDATE CUSTOMER
# =========================================================

@app.put("/customers/{customer_id}")
def update_customer(
    customer_id: int,
    customer: CustomerUpdate,
    current_user: dict = Depends(get_current_user)
):

    if (
        current_user["role"] == "user"
        and current_user["customer_id"] != customer_id
    ):

        raise HTTPException(
            status_code=403,
            detail="Users can update only their own account"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE customers
        SET customer_name = %s,
            email = %s,
            country = COALESCE(%s, country)
        WHERE customer_id = %s
        RETURNING customer_id,
                  customer_name,
                  country,
                  email
    """, (
        customer.customer_name,
        customer.email,
        customer.country,
        customer_id
    ))

    row = cursor.fetchone()

    if row is None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Customer not found"
        )

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Customer completely updated",
        "customer": {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3]
        }
    }


# =========================================================
# PATCH CUSTOMER
# =========================================================

@app.patch("/customers/{customer_id}")
def patch_customer(
    customer_id: int,
    customer: CustomerPatch,
    current_user: dict = Depends(get_current_user)
):

    if (
        current_user["role"] == "user"
        and current_user["customer_id"] != customer_id
    ):

        raise HTTPException(
            status_code=403,
            detail="Users can change only their own country"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE customers
        SET country = %s
        WHERE customer_id = %s
        RETURNING customer_id,
                  customer_name,
                  country,
                  email
    """, (
        customer.country,
        customer_id
    ))

    row = cursor.fetchone()

    if row is None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Customer not found"
        )

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Customer partially updated",
        "customer": {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3]
        }
    }


# =========================================================
# DELETE CUSTOMER
# =========================================================

@app.delete("/customers/{customer_id}")
def delete_customer(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):

    role = current_user["role"]

    if role == "user":

        raise HTTPException(
            status_code=403,
            detail="Users are not allowed to delete customers"
        )

    if role not in ["admin", "super-admin"]:

        raise HTTPException(
            status_code=403,
            detail="You do not have permission to delete customers"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM customers
        WHERE customer_id = %s
        RETURNING customer_id,
                  customer_name,
                  country,
                  email
    """, (customer_id,))

    row = cursor.fetchone()

    if row is None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="Customer not found"
        )

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Customer deleted successfully",
        "customer": {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3]
        }
    }


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register_user(user: RegisterUser):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id
        FROM customers
        WHERE email = %s
    """, (user.email,))

    existing_user = cursor.fetchone()

    if existing_user is not None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    hashed_password = password_hash.hash(user.password)

    cursor.execute("""
        INSERT INTO customers (
            customer_name,
            country,
            email,
            password,
            role,
            can_delete
        )
        VALUES (%s, %s, %s, %s, 'user', FALSE)
        RETURNING customer_id,
                  customer_name,
                  country,
                  email,
                  role
    """, (
        user.customer_name,
        user.country,
        user.email,
        hashed_password
    ))

    row = cursor.fetchone()

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Registration successful",
        "customer": {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3],
            "role": row[4]
        }
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login_user(user: LoginUser):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id,
               customer_name,
               country,
               email,
               password,
               role,
               can_delete
        FROM customers
        WHERE email = %s
    """, (user.email,))

    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row is None:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    stored_password = row[4]

    if not password_hash.verify(
        user.password,
        stored_password
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    database_role = row[5]

    token_data = {
        "customer_id": row[0],
        "email": row[3],
        "role": database_role,
        "can_delete": row[6]
    }

    access_token = jwt.encode(
        token_data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "message": "Login successful",
        "access_token": access_token,
        "customer": {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3],
            "role": database_role
        }
    }


# =========================================================
# ADMIN / SUPER ADMIN
# GRANT OR REVOKE DELETE PERMISSION
# =========================================================

@app.put("/admin/users/{customer_id}/delete-permission")
def update_delete_permission(
    customer_id: int,
    permission: PermissionUpdate,
    current_user: dict = Depends(get_current_user)
):

    current_role = current_user["role"]

    if current_role not in ["admin", "super-admin"]:

        raise HTTPException(
            status_code=403,
            detail="Only Admin or Super Admin can grant permissions"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT role
        FROM customers
        WHERE customer_id = %s
    """, (customer_id,))

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    target_role = user[0]

    if (
        current_role == "admin"
        and target_role == "super-admin"
    ):

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=403,
            detail="Admin cannot modify Super Admin permissions"
        )

    cursor.execute("""
        UPDATE customers
        SET can_delete = %s
        WHERE customer_id = %s
    """, (
        permission.can_delete,
        customer_id
    ))

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Delete permission updated",
        "customer_id": customer_id,
        "can_delete": permission.can_delete
    }


# =========================================================
# ADMIN / SUPER ADMIN
# VIEW USERS AND THEIR PERMISSIONS
# =========================================================

@app.get("/admin/users")
def get_admin_users(
    current_user: dict = Depends(get_current_user)
):

    if current_user["role"] not in ["admin", "super-admin"]:

        raise HTTPException(
            status_code=403,
            detail="Only Admin or Super Admin can access this page"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id,
               customer_name,
               email,
               role,
               can_delete
        FROM customers
        ORDER BY customer_id
    """)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    users = []

    for row in rows:

        users.append({
            "customer_id": row[0],
            "customer_name": row[1],
            "email": row[2],
            "role": row[3],
            "can_delete": row[4]
        })

    return {
        "users": users
    }


# =========================================================
# SEND OTP EMAIL
# =========================================================

def send_otp_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = "Customer Management System - Password Reset OTP"
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email

    message.set_content(
        f"""Hello,

Your password reset OTP is:

{otp}

This OTP is valid for 5 minutes.

If you did not request a password reset, you can ignore this email.

Customer Management System
"""
    )

    try:

        print("Connecting to Gmail SMTP server...")

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=30
        ) as server:

            server.ehlo()

            print("Starting TLS...")

            server.starttls()

            server.ehlo()

            print("Logging into Gmail...")

            server.login(
                SENDER_EMAIL,
                SENDER_PASSWORD
            )

            print("Sending OTP email...")

            server.send_message(message)

        print("OTP email sent successfully.")

    except smtplib.SMTPAuthenticationError:

        print("Gmail authentication failed.")

        raise HTTPException(
            status_code=500,
            detail="Gmail authentication failed. Check your Gmail App Password."
        )

    except smtplib.SMTPException as e:

        print("SMTP error:", str(e))

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP email. SMTP error occurred."
        )

    except Exception as e:

        print("Email sending failed:", str(e))

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP email."
        )


# =========================================================
# FORGOT PASSWORD - SEND OTP
# =========================================================

@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id
        FROM customers
        WHERE email = %s
    """, (request.email,))

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        conn.close()

        return {
            "message": "If the email exists, an OTP has been sent."
        }

    # Generate 6-digit OTP
    otp = str(secrets.randbelow(900000) + 100000)

    # OTP valid for 5 minutes
    expiry = datetime.now() + timedelta(minutes=5)

    cursor.execute("""
        UPDATE customers
        SET reset_otp = %s,
            reset_otp_expiry = %s
        WHERE customer_id = %s
    """, (
        otp,
        expiry,
        user[0]
    ))

    conn.commit()

    cursor.close()
    conn.close()

    # Send OTP
    send_otp_email(
        request.email,
        otp
    )

    return {
        "message": "OTP sent successfully to your email."
    }


# =========================================================
# RESET PASSWORD
# =========================================================

@app.post("/reset-password")
def reset_password(request: ResetPasswordRequest):

    if not request.otp.isdigit() or len(request.otp) != 6:

        raise HTTPException(
            status_code=400,
            detail="OTP must be a 6-digit number"
        )

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT customer_id
        FROM customers
        WHERE email = %s
          AND reset_otp = %s
          AND reset_otp_expiry > %s
    """, (
        request.email,
        request.otp,
        datetime.now()
    ))

    user = cursor.fetchone()

    if user is None:

        cursor.close()
        conn.close()

        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OTP"
        )

    hashed_password = password_hash.hash(
        request.new_password
    )

    cursor.execute("""
        UPDATE customers
        SET password = %s,
            reset_otp = NULL,
            reset_otp_expiry = NULL
        WHERE customer_id = %s
    """, (
        hashed_password,
        user[0]
    ))

    conn.commit()

    cursor.close()
    conn.close()

    return {
        "message": "Password changed successfully."
    }
from fastapi.responses import FileResponse

@app.get("/")
def home():
    return FileResponse("../frontend/login.html")


@app.get("/login.html")
def login_page():
    return FileResponse("../frontend/login.html")


@app.get("/register.html")
def register_page():
    return FileResponse("../frontend/register.html")


@app.get("/forgot-password.html")
def forgot_password_page():
    return FileResponse("../frontend/forgot-password.html")


@app.get("/reset-password.html")
def reset_password_page():
    return FileResponse("../frontend/reset-password.html")


@app.get("/index.html")
def index_page():
    return FileResponse("../frontend/index.html")