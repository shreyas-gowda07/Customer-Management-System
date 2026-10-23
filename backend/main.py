import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import psycopg2
from pwdlib import PasswordHash
from jose import jwt, JWTError
from datetime import datetime, timedelta
import secrets
import hashlib
import hmac
import smtplib
from email.message import EmailMessage
from log import logger


load_dotenv()


# =========================================================
# JWT SETTINGS
# =========================================================

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"


# =========================================================
# EMAIL SETTINGS
# =========================================================

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")


# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI()



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
        host="host.docker.internal",
        database="postgres",
        user="postgres",
        password=os.getenv("DB_PASSWORD"),
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

class RequestLoginOTP(BaseModel):
    email:EmailStr

class VerifyLoginOTP(BaseModel):
    email: EmailStr
    otp: str    


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
# AUTHENTICATION
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    logger.info("Authentication attempt started")

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

            logger.warning(
                "Authentication failed - required information "
                "missing from token"
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

        logger.info(
            f"Authentication successful: "
            f"user={email}, "
            f"customer_id={customer_id}, "
            f"role={role}"
        )

        return {
            "customer_id": customer_id,
            "email": email,
            "role": role,
            "can_delete": can_delete
        }

    except JWTError:

        logger.warning(
            "Authentication failed - invalid or expired JWT token"
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    except HTTPException:
        raise

    except Exception as e:

        logger.error(
            f"Unexpected authentication error: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Authentication error occurred"
        )


# =========================================================
# GET ALL CUSTOMERS
# =========================================================

@app.get("/customers")
def get_customers(
    current_user: dict = Depends(get_current_user)
):
    logger.info(
        f"Get all customers attempt by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:
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

        customers = []

        for row in rows:
            customers.append({
                "customer_id": row[0],
                "customer_name": row[1],
                "country": row[2],
                "email": row[3]
            })

        logger.info(
            f"Customers retrieved successfully: "
            f"count={len(customers)}, "
            f"by user={current_user['email']}"
        )

        return {
            "customers": customers
        }

    except psycopg2.Error as e:

        logger.error(
            f"Database error while retrieving customers: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve customers"
        )

    except Exception as e:

        logger.error(
            f"Unexpected error while retrieving customers: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# GET ONE CUSTOMER
# =========================================================

@app.get("/customers/{customer_id}")
def get_customer(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):
    logger.info(
        f"Get customer attempt: "
        f"customer_id={customer_id}, "
        f"by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:
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

        if row is None:

            logger.warning(
                f"Get customer failed - customer not found: "
                f"customer_id={customer_id}, "
                f"requested by={current_user['email']}"
            )

            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        logger.info(
            f"Customer retrieved successfully: "
            f"customer_id={customer_id}, "
            f"by user={current_user['email']}"
        )

        return {
            "customer_id": row[0],
            "customer_name": row[1],
            "country": row[2],
            "email": row[3]
        }

    except HTTPException:
        raise

    except psycopg2.Error as e:

        logger.error(
            f"Database error while retrieving customer "
            f"customer_id={customer_id}: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve customer"
        )

    except Exception as e:

        logger.error(
            f"Unexpected error while retrieving customer "
            f"customer_id={customer_id}: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# CREATE CUSTOMER
# =========================================================

@app.post("/customers")
def create_customer(
    customer: CustomerCreate,
    current_user: dict = Depends(get_current_user)
):
    logger.info(
        f"Create customer attempt by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        if current_user["role"] not in ["admin", "super-admin"]:

            logger.warning(
                f"Create customer denied - insufficient permission: "
                f"user={current_user['email']}"
            )

            raise HTTPException(
                status_code=403,
                detail="Only Admin or Super-Admin can add users"
            )

        if customer.role not in ["user", "admin"]:

            logger.warning(
                f"Create customer failed - invalid role: "
                f"role={customer.role}"
            )

            raise HTTPException(
                status_code=400,
                detail="New users can only be User or Admin"
            )

        conn = get_connection()
        cursor = conn.cursor()

        hashed_password = password_hash.hash(
            customer.password
        )

        cursor.execute(
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

        customer_id = cursor.fetchone()[0]

        conn.commit()

        logger.info(
            f"Customer created successfully: "
            f"customer_id={customer_id}, "
            f"created by={current_user['email']}"
        )

        return {
            "message": "Customer created successfully",
            "customer_id": customer_id,
            "role": customer.role
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.errors.UniqueViolation:

        if conn:
            conn.rollback()

        logger.warning(
            f"Create customer failed - email already exists: "
            f"{customer.email}"
        )

        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error while creating customer: "
            f"{str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to create customer"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error while creating customer: "
            f"{str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
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
    logger.info(
        f"Update customer attempt: "
        f"customer_id={customer_id}, "
        f"by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        if (
            current_user["role"] == "user"
            and current_user["customer_id"] != customer_id
        ):

            logger.warning(
                f"Update customer denied: "
                f"user={current_user['email']} "
                f"tried to update customer_id={customer_id}"
            )

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

            logger.warning(
                f"Update customer failed - customer not found: "
                f"customer_id={customer_id}"
            )

            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        conn.commit()

        logger.info(
            f"Customer updated successfully: "
            f"customer_id={customer_id}, "
            f"by user={current_user['email']}"
        )

        return {
            "message": "Customer completely updated",
            "customer": {
                "customer_id": row[0],
                "customer_name": row[1],
                "country": row[2],
                "email": row[3]
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.errors.UniqueViolation:

        if conn:
            conn.rollback()

        logger.warning(
            f"Update customer failed - email already exists: "
            f"customer_id={customer_id}, "
            f"email={customer.email}"
        )

        raise HTTPException(
            status_code=400,
            detail="Email already exists"
        )

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error while updating customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update customer"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error while updating customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# PATCH CUSTOMER
# =========================================================

@app.patch("/customers/{customer_id}")
def patch_customer(
    customer_id: int,
    customer: CustomerPatch,
    current_user: dict = Depends(get_current_user)
):
    logger.info(
        f"Patch customer attempt: "
        f"customer_id={customer_id}, "
        f"by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        if (
            current_user["role"] == "user"
            and current_user["customer_id"] != customer_id
        ):

            logger.warning(
                f"Patch customer denied: "
                f"user={current_user['email']} "
                f"tried to change customer_id={customer_id}"
            )

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

            logger.warning(
                f"Patch customer failed - customer not found: "
                f"customer_id={customer_id}"
            )

            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        conn.commit()

        logger.info(
            f"Customer country patched successfully: "
            f"customer_id={customer_id}, "
            f"by user={current_user['email']}"
        )

        return {
            "message": "Customer partially updated",
            "customer": {
                "customer_id": row[0],
                "customer_name": row[1],
                "country": row[2],
                "email": row[3]
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error while patching customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to patch customer"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error while patching customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# DELETE CUSTOMER
# =========================================================

@app.delete("/customers/{customer_id}")
def delete_customer(
    customer_id: int,
    current_user: dict = Depends(get_current_user)
):
    logger.info(
        f"Delete customer attempt: "
        f"customer_id={customer_id}, "
        f"by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        role = current_user["role"]

        if role == "user":

            logger.warning(
                f"Delete customer denied - "
                f"user={current_user['email']} "
                f"tried to delete customer_id={customer_id}"
            )

            raise HTTPException(
                status_code=403,
                detail="Users are not allowed to delete customers"
            )

        if role not in ["admin", "super-admin"]:

            logger.warning(
                f"Delete customer denied - insufficient permission: "
                f"user={current_user['email']}"
            )

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

            logger.warning(
                f"Delete customer failed - customer not found: "
                f"customer_id={customer_id}"
            )

            raise HTTPException(
                status_code=404,
                detail="Customer not found"
            )

        conn.commit()

        logger.info(
            f"Customer deleted successfully: "
            f"customer_id={customer_id}, "
            f"by user={current_user['email']}"
        )

        return {
            "message": "Customer deleted successfully",
            "customer": {
                "customer_id": row[0],
                "customer_name": row[1],
                "country": row[2],
                "email": row[3]
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error while deleting customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to delete customer"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error while deleting customer: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# REGISTER
# =========================================================

@app.post("/register")
def register_user(user: RegisterUser):

    logger.info(
        f"Registration attempt: email={user.email}"
    )

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT customer_id
            FROM customers
            WHERE email = %s
        """, (user.email,))

        existing_user = cursor.fetchone()

        if existing_user is not None:

            logger.warning(
                f"Registration failed - email already registered: "
                f"{user.email}"
            )

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

        logger.info(
            f"Registration successful: "
            f"customer_id={row[0]}, "
            f"email={user.email}"
        )

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

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.errors.UniqueViolation:

        if conn:
            conn.rollback()

        logger.warning(
            f"Registration failed - duplicate email: "
            f"{user.email}"
        )

        raise HTTPException(
            status_code=409,
            detail="Email already registered"
        )

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error during registration: "
            f"email={user.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to register user"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error during registration: "
            f"email={user.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# LOGIN
# =========================================================

@app.post("/login")
def login_user(user: LoginUser):

    logger.info(
        f"Login attempt: {user.email}"
    )

    conn = None
    cursor = None

    try:

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

        if row is None:

            logger.warning(
                f"Login failed - user not found: {user.email}"
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        stored_password = row[4]

        if not password_hash.verify(
            user.password,
            stored_password
        ):

            logger.warning(
                f"Login failed - incorrect password: {user.email}"
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid email or password"
            )

        database_role = row[5]

        token_data = {
            "customer_id": row[0],
            "email": row[3],
            "role": database_role,
            "can_delete": row[6],
            "exp": datetime.utcnow() + timedelta(minutes=15)
        }

        access_token = jwt.encode(
            token_data,
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        logger.info(
            f"Login successful: {user.email}"
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

    except HTTPException:
        raise

    except psycopg2.Error as e:

        logger.error(
            f"Database error during login: "
            f"email={user.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to process login"
        )

    except Exception as e:

        logger.error(
            f"Unexpected error during login: "
            f"email={user.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

# =========================================================
# EMAIL OTP LOGIN
# =========================================================

def send_login_otp_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = "Customer Management System - Login OTP"
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email

    message.set_content(f"""Hello,

Your login OTP is:

{otp}

This OTP is valid for 5 minutes.

If you did not request this OTP, you can ignore this email.

Customer Management System
""")

    try:
        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=30
        ) as server:

            server.ehlo()
            server.starttls()
            server.ehlo()

            server.login(
                SENDER_EMAIL,
                SENDER_PASSWORD
            )

            server.send_message(message)

        logger.info(
            f"Login OTP email sent to {receiver_email}"
        )

    except Exception as e:

        logger.error(
            f"Unable to send login OTP email: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to send login OTP email"
        )


# =========================================================
# REQUEST LOGIN OTP
# =========================================================

@app.post("/login-otp/request")
def request_login_otp(request: RequestLoginOTP):

    conn = None
    cursor = None

    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT customer_id,
                   login_otp_last_sent
            FROM customers
            WHERE LOWER(email) = LOWER(%s)
        """, (request.email,))

        user = cursor.fetchone()

        # Generic response for an email that does not exist
        if user is None:

            logger.warning(
                f"Login OTP requested for unknown email: "
                f"{request.email}"
            )

            return {
                "message": "If the email exists, an OTP has been sent."
            }

        customer_id = user[0]
        last_sent = user[1]

        # Allow only one OTP request per 60 seconds
        if last_sent is not None:

            elapsed_seconds = (
                datetime.now() - last_sent
            ).total_seconds()

            if elapsed_seconds < 60:

                raise HTTPException(
                    status_code=429,
                    detail="Please wait before requesting another OTP"
                )

        # Generate a 6-digit OTP
        otp = str(
            secrets.randbelow(900000) + 100000
        )

        # Store a hash instead of the original OTP
        otp_hash = hashlib.sha256(
            otp.encode()
        ).hexdigest()

        expiry = datetime.now() + timedelta(minutes=5)

        cursor.execute("""
            UPDATE customers
            SET login_otp_hash = %s,
                login_otp_expiry = %s,
                login_otp_attempts = 0,
                login_otp_last_sent = %s
            WHERE customer_id = %s
        """, (
            otp_hash,
            expiry,
            datetime.now(),
            customer_id
        ))

        conn.commit()

        # Send OTP using the existing SMTP configuration
        send_login_otp_email(
            request.email,
            otp
        )

        logger.info(
            f"Login OTP requested successfully for "
            f"customer_id={customer_id}"
        )

        return {
            "message": "If the email exists, an OTP has been sent."
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Error requesting login OTP: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to process login OTP request"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# VERIFY LOGIN OTP
# =========================================================

@app.post("/login-otp/verify")
def verify_login_otp(request: VerifyLoginOTP):

    conn = None
    cursor = None

    try:

        # Validate OTP format
        if not request.otp.isdigit() or len(request.otp) != 6:

            raise HTTPException(
                status_code=400,
                detail="OTP must be a 6-digit number"
            )

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT customer_id,
                   customer_name,
                   country,
                   email,
                   role,
                   can_delete,
                   login_otp_hash,
                   login_otp_expiry,
                   login_otp_attempts
            FROM customers
            WHERE LOWER(email) = LOWER(%s)
        """, (request.email,))

        row = cursor.fetchone()

        if row is None:

            raise HTTPException(
                status_code=401,
                detail="Invalid email or OTP"
            )

        stored_otp_hash = row[6]
        otp_expiry = row[7]
        otp_attempts = row[8]

        # Check whether an OTP was requested
        if stored_otp_hash is None or otp_expiry is None:

            raise HTTPException(
                status_code=400,
                detail="Please request a login OTP first"
            )

        # Maximum 5 verification attempts
        if otp_attempts >= 5:

            raise HTTPException(
                status_code=429,
                detail="Too many OTP attempts. Request a new OTP."
            )

        # Check expiry
        if datetime.now() > otp_expiry:

            cursor.execute("""
                UPDATE customers
                SET login_otp_hash = NULL,
                    login_otp_expiry = NULL,
                    login_otp_attempts = 0
                WHERE customer_id = %s
            """, (row[0],))

            conn.commit()

            raise HTTPException(
                status_code=400,
                detail="OTP has expired. Please request a new OTP."
            )

        # Hash the entered OTP
        entered_otp_hash = hashlib.sha256(
            request.otp.encode()
        ).hexdigest()

        # Compare hashes securely
        if not hmac.compare_digest(
            entered_otp_hash,
            stored_otp_hash
        ):

            cursor.execute("""
                UPDATE customers
                SET login_otp_attempts = login_otp_attempts + 1
                WHERE customer_id = %s
            """, (row[0],))

            conn.commit()

            logger.warning(
                f"Incorrect login OTP for "
                f"customer_id={row[0]}"
            )

            raise HTTPException(
                status_code=401,
                detail="Invalid email or OTP"
            )

        # OTP is valid. Consume it so it cannot be reused.
        cursor.execute("""
            UPDATE customers
            SET login_otp_hash = NULL,
                login_otp_expiry = NULL,
                login_otp_attempts = 0
            WHERE customer_id = %s
        """, (row[0],))

        conn.commit()

        # Create JWT using the same settings as password login
        token_data = {
            "customer_id": row[0],
            "email": row[3],
            "role": row[4],
            "can_delete": row[5],
            "exp": datetime.utcnow() + timedelta(minutes=15)
        }

        access_token = jwt.encode(
            token_data,
            SECRET_KEY,
            algorithm=ALGORITHM
        )

        logger.info(
            f"OTP login successful: {request.email}"
        )

        return {
            "message": "Login successful",
            "access_token": access_token,
            "customer": {
                "customer_id": row[0],
                "customer_name": row[1],
                "country": row[2],
                "email": row[3],
                "role": row[4]
            }
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error during OTP login: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to process OTP login"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

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

    logger.info(
        f"Delete permission update attempt: "
        f"target_customer_id={customer_id}, "
        f"requested by={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        current_role = current_user["role"]

        if current_role not in ["admin", "super-admin"]:

            logger.warning(
                f"Delete permission update denied - "
                f"insufficient permission: "
                f"user={current_user['email']}"
            )

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

            logger.warning(
                f"Delete permission update failed - "
                f"user not found: "
                f"customer_id={customer_id}"
            )

            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        target_role = user[0]

        if (
            current_role == "admin"
            and target_role == "super-admin"
        ):

            logger.warning(
                f"Delete permission update denied - "
                f"Admin attempted to modify Super Admin: "
                f"target_customer_id={customer_id}, "
                f"requested by={current_user['email']}"
            )

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

        logger.info(
            f"Delete permission updated successfully: "
            f"customer_id={customer_id}, "
            f"can_delete={permission.can_delete}, "
            f"updated by={current_user['email']}"
        )

        return {
            "message": "Delete permission updated",
            "customer_id": customer_id,
            "can_delete": permission.can_delete
        }

    except HTTPException:
        if conn:
            conn.rollback()
        raise

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error while updating delete permission: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to update delete permission"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error while updating delete permission: "
            f"customer_id={customer_id}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# ADMIN / SUPER ADMIN
# VIEW USERS AND THEIR PERMISSIONS
# =========================================================

@app.get("/admin/users")
def get_admin_users(
    current_user: dict = Depends(get_current_user)
):

    logger.info(
        f"Get admin users attempt by user={current_user['email']}"
    )

    conn = None
    cursor = None

    try:

        if current_user["role"] not in ["admin", "super-admin"]:

            logger.warning(
                f"Get admin users denied - insufficient permission: "
                f"user={current_user['email']}"
            )

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

        users = []

        for row in rows:
            users.append({
                "customer_id": row[0],
                "customer_name": row[1],
                "email": row[2],
                "role": row[3],
                "can_delete": row[4]
            })

        logger.info(
            f"Admin users retrieved successfully: "
            f"count={len(users)}, "
            f"requested by={current_user['email']}"
        )

        return {
            "users": users
        }

    except HTTPException:
        raise

    except psycopg2.Error as e:

        logger.error(
            f"Database error while retrieving admin users: "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve users"
        )

    except Exception as e:

        logger.error(
            f"Unexpected error while retrieving admin users: "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# SEND OTP EMAIL
# =========================================================

def send_otp_email(receiver_email, otp):

    message = EmailMessage()

    message["Subject"] = (
        "Customer Management System - Password Reset OTP"
    )

    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email

    message.set_content(f"""Hello,

Your password reset OTP is:

{otp}

This OTP is valid for 5 minutes.

If you did not request a password reset, you can ignore this email.

Customer Management System
""")

    try:

        logger.info(
            f"Connecting to Gmail SMTP server for "
            f"recipient={receiver_email}"
        )

        with smtplib.SMTP(
            SMTP_SERVER,
            SMTP_PORT,
            timeout=30
        ) as server:

            logger.info(
                "Starting TLS connection with Gmail SMTP server"
            )

            server.ehlo()
            server.starttls()
            server.ehlo()

            logger.info(
                "Authenticating with Gmail SMTP server"
            )

            server.login(
                SENDER_EMAIL,
                SENDER_PASSWORD
            )

            logger.info(
                f"Sending OTP email to recipient={receiver_email}"
            )

            server.send_message(message)

        logger.info(
            f"OTP email sent successfully to "
            f"recipient={receiver_email}"
        )

    except smtplib.SMTPAuthenticationError as e:

        logger.error(
            f"Gmail SMTP authentication failed for "
            f"recipient={receiver_email}: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Gmail authentication failed. "
                   "Check your Gmail App Password."
        )

    except smtplib.SMTPException as e:

        logger.error(
            f"SMTP error while sending OTP email to "
            f"recipient={receiver_email}: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP email. "
                   "SMTP error occurred."
        )

    except Exception as e:

        logger.error(
            f"Unexpected error while sending OTP email to "
            f"recipient={receiver_email}: {str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to send OTP email."
        )


# =========================================================
# FORGOT PASSWORD - SEND OTP
# =========================================================

@app.post("/forgot-password")
def forgot_password(
    request: ForgotPasswordRequest
):

    logger.info(
        f"Forgot password attempt: email={request.email}"
    )

    conn = None
    cursor = None

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT customer_id
            FROM customers
            WHERE email = %s
        """, (request.email,))

        user = cursor.fetchone()

        if user is None:

            logger.warning(
                f"Forgot password requested for "
                f"non-existing email: {request.email}"
            )

            return {
                "message": "If the email exists, an OTP has been sent."
            }

        otp = str(
            secrets.randbelow(900000) + 100000
        )

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

        logger.info(
            f"Password reset OTP generated and stored: "
            f"customer_id={user[0]}, "
            f"email={request.email}"
        )

        send_otp_email(
            request.email,
            otp
        )

        logger.info(
            f"Password reset OTP email sent successfully: "
            f"email={request.email}"
        )

        return {
            "message": "OTP sent successfully to your email."
        }

    except HTTPException:

        if conn:
            conn.rollback()

        logger.error(
            f"OTP email sending failed: "
            f"email={request.email}",
            exc_info=True
        )

        raise

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error during forgot password: "
            f"email={request.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to process password reset request"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error during forgot password: "
            f"email={request.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


# =========================================================
# RESET PASSWORD
# =========================================================

@app.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest
):

    logger.info(
        f"Password reset attempt: email={request.email}"
    )

    conn = None
    cursor = None

    try:

        if not request.otp.isdigit() or len(request.otp) != 6:

            logger.warning(
                f"Password reset failed - invalid OTP format: "
                f"email={request.email}"
            )

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

            logger.warning(
                f"Password reset failed - invalid or expired OTP: "
                f"email={request.email}"
            )

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

        logger.info(
            f"Password reset successful: "
            f"customer_id={user[0]}, "
            f"email={request.email}"
        )

        return {
            "message": "Password changed successfully."
        }

    except HTTPException:

        if conn:
            conn.rollback()

        raise

    except psycopg2.Error as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Database error during password reset: "
            f"email={request.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to reset password"
        )

    except Exception as e:

        if conn:
            conn.rollback()

        logger.error(
            f"Unexpected error during password reset: "
            f"email={request.email}, "
            f"error={str(e)}",
            exc_info=True
        )

        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()


