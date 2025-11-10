import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pydantic import BaseModel
from passlib.context import CryptContext
from database import db, create_document, get_documents
from schemas import User, Group, Expense
import requests

# Environment
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = "HS256"
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY", "")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="TravelSplit AI")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()


# Helpers
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def create_token(payload: dict, expires_minutes: int = 60 * 24) -> str:
    to_encode = payload.copy()
    to_encode["exp"] = datetime.utcnow() + timedelta(minutes=expires_minutes)
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = creds.credentials
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {"_id": user_id, "email": data.get("email"), "name": data.get("name")}


# Auth Models
class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class CreateGroupRequest(BaseModel):
    name: str


class JoinGroupRequest(BaseModel):
    code: str


class ExpenseRequest(BaseModel):
    group_id: str
    title: str
    amount: float
    currency: str
    category: str
    payer_id: str
    participants: List[str]
    notes: Optional[str] = None


@app.get("/")
def root():
    return {"app": "TravelSplit AI", "status": "ok"}


# Auth endpoints
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: RegisterRequest):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=payload.name, email=payload.email, password_hash=hash_password(payload.password))
    user_id = create_document("user", user)
    token = create_token({"user_id": user_id, "email": payload.email, "name": payload.name})
    return TokenResponse(access_token=token)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = create_token({"user_id": str(user["_id"]), "email": user["email"], "name": user.get("name")})
    return TokenResponse(access_token=token)


# Group endpoints
import random
import string

def generate_group_code(length: int = 6) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


@app.post("/groups")
def create_group(payload: CreateGroupRequest, user=Depends(get_current_user)):
    code = generate_group_code()
    group = Group(name=payload.name, code=code, owner_id=user["_id"], members=[user["_id"]])
    group_id = create_document("group", group)
    return {"group_id": group_id, "code": code}


@app.post("/groups/join")
def join_group(payload: JoinGroupRequest, user=Depends(get_current_user)):
    grp = db["group"].find_one({"code": payload.code})
    if not grp:
        raise HTTPException(status_code=404, detail="Group not found")
    if str(user["_id"]) not in [str(m) for m in grp.get("members", [])]:
        db["group"].update_one({"_id": grp["_id"]}, {"$addToSet": {"members": user["_id"]}})
    return {"group_id": str(grp["_id"]) }


@app.get("/groups/{group_id}")
def get_group(group_id: str, user=Depends(get_current_user)):
    from bson import ObjectId
    grp = db["group"].find_one({"_id": ObjectId(group_id)})
    if not grp:
        raise HTTPException(status_code=404, detail="Group not found")
    return {
        "_id": str(grp["_id"]),
        "name": grp.get("name"),
        "code": grp.get("code"),
        "members": [str(m) for m in grp.get("members", [])]
    }


# Expenses
@app.post("/expenses")
def add_expense(payload: ExpenseRequest, user=Depends(get_current_user)):
    exp = Expense(
        group_id=payload.group_id,
        title=payload.title,
        amount=payload.amount,
        currency=payload.currency,
        category=payload.category,
        payer_id=payload.payer_id,
        participants=payload.participants,
        notes=payload.notes,
    )
    exp_id = create_document("expense", exp)
    return {"expense_id": exp_id}


@app.get("/expenses/{group_id}")
def list_expenses(group_id: str, user=Depends(get_current_user)):
    items = get_documents("expense", {"group_id": group_id})
    for it in items:
        it["_id"] = str(it["_id"])  # type: ignore
    return items


# Currency conversion
@app.get("/rates")
def get_rates(base: str = "USD"):
    url = f"https://api.exchangerate.host/latest?base={base}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail="Rate provider error")
    return r.json()


# Payment intents (Stripe test)
class StripeIntentRequest(BaseModel):
    amount: int
    currency: str = "usd"
    description: Optional[str] = None


@app.post("/payments/stripe-intent")
def create_stripe_intent(payload: StripeIntentRequest, user=Depends(get_current_user)):
    if not STRIPE_API_KEY:
        raise HTTPException(status_code=400, detail="Stripe not configured")
    try:
        import stripe
        stripe.api_key = STRIPE_API_KEY
        intent = stripe.PaymentIntent.create(amount=payload.amount, currency=payload.currency, description=payload.description or "TravelSplit settlement")
        return {"client_secret": intent.client_secret}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Razorpay order (test)
class RazorpayOrderRequest(BaseModel):
    amount: int
    currency: str = "INR"
    receipt: Optional[str] = None


@app.post("/payments/razorpay-order")
def create_razorpay_order(payload: RazorpayOrderRequest, user=Depends(get_current_user)):
    if not (RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET):
        raise HTTPException(status_code=400, detail="Razorpay not configured")
    try:
        import razorpay
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        order = client.order.create({"amount": payload.amount, "currency": payload.currency, "receipt": payload.receipt or f"rcpt_{datetime.utcnow().timestamp()}"})
        return order
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Simple OCR stub endpoint
@app.post("/ocr/upload")
def upload_receipt(file: UploadFile = File(...), user=Depends(get_current_user)):
    return {"filename": file.filename}


# Insights
@app.get("/insights/{group_id}")
def insights(group_id: str, user=Depends(get_current_user)):
    expenses = get_documents("expense", {"group_id": group_id})
    total = sum(e.get("amount", 0) for e in expenses)
    by_user: Dict[str, float] = {}
    for e in expenses:
        payer = e.get("payer_id")
        by_user[payer] = by_user.get(payer, 0) + e.get("amount", 0)
    top_spender = max(by_user.items(), key=lambda x: x[1])[0] if by_user else None
    return {"total": total, "top_spender": top_spender, "members_spend": by_user}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
