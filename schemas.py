"""
Database Schemas for TravelSplit AI

Each Pydantic model represents a collection in MongoDB.
Collection name is the lowercase of the class name (e.g., User -> "user").
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict
from datetime import datetime

class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    avatar_url: Optional[str] = None

class Group(BaseModel):
    name: str
    code: str = Field(..., description="Join code")
    owner_id: str
    members: List[str] = Field(default_factory=list, description="User IDs in the group")

class Expense(BaseModel):
    group_id: str
    title: str
    amount: float
    currency: str = Field(..., description="ISO currency code, e.g., USD")
    category: str = Field(..., description="food, stay, travel, misc")
    payer_id: str
    participants: List[str]
    notes: Optional[str] = None
    date: Optional[datetime] = None
    ocr_text: Optional[str] = None
    meta: Dict[str, str] = Field(default_factory=dict)
