from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class UserToken(Base):
    __tablename__ = "user_tokens"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), nullable=False)
    role = Column(String(100), nullable=False)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    issued_at = Column(DateTime, default=datetime.now(timezone.utc))
    expires_at = Column(DateTime)
    refresh_expires_at = Column(DateTime(timezone=True), nullable=True) 
    ip_address = Column(String(100))
    user_agent = Column(Text)