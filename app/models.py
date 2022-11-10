from .database import Base
from sqlalchemy import TIMESTAMP, Column, Integer, String, Boolean, text
from .config import settings

class User(Base):
    __tablename__ = settings.DATABASE_PREFIX + 'user'
    id = Column(Integer, primary_key = True, index = True)
    name = Column(String(255), nullable = False)
    email = Column(String(255), nullable = False, unique = True)
    password = Column(String(255), nullable = False)
    photo = Column(String(255), nullable = True)
    verified = Column(Boolean, nullable = False, server_default=text('False'))
    role = Column(String(255), nullable=False, server_default="user")
    created_at = Column(TIMESTAMP(timezone=True),nullable=False, server_default=text("now()"))
    updated_at = Column(TIMESTAMP(timezone=True),nullable=False, server_default=text("now()"))