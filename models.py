from sqlalchemy import Column, Integer, String, Boolean
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    # Поля для нашей будущей MFA (Многофакторной аутентификации)
    is_mfa_enabled = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True) # Здесь будем хранить секрет Google Authenticator
    backup_codes = Column(String, nullable=True)
