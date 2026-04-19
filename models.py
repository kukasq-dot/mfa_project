from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from database import Base

# Таблица для временных токенов привязки бота (живут 10 минут)
class TelegramBinding(Base):
    __tablename__ = "telegram_bindings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    bind_token = Column(String, unique=True, index=True, nullable=False) # Уникальный UUID
    expires_at = Column(DateTime, nullable=False)

# Таблица для временных 6-значных кодов авторизации (живут 3 минуты)
class TelegramOTP(Base):
    __tablename__ = "telegram_otps"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    otp_hash = Column(String, nullable=False) # Храним только bcrypt хеш кода!
    expires_at = Column(DateTime, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    # Поля для нашей будущей MFA (Многофакторной аутентификации)
    is_mfa_enabled = Column(Boolean, default=False)
    totp_secret = Column(String, nullable=True) # Здесь будем хранить секрет Google Authenticator
    backup_codes = Column(String, nullable=True)
    telegram_chat_id = Column(String, nullable=True, unique=True)
