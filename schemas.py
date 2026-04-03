import re
from pydantic import BaseModel, Field, field_validator

# Схема для получения данных от пользователя при регистрации
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Логин пользователя")
    password: str = Field(..., min_length=8, description="Пароль пользователя")

    # Пишем собственный валидатор пароля для Pydantic V2
    @field_validator('password')
    @classmethod
    def validate_password_complexity(cls, value):
        # Используем стандартный модуль re для сложных проверок
        if not re.match(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$", value):
            raise ValueError("Пароль должен содержать минимум 8 символов, включая хотя бы одну букву и цифру")
        return value

# Схема для отправки ответа пользователю (БЕЗ ПАРОЛЯ!)
class UserResponse(BaseModel):
    id: int
    username: str
    is_mfa_enabled: bool

    class Config:
        from_attributes = True

# Схема для токена
class Token(BaseModel):
    access_token: str
    token_type: str

# Схема для проверки кода из Google Authenticator
class MFACode(BaseModel):
    code: str = Field(..., min_length=6, max_length=6)