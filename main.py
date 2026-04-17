import os
from datetime import datetime, timedelta
import jwt
from fastapi import FastAPI, Depends, HTTPException, Form, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import pyotp
import qrcode
import base64
from io import BytesIO

import secrets

# Импорты для лимитера (защита от брутфорса)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
import schemas
from database import engine, get_db

# Даем команду SQLAlchemy создать таблицы
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="MFA System API",
    description="API для системы многофакторной аутентификации. Дипломный проект."
)

# Настраиваем лимитер (определяет пользователя по IP-адресу)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Подключаем папку со статикой (фронтенд)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- НАСТРОЙКИ БЕЗОПАСНОСТИ И JWT ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "my_super_secret_diploma_key_2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Функция для чтения токена из защищенной HttpOnly куки
def get_token_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return token

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- ЭНДПОИНТЫ ---

@app.get("/")
def serve_frontend():
    return FileResponse("static/index.html")

@app.post("/register", response_model=schemas.UserResponse)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Пользователь с таким логином уже существует")
    
    hashed_pwd = get_password_hash(user.password)
    new_user = models.User(username=user.username, hashed_password=hashed_pwd)
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user

# Защита: Ограничение 5 запросов в минуту с одного IP
@app.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request, 
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    mfa_code: str = Form(None),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")
    
    if user.is_mfa_enabled:
        if not mfa_code:
            return {"mfa_required": True, "message": "Введите код из приложения ИЛИ резервный код"}
        
        # Загружаем резервные коды пользователя в виде списка
        backup_codes_list = user.backup_codes.split(",") if user.backup_codes else []
        
        is_valid_totp = False
        is_backup_code = False

        # 1. Проверяем, является ли это одноразовым резервным кодом
        if mfa_code in backup_codes_list:
            is_backup_code = True
            # Удаляем использованный код (он одноразовый!)
            backup_codes_list.remove(mfa_code)
            user.backup_codes = ",".join(backup_codes_list)
            db.commit()
        else:
            # 2. Если это не резервный код, проверяем Google Authenticator
            totp = pyotp.TOTP(user.totp_secret)
            is_valid_totp = totp.verify(mfa_code)

        # Если оба варианта не подошли — кидаем ошибку
        if not (is_valid_totp or is_backup_code):
            raise HTTPException(status_code=400, detail="Неверный код MFA или резервный код!")
    
    access_token = create_access_token(data={"sub": user.username})
    
    # Защита: Устанавливаем HttpOnly куку
    response.set_cookie(
        key="access_token", 
        value=access_token, 
        httponly=True,  # Кука недоступна для JavaScript (защита от XSS)
        secure=False,   # Для HTTPS на продакшене поставить True
        samesite="lax", # Защита от CSRF
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    return {"message": "Успешный вход"}

@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Успешный выход"}

@app.get("/auth/status")
def check_status(token: str = Depends(get_token_from_cookie)):
    return {"authenticated": True}

@app.get("/protected_data")
def protected_route(token: str = Depends(get_token_from_cookie)):
    return {"message": "Успешный доступ в защищенную зону! Ваш токен валиден.", "token": token}

@app.get("/mfa/setup")
def setup_mfa(token: str = Depends(get_token_from_cookie), db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()

    if user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="Двухфакторная защита уже включена и настроена!")

    if user.totp_secret:
        secret = user.totp_secret
    else:
        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.commit()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="Diploma MFA App")

    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {
        "secret": secret, 
        "qr_code_url": f"data:image/png;base64,{qr_base64}"
    }

# Защита: Ограничение перебора MFA
@app.post("/mfa/verify")
@limiter.limit("5/minute")
def verify_mfa(
    request: Request,
    mfa_data: schemas.MFACode, 
    token: str = Depends(get_token_from_cookie), 
    db: Session = Depends(get_db)
):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Сначала сгенерируйте QR-код (MFA Setup)")

    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(mfa_data.code):
        user.is_mfa_enabled = True 
        
        # ГЕНЕРАЦИЯ РЕЗЕРВНЫХ КОДОВ (5 штук по 8 символов)
        codes = [secrets.token_hex(4) for _ in range(5)]
        user.backup_codes = ",".join(codes) # Сохраняем в БД через запятую
        
        db.commit()
        return {
            "message": "MFA успешно включена! Обязательно сохраните резервные коды.",
            "backup_codes": codes # Отправляем коды на фронтенд
        }
    else:
        raise HTTPException(status_code=400, detail="Неверный код. Попробуйте еще раз.")