import os
from datetime import datetime, timedelta
import jwt # Не забудь, что мы устанавливали PyJWT
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import FastAPI, Depends, HTTPException, Form

import pyotp
import qrcode
import base64
from io import BytesIO

import models
import schemas
from database import engine, get_db

# Даем команду SQLAlchemy создать таблицы в базе данных (если их еще нет)
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="MFA System API",
    description="API для системы многофакторной аутентификации. Дипломный проект."
)

# Подключаем папку со статикой (наш фронтенд)
app.mount("/static", StaticFiles(directory="static"), name="static")

# --- НАСТРОЙКИ БЕЗОПАСНОСТИ И JWT ---
# Секретный ключ для подписи токенов (берем из .env)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "my_super_secret_diploma_key_2025")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Токен "сгорает" через 30 минут

# Настройка хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Эта штука включает проверку токена и красивую кнопку "Authorize" в Swagger
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

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

# 1. Отдача главной страницы (Фронтенд)
@app.get("/")
def serve_frontend():
    return FileResponse("static/index.html")

# 2. Регистрация
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

# 3. Вход в систему (с проверкой MFA!)
@app.post("/login")
def login(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    mfa_code: str = Form(None), # Новое поле: код из приложения (может быть пустым)
    db: Session = Depends(get_db)
):
    # 1. Ищем пользователя и проверяем пароль
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")
    
    # 2. ПРОВЕРКА ВТОРОГО ФАКТОРА
    if user.is_mfa_enabled:
        # Если код еще не ввели, просим фронтенд его запросить
        if not mfa_code:
            return {"mfa_required": True, "message": "Введите 6-значный код из Google Authenticator"}
        
        # Если код ввели, проверяем его правильность
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(mfa_code):
            raise HTTPException(status_code=400, detail="Неверный код MFA! Попробуйте еще раз.")
    
    # 3. Если MFA выключена ИЛИ код оказался верным — выдаем токен!
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# 4. Защищенная зона (пускает только с токеном)
@app.get("/protected_data")
def protected_route(token: str = Depends(oauth2_scheme)):
    return {"message": "Успешный доступ в защищенную зону! Ваш токен валиден.", "token": token}

# 5. Эндпоинт для генерации QR-кода (настройка MFA)
@app.get("/mfa/setup")
def setup_mfa(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # Расшифровываем токен
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()

    # --- НАЧАЛО БЛОКА ЗАЩИТЫ ---
    # ЗАЩИТА 1: Если MFA уже включена, блокируем перезапись!
    if user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="Двухфакторная защита уже включена и настроена!")

    # ЗАЩИТА 2: Если пользователь уже запрашивал код, но не завершил настройку,
    # мы выдаем ему старый ключ, чтобы телефон не рассинхронизировался.
    if user.totp_secret:
        secret = user.totp_secret
    else:
        # Только если ключа вообще нет, генерируем новый
        secret = pyotp.random_base32()
        user.totp_secret = secret
        db.commit()
    # --- КОНЕЦ БЛОКА ЗАЩИТЫ ---

    # Создаем ссылку для Google Authenticator
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name="Diploma MFA App")

    # Рисуем картинку QR-кода
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {
        "secret": secret, 
        "qr_code_url": f"data:image/png;base64,{qr_base64}"
    }

# 6. Эндпоинт для проверки 6-значного кода и включения MFA
@app.post("/mfa/verify")
def verify_mfa(mfa_data: schemas.MFACode, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    user = db.query(models.User).filter(models.User.username == username).first()

    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="Сначала сгенерируйте QR-код (MFA Setup)")

    # Проверяем введенный код
    totp = pyotp.TOTP(user.totp_secret)
    if totp.verify(mfa_data.code):
        user.is_mfa_enabled = True # Включаем защиту в базе данных!
        db.commit()
        return {"message": "MFA успешно включена! Ваш аккаунт под защитой."}
    else:
        raise HTTPException(status_code=400, detail="Неверный код. Попробуйте еще раз.")