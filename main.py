import os
import uuid
import base64
import secrets
from datetime import datetime, timedelta
from io import BytesIO

import jwt
import pyotp
import qrcode
from fastapi import FastAPI, Depends, HTTPException, Form, Response, Request, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from passlib.context import CryptContext

# Импорты для лимитера (защита от брутфорса)
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
import schemas
from database import engine, get_db
from telegram_utils import send_telegram_message

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

# ИСПРАВЛЕНО: Безопасное извлечение и проверка токена
def get_current_user_from_token(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Не авторизован")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Некорректный токен")
            
        user = db.query(models.User).filter(models.User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="Пользователь не найден")
            
        return user
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Время действия токена истекло. Войдите заново.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Недействительный токен")

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

@app.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request, 
    response: Response,
    background_tasks: BackgroundTasks,
    form_data: OAuth2PasswordRequestForm = Depends(), 
    mfa_code: str = Form(None),
    mfa_method: str = Form(None),     # НОВОЕ: Какой метод выбрал пользователь
    request_code: bool = Form(False), # НОВОЕ: Флаг "Пришлите мне код в ТГ"
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Неверный логин или пароль")
    
    if user.is_mfa_enabled:
        # ШАГ 1: Если метод еще не выбран, собираем список доступных методов и отдаем на фронт
        if not mfa_method:
            available_methods = []
            if user.telegram_chat_id:
                available_methods.append({"id": "telegram", "name": "Telegram Bot"})
            if user.totp_secret:
                available_methods.append({"id": "totp", "name": "Google Authenticator"})
            if user.backup_codes:
                available_methods.append({"id": "backup", "name": "Резервные коды"})
            
            return {
                "mfa_required": True, 
                "step": "select_method", 
                "available_methods": available_methods,
                "message": "Выберите способ подтверждения входа"
            }

        # ШАГ 2: Если пользователь нажал кнопку "Telegram", генерируем и отправляем код
        if mfa_method == "telegram" and request_code:
            if not user.telegram_chat_id:
                raise HTTPException(status_code=400, detail="Telegram не привязан к аккаунту")
            
            # Удаляем старые коды и генерируем новый
            db.query(models.TelegramOTP).filter(models.TelegramOTP.user_id == user.id).delete()
            import random
            code = str(random.randint(100000, 999999))
            hashed_code = get_password_hash(code)
            
            new_otp = models.TelegramOTP(
                user_id=user.id, otp_hash=hashed_code,
                expires_at=datetime.utcnow() + timedelta(minutes=1)
            )
            db.add(new_otp)
            db.commit()
            
            text = f"🔐 Ваш код для входа:\n<b><pre>{code}</pre></b>\n\n⏳ <i>Действителен 1 минуту.</i>"
            background_tasks.add_task(send_telegram_message, user.telegram_chat_id, text)
            
            return {"mfa_required": True, "step": "enter_code", "method": "telegram", "message": "Код отправлен в ваш Telegram"}

        # ШАГ 3: Проверка самого кода
        if not mfa_code:
            raise HTTPException(status_code=400, detail="Введите код подтверждения")
        
        is_valid = False

        if mfa_method == "backup" and user.backup_codes:
            backup_codes_list = user.backup_codes.split(",")
            for hashed_code in backup_codes_list:
                if verify_password(mfa_code, hashed_code):
                    is_valid = True
                    backup_codes_list.remove(hashed_code)
                    user.backup_codes = ",".join(backup_codes_list) if backup_codes_list else None
                    db.commit()
                    break

        elif mfa_method == "telegram" and user.telegram_chat_id:
            tg_otp = db.query(models.TelegramOTP).filter(models.TelegramOTP.user_id == user.id).first()
            if tg_otp and tg_otp.expires_at > datetime.utcnow():
                if verify_password(mfa_code, tg_otp.otp_hash):
                    is_valid = True
                    db.delete(tg_otp)
                    db.commit()

        elif mfa_method == "totp" and user.totp_secret:
            totp = pyotp.TOTP(user.totp_secret)
            is_valid = totp.verify(mfa_code)

        if not is_valid:
            raise HTTPException(status_code=400, detail="Неверный код или срок действия истек!")
    
    # Если все проверки пройдены — выдаем токен сессии
    access_token = create_access_token(data={"sub": user.username})
    response.set_cookie(
        key="access_token", value=access_token, httponly=True,
        secure=False, samesite="lax", max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    return {"message": "Успешный вход"}
@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Успешный выход"}

@app.get("/auth/status")
def check_status(current_user: models.User = Depends(get_current_user_from_token)):
    return {"authenticated": True, "username": current_user.username}

@app.get("/protected_data")
def protected_route(request: Request, current_user: models.User = Depends(get_current_user_from_token)):
    # Достаем токен еще раз, чтобы вытащить его payload (время жизни)
    token = request.cookies.get("access_token")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
    # Считаем оставшиеся резервные коды
    backup_count = 0
    if current_user.backup_codes:
        backup_count = len(current_user.backup_codes.split(","))
        
    # Улучшенная логика определения методов (перечисляем все активные)
    mfa_method = "Не настроена"
    if current_user.is_mfa_enabled:
        active_methods = []
        if current_user.telegram_chat_id: active_methods.append("Telegram")
        if current_user.totp_secret: active_methods.append("Google Auth")
        
        mfa_method = " + ".join(active_methods) if active_methods else "Включена"
    
    return {
        "message": "Успех",
        "jwt_payload": {
            "sub": payload.get("sub"),
            "exp": payload.get("exp")
        },
        "security": {
            "is_mfa_enabled": current_user.is_mfa_enabled,
            "mfa_method": mfa_method,
            "backup_codes": backup_count,
            "telegram_linked": bool(current_user.telegram_chat_id),
            "totp_linked": bool(current_user.totp_secret) # <-- ДОБАВЛЕНО: статус Google Auth
        }
    }

# --- MFA ЭНДПОИНТЫ ---

@app.get("/mfa/setup")
def setup_mfa(current_user: models.User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    # ИСПРАВЛЕНО: Теперь мы проверяем только наличие ключа от самого Google Auth
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Google Authenticator уже привязан к вашему аккаунту!")

    # Генерируем новый секрет для Google Auth
    secret = pyotp.random_base32()
    current_user.totp_secret = secret
    db.commit()

    # Создаем ссылку для QR-кода
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.username, issuer_name="Diploma MFA App")

    # Рисуем QR-код
    qr = qrcode.make(provisioning_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return {
        "secret": secret, 
        "qr_code_url": f"data:image/png;base64,{qr_base64}"
    }

@app.post("/mfa/verify")
@limiter.limit("5/minute")
def verify_mfa(
    request: Request,
    mfa_data: schemas.MFACode, 
    current_user: models.User = Depends(get_current_user_from_token), 
    db: Session = Depends(get_db)
):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Сначала сгенерируйте QR-код (MFA Setup)")

    totp = pyotp.TOTP(current_user.totp_secret)
    if totp.verify(mfa_data.code):
        current_user.is_mfa_enabled = True 
        
        # ИСПРАВЛЕНО: Генерируем коды и сохраняем их ХЕШИ в базу
        codes = [secrets.token_hex(4) for _ in range(4)]
        hashed_codes = [get_password_hash(code) for code in codes]
        current_user.backup_codes = ",".join(hashed_codes)
        
        db.commit()
        return {
            "message": "MFA успешно включена! Обязательно сохраните резервные коды.",
            "backup_codes": codes # Отдаем пользователю чистые коды 1 раз
        }
    else:
        raise HTTPException(status_code=400, detail="Неверный код. Попробуйте еще раз.")


# --- TELEGRAM ЭНДПОИНТЫ ---

@app.post("/api/mfa/telegram/generate-link")
async def generate_telegram_link(
    current_user: models.User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)
):
    # ЗАЩИТА 1: Проверяем, не привязан ли уже Telegram
    if current_user.telegram_chat_id:
        raise HTTPException(status_code=400, detail="Telegram уже привязан к вашему аккаунту!")

    # ЗАЩИТА 2: Удаляем старые сгенерированные ссылки (защита от спама нажатиями)
    db.query(models.TelegramBinding).filter(models.TelegramBinding.user_id == current_user.id).delete()
    db.commit()

    # Генерируем уникальный токен привязки
    bind_token = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(minutes=10)
    
    # Сохраняем в БД
    new_binding = models.TelegramBinding(
        user_id=current_user.id,
        bind_token=bind_token,
        expires_at=expires
    )
    db.add(new_binding)
    db.commit()
    
    bot_username = "mfa_secure_bot" 
    # Прямая ссылка для открытия приложения
    telegram_url = f"tg://resolve?domain={bot_username}&start={bind_token}"
    
    return {"telegram_url": telegram_url, "expires_in": "10 minutes"}

@app.post("/api/telegram/webhook")
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    data = await request.json()
    
    if "message" in data and "text" in data["message"]:
        chat_id = str(data["message"]["chat"]["id"])
        text = data["message"]["text"]
        
        if text.startswith("/start "):
            bind_token = text.split(" ")[1]
            
            binding = db.query(models.TelegramBinding).filter(models.TelegramBinding.bind_token == bind_token).first()
            
            if binding:
                if binding.expires_at > datetime.utcnow():
                    user = db.query(models.User).filter(models.User.id == binding.user_id).first()
                    user.telegram_chat_id = chat_id
                    
                    # ИСПРАВЛЕНИЕ: Включаем глобальный флажок МФА!
                    user.is_mfa_enabled = True 
                    
                    db.delete(binding)
                    db.commit()
                    
                    success_text = f"✅ <b>{user.username}</b>, аккаунт успешно привязан!\n🔒 Двухфакторная защита активирована. Теперь при входе коды будут приходить сюда."
                    background_tasks.add_task(send_telegram_message, chat_id, success_text)
                    
                    return {"status": "success"}
                else:
                    db.delete(binding)
                    db.commit()
                    background_tasks.add_task(send_telegram_message, chat_id, "❌ Ссылка устарела. Сгенерируйте новую в личном кабинете.")
    
    return {"status": "ok"}