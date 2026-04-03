import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# Загружаем переменные из скрытого файла .env
load_dotenv()

# Получаем нашу ссылку на базу данных
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

# Создаем "движок" - основную точку подключения
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Создаем фабрику сессий (через них мы будем отправлять данные в базу)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Базовый класс для всех наших будущих таблиц (Пользователи, Ключи)
Base = declarative_base()

# Специальная функция, которая будет открывать и закрывать соединение для каждого запроса пользователя
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()