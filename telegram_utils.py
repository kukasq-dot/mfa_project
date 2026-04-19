import os
import httpx
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

async def send_telegram_message(chat_id: str, text: str):
    """
    Асинхронно отправляет сообщение пользователю в Telegram.
    """
    if not TELEGRAM_BOT_TOKEN:
        print("Ошибка: TELEGRAM_BOT_TOKEN не задан в .env")
        return None

    async with httpx.AsyncClient() as client:
        url = f"{TELEGRAM_API_URL}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML" # Позволяет использовать <b>жирный</b> текст
        }
        try:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            print(f"Ошибка при отправке сообщения в Telegram: {e}")
            return None

async def set_webhook(webhook_url: str):
    """
    Устанавливает вебхук, чтобы Telegram знал, куда слать сообщения от пользователей.
    """
    async with httpx.AsyncClient() as client:
        url = f"{TELEGRAM_API_URL}/setWebhook"
        response = await client.post(url, json={"url": webhook_url})
        return response.json()