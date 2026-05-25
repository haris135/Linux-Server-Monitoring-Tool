import os
from dotenv import load_dotenv
load_dotenv()
DB_CFG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "siem"),
    "password": os.getenv("DB_PASS"),
    "database": os.getenv("DB_NAME", "siem"),
    "cursorclass": None,
    "autocommit": True,
}
UI_REFRESH_SEC = int(os.getenv("UI_REFRESH_SEC", "10"))

