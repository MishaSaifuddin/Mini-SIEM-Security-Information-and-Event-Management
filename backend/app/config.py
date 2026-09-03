import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "mini-siem-secret-key-change-in-prod")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8
    
    DB_ENGINE = os.environ.get("DB_ENGINE", "sqlite")
    
    SQLITE_PATH = BASE_DIR / "mini_siem.db"
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
    MYSQL_USER = os.environ.get("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
    MYSQL_DB = os.environ.get("MYSQL_DB", "mini_siem")
    
    @classmethod
    def get_database_url(cls):
        if cls.DB_ENGINE == "mysql":
            return (f"mysql+pymysql://{cls.MYSQL_USER}:{cls.MYSQL_PASSWORD}"
                    f"@{cls.MYSQL_HOST}:{cls.MYSQL_PORT}/{cls.MYSQL_DB}?charset=utf8mb4")
        return f"sqlite:///{cls.SQLITE_PATH}"

    API_PREFIX = "/api"
    CORS_ORIGINS = ["*"]
