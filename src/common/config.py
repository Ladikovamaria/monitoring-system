# src/common/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    server_host: str = "127.0.0.1"
    server_port: int = 8000
    database_url: str = "postgresql://monitsys_user:12345@localhost:5432/monitsys"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()