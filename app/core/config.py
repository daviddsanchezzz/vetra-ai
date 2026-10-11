"""
pydantic-settings reads configuration from environment variables (and an
optional .env file) into one typed, validated object, instead of scattering
os.environ[...] calls with no central place that knows what's required.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ai_service_token: str
    ai_service_jwt_public_key: str
    node_internal_url: str = "http://localhost:5000"
    openai_api_key: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
