from pydantic import BaseSettings


class Settings(BaseSettings):
    DATABASE_HOST: str
    DATABASE_PORT: int
    DATABASE_DB: str
    DATABASE_USER: str
    DATABASE_PASSWORD: str
    DATABASE_PREFIX: str

    # Token 相关
    ACCESS_TOKEN_EXPIRES_IN: int
    REFRESH_TOKEN_EXPIRES_IN: int
    JWT_ALGORITHM: str
    JWT_PRIVATE_KEY: str
    JWT_PUBLIC_KEY: str

    CLIENT_ORIGIN: str

    class Config:
        env_file = './.env'

settings = Settings()