from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    openslice_host: str = "10.255.32.80"
    so_host: str = "155.54.95.79:8002"
    log_level: str = "INFO"
    version: int = 2
    sub_version: int = 1

settings = Settings()
