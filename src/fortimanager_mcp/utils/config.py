"""Configuration management for FortiManager MCP server."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """FortiManager MCP server settings."""

    # FortiManager connection
    fortimanager_host: str = ""
    fortimanager_port: int = 443
    fortimanager_username: str = ""
    fortimanager_password: str = ""
    fortimanager_api_token: str = ""
    fortimanager_verify_ssl: bool = False
    fortimanager_timeout: int = 30
    fortimanager_max_retries: int = 3

    # Tool mode
    fmg_tool_mode: str = "full"  # "full" or "dynamic"

    # Security
    fmg_allowed_output_dirs: str = "/tmp,./output"

    # Logging
    log_level: str = "INFO"

    class Config:
        """Pydantic config."""

        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()
