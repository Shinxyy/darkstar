"""
Configuration settings for the Darkstar framework.

This module loads configuration values from environment variables
and provides them to other modules in the application.

Configuration includes:
- Database connection parameters
- API keys for external services
- Authentication credentials for scanners
"""

from dotenv import load_dotenv
import os
from colorama import Fore, Style, init
from common.logger import setup_logger
import logging


setup_logger()
logger = logging.getLogger(__name__)


# Initialize colorama
init(autoreset=True)


def debug_config(key, masked=False):
    """Print configuration loading status."""
    value = os.getenv(key)
    status = (
        f"{Fore.GREEN}OK{Style.RESET_ALL}"
        if value
        else f"{Fore.RED}MISSING{Style.RESET_ALL}"
    )
    display_value = "********" if masked and value else value
    logger.info(f"[CONFIG] {key}: {status} ({display_value})")


load_dotenv()

# Database config with debug output
debug_config("DB_USER")
debug_config("DB_PASSWORD", masked=True)
debug_config("DB_HOST")
debug_config("DB_NAME")

db_config = {
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "host": os.getenv("DB_HOST"),
    "database": os.getenv("DB_NAME"),
}

# API keys with debug output
debug_config("HIBP_KEY", masked=True)
HIBP_KEY = os.getenv("HIBP_KEY")

# OpenVAS credentials with debug output
debug_config("OPENVAS_USER")
debug_config("OPENVAS_PASSWORD", masked=True)
OPENVAS_USER = os.getenv("OPENVAS_USER")
OPENVAS_PASSWORD = os.getenv("OPENVAS_PASSWORD")
