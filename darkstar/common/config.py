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
import sys
from colorama import Fore, Style, init
from common.logger import setup_logger
import logging
import argparse


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

def load_environment(env_file=None):
    """
    Load environment variables from a specified file.
    
    Args:
        env_file (str, optional): Path to the .env file. If None, checks command line args.
    
    Returns:
        str: Path to the loaded environment file
    """
    # Default path should be /app/.env for Docker environments
    default_env_path = "/app/.env"
    
    # If no env_file is specified, check for custom env file from command line arguments
    if env_file is None:
        env_file = default_env_path  # Use Docker default path
        for i, arg in enumerate(sys.argv):
            if arg in ["-env", "--envfile"] and i + 1 < len(sys.argv):
                env_file = sys.argv[i + 1]
                break
    
    # Check if the file exists
    if not os.path.exists(env_file):
        logger.warning(f"{Fore.YELLOW}[CONFIG] Environment file not found: {env_file}")
        if env_file != default_env_path and os.path.exists(default_env_path):
            logger.info(f"{Fore.GREEN}[CONFIG] Falling back to default: {default_env_path}")
            env_file = default_env_path
    
    # Load environment variables from the specified file
    success = load_dotenv(dotenv_path=env_file, override=True)
    
    if success:
        logger.info(f"{Fore.GREEN}[CONFIG] Successfully loaded environment from: {env_file}")
    else:
        logger.warning(f"{Fore.YELLOW}[CONFIG] Could not load environment from: {env_file}")
    
    # Print environment sources to aid in debugging
    logger.info(f"{Fore.CYAN}[CONFIG] Environment files checked: {env_file}")
    
    return env_file

# Load environment variables with explicit default to Docker path
# We'll use override=True to ensure .env values take precedence over system environment
env_file = load_environment()

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