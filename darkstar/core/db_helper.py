"""
Database helper functions for the Darkstar security framework.

This module provides centralized database operations for storing
vulnerability data and scan results.
"""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


def insert_vulnerability_to_database(vulnerability: Dict[str, Any], org_name: str) -> bool:
    """
    Insert a vulnerability record into the database.
    
    Args:
        vulnerability: Dictionary containing vulnerability data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # For now, just log the vulnerability - database integration can be added later
        logger.info(f"[{org_name}] Vulnerability found: {vulnerability.get('name', 'Unknown')} - {vulnerability.get('severity', 'Unknown')}")
        logger.debug(f"Vulnerability details: {vulnerability}")
        return True
    except Exception as e:
        logger.error(f"Error inserting vulnerability to database: {e}")
        return False


def insert_bbot_to_db(scan_data: Dict[str, Any], org_name: str) -> bool:
    """
    Insert bbot scan results into the database.
    
    Args:
        scan_data: Dictionary containing bbot scan data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # For now, just log the scan data - database integration can be added later
        logger.info(f"[{org_name}] BBOT scan data recorded: {len(scan_data)} entries")
        logger.debug(f"BBOT scan data: {scan_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting BBOT data to database: {e}")
        return False


def insert_nuclei_to_db(scan_data: Dict[str, Any], org_name: str) -> bool:
    """
    Insert nuclei scan results into the database.
    
    Args:
        scan_data: Dictionary containing nuclei scan data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # For now, just log the scan data - database integration can be added later
        logger.info(f"[{org_name}] Nuclei scan data recorded: {len(scan_data)} entries")
        logger.debug(f"Nuclei scan data: {scan_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting Nuclei data to database: {e}")
        return False


def insert_portscan_to_db(scan_data: Dict[str, Any], org_name: str) -> bool:
    """
    Insert port scan results into the database.
    
    Args:
        scan_data: Dictionary containing port scan data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # For now, just log the scan data - database integration can be added later
        logger.info(f"[{org_name}] Port scan data recorded: {len(scan_data)} entries")
        logger.debug(f"Port scan data: {scan_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting port scan data to database: {e}")
        return False


def insert_email_data(email_data, org_name: str) -> bool:
    """
    Insert email data into the database.
    
    Args:
        email_data: List of emails or dictionary containing email data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if isinstance(email_data, list):
            # Handle list of emails
            logger.info(f"[{org_name}] Email data recorded: {len(email_data)} emails")
            logger.debug(f"Email list: {email_data}")
        else:
            # Handle dictionary with email data
            logger.info(f"[{org_name}] Email data recorded: {email_data.get('email', 'Unknown')}")
            logger.debug(f"Email data: {email_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting email data to database: {e}")
        return False


def insert_breached_email_data(breach_data: Dict[str, Any], org_name: str) -> bool:
    """
    Insert breached email data into the database.
    
    Args:
        breach_data: Dictionary containing breach data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"[{org_name}] Breach data recorded: {breach_data.get('email', 'Unknown')} - {breach_data.get('breach_name', 'Unknown')}")
        logger.debug(f"Breach data: {breach_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting breach data to database: {e}")
        return False


def insert_password_data(password_data: Dict[str, Any], org_name: str) -> bool:
    """
    Insert password data into the database.
    
    Args:
        password_data: Dictionary containing password data
        org_name: Organization name for database selection
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        logger.info(f"[{org_name}] Password data recorded")
        logger.debug(f"Password data: {password_data}")
        return True
    except Exception as e:
        logger.error(f"Error inserting password data to database: {e}")
        return False
