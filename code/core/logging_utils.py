"""Structured logging and PII redaction utilities.
Ensures personal data (emails, phone numbers, customer names) does not leak into logs.
"""
import re
import logging
import sys
from typing import Optional

# Precompiled regex patterns for PII detection
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_REGEX = re.compile(r'(\+?\d{1,3}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b')

def mask_email(email: str) -> str:
    """Masks an email address to protect privacy.
    Example: 'nadia.ionescu@yahoo.com' -> 'n***u@y***m'
    """
    if not email or "@" not in email:
        return "[REDACTED_EMAIL]"
    try:
        user_part, domain_part = email.split("@", 1)
        if len(user_part) <= 2:
            masked_user = user_part[0] + "***"
        else:
            masked_user = user_part[0] + "***" + user_part[-1]
            
        if "." in domain_part:
            d_name, d_tld = domain_part.rsplit(".", 1)
            masked_domain = d_name[0] + "***." + d_tld
        else:
            masked_domain = domain_part[0] + "***"
        return f"{masked_user}@{masked_domain}"
    except Exception:
        return "[REDACTED_EMAIL]"

def mask_phone(phone: str) -> str:
    """Masks a phone number.
    Example: '+55 21 90180-9087' -> '+55 *** 9087'
    """
    if not phone:
        return "[REDACTED_PHONE]"
    digits = re.sub(r'\D', '', phone)
    if len(digits) < 4:
        return "[REDACTED_PHONE]"
    last4 = digits[-4:]
    return f"***-***-{last4}"

def sanitize_text(text: str) -> str:
    """Replaces detectable PII patterns in log messages with masked values."""
    if not isinstance(text, str):
        return str(text)
    
    # Redact emails
    text = EMAIL_REGEX.sub(lambda m: mask_email(m.group(0)), text)
    # Redact phones that look like phone numbers (at least 7 digits)
    text = PHONE_REGEX.sub(lambda m: mask_phone(m.group(0)) if len(re.sub(r'\D', '', m.group(0))) >= 7 else m.group(0), text)
    return text

class PIISanitizingFormatter(logging.Formatter):
    """Custom formatter that automatically redacts PII from all log records."""
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return sanitize_text(original)

def get_logger(name: str = "audit_agent", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a PII-safe logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = PIISanitizingFormatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
