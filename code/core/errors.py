"""Structured exceptions for data loading, schema validation, and audit processing.
"""
from typing import Optional, Dict, Any

class AuditAgentBaseError(Exception):
    """Base exception for all deletion audit agent errors."""
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Details: {self.details}"
        return self.message


class DataValidationError(AuditAgentBaseError):
    """Raised when data fails schema or contract validation."""
    pass


class MissingFileError(DataValidationError):
    """Raised when an expected dataset or evidence file is missing."""
    pass


class MissingFieldError(DataValidationError):
    """Raised when a required schema column or dictionary key is missing."""
    pass


class MalformedRowError(DataValidationError):
    """Raised when a tabular record row is malformed or cannot be parsed."""
    pass


class DuplicateRecordError(DataValidationError):
    """Raised when an unexpected duplicate primary key is encountered."""
    pass


class InvalidDataFormatError(DataValidationError):
    """Raised when field value fails type, format, or enum validation."""
    pass


class ConfigurationError(AuditAgentBaseError):
    """Raised when environment or runtime configuration is invalid."""
    pass


class PolicyError(AuditAgentBaseError):
    """Base exception for policy parsing and evaluation errors."""
    pass


class UnknownPolicyCategoryError(PolicyError):
    """Raised when encountering a record category with no defined policy rule."""
    pass


class ContradictoryPolicyError(PolicyError):
    """Raised when multiple conflicting rules define contradictory actions for the same category."""
    pass


class DependencyCycleError(AuditAgentBaseError):
    """Raised when a circular dependency is detected in the remediation plan."""
    pass


class UnauthorizedDestructiveActionError(AuditAgentBaseError):
    """Raised when a destructive remediation operation lacks explicit authorization."""
    pass


class AIAgentError(AuditAgentBaseError):
    """Base exception for AI-assisted investigation agent errors."""
    pass


class ToolValidationError(AIAgentError):
    """Raised when tool arguments fail strict schema validation."""
    pass


class PromptInjectionError(AIAgentError):
    """Raised or flagged when adversarial prompt injection patterns are detected."""
    pass


class ProviderError(AIAgentError):
    """Raised when an external model provider fails, times out, or returns a 5xx error."""
    pass


class ExcessiveToolCallsError(AIAgentError):
    """Raised when an agent loop exceeds the bounded iteration or call limits."""
    pass


class UngroundedClaimError(AIAgentError):
    """Raised when an agent submits a finding or claim lacking grounded evidence."""
    pass

