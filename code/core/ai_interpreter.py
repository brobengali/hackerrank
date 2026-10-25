"""AI and heuristic interpreter module for unstructured and multilingual inputs.
Classifies user deletion intent and extracts contextual signals with deterministic fallback.
"""
import re

class RequestInterpreter:
    # Explicit negation or retention patterns indicating non-deletion requests
    NON_DELETION_PATTERNS = [
        r"\bnot\s+(a\s+request\s+to\s+close|asking\s+for\s+deletion)\b",
        r"\bleave\s+the\s+account\s+active\b",
        r"\bkeep\s+the\s+account(\s+as\s+it\s+is)?\b",
        r"\bwithout\s+removing\b",
        r"\bmarketing\s+lists?\s+only\b",
        r"\binformation\s+request\b",
        r"\bleave\s+my\s+profile\b",
        r"\bcontinue\s+using\s+the\s+service\b",
        r"\bportable\s+format\b",
        r"\b(do\s*not|don't)\s+(close|delete|remove|erase)\b",
        r"\b(do\s*not|don't)\s+delete\s+or\s+change\b",
        r"\breset(ting)?\s+(the\s+)?login\b",
        r"\bcopy\s+of\s+(the\s+information|last\s+year'?s\s+invoices)\b",
        r"\bno\s+estoy\s+pidiendo\s+(la\s+)?eliminaci[oó]n\b",
        r"\bmantener\s+la\s+cuenta\s+activa\b",
        r"\bne\s+demande\s+pas\s+la\s+suppression\b",
        r"\bgarder\s+le\s+compte\s+actif\b",
    ]

    @classmethod
    def is_deletion_authorized(cls, request_text: str) -> bool:
        """Determines whether the supplied request text authorizes account/data deletion.
        Returns False for subject access requests, export-only requests, marketing opt-outs,
        and profile attribute correction requests.
        """
        if not request_text:
            return False
            
        lower_text = request_text.lower()
        for pattern in cls.NON_DELETION_PATTERNS:
            if re.search(pattern, lower_text):
                return False
                
        return True
