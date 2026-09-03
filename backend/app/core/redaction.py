"""Redazione e sanitizzazione dei dati prima di log, report e prompt AI."""
from __future__ import annotations

import re
from typing import Any

# Segreti e credenziali: non devono mai raggiungere report, log o modello AI.
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|bearer|authorization)\b\s*[:=]\s*\S+"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),                                          # AWS key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),                                         # GitHub token
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bset-cookie\b\s*:\s*\S+"),
    re.compile(r"\b[a-fA-F0-9]{32,}\b"),  # hash/credenziali in chiaro nei leak
]

# Sequenze tipiche di prompt injection nei contenuti raccolti da Internet.
_INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bignore (all |the )?(previous|prior|above) instructions?\b"),
    re.compile(r"(?i)\bdisregard (all |the )?(previous|prior|above)\b"),
    re.compile(r"(?i)\byou are now\b.{0,40}\b(assistant|ai|model|dan)\b"),
    re.compile(r"(?i)\bsystem\s*prompt\b"),
    re.compile(r"(?i)</?(system|assistant|user|instructions?)>"),
    re.compile(r"(?i)\bnew instructions?\s*:"),
    re.compile(r"(?i)\bact as (an? )?(admin|root|developer mode)\b"),
    re.compile(r"(?i)\b(execute|run)\s+(the\s+)?(following\s+)?(command|shell|code)\b"),
]

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

REDACTED = "[REDACTED]"
NEUTRALIZED = "[CONTENUTO-NEUTRALIZZATO]"

MAX_FIELD_LENGTH = 2000


def redact_secrets(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def neutralize_injection(text: str) -> str:
    """Neutralizza istruzioni presenti nei contenuti raccolti da Internet.

    Principio: i contenuti esterni sono DATI, mai istruzioni. Questa funzione
    e' l'ultima barriera prima che un testo entri in un prompt AI.
    """
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub(NEUTRALIZED, text)
    return text


def mask_email(email: str, unmask: bool = False) -> str:
    """Mascheratura degli indirizzi e-mail: solo i ruoli con `pii:unmask`
    vedono il valore completo (sezione 19)."""
    if unmask:
        return email
    if "@" not in email:
        return REDACTED
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = local[0] + "*" if local else "*"
    else:
        masked_local = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked_local}@{domain}"


def sanitize_text(value: str, max_length: int = MAX_FIELD_LENGTH) -> str:
    """Pipeline completa applicata a QUALSIASI stringa proveniente dall'esterno."""
    value = _CONTROL_CHARS.sub(" ", value)
    value = redact_secrets(value)
    value = neutralize_injection(value)
    value = " ".join(value.split())
    if len(value) > max_length:
        value = value[: max_length - 3] + "..."
    return value


def sanitize_structure(data: Any, max_depth: int = 8, _depth: int = 0) -> Any:
    """Sanitizza ricorsivamente una struttura JSON proveniente da un tool.

    Limita anche la profondita' e la dimensione per prevenire strutture
    patologiche (decompression/expansion bomb).
    """
    if _depth >= max_depth:
        return "[STRUTTURA-TRONCATA]"
    if isinstance(data, str):
        return sanitize_text(data)
    if isinstance(data, dict):
        return {
            sanitize_text(str(key), 128): sanitize_structure(value, max_depth, _depth + 1)
            for key, value in list(data.items())[:200]
        }
    if isinstance(data, list):
        return [sanitize_structure(item, max_depth, _depth + 1) for item in data[:500]]
    if isinstance(data, (int, float, bool)) or data is None:
        return data
    return sanitize_text(str(data))


# Chiavi che non devono mai comparire nell'output verso AI o report.
FORBIDDEN_KEYS = {
    "password", "passwd", "pwd", "hash", "hashes", "credential", "credentials",
    "cookie", "cookies", "set-cookie", "authorization", "token", "api_key",
    "apikey", "secret", "private_key", "session", "leak_content", "raw_body",
    "attachment", "attachments", "payload",
}


def strip_forbidden_keys(data: Any) -> Any:
    """Rimuove ricorsivamente le chiavi vietate da una struttura."""
    if isinstance(data, dict):
        return {
            key: strip_forbidden_keys(value)
            for key, value in data.items()
            if key.lower() not in FORBIDDEN_KEYS
        }
    if isinstance(data, list):
        return [strip_forbidden_keys(item) for item in data]
    return data
