"""
hydra/utils/crypto.py — Генерация паролей/токенов и детерминированное выведение ключей.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

# Без неоднозначных символов (0/O, 1/l/I) — для ручного ввода с телефона.
_PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"


def gen_password(length: int = 16) -> str:
    """Случайный пароль из _PASSWORD_CHARS."""
    return "".join(secrets.choice(_PASSWORD_CHARS) for _ in range(length))


def gen_token(nbytes: int = 24) -> str:
    """secrets.token_urlsafe(nbytes)."""
    return secrets.token_urlsafe(nbytes)


def derive_key(purpose: str, seed: str) -> str:
    """Детерминированный ключ: base64(sha256(f'{purpose}|{seed}')).

    Используется AWG и другими плагинами для воспроизводимых per-user кредов.
    """
    digest = hashlib.sha256(f"{purpose}|{seed}".encode()).digest()
    return base64.b64encode(digest).decode()


def derive_hex_key(purpose: str, seed: str) -> str:
    """Детерминированный hex-ключ: sha256(f'{purpose}|{seed}').

    Используется NaiveProxy для URL-безопасных учетных данных без спецсимволов.
    """
    return hashlib.sha256(f"{purpose}|{seed}".encode()).hexdigest()
