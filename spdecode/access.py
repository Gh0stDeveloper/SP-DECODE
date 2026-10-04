from __future__ import annotations

from functools import wraps
from typing import Any

from .config import AppConfig


def is_admin(user_id: Any, config: AppConfig) -> bool:
    if user_id is None or isinstance(user_id, bool):
        return False
    try:
        return int(user_id) in config.admins
    except (TypeError, ValueError):
        return False


def is_authorized(message: Any, config: AppConfig) -> bool:
    """Autoriza admins, grupos permitidos o cualquier grupo si el modo global está activo."""
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat = getattr(message, "chat", None)
    chat_id = getattr(chat, "id", None)
    chat_type = str(getattr(chat, "type", "") or "").lower()

    if is_admin(user_id, config):
        return True
    if config.allow_all_groups and chat_type in {"group", "supergroup"}:
        return True
    return chat_id in config.allowed_groups


def require_authorized(resource: str = "Este contenido"):
    """Protege un handler con la política de acceso única de SP-DECODE."""

    def decorator(handler):
        @wraps(handler)
        def wrapped(message, *args, **kwargs):
            from .runtime import bot, settings

            if not is_authorized(message, settings):
                access_hint = (
                    "El bot acepta cualquier grupo, pero este chat no es un grupo autorizado."
                    if settings.allow_all_groups
                    else "Usa /id para consultar los identificadores que debes añadir a config.json."
                )
                bot.reply_to(
                    message,
                    "<b>Acceso no autorizado</b>\n"
                    f"{resource} solo se procesa para administradores o en grupos autorizados.\n"
                    f"{access_hint}",
                    parse_mode="HTML",
                )
                return None
            return handler(message, *args, **kwargs)

        wrapped.__spdecode_requires_authorization__ = True
        return wrapped

    return decorator
