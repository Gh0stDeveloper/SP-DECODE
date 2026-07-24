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
    """Autoriza administradores en cualquier chat y usuarios de grupos permitidos."""
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    return is_admin(user_id, config) or chat_id in config.allowed_groups


def require_authorized(resource: str = "Este contenido"):
    """Protege un handler con la política de acceso única de SP-DECODE.

    El import diferido evita dependencias circulares durante el arranque. Todos
    los handlers que descifran archivos o textos deben usar este decorador.
    """

    def decorator(handler):
        @wraps(handler)
        def wrapped(message, *args, **kwargs):
            from .runtime import bot, settings

            if not is_authorized(message, settings):
                bot.reply_to(
                    message,
                    "<b>Acceso no autorizado</b>\n"
                    f"{resource} solo se procesa para administradores o en grupos permitidos.\n"
                    "Usa /id para consultar los identificadores que debes añadir a config.json.",
                    parse_mode="HTML",
                )
                return None
            return handler(message, *args, **kwargs)

        wrapped.__spdecode_requires_authorization__ = True
        return wrapped

    return decorator
