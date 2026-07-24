from __future__ import annotations

import logging

import telebot

from .config import load_config

logger = logging.getLogger("sp-decode")

try:
    settings = load_config()
except Exception as exc:
    raise SystemExit(f"Error de configuración: {exc}") from exc

settings.downloads_dir.mkdir(parents=True, exist_ok=True)
settings.results_dir.mkdir(parents=True, exist_ok=True)

bot = telebot.TeleBot(settings.token)

logger.info(
    "Configuración cargada: %d admin(s), %d grupo(s) permitido(s).",
    len(settings.admins),
    len(settings.allowed_groups),
)
