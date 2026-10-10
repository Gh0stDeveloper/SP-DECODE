"""Telegram message handlers for authorized 66.py configuration protocol batches.

Runs the same standalone Python decoders used by bot file imports. Never
executes scripts from Telegram text, fetches URLs or leaks private RSA keys.
"""
from __future__ import annotations

import logging

from decoders.Python import (
    eut, falcon_links, happ_links, intvpn, izph, juanscript, npvt_links,
    slipnet, wyrvpn, wyrlite, xor_family,
)
from decoders.Python.HTTPTWEAK import run as decode_http_tweak
from spdecode.access import require_authorized
from spdecode.runtime import bot
from spdecode.handlers.text_protocols import _send_decoder_text_result

logger = logging.getLogger("sp-decode")

TEXT_HANDLERS = {
    **{p: ("HAPP", happ_links.decode_text) for p in happ_links.SCHEMES},
    **{p: ("XOR VPN", xor_family.decode_text) for p in xor_family.SCHEMES},
    "falcontunnel://import/": ("Falcon Tunnel", falcon_links.decode_text),
    "npvt-ssh://": ("NPVT SSH", npvt_links.decode_text),
    "dns://": ("DNS JSON", npvt_links.decode_text),
    "npvs1:": ("NPVS1 legacy values", npvt_links.decode_text),
    "slipnet-enc://": ("SlipNet ENC", lambda s: slipnet.run(s.encode("utf-8"))),
    "slipnet://": ("SlipNet", lambda s: slipnet.run(
        ("slipnet-enc://"+s.split("://",1)[1]).encode("utf-8"))),
    "wyrlite://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrvpnlite://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrl://": ("WyrLite", lambda s: wyrlite.run(s.encode("utf-8"))),
    "wyrvpn://": ("WyrVPN", lambda s: wyrvpn.run(s.encode("utf-8"))),
    "intvpn://": ("IntVPN", lambda s: intvpn.run(s.encode("utf-8"))),
    "juanscript://": ("JuanScript", lambda s: juanscript.run(s.encode("utf-8"))),
    "mobi://": ("JuanScript", lambda s: juanscript.run(s.encode("utf-8"))),
    "eut-settings://": ("EUT Settings", lambda s: eut.run(s.encode("utf-8"))),
    "httptweak://": ("HTTP Tweak", lambda s: decode_http_tweak(s.encode("utf-8"))),
    "izph://": ("IZPH VPN Pro", lambda s: izph.run(s.encode("utf-8"))),
    "izphvpnpro://": ("IZPH VPN Pro", lambda s: izph.run(s.encode("utf-8"))),
}
_PREFIXES = tuple(sorted(TEXT_HANDLERS, key=len, reverse=True))


def _match(message):
    value = getattr(message, "text", "") or ""
    if not isinstance(value,str) or len(value)>2*1024*1024:
        return None
    text=value.strip()
    return next((p for p in _PREFIXES if text.lower().startswith(p)),None)


@bot.message_handler(func=lambda message: _match(message) is not None)
@require_authorized("Los textos de configuraciones VPN")
def decode_config_batch_text(message):
    text=(getattr(message,"text","") or "").strip()
    prefix=_match(message)
    if prefix is None:
        return
    name, decoder=TEXT_HANDLERS[prefix]
    try:
        output=decoder(text)
        if isinstance(output,(dict,list)):
            import json
            output=json.dumps(output,ensure_ascii=False,indent=2)
        if not output:
            if prefix.startswith("happ://"):
                bot.reply_to(message, "HAPP: no se pudo descifrar. Comprueba las claves RSA privadas configuradas en el servidor.")
            else:
                bot.reply_to(message, "No se pudo descifrar la configuración con este formato.")
            return
        _send_decoder_text_result(message,name,str(output))
    except Exception:
        logger.exception("Configuration text decoding failed for %s",prefix)
        bot.reply_to(message,"Error interno al descifrar la configuración.")


# ---------------------------------------------------------------------------
# Password-protected V2Box exports: short-lived private-chat reply workflow.
# No extra commands and no persistence or logging of the user password.
# ---------------------------------------------------------------------------
from dataclasses import dataclass
from threading import RLock
from time import monotonic
from decoders.Python.v2box_export import decode_file as decode_v2box_export

@dataclass
class _V2BoxPending:
    encrypted: bytes
    prompt_id: int
    expires_at: float
    attempts: int = 0

_PENDING_V2BOX: dict[tuple[int, int], _V2BoxPending] = {}
_PENDING_LOCK = RLock()
_V2BOX_TTL_SECONDS = 180


def _prune_v2box_locked(now: float) -> None:
    for key, session in list(_PENDING_V2BOX.items()):
        if session.expires_at <= now:
            del _PENDING_V2BOX[key]


def prompt_v2box_password(message, encrypted: bytes) -> None:
    """Called only for v2box_export.__need_password__ in documents handler."""
    if getattr(message.chat, "type", "") != "private":
        bot.reply_to(
            message,
            "El archivo V2Box tiene contraseña. Envíalo en el chat privado "
            "del bot para descifrarlo; no publiques contraseñas en grupos.",
        )
        return
    if not encrypted or len(encrypted) > 2 * 1024 * 1024:
        bot.reply_to(message, "El archivo V2Box excede el límite de descifrado.")
        return
    user_id = getattr(message.from_user, "id", None)
    if user_id is None:
        return
    now = monotonic()
    with _PENDING_LOCK:
        _prune_v2box_locked(now)
        if len(_PENDING_V2BOX) >= 30 and (message.chat.id, user_id) not in _PENDING_V2BOX:
            bot.reply_to(message, "Hay demasiadas solicitudes pendientes. Intenta después.")
            return
    prompt = bot.reply_to(
        message,
        "V2Box requiere la contraseña que configuró el creador del archivo. "
        "Responde a ESTE mensaje con la contraseña en el chat privado. "
        "Caduca en 3 minutos y se permiten 3 intentos. "
        "No la envíes en grupos.",
    )
    with _PENDING_LOCK:
        _PENDING_V2BOX[(message.chat.id, user_id)] = _V2BoxPending(
            encrypted=bytes(encrypted),
            prompt_id=prompt.message_id,
            expires_at=now + _V2BOX_TTL_SECONDS,
        )


def _is_v2box_password_reply(message) -> bool:
    if getattr(message.chat, "type", None) != "private":
        return False
    reply = getattr(message, "reply_to_message", None)
    if reply is None:
        return False
    user_id = getattr(message.from_user, "id", None)
    if user_id is None:
        return False
    key = (message.chat.id, user_id)
    with _PENDING_LOCK:
        _prune_v2box_locked(monotonic())
        item = _PENDING_V2BOX.get(key)
        return item is not None and reply.message_id == item.prompt_id


@bot.message_handler(func=_is_v2box_password_reply)
@require_authorized("Las contraseñas de archivos V2Box")
def handle_v2box_password_reply(message):
    user_id = message.from_user.id
    key = (message.chat.id, user_id)
    password = (getattr(message, "text", "") or "").strip()
    if not password or len(password) > 256:
        bot.reply_to(message, "La contraseña está vacía o es demasiado larga.")
        return
    with _PENDING_LOCK:
        pending = _PENDING_V2BOX.get(key)
        if pending is None or pending.expires_at <= monotonic():
            _PENDING_V2BOX.pop(key, None)
            return
        pending.attempts += 1
        encrypted = pending.encrypted
        attempts = pending.attempts
        if attempts >= 3:
            _PENDING_V2BOX.pop(key, None)
    try:
        decoded = decode_v2box_export(encrypted, password=password)
    except Exception:
        logger.exception("V2Box password-protected export failed internally")
        decoded = None
    if decoded is None:
        bot.reply_to(
            message,
            "No se pudo descifrar V2Box con esa contraseña. "
            + ("Se cerró esta solicitud." if attempts >= 3 else
               "Responde nuevamente al mensaje inicial del bot."),
        )
        return
    with _PENDING_LOCK:
        _PENDING_V2BOX.pop(key, None)
    import json
    _send_decoder_text_result(
        message, "V2Box Export",
        json.dumps(decoded, ensure_ascii=False, indent=2),
    )
