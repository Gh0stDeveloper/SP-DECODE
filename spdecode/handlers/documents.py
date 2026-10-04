from __future__ import annotations

import logging
import subprocess

from spdecode.access import require_authorized
from spdecode.executor import execute_decoder
from spdecode.registry import DECODER_REGISTRY, get_decoder, get_supported_extension
from spdecode.runtime import bot, settings
from spdecode.utils import clean_filename, html_pre, split_message

logger = logging.getLogger("sp-decode")



def send_decoder_output(message, output: str) -> None:
    parts = split_message(output)
    for index, part in enumerate(parts, start=1):
        header = "SP-DECODE"
        if len(parts) > 1:
            header += f" — parte {index}/{len(parts)}"
        bot.reply_to(
            message,
            f"<b>{header}</b>\n<pre>{html_pre(part)}</pre>",
            parse_mode="HTML",
        )


@bot.message_handler(content_types=["document"])
@require_authorized("Los archivos")
def process_received_file(message):
    if message.document is None:
        return

    file_size = getattr(message.document, "file_size", 0) or 0
    if file_size > settings.max_file_size_bytes:
        bot.reply_to(
            message,
            "<b>Archivo demasiado grande</b>\n"
            f"El límite configurado es de {settings.max_file_size_mb} MB.",
            parse_mode="HTML",
        )
        return

    original_name = message.document.file_name or "archivo"
    file_name = clean_filename(original_name)
    file_extension = get_supported_extension(file_name)

    if file_extension is None:
        bot.reply_to(
            message,
            "<b>Formato no soportado</b>\n"
            f"Archivo: <code>{html_pre(file_name)}</code>\n"
            "Usa /formats para consultar todos los formatos disponibles.",
            parse_mode="HTML",
        )
        return

    unique_id = f"{message.chat.id}_{message.message_id}"
    received_file_path = settings.downloads_dir / f"{unique_id}_{file_name}"
    result_file_path = settings.results_dir / f"result_{unique_id}.txt"

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        received_file_path.write_bytes(downloaded_file)

        spec = get_decoder(file_extension)
        result = execute_decoder(
            spec,
            received_file_path,
            timeout_seconds=settings.decoder_timeout_seconds,
        )

        output_to_send = result.stdout

        result_file_path.write_text(
            output_to_send or result.output,
            encoding="utf-8",
            errors="replace",
        )

        if output_to_send:
            send_decoder_output(message, output_to_send)
        elif result.stderr:
            bot.reply_to(
                message,
                "<b>Error del decodificador</b>\n"
                f"Código de salida: <code>{result.returncode}</code>\n"
                f"<pre>{html_pre(result.stderr[:3300])}</pre>",
                parse_mode="HTML",
            )
        else:
            bot.reply_to(
                message,
                "<b>Sin resultado</b>\nEl decodificador terminó sin producir salida.",
                parse_mode="HTML",
            )

        with result_file_path.open("rb") as result_file_to_send:
            username = getattr(message.from_user, "username", None) or "anónimo"
            caption = (
                "SP-DECODE — resultado\n"
                f"Archivo: {file_name}\n"
                f"Formato: .{file_extension}\n"
                f"Usuario: @{username}\n"
                "@GhostDeve | @CodeBreakersHub"
            )
            bot.send_document(
                chat_id=message.chat.id,
                document=result_file_to_send,
                caption=caption,
                reply_to_message_id=message.message_id,
            )

    except subprocess.TimeoutExpired:
        bot.reply_to(
            message,
            "<b>Tiempo agotado</b>\n"
            f"El decodificador superó el límite de {settings.decoder_timeout_seconds} segundos.",
            parse_mode="HTML",
        )
    except FileNotFoundError as exc:
        logger.error("Dependencia o archivo faltante: %s", exc)
        bot.reply_to(
            message,
            "<b>No se pudo iniciar el decodificador</b>\n"
            f"<code>{html_pre(str(exc))}</code>",
            parse_mode="HTML",
        )
    except Exception as exc:
        logger.exception("Error procesando '%s'", file_name)
        bot.reply_to(
            message,
            "<b>Error al procesar el archivo</b>\n"
            f"<code>{html_pre(str(exc))}</code>",
            parse_mode="HTML",
        )
    finally:
        for path in (received_file_path, result_file_path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                logger.warning("No se pudo eliminar el archivo temporal: %s", path)
