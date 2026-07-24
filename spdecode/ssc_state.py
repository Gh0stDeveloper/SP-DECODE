from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Any


@dataclass(slots=True)
class SSCTextSession:
    fragments: dict[int, str] = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)
    updated_at: float = field(default_factory=time.monotonic)
    first_message_id: int | None = None

    @property
    def payload(self) -> str:
        """Reconstruye el texto en orden de message_id para tolerar handlers concurrentes."""
        return "".join(self.fragments[key] for key in sorted(self.fragments))

    @property
    def parts(self) -> int:
        return len(self.fragments)

    @property
    def char_count(self) -> int:
        return sum(len(fragment) for fragment in self.fragments.values())


_lock = RLock()
_sessions: dict[tuple[int, int], SSCTextSession] = {}


def session_key(message: Any) -> tuple[int, int] | None:
    chat_id = getattr(getattr(message, "chat", None), "id", None)
    user_id = getattr(getattr(message, "from_user", None), "id", None)
    if chat_id is None or user_id is None:
        return None
    try:
        return int(chat_id), int(user_id)
    except (TypeError, ValueError):
        return None


def _message_id(message: Any) -> int:
    raw = getattr(message, "message_id", None)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(time.time_ns())


def _is_expired(session: SSCTextSession, timeout_seconds: int, now: float | None = None) -> bool:
    current = time.monotonic() if now is None else now
    return current - session.updated_at > timeout_seconds


def cleanup_expired(timeout_seconds: int) -> int:
    now = time.monotonic()
    removed = 0
    with _lock:
        expired = [
            key for key, session in _sessions.items()
            if _is_expired(session, timeout_seconds, now)
        ]
        for key in expired:
            _sessions.pop(key, None)
            removed += 1
    return removed


def get_session(message: Any, timeout_seconds: int) -> SSCTextSession | None:
    key = session_key(message)
    if key is None:
        return None
    now = time.monotonic()
    with _lock:
        session = _sessions.get(key)
        if session is not None and _is_expired(session, timeout_seconds, now):
            _sessions.pop(key, None)
            return None
        return session


def start_session(message: Any, fragment: str) -> SSCTextSession | None:
    key = session_key(message)
    if key is None:
        return None
    now = time.monotonic()
    message_id = _message_id(message)
    session = SSCTextSession(
        fragments={message_id: fragment},
        created_at=now,
        updated_at=now,
        first_message_id=message_id,
    )
    with _lock:
        _sessions[key] = session
    return session


def append_to_session(message: Any, fragment: str, timeout_seconds: int) -> SSCTextSession | None:
    key = session_key(message)
    if key is None:
        return None
    now = time.monotonic()
    with _lock:
        session = _sessions.get(key)
        if session is None:
            return None
        if _is_expired(session, timeout_seconds, now):
            _sessions.pop(key, None)
            return None
        session.fragments[_message_id(message)] = fragment
        session.updated_at = now
        return session


def clear_session(message: Any) -> bool:
    key = session_key(message)
    if key is None:
        return False
    with _lock:
        return _sessions.pop(key, None) is not None


def has_session(message: Any, timeout_seconds: int) -> bool:
    return get_session(message, timeout_seconds) is not None
