"""Bounded operation errors and readable OpenSSH connection diagnostics."""

from hydra.utils.commands import bounded_reason, redact_text


def safe_reason(reason: str) -> str:
    text = redact_text(str(reason))
    return "".join(char for char in text if char.isprintable())[:256]


def ssh_failure_reason(result: object) -> str:
    stderr = getattr(result, "stderr", "") or ""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    lowered = str(stderr).lower()
    if "remote host identification has changed" in lowered:
        return "SSH host key изменился. Проверьте сервер; удаление по SSH остановлено."
    if "host key verification failed" in lowered:
        return "Не удалось проверить закреплённый SSH host key. Проверьте сервер и сохранённый ключ."
    if "permission denied" in lowered:
        return "SSH отклонил авторизацию. Проверьте пользователя, пароль или SSH-ключ."
    if "connection timed out" in lowered or "no route to host" in lowered:
        return "Сервер недоступен по SSH. Проверьте адрес, порт и доступность сервера."
    if "connection refused" in lowered:
        return "Сервер отклонил SSH-соединение. Проверьте SSH-порт и службу SSH."
    return bounded_reason(result) or "SSH operation failed"
