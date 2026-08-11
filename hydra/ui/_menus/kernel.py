"""Provider-aware Sing-Box kernel menu actions."""
from __future__ import annotations

from typing import Callable, Protocol

from hydra.core.state_models import AppState
from hydra.services.application import ApplicationService


class KernelMenuDependencies(Protocol):
    def info(self, message: str) -> None: ...

    def success(self, message: str) -> None: ...

    def warn(self, message: str) -> None: ...

    def prompt(self, message: str) -> str: ...

    def error(self, message: str) -> None: ...

    def apply_error_text(
        self,
        message: str,
        app: ApplicationService,
    ) -> str: ...


def handle_kernel_choice(
    choice: str,
    state: AppState,
    app: ApplicationService,
    deps: KernelMenuDependencies,
    *,
    installed: bool,
    update_available: bool,
    confirm_action: Callable[..., bool],
) -> bool:
    """Handle provider install/update/switch choices and report consumption."""
    if choice == "1":
        deps.info(f"Устанавливаю {state.kernel.provider}...")
        try:
            result = app.kernel.switch(
                state,
                state.kernel.provider,
                channel=state.kernel.channel,
                force=installed,
            )
        except Exception as exc:
            deps.error(str(exc) or exc.__class__.__name__)
            deps.prompt("Нажмите Enter")
            return True
        if result.ok:
            deps.success(
                f"Sing-Box {app.admin.singbox_diagnostics().version} установлен",
            )
            if app.apply(state):
                deps.success("Конфигурация пересобрана и применена")
            else:
                deps.warn(
                    deps.apply_error_text(
                        "Не удалось автоматически применить конфигурацию",
                        app,
                    ),
                )
        else:
            deps.error("Не удалось установить")
        deps.prompt("Нажмите Enter")
        return True

    if choice == "6" and installed and update_available:
        deps.info("Устанавливаю обновление Sing-Box...")
        try:
            result = app.kernel.switch(
                state,
                state.kernel.provider,
                channel=state.kernel.channel,
                force=True,
            )
        except Exception as exc:
            deps.error(str(exc) or exc.__class__.__name__)
            deps.prompt("Нажмите Enter")
            return True
        if result.ok:
            deps.success(result.message)
            if app.apply(state):
                deps.success("Конфигурация пересобрана и применена")
            else:
                deps.warn(
                    deps.apply_error_text(
                        "Не удалось автоматически применить конфигурацию",
                        app,
                    ),
                )
        else:
            deps.error(result.message)
        deps.prompt("Нажмите Enter")
        return True

    if choice == "7":
        provider = (
            "hydracore"
            if state.kernel.provider == "sing-box-extended"
            else "sing-box-extended"
        )
        if not confirm_action(
            f"Переключить рабочее ядро на {provider}?",
            default=False,
        ):
            return True
        deps.info(f"Проверяю и устанавливаю {provider}...")
        try:
            result = app.kernel.switch(state, provider, channel="stable")
        except Exception as exc:
            deps.error(str(exc) or exc.__class__.__name__)
            deps.prompt("Нажмите Enter")
            return True
        if result.ok:
            deps.success(result.message)
        else:
            deps.error(result.message or "Не удалось переключить ядро")
        deps.prompt("Нажмите Enter")
        return True

    if choice == "8" and state.kernel.provider == "hydracore":
        channel = "stable" if state.kernel.channel == "debug" else "debug"
        if not confirm_action(
            f"Переключить Hydracore на канал {channel}?",
            default=False,
        ):
            return True
        deps.info(f"Проверяю и устанавливаю Hydracore {channel}...")
        try:
            result = app.kernel.switch(
                state,
                "hydracore",
                channel=channel,
                force=True,
            )
        except Exception as exc:
            deps.error(str(exc) or exc.__class__.__name__)
            deps.prompt("Нажмите Enter")
            return True
        if result.ok:
            deps.success(result.message)
            if app.apply(state):
                deps.success("Конфигурация пересобрана и применена")
            else:
                deps.warn(
                    deps.apply_error_text(
                        "Не удалось автоматически применить конфигурацию",
                        app,
                    ),
                )
        else:
            deps.error(result.message or "Не удалось переключить канал Hydracore")
        deps.prompt("Нажмите Enter")
        return True

    return False


__all__ = ["KernelMenuDependencies", "handle_kernel_choice"]
