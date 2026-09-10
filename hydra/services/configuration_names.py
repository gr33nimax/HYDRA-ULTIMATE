"""Application-facing operations for persisted client configuration names."""
from __future__ import annotations

from hydra.core.configuration_names import (
    normalize_configuration_name,
    resolve_configuration_name,
    validate_configuration_key,
)
from hydra.core.state_models import AppState, User, find_user


class ConfigurationNameService:
    """Resolve and mutate names using stable technical profile/variant keys."""

    def resolve(self, state: AppState, user: User, key: str, default: str) -> str:
        return resolve_configuration_name(
            key=key,
            default=default,
            global_names=state.configuration_names,
            user_names=user.configuration_name_overrides,
        )

    def set_global(self, state: AppState, key: str, value: str) -> None:
        self._set(state.configuration_names, key, value)

    def set_user(self, state: AppState, email: str, key: str, value: str) -> User:
        user = find_user(state, email)
        if user is None:
            raise ValueError(f"user not found: {email}")
        self._set(user.configuration_name_overrides, key, value)
        return user

    @staticmethod
    def _set(names: dict[str, str], key: str, value: str) -> None:
        key = validate_configuration_key(key)
        name = normalize_configuration_name(value)
        if name:
            names[key] = name
        else:
            names.pop(key, None)
