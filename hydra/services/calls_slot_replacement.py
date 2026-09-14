"""Transactional one-room replacement for the managed VK creator pool."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.services.headless_creator_infrastructure import extract_vk_join_link
from hydra.services.headless_creator_release import extract_call_hash


@dataclass
class CallsSlotReplacement:
    source: Any
    slot: int
    previous_metadata: dict[str, object]
    previous_generation: str
    target_generation: str
    links: list[str]
    target_file: Path

    def finalize(self) -> None:
        unit = self._unit(self.previous_generation)
        for action in ("stop", "disable"):
            if self.source.host.run(["systemctl", action, unit]).returncode:
                raise RuntimeError(f"failed to {action} replaced VK creator unit")
        self.source.host.remove_file(self._file(self.previous_generation), missing_ok=True)

    def rollback(self) -> None:
        previous_unit = self._unit(self.previous_generation)
        self.source.host.run(["systemctl", "enable", previous_unit])
        self.source.host.run(["systemctl", "start", previous_unit])
        self.source.host.atomic_write(
            self.source.pool_state_file,
            json.dumps(self.previous_metadata, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        for action in ("stop", "disable"):
            self.source.host.run(["systemctl", action, self._unit(self.target_generation)])
        self.source.host.remove_file(self.target_file, missing_ok=True)

    def _unit(self, generation: str) -> str:
        return f"{self.source.managed_unit_prefix}@{generation}-{self.slot}.service"

    def _file(self, generation: str) -> Path:
        return self.source.pool_dir / f"{generation}-{self.slot}.call.txt"


def stage_calls_slot_replacement(source: Any, slot: int) -> CallsSlotReplacement:
    metadata = source.pool_metadata()
    hashes = metadata.get("hashes")
    if not isinstance(hashes, list) or len(hashes) != 4 or not 1 <= slot <= 4:
        raise ValueError("VK Calls pool cannot replace an invalid room slot")
    slots = _slots(metadata)
    links = _links(source, slots)
    previous_generation = str(slots[slot - 1]["generation"])
    target_generation = "b" if previous_generation == "a" else "a"
    target_file = source.pool_dir / f"{target_generation}-{slot}.call.txt"
    unit = f"{source.managed_unit_prefix}@{target_generation}-{slot}.service"
    source.validate_credentials()
    source.host.ensure_directory(source.pool_dir, mode=0o700)
    source._write_creator_unit()
    if source.host.run(["systemctl", "daemon-reload"]).returncode:
        raise RuntimeError("systemd daemon-reload failed")
    for action in ("stop", "disable"):
        source.host.run(["systemctl", action, unit])
    source.host.remove_file(target_file, missing_ok=True)
    try:
        if source.host.run(["systemctl", "enable", unit]).returncode:
            raise RuntimeError("failed to enable replacement VK creator unit")
        if source.host.run(["systemctl", "restart", unit]).returncode:
            raise RuntimeError("failed to start replacement VK creator unit")
        replacement = _wait_for_link(target_file)
        if replacement in {link for index, link in enumerate(links, start=1) if index != slot}:
            raise RuntimeError("replacement VK room duplicates a retained room")
        links[slot - 1] = replacement
        updated_slots = [dict(entry) for entry in slots]
        updated_slots[slot - 1]["generation"] = target_generation
        payload = dict(metadata)
        payload.update(
            {
                "hashes": [extract_call_hash(link) for link in links],
                "room_count": 4,
                "slots": updated_slots,
            }
        )
        source.host.atomic_write(
            source.pool_state_file,
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            mode=0o600,
        )
        return CallsSlotReplacement(source, slot, metadata, previous_generation, target_generation, links, target_file)
    except (OSError, RuntimeError, TimeoutError, ValueError):
        for action in ("stop", "disable"):
            source.host.run(["systemctl", action, unit])
        source.host.remove_file(target_file, missing_ok=True)
        raise


def _slots(metadata: dict[str, object]) -> list[dict[str, object]]:
    raw = metadata.get("slots")
    if isinstance(raw, list) and len(raw) == 4:
        slots = [entry for entry in raw if isinstance(entry, dict)]
        if len(slots) == 4 and all(entry.get("generation") in {"a", "b"} for entry in slots):
            return [{"generation": entry["generation"], "index": index} for index, entry in enumerate(slots, start=1)]
    generation = str(metadata.get("generation", ""))
    if generation not in {"a", "b"}:
        raise ValueError("VK Calls pool has no active creator generation")
    return [{"generation": generation, "index": index} for index in range(1, 5)]


def _links(source: Any, slots: list[dict[str, object]]) -> list[str]:
    links: list[str] = []
    for entry in slots:
        path = source.pool_dir / f"{entry['generation']}-{entry['index']}.call.txt"
        try:
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            links.append(extract_vk_join_link(lines[-1]))
        except (OSError, IndexError, ValueError) as exc:
            raise RuntimeError("VK Calls pool contains an invalid retained room") from exc
    if len(set(links)) != 4:
        raise RuntimeError("VK Calls pool contains duplicate retained rooms")
    return links


def _wait_for_link(path: Path) -> str:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            return extract_vk_join_link(lines[-1])
        except (OSError, IndexError, ValueError):
            time.sleep(1)
    raise TimeoutError("replacement VK creator did not return a valid room")
