import json
from subprocess import CompletedProcess

from hydra.core.host import HostBackend
from hydra.services.calls_slot_replacement import stage_calls_slot_replacement
from hydra.services.headless_creator_release import extract_call_hash


class Host(HostBackend):
    def __init__(self, pool):
        super().__init__()
        self.pool = pool
        self.commands = []

    def run(self, args, **kwargs):
        command = [str(value) for value in args]
        self.commands.append(command)
        if command[:2] == ["systemctl", "restart"]:
            instance = command[-1].split("@", 1)[1].removesuffix(".service")
            (self.pool / f"{instance}.call.txt").write_text(
                f"https://vk.com/call/join/replacement-{instance}\n",
                encoding="utf-8",
            )
        return CompletedProcess(command, 0)


class Source:
    managed_unit_prefix = "hydra-headless-creator-vk-calls"

    def __init__(self, pool):
        self.pool_dir = pool
        self.pool_state_file = pool / "state.json"
        self.host = Host(pool)

    def pool_metadata(self):
        return json.loads(self.pool_state_file.read_text(encoding="utf-8"))

    def validate_credentials(self):
        return None

    def _write_creator_unit(self):
        return None


def _source(tmp_path):
    links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    for index, link in enumerate(links, start=1):
        (tmp_path / f"a-{index}.call.txt").write_text(link + "\n", encoding="utf-8")
    source = Source(tmp_path)
    source.pool_state_file.write_text(
        json.dumps(
            {
                "generation": "a",
                "room_count": 4,
                "refreshed_at": "2026-01-01T00:00:00+00:00",
                "hashes": [extract_call_hash(link) for link in links],
            }
        ),
        encoding="utf-8",
    )
    return source, links


def test_slot_stage_switches_only_one_unit_and_finalizes_after_apply(tmp_path) -> None:
    source, old_links = _source(tmp_path)

    stage = stage_calls_slot_replacement(source, 2)

    assert stage.links == [old_links[0], "https://vk.com/call/join/replacement-b-2", old_links[2], old_links[3]]
    assert (tmp_path / "a-2.call.txt").exists()
    assert source.pool_metadata()["slots"][1] == {"generation": "b", "index": 2}
    stage.finalize()

    assert not (tmp_path / "a-2.call.txt").exists()
    assert (tmp_path / "a-1.call.txt").exists()
    assert (tmp_path / "a-3.call.txt").exists()


def test_slot_stage_rollback_restores_metadata_and_keeps_prior_unit(tmp_path) -> None:
    source, _old_links = _source(tmp_path)
    original = source.pool_metadata()

    stage = stage_calls_slot_replacement(source, 3)
    stage.rollback()

    assert source.pool_metadata() == original
    assert (tmp_path / "a-3.call.txt").exists()
    assert not (tmp_path / "b-3.call.txt").exists()
