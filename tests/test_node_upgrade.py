from subprocess import CompletedProcess

import pytest

from hydra.contracts.node_validation import NODE_CONTRACT_VERSION


class _Host:
    def __init__(self, active_units=()):
        self.active_units = set(active_units)
        self.calls = []

    def run(self, args, **kwargs):
        self.calls.append((list(args), kwargs))
        if args[0] == "systemctl":
            active = args[-1] in self.active_units
            return CompletedProcess(args, 0 if active else 3, stdout="active" if active else "inactive", stderr="")
        return CompletedProcess(args, 0, stdout="", stderr="")


def _scheduler_type():
    from hydra.services.nodes.upgrade import NodeUpgradeScheduler

    return NodeUpgradeScheduler


def test_upgrade_schedules_delayed_exact_revision_outside_hydra_units():
    revision = "a" * 40
    host = _Host()
    scheduler = _scheduler_type()(host=host)

    result = scheduler.schedule(branch="feature/node", revision=revision)

    commands = [args for args, _ in host.calls]
    scheduled = next(args for args in commands if args[0] == "systemd-run")
    assert result == {"status": "scheduled", "branch": "feature/node", "revision": revision}
    assert "--no-block" in scheduled
    assert "--collect" in scheduled
    assert "--on-active=5s" in scheduled
    assert f"--unit=node-upgrade-{revision}" in scheduled
    assert f"--property=Environment=HYDRA_REF=feature/node" in scheduled
    assert f"--property=Environment=HYDRA_TARGET_REV={revision}" in scheduled
    assert (
        "--property=Environment=HYDRA_EXPECT_NODE_CONTRACT_VERSION="
        f"{NODE_CONTRACT_VERSION}"
    ) in scheduled
    assert "--property=TimeoutStartSec=infinity" in scheduled
    assert scheduled[-2:] == ["/bin/bash", "/opt/hydra/updater.sh"]
    assert not any("hydra-node-upgrade" in arg for arg in scheduled)


def test_repeated_upgrade_request_does_not_schedule_an_active_job_again():
    revision = "b" * 40
    unit = f"node-upgrade-{revision}.timer"
    host = _Host(active_units={unit})
    scheduler = _scheduler_type()(host=host)

    result = scheduler.schedule(branch="main", revision=revision)

    assert result["status"] == "scheduled"
    assert result["already_scheduled"] is True
    assert not any(args[0] == "systemd-run" for args, _ in host.calls)


@pytest.mark.parametrize(
    ("branch", "revision"),
    [
        ("main; touch /tmp/pwned", "a" * 40),
        ("main", "not-a-commit"),
        ("../main", "a" * 40),
    ],
)
def test_invalid_upgrade_target_is_rejected_before_host_calls(branch, revision):
    host = _Host()
    scheduler = _scheduler_type()(host=host)

    with pytest.raises(ValueError):
        scheduler.schedule(branch=branch, revision=revision)

    assert host.calls == []
