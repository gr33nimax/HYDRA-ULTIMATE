"""Queue the transactional updater outside the API service's unit group."""

from __future__ import annotations

from dataclasses import dataclass

from hydra.contracts.node_validation import (
    NODE_CONTRACT_VERSION,
    checked_node_branch,
    checked_node_revision,
)
from hydra.core.host import HostBackend


@dataclass(frozen=True)
class NodeUpgradeScheduler:
    host: HostBackend

    def schedule(self, branch: str, revision: str) -> dict[str, object]:
        branch = checked_node_branch(branch, context="branch")
        revision = checked_node_revision(revision, context="revision")
        unit = f"node-upgrade-{revision}"
        for suffix in (".timer", ".service"):
            active = self.host.run(
                ["systemctl", "is-active", "--quiet", f"{unit}{suffix}"],
                timeout=2,
            )
            if active.returncode == 0:
                return {
                    "status": "scheduled",
                    "branch": branch,
                    "revision": revision,
                    "already_scheduled": True,
                }

        # Keep the worker outside hydra-*; upgrade.sh stops that group itself.
        result = self.host.run(
            [
                "systemd-run",
                "--quiet",
                "--collect",
                "--no-block",
                "--on-active=5s",
                f"--unit={unit}",
                "--property=Type=oneshot",
                "--property=WorkingDirectory=/opt/hydra",
                "--property=TimeoutStartSec=infinity",
                f"--property=Environment=HYDRA_REF={branch}",
                f"--property=Environment=HYDRA_TARGET_REV={revision}",
                f"--property=Environment=HYDRA_EXPECT_NODE_CONTRACT_VERSION={NODE_CONTRACT_VERSION}",
                "/bin/bash",
                "/opt/hydra/updater.sh",
            ],
            timeout=5,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError("could not schedule node upgrade")
        return {"status": "scheduled", "branch": branch, "revision": revision}


__all__ = ["NodeUpgradeScheduler"]
