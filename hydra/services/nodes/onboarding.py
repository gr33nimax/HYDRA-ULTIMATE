"""Install, or continue, one managed node: SSH provisioning plus first publication.

Two entry points share one path. ``add`` installs a node that does not exist yet;
``resume`` continues one whose install already happened but whose control identity or
first publication did not complete. The difference is exactly one step — whether
``bootstrap.install`` runs — because a resumed node must never be reinstalled: the VPS
already carries HYDRA, and a second install would either refuse or replace a working
installation.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from hydra.contracts.node_validation import (
    checked_node_branch,
    checked_node_revision,
)
from hydra.core.state_models import AppState
from hydra.core.state_nodes import NodeConfig
from hydra.services.nodes.credentials import NodeControlCredentials
from hydra.services.nodes.reconciler import NodeSyncResult
from hydra.services.nodes.ssh_auth import SshPasswordAuth

_LOGGER = logging.getLogger(__name__)


class NodeProvisioningPort(Protocol):
    """The SSH side of node onboarding, injected so no host call lives here."""

    def resolve_revision(self, branch: str) -> str: ...

    def install(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        branch: str,
        revision: str,
        confirm_fingerprint: Callable[[str], bool],
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> str: ...

    def provision_control_identity(
        self,
        *,
        node_id: str,
        address: str,
        ssh_port: int,
        base_url: str,
        control_port: int,
        ssh_user: str = "root",
        auth: SshPasswordAuth | None = None,
    ) -> NodeControlCredentials: ...


@dataclass
class NodeOnboarding:
    """Bring one node from "not managed" to "published"."""

    # Real stages, reported as they happen: the UI prints what actually ran instead of
    # an animation that pretends to know how far the install got.

    state_reader: Callable[[], AppState]
    state_updater: Callable
    bootstrap: NodeProvisioningPort | None
    refresh: Callable[..., NodeSyncResult]
    # Needed to undo an install whose registration failed; a resumed node has no install
    # to undo, so these stay optional and are required only where they are used.
    uninstall_remote: Callable[[NodeConfig], None] | None = None
    forget_node_credentials: Callable[[str], None] | None = None
    import_remote_cookies: Callable[[NodeConfig, str], None] | None = None

    def add(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
        auth: SshPasswordAuth | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> NodeSyncResult:
        candidate = self._checked_new_node(node, base_url=base_url, confirm_fingerprint=confirm_fingerprint)
        self._checked_cookies(vk_cookie_source)
        bootstrap, uninstall_remote, forget_credentials = self._provisioning()
        branch = checked_node_branch(candidate.branch, context="branch")
        revision = checked_node_revision(candidate.revision, context="revision")

        _report(progress, "ssh")
        bootstrap.install(
            node_id=candidate.id,
            address=candidate.address,
            ssh_port=candidate.ssh_port,
            branch=branch,
            revision=revision,
            confirm_fingerprint=confirm_fingerprint,
            ssh_user=candidate.ssh_user,
            auth=auth,
        )
        _report(progress, "install")
        try:
            self._provision(candidate, base_url=base_url, auth=auth)
        except Exception as exc:
            raise RuntimeError(
                "node was installed but control identity provisioning failed; "
                "the same node ID can be connected without reinstalling",
            ) from exc
        _report(progress, "identity")
        return self._register_and_publish(
            candidate,
            vk_cookie_source=vk_cookie_source,
            installed=True,
            progress=progress,
        )

    def resume(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
        vk_cookie_source: str | None = None,
        auth: SshPasswordAuth | None = None,
        progress: Callable[[str], None] | None = None,
    ) -> NodeSyncResult:
        """Continue a node whose install happened but whose identity never arrived.

        The install step is deliberately skipped: the operator is recovering the same
        node, not creating one. Provisioning still verifies the pinned SSH host key, so
        resuming cannot silently adopt a different machine.
        """
        candidate = self._checked_new_node(node, base_url=base_url, confirm_fingerprint=confirm_fingerprint)
        self._checked_cookies(vk_cookie_source)
        if self.bootstrap is None:
            raise RuntimeError("node provisioning is unavailable")
        _report(progress, "ssh")
        try:
            self._provision(candidate, base_url=base_url, auth=auth)
        except Exception as exc:
            raise RuntimeError(
                "control identity provisioning failed; the node must already be installed "
                "and reachable over the pinned SSH host key",
            ) from exc
        _report(progress, "identity")
        return self._register_and_publish(
            candidate,
            vk_cookie_source=vk_cookie_source,
            installed=False,
            progress=progress,
        )

    def _checked_new_node(
        self,
        node: NodeConfig,
        *,
        base_url: str,
        confirm_fingerprint: Callable[[str], bool],
    ) -> NodeConfig:
        candidate = NodeConfig(**vars(node))
        candidate.validate(path=f"nodes.{candidate.id}")
        if candidate.control_fingerprint or candidate.generation or candidate.published_generation:
            raise ValueError("new node must not contain control credentials or runtime generations")
        if candidate.desired_digest or candidate.published_digest:
            raise ValueError("new node must not contain published snapshot digests")
        if not isinstance(base_url, str) or not base_url.strip() or not callable(confirm_fingerprint):
            raise ValueError("base_url and SSH fingerprint confirmation are required")
        if any(item.id == candidate.id for item in self.state_reader().nodes):
            raise ValueError(f"managed node {candidate.id} already exists")
        return candidate

    @staticmethod
    def _checked_cookies(vk_cookie_source: str | None) -> None:
        if vk_cookie_source is None:
            return
        from hydra.services.nodes.cookies import load_cookie_file

        load_cookie_file(vk_cookie_source)

    def _provisioning(self) -> tuple[NodeProvisioningPort, Callable[[NodeConfig], None], Callable[[str], None]]:
        """The install side of onboarding, required only where an install is undone."""
        if self.bootstrap is None or self.uninstall_remote is None or self.forget_node_credentials is None:
            raise RuntimeError("node provisioning is unavailable")
        return self.bootstrap, self.uninstall_remote, self.forget_node_credentials

    def _provision(
        self,
        candidate: NodeConfig,
        *,
        base_url: str,
        auth: SshPasswordAuth | None = None,
    ) -> None:
        if self.bootstrap is None:
            raise RuntimeError("node provisioning is unavailable")
        credentials = self.bootstrap.provision_control_identity(
            node_id=candidate.id,
            address=candidate.address,
            ssh_port=candidate.ssh_port,
            base_url=base_url,
            control_port=candidate.control_port,
            ssh_user=candidate.ssh_user,
            auth=auth,
        )
        candidate.control_fingerprint = credentials.node_fingerprint
        candidate.validate(path=f"nodes.{candidate.id}")

    def _register_and_publish(
        self,
        candidate: NodeConfig,
        *,
        vk_cookie_source: str | None,
        installed: bool,
        progress: Callable[[str], None] | None = None,
    ) -> NodeSyncResult:
        def register(state: AppState) -> None:
            if any(item.id == candidate.id for item in state.nodes):
                raise ValueError(f"managed node {candidate.id} already exists")
            state.nodes.append(NodeConfig(**vars(candidate)))

        try:
            self.state_updater(register)
        except Exception as exc:
            if installed and self.uninstall_remote is not None and self.forget_node_credentials is not None:
                try:
                    self.uninstall_remote(candidate)
                    self.forget_node_credentials(candidate.id)
                except Exception:
                    raise RuntimeError("node registration failed and remote cleanup did not complete") from exc
            raise
        _report(progress, "register")
        try:
            if vk_cookie_source is not None:
                if self.import_remote_cookies is None:
                    raise RuntimeError("node cookie import is unavailable")
                self.import_remote_cookies(candidate, vk_cookie_source)
            _report(progress, "publish")
            return self.refresh(candidate.id)
        except Exception as exc:
            raise RuntimeError("node was provisioned but its initial snapshot was not published") from exc


def _report(progress: Callable[[str], None] | None, stage: str) -> None:
    """Report one real boundary; a missing reporter is not an error."""
    if progress is None:
        return
    try:
        progress(stage)
    except Exception:
        _LOGGER.warning("node progress reporter failed at %s", stage)


__all__ = ["NodeOnboarding", "NodeProvisioningPort"]
