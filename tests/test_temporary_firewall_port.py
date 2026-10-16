"""Temporary ACME access must close even when opening failed after a partial effect."""
from unittest.mock import MagicMock

import pytest

from hydra.utils import firewall


@pytest.mark.parametrize("proto", ["tcp", "udp"])
@pytest.mark.parametrize("failure", ["opening", "body", "none"])
def test_temporary_port_is_closed_on_every_error_path(monkeypatch, proto, failure):
    monkeypatch.setattr(firewall, "port_is_open", lambda *_args: False)
    opened = MagicMock(side_effect=OSError("partial open") if failure == "opening" else None)
    closed = MagicMock()
    monkeypatch.setattr(firewall, f"open_{proto}", opened)
    monkeypatch.setattr(firewall, f"close_{proto}", closed)

    def operation():
        with firewall.temporary_open_port(proto, 80, "temp-certbot"):
            if failure == "body":
                raise OSError("ACME failed")

    if failure == "none":
        operation()
    else:
        with pytest.raises(OSError):
            operation()
    opened.assert_called_once_with(80, "temp-certbot")
    closed.assert_called_once_with(80, "temp-certbot")


def test_existing_port_is_never_removed(monkeypatch):
    monkeypatch.setattr(firewall, "port_is_open", lambda *_args: True)
    opened, closed = MagicMock(), MagicMock()
    monkeypatch.setattr(firewall, "open_tcp", opened)
    monkeypatch.setattr(firewall, "close_tcp", closed)
    with firewall.temporary_open_port("tcp", 80, "temp-certbot"):
        pass
    opened.assert_not_called()
    closed.assert_not_called()
