import socket

import pytest


@pytest.fixture(scope="session")
def example_domain() -> str:
    return "example.com"


@pytest.fixture(autouse=True)
def block_network(monkeypatch) -> None:
    # Disable external networking by patching socket connect
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: None)
