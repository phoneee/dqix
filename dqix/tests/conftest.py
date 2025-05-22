import pytest
import socket


@pytest.fixture(scope="session")
def example_domain():
    return "example.com"


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    # Disable external networking by patching socket connect
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: None)
