"""Shared fixtures.

server_http reads its configuration at import time and exits the process if it
is unusable, so every test needs the minimum environment in place before the
module is imported, and anything that varies the configuration has to reload it.
"""

import importlib
import sys

import pytest

TENANT_ID = "00000000-0000-0000-0000-000000000000"
AUDIENCE = "api://test"


@pytest.fixture(autouse=True)
def base_env(monkeypatch):
    """The configuration every mode needs, and no mode-specific settings."""
    monkeypatch.setenv("TENANT_ID", TENANT_ID)
    monkeypatch.setenv("AUDIENCE", AUDIENCE)
    for name in (
        "AUTH_MODE",
        "ENTRA_CLIENT_ID",
        "ENTRA_CLIENT_SECRET",
        "OBO_CLIENT_ID",
        "OBO_CLIENT_SECRET",
        "CLIENT_ID",
        "CLIENT_SECRET",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def load_server_http(monkeypatch):
    """Import server_http fresh under a given environment.

    The module is dropped from sys.modules rather than reloaded, so each call
    re-runs its configuration block against exactly the environment asked for,
    and a mode that refuses to start raises here rather than leaking into the
    next test.
    """
    module_name = "mcp_for_powerbi.server_http"

    def load(**env):
        for key, value in env.items():
            if value is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, value)
        sys.modules.pop(module_name, None)
        return importlib.import_module(module_name)

    yield load

    sys.modules.pop(module_name, None)
