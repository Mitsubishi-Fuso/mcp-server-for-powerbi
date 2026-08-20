"""Mode selection refuses to guess."""

import pytest

from mcp_for_powerbi.auth_mode import CUSTODY, OBO, SUPPORTED_MODES, AuthModeError, resolve_auth_mode


@pytest.mark.parametrize(
    ("configured", "has_credentials", "expected"),
    [
        (None, True, OBO),
        ("", True, OBO),
        ("obo", True, OBO),
        ("  OBO  ", True, OBO),
        ("custody", True, CUSTODY),
        ("  CUSTODY  ", True, CUSTODY),
    ],
)
def test_resolves(configured, has_credentials, expected):
    assert resolve_auth_mode(configured, has_credentials=has_credentials) == expected


def test_unset_without_credentials_is_refused():
    """The old silent fallback to passthrough lived here."""
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode(None, has_credentials=False)
    assert "AUTH_MODE is not set" in str(exc.value)
    for mode in SUPPORTED_MODES:
        assert mode in str(exc.value)


@pytest.mark.parametrize("mode", [OBO, CUSTODY])
def test_a_mode_needing_credentials_is_refused_without_them(mode):
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode(mode, has_credentials=False)
    assert "ENTRA_CLIENT_ID" in str(exc.value)


@pytest.mark.parametrize("configured", ["passthrough", "bogus", "on-behalf-of", "none", "proxy"])
def test_unknown_mode_is_refused(configured):
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode(configured, has_credentials=True)
    assert "not a supported mode" in str(exc.value)


def test_passthrough_is_gone():
    """It is not merely undocumented; asking for it by name fails."""
    with pytest.raises(AuthModeError):
        resolve_auth_mode("passthrough", has_credentials=True)


def test_every_reachable_mode_uses_this_servers_own_registration():
    """Neither remaining mode accepts a token Entra issued for something else."""
    assert set(SUPPORTED_MODES) == {OBO, CUSTODY}
