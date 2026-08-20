"""Mode selection refuses to guess."""

import pytest

from mcp_for_powerbi.auth_mode import OBO, PASSTHROUGH, SUPPORTED_MODES, AuthModeError, resolve_auth_mode


@pytest.mark.parametrize(
    ("configured", "has_credentials", "expected"),
    [
        (None, True, OBO),
        ("", True, OBO),
        ("obo", True, OBO),
        ("  OBO  ", True, OBO),
        ("passthrough", False, PASSTHROUGH),
        ("passthrough", True, PASSTHROUGH),
        ("PassThrough", False, PASSTHROUGH),
    ],
)
def test_resolves(configured, has_credentials, expected):
    assert resolve_auth_mode(configured, has_credentials=has_credentials) == expected


def test_unset_without_credentials_is_refused():
    """The old silent fallback to passthrough lived here; it has to be named now."""
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode(None, has_credentials=False)
    assert "AUTH_MODE is not set" in str(exc.value)
    for mode in SUPPORTED_MODES:
        assert mode in str(exc.value)


def test_obo_without_credentials_is_refused():
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode("obo", has_credentials=False)
    assert "ENTRA_CLIENT_ID" in str(exc.value)


@pytest.mark.parametrize("configured", ["custody", "bogus", "on-behalf-of", "none"])
def test_unknown_mode_is_refused(configured):
    with pytest.raises(AuthModeError) as exc:
        resolve_auth_mode(configured, has_credentials=True)
    assert "not a supported mode" in str(exc.value)


def test_passthrough_is_never_reached_by_accident():
    """Only an explicit request selects it; no combination of credentials does."""
    for has_credentials in (True, False):
        for configured in (None, ""):
            try:
                assert resolve_auth_mode(configured, has_credentials=has_credentials) != PASSTHROUGH
            except AuthModeError:
                pass
