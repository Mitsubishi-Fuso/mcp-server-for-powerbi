"""Selection of the scheme by which the server obtains a Power BI token.

Both supported modes obtain a token addressed to this server's own client
registration. Neither accepts a token that Entra issued for something else,
which the MCP authorization spec prohibits and which this server used to do
whenever client credentials happened to be absent.

A deployment names the scheme it wants. Anything unrecognised, or a mode whose
prerequisites are missing, stops the server rather than quietly selecting
something else.
"""

OBO = "obo"
CUSTODY = "custody"

SUPPORTED_MODES = (OBO, CUSTODY)


class AuthModeError(RuntimeError):
    """The requested authentication mode cannot be honoured."""


class ReauthenticationRequired(Exception):
    """Only a fresh interactive sign-in can fix this.

    Each mode has its own version - a conditional access claims challenge under
    OBO, a refused refresh token under custody - but they need the same
    handling, and the tools must not see either as an ordinary failure they
    could report and move on from.
    """


def resolve_auth_mode(configured: str | None, *, has_credentials: bool) -> str:
    """Return the mode to run in, or raise if the configuration is unusable."""
    requested = (configured or "").strip().lower()

    if not requested:
        # Deployments already carrying credentials were running OBO, and keep
        # doing so without being asked to change anything.
        if has_credentials:
            return OBO
        raise AuthModeError(
            "AUTH_MODE is not set and no Entra client credentials are configured. "
            f"Set AUTH_MODE to one of: {', '.join(SUPPORTED_MODES)}."
        )

    if requested not in SUPPORTED_MODES:
        raise AuthModeError(
            f"AUTH_MODE={requested!r} is not a supported mode. Choose one of: {', '.join(SUPPORTED_MODES)}."
        )

    if requested in (OBO, CUSTODY) and not has_credentials:
        raise AuthModeError(
            f"AUTH_MODE={requested} requires ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET "
            "(or the deprecated OBO_CLIENT_ID / OBO_CLIENT_SECRET)."
        )

    return requested
