"""Selection of the scheme by which the server obtains a Power BI token.

The server used to decide this implicitly: run the On-Behalf-Of exchange when
client credentials happened to be present, and otherwise reuse the caller's own
bearer token for Power BI. That second path is token passthrough - the server
accepting a token that was issued for a different resource - which the MCP
authorization spec prohibits, and nothing in the configuration made it evident
that a deployment had ended up there.

A deployment now names the scheme it wants. Anything unrecognised, or a mode
whose prerequisites are missing, stops the server rather than quietly selecting
something else.
"""

OBO = "obo"
PASSTHROUGH = "passthrough"

SUPPORTED_MODES = (OBO, PASSTHROUGH)

PASSTHROUGH_WARNING = (
    "AUTH_MODE=passthrough sends the caller's own access token on to Power BI. The MCP "
    "authorization spec prohibits accepting a token that was not issued for this server, "
    "so this mode is deprecated and will be removed."
)


class AuthModeError(RuntimeError):
    """The requested authentication mode cannot be honoured."""


def resolve_auth_mode(configured: str | None, *, has_credentials: bool) -> str:
    """Return the mode to run in, or raise if the configuration is unusable."""
    requested = (configured or "").strip().lower()

    if not requested:
        # Deployments that already carry credentials were running OBO, and
        # keep doing so without being asked to change anything. Those that
        # were relying on the old fallback have to say so out loud.
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

    if requested == OBO and not has_credentials:
        raise AuthModeError(
            "AUTH_MODE=obo requires ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET "
            "(or the deprecated OBO_CLIENT_ID / OBO_CLIENT_SECRET)."
        )

    return requested
