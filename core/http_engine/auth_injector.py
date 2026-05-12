"""Auth injection and X-ARIA-* meta-header stripping for the HTTP engine."""
from __future__ import annotations

from dataclasses import dataclass

from core.payload_factory.models import PayloadRequest

_ARIA_PREFIX = "X-ARIA-"


@dataclass
class AuthConfig:
    """Authentication configuration for a scan session."""

    type: str = "none"              # "bearer" | "api_key" | "basic" | "none"
    token: str = ""                 # primary credential / token
    header_name: str = "Authorization"
    other_user_token: str = ""      # injected when X-ARIA-Other-User is set


class AuthInjector:
    """Prepares the final outgoing headers for a PayloadRequest.

    Processing order:
    1. Strip all X-ARIA-* keys — they are internal control signals, never wire-sent.
    2. If X-ARIA-Skip-Auth was present (or auth type is "none"), return stripped headers.
    3. If the request already has an Authorization header, keep it as-is (exploit
       modules like jwt_exploit intentionally craft their own tokens).
    4. Otherwise inject the session credential.
    """

    def __init__(self, auth_config: AuthConfig) -> None:
        self._config = auth_config

    def inject(self, request: PayloadRequest) -> dict[str, str]:
        """Return final headers ready to be sent over the wire."""
        skip_auth = request.headers.get("X-ARIA-Skip-Auth", "").lower() == "true"
        use_other = request.headers.get("X-ARIA-Other-User", "").lower() == "true"

        # Step 1: strip internal meta-headers
        headers = {k: v for k, v in request.headers.items() if not k.startswith(_ARIA_PREFIX)}

        # Step 2: no auth needed
        if skip_auth or self._config.type == "none":
            return headers

        # Step 3: don't clobber auth the request already carries (jwt exploit variants)
        if "Authorization" in headers:
            return headers

        # Step 4: inject session credential
        cfg = self._config
        token = (cfg.other_user_token if use_other and cfg.other_user_token else cfg.token)

        if cfg.type == "bearer":
            headers["Authorization"] = f"Bearer {token}"
        elif cfg.type == "api_key":
            headers[cfg.header_name] = token
        elif cfg.type == "basic":
            headers["Authorization"] = f"Basic {token}"

        return headers
