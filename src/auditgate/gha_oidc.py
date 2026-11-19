"""
Helper de Workload Identity Federation para GitHub Actions.

GitHub emite JWT de ~5 minutos con `jti`; Anthropic acepta cada `jti` una sola
vez. Por eso pedimos un JWT FRESCO justo antes de cada llamada al API (el SDK
relee ANTHROPIC_IDENTITY_TOKEN_FILE en cada intercambio).

Fuera de Actions (o sin `id-token: write`) no hace nada.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

AUDIENCE = "https://api.anthropic.com"


def wif_configured() -> bool:
    """True si el entorno tiene las variables minimas de WIF."""
    return bool(
        os.environ.get("ANTHROPIC_FEDERATION_RULE_ID")
        and os.environ.get("ANTHROPIC_ORGANIZATION_ID")
        and (os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE") or os.environ.get("ANTHROPIC_IDENTITY_TOKEN"))
    )


def has_anthropic_credentials() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
        or wif_configured()
    )


def refresh_identity_token() -> bool:
    """Pide un JWT nuevo a GitHub y lo escribe en ANTHROPIC_IDENTITY_TOKEN_FILE.

    Devuelve True si escribio un token. No hace nada si no corre en Actions.
    """
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    path = os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE")
    if not (url and bearer and path):
        return False
    sep = "&" if "?" in url else "?"
    req = urllib.request.Request(
        f"{url}{sep}audience={urllib.parse.quote(AUDIENCE, safe='')}",
        headers={"Authorization": f"Bearer {bearer}"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 — URL del runner de GitHub
        token = json.load(resp)["value"]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token)
    return True
