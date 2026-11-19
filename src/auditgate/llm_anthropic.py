"""Adaptador de Claude (SDK oficial de Anthropic) para la capa llm.py."""
from __future__ import annotations

import json

import anthropic

from auditgate.gha_oidc import refresh_identity_token


def complete_json(cfg, system: str, user: str, schema: dict, *, schema_name: str, effort: str, long_running: bool) -> dict:
    if cfg.api_key:
        client = anthropic.Anthropic(api_key=cfg.api_key)
    else:
        # Sin llave: Workload Identity Federation. JWT fresco (jti de un solo uso).
        refresh_identity_token()
        client = anthropic.Anthropic()

    params = dict(
        model=cfg.model,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",  # si el modelo declina, el API reintenta en un modelo de respaldo
        system=system,
        output_config={"effort": effort, "format": {"type": "json_schema", "schema": schema}},
        messages=[{"role": "user", "content": user}],
    )
    if long_running:
        with client.beta.messages.stream(max_tokens=64000, **params) as stream:
            response = stream.get_final_message()
    else:
        response = client.beta.messages.create(max_tokens=16000, **params)

    if response.stop_reason == "refusal":
        raise RuntimeError("El modelo declino la tarea (stop_reason=refusal).")
    if response.stop_reason == "max_tokens":
        raise RuntimeError("Salida truncada (max_tokens).")
    text = next(b.text for b in response.content if b.type == "text")
    return json.loads(text)
