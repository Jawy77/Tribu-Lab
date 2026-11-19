"""
Adaptador para Grok (xAI), OpenAI y cualquier API compatible con OpenAI
(Ollama, OpenRouter, vLLM, LM Studio...) usando el SDK `openai`.

Pide salida estructurada con JSON Schema estricto. Si el endpoint no la
soporta, degrada a JSON libre con el schema en el prompt; en ambos casos
llm.py valida el resultado contra el schema antes de usarlo.
"""
from __future__ import annotations

import json
import re

import openai
from openai import OpenAI


def _client(cfg) -> OpenAI:
    kwargs = {"api_key": cfg.api_key or "not-needed"}  # endpoints locales pueden no exigir llave
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    return OpenAI(**kwargs)


def _parse(text: str) -> dict:
    text = (text or "").strip()
    fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fenced:
        text = fenced.group(1)
    return json.loads(text)


def complete_json(cfg, system: str, user: str, schema: dict, *, schema_name: str, effort: str, long_running: bool) -> dict:
    client = _client(cfg)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    attempts = [
        {"type": "json_schema", "json_schema": {"name": schema_name, "schema": schema, "strict": True}},
        {"type": "json_object"},
        None,
    ]
    last_error: Exception | None = None
    for fmt in attempts:
        msgs = messages
        if fmt is None or fmt["type"] == "json_object":
            # Sin JSON Schema nativo: el schema va en el prompt y llm.py valida igual.
            msgs = [
                {
                    "role": "system",
                    "content": system
                    + "\n\nResponde SOLO con un objeto JSON valido contra este JSON Schema, sin texto adicional:\n"
                    + json.dumps(schema, ensure_ascii=False),
                },
                {"role": "user", "content": user},
            ]
        kwargs = {"model": cfg.model, "messages": msgs}
        if fmt is not None:
            kwargs["response_format"] = fmt
        try:
            response = client.chat.completions.create(**kwargs)
        except openai.BadRequestError as exc:  # el endpoint no soporta este response_format
            last_error = exc
            continue
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            raise RuntimeError(f"El modelo declino la tarea: {message.refusal}")
        if response.choices[0].finish_reason == "length":
            raise RuntimeError("Salida truncada (finish_reason=length).")
        return _parse(message.content)
    raise RuntimeError(f"El endpoint rechazo todos los formatos de salida: {last_error}")
