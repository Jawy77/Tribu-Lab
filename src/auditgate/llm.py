"""
Capa de modelos de Auditgate: el agente no depende de un proveedor.

La metodologia (prompts + JSON Schema) vive en Auditgate; el modelo lo elige
quien instala la herramienta. Configuracion por variables de entorno:

    AUDITGATE_LLM_PROVIDER   anthropic (default) | xai | openai | openai-compatible
    AUDITGATE_LLM_MODEL      modelo del proveedor (obligatorio salvo en anthropic)
    AUDITGATE_LLM_BASE_URL   endpoint propio (openai-compatible: Ollama, OpenRouter, vLLM...)
    AUDITGATE_LLM_API_KEY    llave del proveedor (en Actions viene del Environment
                             `auditgate`; nunca se imprime ni se escribe a disco)

Con provider=anthropic y sin llave, se usa Workload Identity Federation (OIDC).
"""
from __future__ import annotations

import os
from dataclasses import dataclass

PROVIDERS = ("anthropic", "xai", "openai", "openai-compatible")

DEFAULT_BASE_URLS = {
    "xai": "https://api.x.ai/v1",
    "openai": None,  # el SDK usa su endpoint por defecto
}


class LLMConfigError(RuntimeError):
    """Configuracion incompleta: el agente se omite sin romper el pipeline."""


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    base_url: str | None
    api_key: str | None

    @property
    def label(self) -> str:
        return f"{self.provider}/{self.model}"


def load_config(default_model: str | None = None) -> LLMConfig:
    provider = (os.environ.get("AUDITGATE_LLM_PROVIDER") or "anthropic").strip().lower()
    if provider not in PROVIDERS:
        raise LLMConfigError(
            f"AUDITGATE_LLM_PROVIDER='{provider}' no soportado. Usa uno de: {', '.join(PROVIDERS)}"
        )
    model = (os.environ.get("AUDITGATE_LLM_MODEL") or "").strip()
    if not model and provider == "anthropic":
        model = default_model or "claude-opus-5-5"
    if not model:
        raise LLMConfigError(
            f"Falta AUDITGATE_LLM_MODEL para el proveedor '{provider}' "
            "(cada proveedor nombra sus modelos; Auditgate no adivina)."
        )
    base_url = (os.environ.get("AUDITGATE_LLM_BASE_URL") or "").strip() or DEFAULT_BASE_URLS.get(provider)
    if provider == "openai-compatible" and not base_url:
        raise LLMConfigError("openai-compatible requiere AUDITGATE_LLM_BASE_URL.")
    api_key = (os.environ.get("AUDITGATE_LLM_API_KEY") or "").strip() or None
    return LLMConfig(provider=provider, model=model, base_url=base_url, api_key=api_key)


def _anthropic_wif_configured() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_FEDERATION_RULE_ID")
        and os.environ.get("ANTHROPIC_ORGANIZATION_ID")
        and (os.environ.get("ANTHROPIC_IDENTITY_TOKEN_FILE") or os.environ.get("ANTHROPIC_IDENTITY_TOKEN"))
    )


def has_credentials(cfg: LLMConfig) -> bool:
    if cfg.api_key:
        return True
    if cfg.provider == "anthropic":
        return bool(
            os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or _anthropic_wif_configured()
        )
    # Un endpoint local (p. ej. Ollama) puede no exigir llave.
    return cfg.provider == "openai-compatible"


def complete_json(
    cfg: LLMConfig,
    system: str,
    user: str,
    schema: dict,
    *,
    schema_name: str = "auditgate_result",
    effort: str = "high",
    long_running: bool = False,
) -> dict:
    """Una llamada sin tools que devuelve JSON valido contra `schema`."""
    if cfg.provider == "anthropic":
        from auditgate.llm_anthropic import complete_json as impl
    else:
        from auditgate.llm_openai_compat import complete_json as impl
    result = impl(cfg, system, user, schema, schema_name=schema_name, effort=effort, long_running=long_running)
    validate(result, schema)
    return result


def validate(data: dict, schema: dict) -> None:
    """Valida contra el schema: ningun proveedor queda eximido."""
    import jsonschema

    jsonschema.validate(instance=data, schema=schema)
