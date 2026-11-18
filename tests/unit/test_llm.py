"""Capa de modelos: configuracion, credenciales y degradacion de formatos (sin red)."""
import json
from types import SimpleNamespace

import pytest

import llm

SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["ok", "bad"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}
ENV = ("AUDITGATE_LLM_PROVIDER", "AUDITGATE_LLM_MODEL", "AUDITGATE_LLM_BASE_URL", "AUDITGATE_LLM_API_KEY",
       "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_FEDERATION_RULE_ID",
       "ANTHROPIC_ORGANIZATION_ID", "ANTHROPIC_IDENTITY_TOKEN_FILE", "ANTHROPIC_IDENTITY_TOKEN")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)


def test_default_is_claude():
    cfg = llm.load_config()
    assert (cfg.provider, cfg.model) == ("anthropic", "claude-opus-5-5")


def test_xai_requires_model_and_uses_xai_endpoint(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "xai")
    with pytest.raises(llm.LLMConfigError):
        llm.load_config()
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "grok-test")
    cfg = llm.load_config()
    assert cfg.base_url == "https://api.x.ai/v1"


def test_unknown_provider_rejected(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "nope")
    with pytest.raises(llm.LLMConfigError):
        llm.load_config()


def test_openai_compatible_needs_base_url(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "llama3")
    with pytest.raises(llm.LLMConfigError):
        llm.load_config()


def test_credentials(monkeypatch):
    assert not llm.has_credentials(llm.load_config())  # Claude sin llave ni WIF
    monkeypatch.setenv("ANTHROPIC_FEDERATION_RULE_ID", "fdrl_x")
    monkeypatch.setenv("ANTHROPIC_ORGANIZATION_ID", "org")
    monkeypatch.setenv("ANTHROPIC_IDENTITY_TOKEN_FILE", "/tmp/jwt")
    assert llm.has_credentials(llm.load_config())  # WIF
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "xai")
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "grok-test")
    assert not llm.has_credentials(llm.load_config())  # Grok exige llave
    monkeypatch.setenv("AUDITGATE_LLM_API_KEY", "k")
    assert llm.has_credentials(llm.load_config())


class FakeBadRequest(Exception):
    pass


def test_grok_strict_schema_first(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "xai")
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "grok-test")
    monkeypatch.setenv("AUDITGATE_LLM_API_KEY", "secret-key")
    calls = []
    import llm_openai_compat as mod

    class Completions:
        def create(self, **kwargs):
            calls.append(kwargs)
            msg = SimpleNamespace(content=json.dumps({"verdict": "ok"}), refusal=None)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")])

    inits = []

    class FakeClient:
        def __init__(self, **kwargs):
            inits.append(kwargs)
            self.chat = SimpleNamespace(completions=Completions())

    monkeypatch.setattr(mod, "OpenAI", FakeClient)
    out = llm.complete_json(llm.load_config(), "sys", "user", SCHEMA)
    assert out == {"verdict": "ok"}
    assert inits[0] == {"api_key": "secret-key", "base_url": "https://api.x.ai/v1"}
    assert calls[0]["response_format"]["type"] == "json_schema"
    assert calls[0]["response_format"]["json_schema"]["strict"] is True


def test_degrades_when_endpoint_lacks_json_schema(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "openai-compatible")
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "llama3")
    monkeypatch.setenv("AUDITGATE_LLM_BASE_URL", "http://localhost:11434/v1")
    import llm_openai_compat as mod

    calls = []
    answers = [FakeBadRequest("no json_schema"), FakeBadRequest("no json_object"),
               '```json\n{"verdict": "bad"}\n```']

    class Completions:
        def create(self, **kwargs):
            calls.append(kwargs)
            a = answers[len(calls) - 1]
            if isinstance(a, Exception):
                raise a
            msg = SimpleNamespace(content=a, refusal=None)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")])

    class FakeClient:
        def __init__(self, **kwargs):
            self.chat = SimpleNamespace(completions=Completions())

    monkeypatch.setattr(mod, "OpenAI", FakeClient)
    monkeypatch.setattr(mod.openai, "BadRequestError", FakeBadRequest)
    out = llm.complete_json(llm.load_config(), "sys", "user", SCHEMA)
    assert out == {"verdict": "bad"}
    assert [c.get("response_format", {}).get("type") for c in calls] == ["json_schema", "json_object", None]
    assert "JSON Schema" in calls[2]["messages"][0]["content"]


def test_invalid_json_from_model_is_rejected(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_PROVIDER", "openai")
    monkeypatch.setenv("AUDITGATE_LLM_MODEL", "m")
    monkeypatch.setenv("AUDITGATE_LLM_API_KEY", "k")
    import jsonschema
    import llm_openai_compat as mod

    class FakeClient:
        def __init__(self, **kwargs):
            msg = SimpleNamespace(content=json.dumps({"verdict": "maybe"}), refusal=None)
            resp = SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")])
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: resp))

    monkeypatch.setattr(mod, "OpenAI", FakeClient)
    with pytest.raises(jsonschema.ValidationError):
        llm.complete_json(llm.load_config(), "sys", "user", SCHEMA)


def test_claude_with_user_key_uses_official_sdk(monkeypatch):
    monkeypatch.setenv("AUDITGATE_LLM_API_KEY", "sk-test")
    import llm_anthropic as mod

    seen = {}

    class Msgs:
        def create(self, **kwargs):
            seen.update(kwargs)
            block = SimpleNamespace(type="text", text=json.dumps({"verdict": "ok"}))
            return SimpleNamespace(stop_reason="end_turn", content=[block])

    class FakeAnthropic:
        def __init__(self, **kwargs):
            seen["init"] = kwargs
            self.beta = SimpleNamespace(messages=Msgs())

    monkeypatch.setattr(mod.anthropic, "Anthropic", FakeAnthropic)
    out = llm.complete_json(llm.load_config(), "sys", "user", SCHEMA)
    assert out == {"verdict": "ok"}
    assert seen["init"] == {"api_key": "sk-test"}
    assert seen["model"] == "claude-opus-5-5"
    assert seen["output_config"]["format"]["type"] == "json_schema"
