"""
auditgate — instala y configura Auditgate en un repo de GitHub.

    auditgate scan        corre el gate en tu maquina (el mismo del PR)
    auditgate init        instala el workflow y configura el modelo + la llave
    auditgate set-key     guarda o rota la llave del modelo en el vault
    auditgate doctor      revisa que todo este bien configurado

La llave del modelo:
  - se pide con getpass (no se ve en pantalla ni queda en el historial),
  - se envia a GitHub por stdin (nunca como argumento: no aparece en `ps`),
  - GitHub la cifra (libsodium sealed box) en el Environment `auditgate`,
  - nunca se escribe a disco ni se imprime.

Requisitos: git y GitHub CLI (`gh`) autenticado con permiso de admin del repo.
"""
from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
from pathlib import Path

from auditgate.project import detect_project, unpinned_actions

PLATFORM_REPO = "Jawy77/auditgate"
ENVIRONMENT = "auditgate"
SECRET_NAME = "AUDITGATE_LLM_API_KEY"
WORKFLOW_PATH = Path(".github/workflows/auditgate.yml")

PROVIDERS = {
    "anthropic": "Claude (Anthropic)",
    "xai": "Grok (xAI)",
    "openai": "OpenAI",
    "openai-compatible": "API compatible con OpenAI (Ollama, OpenRouter, vLLM...)",
    "none": "Sin agente de IA (solo el gate determinista)",
}
NEEDS_KEY = {"anthropic", "xai", "openai"}  # openai-compatible: opcional (endpoints locales)


class CLIError(SystemExit):
    def __init__(self, msg: str):
        super().__init__(f"✖ {msg}")


# ── gh / git ─────────────────────────────────────────────────────────────────
def gh(*args: str, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    if not shutil.which("gh"):
        raise CLIError("No encuentro GitHub CLI (`gh`). Instálalo: https://cli.github.com")
    proc = subprocess.run(["gh", *args], input=input_text, capture_output=True, text=True)
    if check and proc.returncode != 0:
        # Nunca reenviamos input_text (puede ser la llave) en mensajes de error.
        raise CLIError(f"`gh {args[0]} {args[1] if len(args) > 1 else ''}` falló: {proc.stderr.strip()[:300]}")
    return proc


def detect_repo(explicit: str | None) -> str:
    if explicit:
        return explicit
    proc = gh("repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner", check=False)
    if proc.returncode != 0:
        raise CLIError("No detecto el repo. Corre dentro del repo o usa --repo owner/nombre.")
    return proc.stdout.strip()


def resolve_platform_sha(ref: str) -> str:
    proc = gh("api", f"repos/{PLATFORM_REPO}/commits/{ref}", "--jq", ".sha", check=False)
    sha = proc.stdout.strip()
    if proc.returncode != 0 or len(sha) != 40:
        raise CLIError(f"No pude resolver '{ref}' en {PLATFORM_REPO} a un SHA.")
    return sha


# ── workflow ─────────────────────────────────────────────────────────────────
def render_workflow(sha: str, ref_label: str, project: dict, enforce_pins: bool) -> str:
    return f"""# Auditgate — https://github.com/{PLATFORM_REPO}
# Generado por `auditgate init`. Version fijada por SHA (supply chain).
name: Auditgate

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  auditgate:
    uses: {PLATFORM_REPO}/.github/workflows/security-platform.yml@{sha} # {ref_label}
    permissions:
      contents: read
      security-events: write # alertas en Code Scanning
      pull-requests: write # comentario del agente de triage
      id-token: write # solo si usas Claude sin llave (WIF)
    # Sin esto, el job del agente NO recibe el secreto del Environment `{ENVIRONMENT}`
    # (en un reusable workflow, los secretos de Environment solo llegan con inherit).
    # Auditgate esta fijado por SHA y solo lee AUDITGATE_LLM_API_KEY.
    secrets: inherit
    with:
      platform-ref: {sha} # mismo SHA que el `uses:`
      requirements: "{project['requirements']}"
      image-dockerfile: "{project['dockerfile']}"
      iac-dir: "{project['iac_dir']}"
      enforce-pinned-actions: {str(enforce_pins).lower()}
      # Modelo del agente: variables del repo. La llave vive en el Environment `{ENVIRONMENT}`.
      llm-provider: ${{{{ vars.AUDITGATE_LLM_PROVIDER }}}}
      llm-model: ${{{{ vars.AUDITGATE_LLM_MODEL }}}}
      llm-base-url: ${{{{ vars.AUDITGATE_LLM_BASE_URL }}}}
"""


# ── llave ────────────────────────────────────────────────────────────────────
def read_key(from_stdin: bool) -> str:
    if from_stdin:
        key = sys.stdin.read().strip()
    else:
        if not sys.stdin.isatty():
            raise CLIError("Para pasar la llave por pipe usa --key-stdin.")
        key = getpass.getpass("API key del proveedor (no se mostrará): ").strip()
    if not key:
        raise CLIError("La llave está vacía.")
    if any(c.isspace() for c in key):
        raise CLIError("La llave tiene espacios: revisa que la pegaste completa.")
    return key


def store_key(repo: str, key: str) -> None:
    # 1) Environment = el vault: solo los jobs que lo declaran reciben el secreto.
    gh("api", "-X", "PUT", f"repos/{repo}/environments/{ENVIRONMENT}", "--silent")
    # 2) La llave viaja por stdin; gh la cifra con la llave pública del repo.
    gh("secret", "set", SECRET_NAME, "--env", ENVIRONMENT, "--repo", repo, input_text=key)


def set_var(repo: str, name: str, value: str) -> None:
    if value:
        gh("variable", "set", name, "--repo", repo, "--body", value)
    else:
        gh("variable", "delete", name, "--repo", repo, check=False)


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{prompt}{suffix}: ").strip()
    return answer or default


def choose_provider(preset: str | None) -> str:
    if preset:
        if preset not in PROVIDERS:
            raise CLIError(f"Proveedor desconocido: {preset}. Opciones: {', '.join(PROVIDERS)}")
        return preset
    print("\n¿Qué modelo usará el agente de triage? (asesor: nunca bloquea un merge)")
    keys = list(PROVIDERS)
    for i, k in enumerate(keys, 1):
        print(f"  {i}. {PROVIDERS[k]}")
    choice = ask("Elige", "1")
    try:
        return keys[int(choice) - 1]
    except (ValueError, IndexError):
        raise CLIError("Opción inválida.") from None


# ── comandos ─────────────────────────────────────────────────────────────────
def cmd_init(args) -> int:
    root = Path.cwd()
    if not (root / ".git").exists():
        raise CLIError("Corre `auditgate init` en la raíz de un repo git.")
    repo = detect_repo(args.repo)
    sha = resolve_platform_sha(args.ref)
    project = detect_project(root)
    print(f"Repo: {repo}\nAuditgate: {args.ref} → {sha[:12]}")
    print(f"Detectado → requirements: {project['requirements'] or '—'} · "
          f"Dockerfile: {project['dockerfile'] or '—'} · Terraform: {project['iac_dir'] or '—'}")

    pins = unpinned_actions(root)
    enforce = True
    if pins:
        print(f"\n⚠ {len(pins)} action(s) sin fijar por SHA en tus workflows:")
        for p in pins[:10]:
            print(f"    {p}")
        print("  Auditgate bloquea esto por defecto (un tag es mutable: caso tj-actions 2025).")
        enforce = args.yes or ask("¿Bloquear ya? (n = solo reportar mientras migras)", "n").lower().startswith("s")

    if WORKFLOW_PATH.exists() and not args.force:
        raise CLIError(f"{WORKFLOW_PATH} ya existe. Usa --force para reemplazarlo.")
    WORKFLOW_PATH.parent.mkdir(parents=True, exist_ok=True)
    WORKFLOW_PATH.write_text(render_workflow(sha, args.ref, project, enforce))
    print(f"\n✔ Workflow escrito: {WORKFLOW_PATH}")

    provider = choose_provider(args.provider)
    if provider == "none":
        set_var(repo, "AUDITGATE_LLM_PROVIDER", "")
        print("✔ Sin agente de IA: el gate determinista funciona igual.")
    else:
        model = args.model if args.model is not None else ask(
            "Modelo" + (" (vacío = default de Claude)" if provider == "anthropic" else " (obligatorio)"),
            "",
        )
        if provider != "anthropic" and not model:
            raise CLIError("Este proveedor necesita el nombre del modelo (p. ej. el que uses en su consola).")
        base_url = args.base_url or ""
        if provider == "openai-compatible" and not base_url:
            base_url = ask("Base URL del endpoint (p. ej. https://openrouter.ai/api/v1)")
            if not base_url:
                raise CLIError("openai-compatible necesita la base URL.")
        set_var(repo, "AUDITGATE_LLM_PROVIDER", provider)
        set_var(repo, "AUDITGATE_LLM_MODEL", model)
        set_var(repo, "AUDITGATE_LLM_BASE_URL", base_url)
        print(f"✔ Variables del repo: provider={provider} model={model or '(default)'}")

        if args.no_key:
            print("• Sin llave por ahora (Claude con WIF, o la cargas luego con `auditgate set-key`).")
        elif provider in NEEDS_KEY or args.key_stdin or ask("¿El endpoint pide API key? (s/n)", "s").lower().startswith("s"):
            key = read_key(args.key_stdin)
            store_key(repo, key)
            del key
            print(f"✔ Llave cifrada en el Environment `{ENVIRONMENT}` (secreto {SECRET_NAME}).")

    print(f"""
Siguiente:
  git add {WORKFLOW_PATH} && git commit -m "ci: instala Auditgate" && git push
  Abre un PR: el gate corre y, si configuraste un modelo, el agente comenta.

Recomendado:
  • En la consola del proveedor, usa una llave dedicada con límite de gasto.
  • Protección de rama: check requerido `auditgate / 🚦 Security Gate`.
  • `auditgate doctor` para revisar la instalación.""")
    return 0


def cmd_set_key(args) -> int:
    repo = detect_repo(args.repo)
    key = read_key(args.key_stdin)
    store_key(repo, key)
    del key
    print(f"✔ Llave guardada/rotada en {repo} → Environment `{ENVIRONMENT}`. Revoca la anterior en tu proveedor.")
    return 0


def cmd_doctor(args) -> int:
    repo = detect_repo(args.repo)
    ok = True

    def check(cond: bool, good: str, bad: str) -> None:
        nonlocal ok
        print(("  ✔ " + good) if cond else ("  ✖ " + bad))
        ok = ok and cond

    print(f"Auditgate doctor — {repo}")
    wf = WORKFLOW_PATH.read_text() if WORKFLOW_PATH.exists() else ""
    check(bool(wf), f"{WORKFLOW_PATH} existe", f"falta {WORKFLOW_PATH} (corre `auditgate init`)")
    if wf:
        import re

        m = re.search(r"security-platform\.yml@([0-9a-f]{40})", wf)
        p = re.search(r"platform-ref:\s*([0-9a-f]{40})", wf)
        check(bool(m), "Auditgate fijado por SHA", "el `uses:` de Auditgate no está fijado por SHA")
        check(bool(m and p and m.group(1) == p.group(1)), "platform-ref coincide con el `uses:`",
              "platform-ref no coincide con el SHA del `uses:`")

    raw = gh("variable", "list", "--repo", repo, "--json", "name,value", check=False).stdout or "[]"
    variables = {v["name"]: v["value"] for v in json.loads(raw)}
    provider = variables.get("AUDITGATE_LLM_PROVIDER", "")
    print(f"  • Proveedor: {provider or 'ninguno (solo gate determinista)'} · "
          f"modelo: {variables.get('AUDITGATE_LLM_MODEL') or '(default)'}")
    if provider and provider != "anthropic":
        check(bool(variables.get("AUDITGATE_LLM_MODEL")), "modelo configurado", "falta AUDITGATE_LLM_MODEL")

    sec = gh("secret", "list", "--env", ENVIRONMENT, "--repo", repo, "--json", "name,updatedAt", check=False)
    secrets_ = json.loads(sec.stdout or "[]") if sec.returncode == 0 else []
    has_key = any(s["name"] == SECRET_NAME for s in secrets_)
    if provider in NEEDS_KEY:
        wif = bool(variables.get("ANTHROPIC_RULE_ID_PR_TRIAGE"))
        check(has_key or (provider == "anthropic" and wif),
              f"llave en el vault (Environment `{ENVIRONMENT}`)" if has_key else "Claude vía WIF (sin llave)",
              f"falta la llave: `auditgate set-key`")

    pins = unpinned_actions(Path.cwd())
    check(not pins, "todas las actions fijadas por SHA", f"{len(pins)} action(s) sin fijar por SHA")
    print("\nTodo en orden." if ok else "\nHay puntos por corregir.")
    return 0 if ok else 1


def cmd_scan(args) -> int:
    from auditgate.scan import ALL_CHECKS, EXIT_ERROR, ScanError, exit_code, render_text, run_scan

    checks = tuple(c.strip() for c in args.checks.split(",")) if args.checks else ALL_CHECKS
    unknown = set(checks) - set(ALL_CHECKS)
    if unknown:
        print(f"✖ checks desconocidos: {', '.join(sorted(unknown))}. Opciones: {', '.join(ALL_CHECKS)}",
              file=sys.stderr)
        return EXIT_ERROR
    try:
        report = run_scan(
            Path.cwd(), base=args.base, checks=checks,
            requirements=args.requirements.split() if args.requirements is not None else None,
            use_registry=not args.no_registry, enforce_pins=not args.no_enforce_pins, strict=args.strict,
        )
    except ScanError as exc:
        if args.json:
            print(json.dumps({"gate": "error", "error": str(exc)}))
        else:
            print(f"✖ {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(report, ensure_ascii=False, indent=2) if args.json else render_text(report))
    return exit_code(report)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="auditgate", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser(
        "scan",
        help="corre el gate en tu máquina sobre los commits nuevos (el mismo del PR)",
        description="Evalúa los commits entre el merge-base con --base y HEAD, en un worktree "
                    "temporal (no toca tus archivos). Exit: 0 pasa · 1 bloqueado · 2 error.",
    )
    p.add_argument("--base", help="rama o SHA base (default: rama por defecto del remoto)")
    p.add_argument("--json", action="store_true", help="salida JSON (para agentes y scripts)")
    p.add_argument("--checks", help="subconjunto, p. ej. sast,deps (default: secrets,sast,deps,actions)")
    p.add_argument("--requirements", help="requirements a auditar, separados por espacio (default: autodetecta)")
    p.add_argument("--no-registry", action="store_true", help="sin reglas del registro de Semgrep (offline)")
    p.add_argument("--no-enforce-pins", action="store_true", help="actions sin SHA solo se reportan")
    p.add_argument("--strict", action="store_true", help="herramienta faltante = error (exit 2)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("init", help="instala Auditgate en el repo actual")
    p.add_argument("--repo", help="owner/nombre (por defecto, el repo actual)")
    p.add_argument("--ref", default="main", help="tag o SHA de Auditgate a fijar (default: main)")
    p.add_argument("--provider", choices=list(PROVIDERS), help="proveedor del agente")
    p.add_argument("--model", help="modelo del proveedor")
    p.add_argument("--base-url", help="endpoint para openai-compatible")
    p.add_argument("--key-stdin", action="store_true", help="leer la llave desde stdin (automatización)")
    p.add_argument("--no-key", action="store_true", help="no pedir llave (Claude con WIF o luego)")
    p.add_argument("--force", action="store_true", help="reemplazar el workflow si existe")
    p.add_argument("--yes", action="store_true", help="aceptar defaults sin preguntar")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("set-key", help="guarda o rota la llave del modelo en el vault")
    p.add_argument("--repo")
    p.add_argument("--key-stdin", action="store_true")
    p.set_defaults(func=cmd_set_key)

    p = sub.add_parser("doctor", help="revisa la instalación")
    p.add_argument("--repo")
    p.set_defaults(func=cmd_doctor)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelado.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
