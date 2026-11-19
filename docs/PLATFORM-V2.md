# Plataforma v2: de "Bunker" a Security Platform

## Por qué v2

El pipeline v1 tenía 12 checks, pero **ninguno bloqueaba**: todos usaban
`continue-on-error`, `|| true` o `soft_fail`. Con 7 vulnerabilidades plantadas,
`main` quedaba en verde. Además el propio pipeline era superficie de ataque:
**20 actions sin fijar por SHA** (dos de ellas en `@master`) y sin bloque `permissions`.

v2 aplica dos ideas:

1. **Security Platform Engineering**: la seguridad se entrega como producto interno
   (*paved road*). Un repo consume `security-platform.yml` con unas 10 líneas y hereda
   todos los controles.
2. **Find → Extract → Codify → Scale** (GitHub Security Lab): los agentes descubren,
   los humanos validan y las reglas deterministas bloquean y escalan.

> **Regla de oro:** el agente descubre y prioriza; el determinismo bloquea.

## Arquitectura

```
                 ┌──────────────── PR / push ────────────────┐
                 │                                           │
  secrets ───────┤ gitleaks (commits del PR) + TruffleHog    │
  sast ──────────┤ Semgrep diff-aware + reglas propias       │
  dependencies ──┤ pip-audit diff-aware                      ├──► 🚦 security-gate ──► merge
  container ─────┤ Trivy CRITICAL con fix + Hadolint         │      (único check requerido)
  iac ───────────┤ Checkov (reporte)                         │
  integrity ─────┤ semgrep --test (reglas) + self-audit + pytest│
                 └───────────────────────────────────────────┘
                     │ SARIF → Code Scanning (alertas en el PR)
                     ▼
  ai-triage ──► comentario en el PR: TP/FP, alcanzabilidad, fix, candidato a regla
                (asesor: continue-on-error, nunca bloquea)

  agent-audit (semanal) ──► issue `needs-validation` ──► humano valida (PoC)
        FIND                                                │
                                         EXTRACT + CODIFY ◄─┘  regla + fixture con tests
                                                │
                                          SCALE ▼  el reusable workflow la lleva a todos los repos

  release (tag) ──► GHCR + SBOM + provenance SLSA + firma cosign keyless (OIDC)
```

## Política del gate

| Control | En PR | En push |
|---|---|---|
| Secretos en los commits del PR (gitleaks) / verificados (TruffleHog) | **bloquea** | reporta |
| SAST `ERROR` **nuevos** (baseline = base del PR) | **bloquea** | reporta |
| Vulnerabilidades **nuevas** en dependencias | **bloquea** | reporta |
| CVE CRITICAL **con fix** en la imagen | **bloquea** | reporta |
| Reglas propias sin tests o con tests rotos | **bloquea** | **bloquea** |
| Workflows con actions sin SHA o *pwn request* | **bloquea** | **bloquea** |
| Tests de seguridad (pytest) | **bloquea** | **bloquea** |
| IaC (Checkov), Hadolint, Bandit, licencias | reporta | reporta |
| Triage AI | comenta | n/a |

**Diff-aware:** la deuda previa no bloquea a nadie; lo nuevo sí. Así un gate
estricto se puede adoptar en repos con historia. La deuda se paga con Dependabot
(con *cooldown* de 7 días) y con las alertas de Code Scanning.

## Guardrails de los agentes

- Corren con **token mínimo**: triage = `pull-requests: write`; audit = `issues: write`.
- **Sin API keys**: identidad federada (OIDC) acotada por regla a este repo, a este
  workflow y al tipo de evento; token efímero y `jti` de un solo uso.
- **No corren en PRs de forks** (sin secretos y con el mayor riesgo de prompt injection).
- Todo el contenido del repo va delimitado como `<untrusted>` y el system prompt
  prohíbe obedecer instrucciones embebidas. Si sospecha una inyección, el agente
  la marca y pide revisión humana.
- **Sin tools ni red**: una llamada con salida estructurada (JSON Schema).
- Los fallos del agente **nunca** rompen el pipeline.
- El modelo es intercambiable: la metodología vive en el taskflow YAML
  (`agents/taskflows/`), no en el modelo.

## Cómo se codifica un hallazgo (el ciclo completo)

1. **Find**: `agent-audit` o un pentest encuentra algo y abre un issue `needs-validation`.
2. **Validate (HITL)**: un humano lo reproduce con PoC.
3. **Extract**: se describe el patrón generalizable.
4. **Codify**: regla en `src/auditgate/rules/<lang>/*.yml` (o en `rules/` de tu repo) más un fixture con `# ruleid:` / `# ok:`.
   `semgrep --test` debe pasar (el gate lo exige).
5. **Scale**: al hacer merge, todos los repos que consumen `security-platform.yml`
   detectan variantes del patrón en su siguiente PR.

Ejemplo real en este repo: las 7 vulnerabilidades de `vulnerable_app/app.py`
(el *Find*) se codificaron en `src/auditgate/rules/python/auditgate-flask.yml`. Esas reglas detectan las
7, con 0 falsos positivos en `app_secure.py`: las dos excepciones están revisadas y
documentadas con `nosemgrep` + justificación.

## Métricas que importan

- MTTR por severidad y tiempo hasta el commit del fix.
- % de PRs bloqueados por el gate y % que se resuelven sin escalar.
- Tasa de falsos positivos por regla (una regla ruidosa se ajusta o se retira).
- Reglas nuevas codificadas por mes a partir de hallazgos.
- % de fixes sugeridos por el agente que se aceptan.
- % de repos que consumen la plataforma.

## Activación

1. **Workload Identity Federation (sin API keys).** Los agentes se autentican con el
   JWT OIDC de GitHub (`aud=https://api.anthropic.com`), que Anthropic cambia por un
   token efímero (~10 min) de una service account. No hay secreto que filtrar ni rotar.
   Variables del repo (no son secretos): `ANTHROPIC_ORGANIZATION_ID`,
   `ANTHROPIC_RULE_ID_PR_TRIAGE`, `ANTHROPIC_RULE_ID_AGENT_AUDIT` y, opcional,
   `ANTHROPIC_SERVICE_ACCOUNT_ID`. Sin ellas, la capa AI se omite sin romper nada.
   Detalle de las reglas en [`docs/WIF-SETUP.md`](WIF-SETUP.md).
2. `./scripts/setup_branch_protection.sh` → check requerido: `platform / 🚦 Security Gate`.
3. Activar *Private vulnerability reporting* y *Code scanning* en Settings → Security.
