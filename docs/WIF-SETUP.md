# Workload Identity Federation: agentes sin API keys

Los agentes (triage en PR y auditoría semanal) no usan `ANTHROPIC_API_KEY`.
GitHub firma un JWT OIDC de unos 5 minutos para el job; Anthropic lo valida contra una
**regla de federación** y entrega un token efímero de una *service account*.
No hay secreto que filtrar, rotar ni robar desde un log.

```
job de GitHub ──(JWT OIDC: sub, aud, repository, workflow_ref, jti)──► Anthropic
                                                                       │ valida issuer + regla
                         token efímero (≈10 min) de la service account ◄┘
```

## 1. Issuer (ya creado)

| Campo | Valor |
|---|---|
| Name | `github-actions` |
| Issuer URL | `https://token.actions.githubusercontent.com` |
| JWKS | OIDC discovery |
| JTI replay protection | Enabled (cada JWT se canjea una sola vez) |

## 2. Service account y workspace

- Workspace dedicado, p. ej. **`ci-agents`**, con **límite de gasto**. Si una regla se
  abusa, el daño máximo es ese límite.
- Service account, p. ej. **`auditgate-ci-agents`**, rol `developer`, miembro de `ci-agents`.

## 3. Regla A: triage en Pull Requests

| Campo | Valor |
|---|---|
| Name | `auditgate-pr-triage` |
| Issuer | `github-actions` |
| Subject (`subject_prefix`) | `repo:Jawy77/auditgate:pull_request` (exacto, **sin** `*`) |
| Audience | `https://api.anthropic.com` |
| Claims | `repository_owner` = `Jawy77` · `repository` = `Jawy77/auditgate` · `event_name` = `pull_request` |
| Condition (CEL) | `claims.job_workflow_ref.startsWith("Jawy77/auditgate/.github/workflows/security-platform.yml@")` |
| Target | service account `auditgate-ci-agents` |
| Workspace | `ci-agents` |
| OAuth scope | `workspace:developer` |
| Token lifetime | `600` s |

Por qué así:
- El `sub` de un PR no incluye la rama, así que la regla se acota además por **repo**
  y por el **workflow que pide el token**. El job de triage vive en el reusable
  workflow, así que su `job_workflow_ref` apunta a `security-platform.yml`.
- **Forks:** GitHub no entrega token OIDC a los runs `pull_request` que vienen de forks,
  y el job además los filtra (`head.repo == github.repository`).
- **Riesgo residual:** un colaborador con permiso de escritura podría modificar
  `security-platform.yml` en su propio PR. Lo mitigan `CODEOWNERS` sobre `.github/`, el
  workspace con límite de gasto y el token de 10 minutos.

## 4. Regla B: auditoría semanal (solo `main`)

| Campo | Valor |
|---|---|
| Name | `auditgate-agent-audit-main` |
| Subject (`subject_prefix`) | `repo:Jawy77/auditgate:ref:refs/heads/main` |
| Audience | `https://api.anthropic.com` |
| Claims | `repository` = `Jawy77/auditgate` · `workflow_ref` = `Jawy77/auditgate/.github/workflows/agent-audit.yml@refs/heads/main` |
| Target / Workspace / Scope / Lifetime | igual que la regla A |

Solo el workflow de auditoría, ejecutado desde `main` (rama protegida), puede pedir un
token con esta regla. El job también exige `github.ref == 'refs/heads/main'`.

## 5. Variables del repositorio (no son secretos)

```bash
gh variable set ANTHROPIC_ORGANIZATION_ID     -R Jawy77/auditgate --body "<uuid de la org>"
gh variable set ANTHROPIC_RULE_ID_PR_TRIAGE   -R Jawy77/auditgate --body "fdrl_..."   # regla A
gh variable set ANTHROPIC_RULE_ID_AGENT_AUDIT -R Jawy77/auditgate --body "fdrl_..."   # regla B
gh variable set ANTHROPIC_SERVICE_ACCOUNT_ID  -R Jawy77/auditgate --body "svac_..."   # opcional
```

Si la regla cubre más de un workspace, se pasa también `anthropic-workspace-id`.

## 6. Detalles que rompen si se ignoran

- **No dejes `ANTHROPIC_API_KEY` en el entorno, ni siquiera vacía.** Tiene prioridad
  sobre la federación, y un string vacío igual ocupa su lugar en la cadena de credenciales.
  Por eso los workflows solo exportan las variables WIF opcionales cuando tienen valor.
- **`jti` de un solo uso.** Un JWT de GitHub se canjea una vez. `src/auditgate/gha_oidc.py`
  pide un JWT nuevo antes de cada llamada (y antes de cada tarea del taskflow), porque
  el SDK relee `ANTHROPIC_IDENTITY_TOKEN_FILE` en cada intercambio.
- **`id-token: write`** solo en los jobs que lo necesitan (triage y audit). En el caller
  (`devsecops-pipeline.yml`) se concede al job `platform`, porque un reusable workflow no
  puede pedir más permisos que los que le da quien lo llama.
