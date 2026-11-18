# Modelos y llaves: tu modelo, tu llave, cifrada en GitHub

El agente de triage (y la auditoría semanal) funciona con el modelo que tú elijas.
La metodología (prompts + JSON Schema) es de Auditgate; el modelo es tuyo.

| Proveedor | `AUDITGATE_LLM_PROVIDER` | Modelo | Endpoint |
|---|---|---|---|
| Claude (Anthropic) | `anthropic` (default) | opcional (default `claude-opus-5-5`) | API de Anthropic, SDK oficial |
| Grok (xAI) | `xai` | **obligatorio** | `https://api.x.ai/v1` |
| OpenAI | `openai` | **obligatorio** | API de OpenAI |
| Compatible con OpenAI | `openai-compatible` | **obligatorio** | `AUDITGATE_LLM_BASE_URL` (Ollama, OpenRouter, vLLM, LM Studio...) |

Auditgate no adivina nombres de modelos: cada proveedor nombra los suyos y cambian seguido.
Usa el que aparezca en la consola de tu proveedor.

**Calidad de salida:** se pide JSON Schema estricto. Si un endpoint no lo soporta, Auditgate
degrada a JSON libre con el schema en el prompt y **valida igual** el resultado. Una respuesta
que no cumple el schema se descarta: el agente nunca publica algo malformado.

## Instalación en 1 comando

```bash
pipx install "git+https://github.com/Jawy77/auditgate"
cd tu-repo
auditgate init            # elige proveedor y modelo; pega tu llave (no se ve en pantalla)
git add .github/workflows/auditgate.yml && git commit -m "ci: instala Auditgate" && git push
```

Para automatizar (por ejemplo, desde otro pipeline o un script de onboarding):

```bash
printf '%s' "$GROK_KEY" | auditgate init --provider xai --model <modelo> --key-stdin --yes
```

Otros comandos: `auditgate set-key` (rotar la llave) y `auditgate doctor` (revisar la instalación).

## Dónde vive la llave (el vault)

```
tu terminal ──getpass──► auditgate ──stdin──► gh ──(cifrada con la llave pública del repo)──► GitHub
                                                                                  │
                    Environment `auditgate` → secreto AUDITGATE_LLM_API_KEY ◄──────┘
                                   │
                                   └──► solo el job "🤖 AI triage" (y la auditoría) lo recibe
```

- **Nunca se ve ni se escribe:** `getpass` no la muestra, viaja por stdin (no aparece en `ps`
  ni en el historial de la shell) y no se guarda en disco ni en el repo.
- **Cifrada en reposo:** GitHub la cifra en el cliente (libsodium sealed box) y la guarda
  cifrada. Ni siquiera tú puedes leerla de vuelta; solo reemplazarla.
- **Alcance mínimo:** es un secreto del **Environment** `auditgate`, no del repo. Solo la
  reciben los jobs que declaran ese environment (triage y auditoría). Los escáneres, Dependabot
  y cualquier otro workflow no la ven.
- **Enmascarada:** si algo la imprime por error, GitHub la tapa en los logs.
- **Sin forks:** los PRs desde forks no reciben secretos y el job de triage además los filtra.

### Recomendaciones

1. Crea una **llave dedicada** para Auditgate con **límite de gasto** en tu proveedor.
   Si alguien la abusara, ese límite es el techo del daño.
2. Rótala con `auditgate set-key` y revoca la anterior en el proveedor.
3. No agregues *required reviewers* al Environment `auditgate`: el triage corre en cada PR y
   quedaría esperando aprobación.

### Riesgo residual (honesto)

Un colaborador con permiso de escritura puede modificar el workflow en su propio PR y usar la
llave en ese run. Es inherente a cualquier secreto en CI. Se mitiga con `CODEOWNERS` sobre
`.github/`, el límite de gasto y la rotación. Si necesitas más, usa la opción sin llave.

## Sin llave: Claude con Workload Identity Federation

Con Claude puedes no guardar ninguna llave: el job canjea su token OIDC de GitHub por un token
de Anthropic de unos 10 minutos. Ver [`WIF-SETUP.md`](WIF-SETUP.md).

## Vault externo (avanzado)

Si tu organización ya usa HashiCorp Vault, AWS Secrets Manager o GCP Secret Manager, el patrón
es el mismo que WIF: el job se autentica con OIDC contra tu vault, lee la llave en ese momento
y la exporta como `AUDITGATE_LLM_API_KEY` solo para el paso de triage. No queda ningún secreto
en GitHub. Puedes hacerlo con un workflow propio que llame al reusable pasando
`secrets: AUDITGATE_LLM_API_KEY`.
