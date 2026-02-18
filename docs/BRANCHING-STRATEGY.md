# Branching Strategy — Bunker DevSecOps

> Estrategia de branches y ambientes para el pipeline de seguridad.

---

## Branches y su Proposito

| Branch | Proposito | Pipeline | Bloquea Merge? | Requiere PR? | Requiere Review? |
|---|---|---|---|---|---|
| `main` | Produccion | 12 checks completos | **SI** — no merge si falla | Si | Si (1+) |
| `develop` | Integracion / Staging | 12 checks completos | **NO** — solo reporta | No | No |
| `feature/*` | Desarrollo individual | SAST + tests (rapido) | **NO** | No | No |
| `hotfix/*` | Fixes urgentes | 12 checks completos | **SI** — igual que main | Si (a main) | Si (1+) |

---

## Flujo de Trabajo

```
feature/nueva-funcionalidad
    |
    |  (push triggers: SAST + tests rapido)
    |
    +-----> develop  (merge libre, pipeline completo REPORTA)
               |
               |  (PR a main, 12 checks, 1 review)
               |
               +-----> main  (pipeline BLOQUEA si falla)
                         ^
                         |
                hotfix/fix-urgente  (PR directo a main)
```

### Ciclo tipico durante el taller:

```bash
# 1. Crear feature branch
git checkout develop
git checkout -b feature/mi-mejora

# 2. Trabajar y pushear (pipeline SAST rapido)
git add .
git commit -m "feat: agregar nuevo check de seguridad"
git push origin feature/mi-mejora

# 3. Merge a develop (pipeline completo, no bloquea)
git checkout develop
git merge feature/mi-mejora
git push origin develop

# 4. PR de develop a main (pipeline completo, BLOQUEA si falla)
gh pr create --base main --head develop \
  --title "feat: integrar mejoras del sprint" \
  --body "12 checks deben pasar antes del merge"

# 5. Despues del merge, limpiar
git branch -d feature/mi-mejora
git push origin --delete feature/mi-mejora
```

---

## Ambientes y Seguridad

En el contexto del taller, los branches mapean directamente a ambientes:

| Branch | Ambiente | Analogia |
|---|---|---|
| `feature/*` | **Development** | Donde cada dev trabaja libremente |
| `develop` | **Staging** | Donde integramos y probamos antes de produccion |
| `main` | **Production** | Protegido, solo codigo verificado |

### Por que dev/staging TAMBIEN necesitan security checks

Un error comun es pensar que solo produccion necesita seguridad. Esto es incorrecto:

**1. Secrets accidentales en dev**
Un desarrollador puede commitear un `.env` con tokens reales mientras prueba. Sin secret scanning en feature branches, ese token llega al historial de git y es irrecuperable (incluso si se borra el archivo, queda en el historial).

**2. Dependencias de dev con CVEs**
Los `requirements.txt` de desarrollo pueden incluir dependencias con vulnerabilidades conocidas. Sin dependency audit en staging, esas deps se arrastran hasta produccion.

**3. Dockerfiles permisivos en dev**
Los Dockerfiles de desarrollo suelen tener:
- `USER root` (para instalar herramientas)
- Puertos de debug abiertos
- Variables de entorno con secrets
- Sin HEALTHCHECK

Sin container scanning en develop, estas configuraciones llegan a produccion.

**4. IaC con permisos excesivos**
Durante desarrollo, es comun usar Security Groups con `0.0.0.0/0` para "que funcione rapido". Sin IaC scanning en develop, estos permisos se quedan.

### La diferencia: REPORTAR vs BLOQUEAR

```
feature/*  ──>  Pipeline REPORTA (feedback rapido, no bloquea al dev)
                "Tienes 3 findings de Bandit — revisa antes de mergear"

develop    ──>  Pipeline REPORTA (visibilidad, no bloquea integracion)
                "Warning: 1 CVE en gunicorn — actualizar antes de ir a main"

main       ──>  Pipeline BLOQUEA (gate de calidad, no pasa sin fix)
                "BLOCKED: 2 critical findings — no se puede mergear"
```

El objetivo es que el desarrollador **siempre sepa** el estado de seguridad de su codigo, pero **solo se bloquee** en produccion donde el riesgo es real.

---

## Configuracion del Pipeline por Branch

El archivo `.github/workflows/devsecops-pipeline.yml` ejecuta:

```yaml
on:
  push:
    branches: [main, develop]    # 12 checks en ambos
  pull_request:
    branches: [main]             # Gate para produccion
```

| Evento | Trigger | Checks | Comportamiento |
|---|---|---|---|
| Push a `main` | Directo (admin) o merge de PR | 12 checks completos | Informativo (PR ya fue aprobado) |
| Push a `develop` | Merge de feature o push directo | 12 checks completos | Solo reporta, no bloquea |
| PR a `main` | Desde develop o hotfix | 12 checks completos | **BLOQUEA** si falla (status check) |
| Push a `feature/*` | Push del developer | No ejecuta pipeline | Sin costo de CI (usar local) |

### Checks locales para feature branches

Los developers pueden ejecutar checks localmente antes de pushear:

```bash
# SAST rapido (< 30 segundos)
bandit -r . -ll --exclude ./.venv,./tests

# Tests de seguridad (< 2 segundos)
pytest tests/ -v -m security

# Secret scan local
gitleaks detect --source . --verbose
```

---

## Branch Protection — Configuracion

El script `scripts/setup_branch_protection.sh` configura las reglas via GitHub CLI:

**main:**
- Requiere Pull Request antes de merge
- Requiere 1 aprobacion de reviewer
- Dismiss stale reviews (si el PR cambia, el review se invalida)
- Requiere que los 6 jobs del pipeline pasen como status checks
- No permite force push
- No permite eliminar el branch

**develop:**
- Requiere que SAST + secret scan + tests pasen
- No requiere PR (merge directo permitido)
- No requiere reviews
- No permite force push

**feature/* y hotfix/*:**
- Sin restricciones (branches efimeros)
- El developer tiene libertad total
- La seguridad se valida cuando llega a develop/main

---

## Rotacion y Limpieza de Branches

```bash
# Ver branches mergeados que se pueden eliminar
git branch --merged main | grep -v "main\|develop"

# Limpiar branches remotos ya mergeados
git remote prune origin

# Eliminar feature branch despues del merge
git branch -d feature/completada
git push origin --delete feature/completada
```

**Convencion de nombres:**

| Patron | Ejemplo | Proposito |
|---|---|---|
| `feature/<desc>` | `feature/add-zap-scan` | Nueva funcionalidad |
| `hotfix/<desc>` | `hotfix/fix-secret-leak` | Fix urgente para main |
| `docs/<desc>` | `docs/update-readme` | Cambios en documentacion |
| `refactor/<desc>` | `refactor/pipeline-v2` | Refactoring sin cambio funcional |

---

*Bunker DevSecOps Workshop — Mantishield / Tribu | Hacklab Bogota | Ethereum Bogota*
