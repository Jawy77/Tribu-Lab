# Política de seguridad

> Este repositorio contiene **código intencionalmente vulnerable** en `vulnerable_app/app.py`
> y fixtures en `rules/` con fines educativos. Esas vulnerabilidades **no** se reportan.

## Reportar una vulnerabilidad

Usa **Private vulnerability reporting** (pestaña *Security → Report a vulnerability*).
No abras issues públicos para vulnerabilidades.

## Qué debe traer un reporte (incluye reportes asistidos por IA)

Se aceptan reportes generados con ayuda de IA **solo si** cumplen todo esto:

1. **PoC reproducible**: pasos o script mínimo que demuestren el impacto real.
2. **Ubicación exacta**: archivo, línea y versión/commit afectado.
3. **Impacto concreto**: qué puede hacer un atacante y bajo qué condiciones.
4. **Validado por un humano**: confirma que reprodujiste el hallazgo.
   Pegar la salida cruda de un scanner o de un LLM sin validar **no es un reporte**.
5. **Fuera de alcance**: `vulnerable_app/app.py`, `rules/**`, fixtures de `skills/**/evals/`.

Los reportes que no cumplan se cierran sin respuesta detallada.

## Proceso

| Paso | Objetivo |
|---|---|
| Acuse de recibo | ≤ 3 días hábiles |
| Triage y severidad | ≤ 7 días hábiles |
| Fix + advisory | según severidad, coordinado con quien reporta |

Quien reporta puede ayudar a revisar el parche. Cada hallazgo confirmado se
convierte en una regla determinista en `rules/` (*Extract → Codify → Scale*), así
el mismo patrón no vuelve a entrar.
