# Contribuir a Auditgate

Gracias por sumarte. Auditgate crece igual que funciona: **cada hallazgo validado se
convierte en una regla con tests**, y esa regla protege a todos los que usan la plataforma.

## La contribución más valiosa: una regla nueva

1. **Abre un issue con la plantilla "Nueva regla"**: el patrón, un ejemplo vulnerable y uno seguro.
2. **Escribe la regla** en `src/auditgate/rules/<lenguaje>/auditgate-<tema>.yml`:
   - `id: auditgate.<lenguaje>.<nombre>`
   - `severity: ERROR` solo si debe **bloquear** un PR; `WARNING` si solo reporta.
   - `metadata` con `cwe`, `owasp` y `origin` (de dónde salió el patrón).
3. **Escribe el fixture** con el mismo nombre de archivo y la extensión del lenguaje:
   - `# ruleid: <id>` en la línea anterior a cada caso que **debe** disparar.
   - `# ok: <id>` en la línea anterior a cada caso que **no** debe disparar (incluye el fix).
4. **Prueba en local**:
   ```bash
   semgrep --test --metrics=off src/auditgate/rules/
   semgrep scan --metrics=off --config src/auditgate/rules/ vulnerable_app/   # no debe romper app_secure.py
   auditgate scan --base main          # el mismo gate que corre en el PR
   ```
5. Abre el PR. El gate exige que los tests de las reglas pasen.

**Reglas para otros lenguajes son especialmente bienvenidas.** Hoy hay reglas propias para
Python y Node.js; para Go, Java, Ruby, PHP, etc. Auditgate depende del registro de Semgrep.
Crea `src/auditgate/rules/<lenguaje>/` con tu regla y su fixture: la cobertura se detecta sola.

Una regla ERROR que genera ruido hace más daño que no tenerla: el gate pierde credibilidad.
Si dudas, empieza en `WARNING`.

## Otras contribuciones

- **Workflows** (`.github/workflows/`): toda action se fija por **SHA de 40 caracteres** con
  el tag en un comentario (`uses: owner/action@<sha> # vX.Y.Z`). El pipeline se audita a sí
  mismo y rechaza actions sin fijar. Pide solo los `permissions` que el job necesita.
- **Agentes** (`src/auditgate/`, `agents/taskflows/`): un agente **nunca** bloquea ni decide un merge.
  El contenido del repo es dato no confiable (prompt injection) y la salida es estructurada.
- **Docs**: español e inglés son bienvenidos.

## Excepciones (`nosemgrep`)

Cada excepción lleva la regla exacta y una justificación revisable:
```python
# nosemgrep: auditgate.flask.untrusted-input-to-dangerous-sink -- ruta resuelta y confinada a BASE_DIR
```
Nunca un `nosemgrep` sin regla ni motivo.

## Reportar vulnerabilidades

No abras issues públicos: sigue [`SECURITY.md`](SECURITY.md).

## Conducta

Este proyecto adopta el [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Ver [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
