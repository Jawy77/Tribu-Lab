# 🎓 Guía: Cómo Crear, Auditar y Publicar Skills para Claude Code

## Taller DevSecOps — Tribu | Hacklab Bogota | Ethereum Bogota

> Esta guía enseña a crear skills profesionales para Claude Code,
> auditarlos por calidad, y empaquetarlos para el Marketplace de Anthropic.

---

## ¿Qué es un Skill?

Un skill es un paquete de instrucciones que le enseña a Claude Code
cómo hacer algo específico. Piénsalo como un manual de procedimientos
que Claude consulta automáticamente cuando detecta que lo necesita.

```
skill-name/
├── SKILL.md          ← Instrucciones principales (OBLIGATORIO)
├── scripts/          ← Código ejecutable (opcional)
├── references/       ← Documentación de consulta (opcional)
├── assets/           ← Archivos para usar en outputs (opcional)
└── evals/            ← Casos de prueba (opcional pero recomendado)
```

## Paso 1: Definir el Propósito

Antes de escribir una línea, responde estas preguntas:

1. **¿Qué debe poder hacer Claude con este skill?**
   Ejemplo: "Crear y auditar pipelines CI/CD con seguridad integrada"

2. **¿Cuándo debe activarse?**
   Ejemplo: "Cuando el usuario mencione DevSecOps, CI/CD, SAST, 
   container scanning, o pipeline security"

3. **¿Cuál es el formato de salida esperado?**
   Ejemplo: "Archivos YAML de GitHub Actions, reportes de auditoría,
   Dockerfiles hardened"

## Paso 2: Crear el SKILL.md

### Frontmatter (Metadatos YAML)

El frontmatter es lo primero que Claude lee. Es lo que decide si
activa el skill o no.

```yaml
---
name: mi-skill-nombre        # kebab-case, max 64 chars
description: >                # max 1024 chars — SÉ AGRESIVO aquí
  Descripción completa de qué hace el skill Y cuándo debe activarse.
  Incluye todos los sinónimos y contextos posibles. Si Claude no 
  activa tu skill, es porque la descripción no es suficientemente
  explícita. Mejor que sobre a que falte.
---
```

### Reglas del Frontmatter

| Campo | Obligatorio | Reglas |
|-------|:-----------:|--------|
| name | ✅ | kebab-case, a-z 0-9 y guiones, max 64 chars |
| description | ✅ | Sin < o >, max 1024 chars |
| license | ❌ | Texto libre |
| allowed-tools | ❌ | Lista de herramientas permitidas |
| compatibility | ❌ | Dependencias necesarias, max 500 chars |
| metadata | ❌ | Metadatos adicionales |

### Propiedades NO permitidas en frontmatter

Cualquier propiedad fuera de las listadas arriba causa error de validación.

### Cuerpo del SKILL.md

Organiza el contenido usando uno de estos patrones:

**Patrón Workflow** (para procesos secuenciales):
```markdown
## Workflow Decision Tree
## Paso 1: Análisis
## Paso 2: Implementación
## Paso 3: Verificación
```

**Patrón Task** (para colecciones de herramientas):
```markdown
## Tarea 1: Escanear código
## Tarea 2: Escanear containers
## Tarea 3: Auditar IaC
```

**Patrón Reference** (para estándares):
```markdown
## Directrices
## Especificaciones
## Ejemplos
```

### Buenas Prácticas de Escritura

- Usa imperativo: "Escanea el código" no "Se debería escanear"
- Incluye ejemplos concretos con input/output
- Explica el POR QUÉ, no solo el QUÉ
- Mantén SKILL.md bajo 500 líneas
- Si necesitas más contenido, ponlo en `references/`
- Referencia los archivos de references/ desde SKILL.md con
  instrucciones claras de cuándo leerlos

## Paso 3: Agregar References (Opcional)

Los references son documentos que Claude carga bajo demanda.
Solo se leen cuando el SKILL.md los referencia explícitamente.

```markdown
## Resources

Para templates de GitHub Actions, consulta:
- `references/github-actions-templates.md`

Para configuraciones de herramientas de seguridad:
- `references/tool-configs.md`
```

Reglas para references:
- Si un reference tiene más de 300 líneas, incluye tabla de contenidos
- Organiza por dominio cuando hay variantes (aws.md, gcp.md, azure.md)
- Claude lee solo el reference relevante, no todos

## Paso 4: Agregar Scripts (Opcional)

Scripts ejecutables que Claude puede correr directamente:

```python
#!/usr/bin/env python3
"""
Script para generar certificados mTLS.
Claude ejecuta este script directamente.
"""

import subprocess
import sys

def generate_certs(output_dir):
    # ... implementación
    pass

if __name__ == "__main__":
    generate_certs(sys.argv[1] if len(sys.argv) > 1 else "./certs")
```

Los scripts se ejecutan sin cargarse en contexto, pero Claude
puede leerlos si necesita modificarlos.

## Paso 5: Crear Evaluaciones

Las evaluaciones verifican que el skill funciona correctamente.

### Estructura de evals.json

```json
{
  "skill_name": "mi-skill",
  "evals": [
    {
      "id": 1,
      "prompt": "Lo que diría un usuario real",
      "expected_output": "Descripción del resultado esperado",
      "files": [],
      "assertions": [
        "El output incluye X",
        "El skill maneja correctamente Y",
        "No incluye Z"
      ]
    }
  ]
}
```

### Tips para buenos evals

- Usa prompts realistas (como hablaría un usuario de verdad)
- Incluye al menos 3-5 casos
- Cubre el happy path Y los edge cases
- Las assertions deben ser verificables objetivamente

## Paso 6: Validar el Skill

Antes de empaquetar, valida la estructura:

```bash
# Validación rápida (verifica frontmatter y estructura)
python quick_validate.py path/to/mi-skill/

# Debe mostrar: "Skill is valid!"
```

### Errores comunes de validación

| Error | Causa | Fix |
|-------|-------|-----|
| "No YAML frontmatter" | Falta `---` al inicio | Agregar frontmatter YAML |
| "Missing 'name'" | No hay campo name | Agregar `name:` |
| "should be kebab-case" | Mayúsculas o espacios | Usar solo a-z, 0-9, - |
| "Unexpected key(s)" | Campo no permitido | Revisar campos permitidos |
| "cannot contain angle brackets" | < o > en description | Remover < y > |

## Paso 7: Empaquetar para Marketplace

### Crear el archivo .skill

```bash
# El archivo .skill es un ZIP con estructura específica
python package_skill.py path/to/mi-skill/ ./dist/

# Output: ./dist/mi-skill.skill
```

### Qué incluye el .skill

- SKILL.md + frontmatter
- scripts/, references/, assets/
- NO incluye: evals/, __pycache__, .DS_Store, node_modules

### Instalar un .skill localmente

Los usuarios pueden instalar el .skill directamente en Claude Code
para probarlo antes de que esté en el marketplace.

## Auditoría de Skills

### Checklist de Auditoría

Cuando revises un skill (tuyo o de otros), verifica:

**Estructura:**
- [ ] SKILL.md existe y tiene frontmatter válido
- [ ] name es kebab-case, max 64 chars
- [ ] description es clara y < 1024 chars
- [ ] description incluye cuándo activarse (triggers)
- [ ] No hay campos no permitidos en frontmatter

**Contenido:**
- [ ] SKILL.md tiene < 500 líneas
- [ ] Instrucciones usan imperativo
- [ ] Incluye ejemplos concretos
- [ ] References tienen tabla de contenidos si > 300 líneas
- [ ] No contiene malware, exploits, o contenido malicioso

**Calidad:**
- [ ] El skill resuelve un problema real
- [ ] Las instrucciones son claras para un modelo de IA
- [ ] Los edge cases están cubiertos
- [ ] Hay evals con assertions verificables
- [ ] El skill no se solapa excesivamente con skills existentes

**Seguridad:**
- [ ] No hay secrets hardcodeados
- [ ] Scripts no descargan código de fuentes no confiables
- [ ] No hay instrucciones que bypaseen restricciones de seguridad
- [ ] El skill no intenta exfiltrar datos

### Ejemplo de Auditoría

```
AUDITORÍA: devsecops-pipeline skill

✅ Estructura válida (frontmatter OK, kebab-case, < 1024 chars)
✅ SKILL.md: 180 líneas (bajo el límite de 500)
✅ Description incluye triggers explícitos
✅ 3 references con contenido relevante
✅ 5 eval cases con assertions claras
⚠️  MEJORA: Agregar más edge cases en evals (fuzzy inputs)
⚠️  MEJORA: Reference tool-configs.md podría tener TOC
✅ Sin problemas de seguridad detectados

SCORE: 8.5/10
```

## Demo en Vivo: Crear un Skill desde Cero

### Con Claude Code CLI

```bash
# 1. Pedirle a Claude Code que cree el skill
claude "Crea un skill para auditar Dockerfiles que detecte
las 10 vulnerabilidades más comunes según CIS Docker Benchmark.
Incluye evals con 3 casos de prueba."

# 2. Claude Code creará la estructura automáticamente

# 3. Validar
python quick_validate.py ./mi-skill/

# 4. Probar con un eval
claude -p "Audita este Dockerfile: FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY . /app
CMD python3 /app/main.py"

# 5. Empaquetar
python package_skill.py ./mi-skill/ ./dist/
```

### Con Claude Web (esta interfaz)

Puedes pedirle a Claude que genere el skill completo en esta
conversación. Claude creará todos los archivos y los empaquetará.

---

## Recursos Adicionales

- [Anthropic Skills Documentation](https://docs.anthropic.com)
- [Claude Code CLI](https://docs.anthropic.com/en/docs/claude-code)
- Skill Creator oficial: disponible como skill de ejemplo en Claude Code
