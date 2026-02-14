---
name: docker-hardening-auditor
description: Audits Dockerfiles for security misconfigurations and hardening gaps based on the CIS Docker Benchmark. Use this skill when the user asks to review, audit, harden, or secure a Dockerfile. Detects running as root, latest tag usage, secrets in ENV, unnecessary exposed ports, missing HEALTHCHECK, missing USER instruction, heavy base images, use of ADD instead of COPY, missing no-install-recommends, and other container security anti-patterns. Provides severity-rated findings with specific remediation code for each issue.
---

# Docker Hardening Auditor Skill

Audit Dockerfiles against the CIS Docker Benchmark and container security best practices. This skill systematically checks for misconfigurations that lead to privilege escalation, supply chain attacks, secret exposure, and unnecessarily large attack surfaces.

## Workflow

```
User provides Dockerfile
├── Parse all instructions
├── Run each check from the checklist
├── Classify findings by severity (CRITICAL / HIGH / MEDIUM / LOW)
├── Generate remediation for each finding
└── Output hardened Dockerfile
```

## Audit Checks

When auditing a Dockerfile, evaluate every instruction against the checks below. Report each finding with its severity, the offending line, and a corrected version.

### CHECK 1: Running as Root (CRITICAL)

If the Dockerfile has no `USER` instruction, the container runs as root by default. This is the single most impactful container hardening step.

What to look for:
- No `USER` instruction anywhere in the Dockerfile
- `USER root` set without switching back to a non-root user before `CMD`/`ENTRYPOINT`

Remediation:
```dockerfile
RUN groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin appuser
USER appuser
```

### CHECK 2: Latest Tag on Base Image (HIGH)

Using `:latest` or no tag at all means the build is not reproducible and may pull a compromised or breaking image without warning.

What to look for:
- `FROM image` (no tag)
- `FROM image:latest`

Remediation: Pin to a specific version and use digest when possible.
```dockerfile
FROM python:3.12-slim@sha256:<digest>
```

### CHECK 3: Secrets in ENV or ARG (CRITICAL)

Environment variables and build arguments are stored in image layers and visible via `docker inspect` or `docker history`. Never put passwords, API keys, or tokens in ENV/ARG.

What to look for:
- `ENV` lines containing: PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, CREDENTIAL, AWS_ACCESS, AWS_SECRET
- `ARG` lines with the same patterns
- Any `ENV` with a value that looks like a credential (long random strings, base64-encoded values)

Remediation: Use Docker secrets, mount secrets at runtime, or use BuildKit secret mounts.
```dockerfile
# Build-time secret (BuildKit)
RUN --mount=type=secret,id=api_key cat /run/secrets/api_key
# Runtime secret
# Pass via docker run --env-file or orchestrator secrets
```

### CHECK 4: Unnecessary Exposed Ports (MEDIUM)

Exposing ports that the application does not need increases the attack surface. Especially watch for management/debug ports.

What to look for:
- `EXPOSE` with multiple ports when only one is needed
- Known dangerous ports: 22 (SSH), 3389 (RDP), 5900 (VNC), 2375/2376 (Docker API), 6379 (Redis), 11211 (Memcached)
- Debug ports: 5005 (Java debug), 9229 (Node.js debug), 4200 (Angular dev)

Remediation: Only expose the port the application listens on.
```dockerfile
EXPOSE 8080
```

### CHECK 5: Missing HEALTHCHECK (MEDIUM)

Without HEALTHCHECK, the orchestrator cannot detect if the application inside the container has crashed or become unresponsive. The container stays in "running" state even if the app is dead.

What to look for:
- No `HEALTHCHECK` instruction in the entire Dockerfile

Remediation:
```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
```

### CHECK 6: Heavy Base Image (LOW)

Full OS images (ubuntu, debian, python:3.x) include hundreds of packages the application does not need. Each extra package is an additional CVE surface.

What to look for:
- `FROM ubuntu` or `FROM debian` (not slim)
- `FROM python:3.x` (not slim or alpine)
- `FROM node:xx` (not slim or alpine)
- `FROM openjdk:xx` (not slim)

Remediation: Use minimal variants.
```dockerfile
FROM python:3.12-slim
# or
FROM python:3.12-alpine
```

### CHECK 7: ADD Instead of COPY (LOW)

`ADD` has implicit tar extraction and URL download capabilities that can introduce unexpected behavior. Use `COPY` for simple file copying.

What to look for:
- `ADD` instruction used for local files (not `.tar.gz`)

Remediation:
```dockerfile
COPY requirements.txt .
COPY . /app
```

### CHECK 8: No Multi-Stage Build (MEDIUM)

Single-stage builds include build tools, compilers, and source code in the final image. Multi-stage builds reduce image size and attack surface.

What to look for:
- Only one `FROM` instruction
- Build tools installed (gcc, make, build-essential) present in the final image

Remediation:
```dockerfile
FROM python:3.12-slim AS builder
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim
COPY --from=builder /install /usr/local
COPY . /app
USER appuser
CMD ["python", "app.py"]
```

### CHECK 9: Package Cache Not Cleaned (LOW)

Leaving package manager caches in the image increases its size unnecessarily.

What to look for:
- `RUN apt-get install` without `&& rm -rf /var/lib/apt/lists/*`
- `RUN pip install` without `--no-cache-dir`
- `RUN apk add` without `--no-cache`

Remediation:
```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
```

## Output Format

For each finding, produce:

```
### [SEVERITY] Finding Title

- **Line:** `<Dockerfile instruction>`
- **Issue:** What is wrong and why it matters
- **CIS Reference:** Section number from CIS Docker Benchmark
- **Remediation:** Corrected instruction
```

After all findings, provide the complete hardened Dockerfile with all fixes applied.

## Resources

For detailed references, see:
- `references/cis-docker-benchmark-checklist.md` — Full checklist based on CIS Docker Benchmark v1.6

For evaluating this skill, see `evals/evals.json`.
