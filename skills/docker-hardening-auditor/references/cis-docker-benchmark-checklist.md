# CIS Docker Benchmark Checklist for Dockerfile Auditing

Based on CIS Docker Benchmark v1.6.0 — Container Images and Build File sections.

## Section 4: Container Images and Build File

### 4.1 Ensure a user for the container has been created (Scored)

**Level:** 1
**Severity:** CRITICAL

Creating a non-root user reduces the attack surface. If the container process is compromised, the attacker has limited privileges.

Check: Verify `USER` instruction exists and is not `root`.

```dockerfile
# NON-COMPLIANT
FROM python:3.12-slim
COPY . /app
CMD ["python", "app.py"]

# COMPLIANT
FROM python:3.12-slim
RUN groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin appuser
COPY --chown=appuser:appuser . /app
USER appuser
CMD ["python", "app.py"]
```

### 4.2 Ensure that containers use only trusted base images (Scored)

**Level:** 1
**Severity:** HIGH

Use official images or images from verified publishers. Pin to a specific version tag and ideally a digest.

Check: Verify `FROM` uses a specific tag (not `latest` or untagged).

```dockerfile
# NON-COMPLIANT
FROM python
FROM python:latest

# COMPLIANT
FROM python:3.12-slim
FROM python:3.12-slim@sha256:abcdef1234567890
```

### 4.3 Ensure that unnecessary packages are not installed (Scored)

**Level:** 1
**Severity:** LOW

Reduce attack surface by not installing packages the application does not need.

Check: Verify `--no-install-recommends` is used with `apt-get install`. Verify no unnecessary development packages remain in the final image.

### 4.4 Ensure images are scanned for vulnerabilities (Not Scored)

**Level:** 1
**Severity:** MEDIUM

Scan images with Trivy, Grype, or Docker Scout before deployment.

### 4.5 Ensure Content trust for Docker is enabled (Scored)

**Level:** 2
**Severity:** MEDIUM

Set `DOCKER_CONTENT_TRUST=1` to require signed images.

### 4.6 Ensure HEALTHCHECK instructions have been added (Scored)

**Level:** 1
**Severity:** MEDIUM

HEALTHCHECK enables the Docker daemon and orchestrators to monitor the application health inside the container.

Check: Verify `HEALTHCHECK` instruction exists.

```dockerfile
# NON-COMPLIANT
FROM python:3.12-slim
COPY . /app
CMD ["python", "app.py"]

# COMPLIANT
FROM python:3.12-slim
COPY . /app
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
CMD ["python", "app.py"]
```

### 4.7 Ensure update instructions are not used alone (Not Scored)

**Level:** 1
**Severity:** LOW

`RUN apt-get update` alone in a layer gets cached and becomes stale. Always combine with install in the same RUN instruction.

```dockerfile
# NON-COMPLIANT
RUN apt-get update
RUN apt-get install -y curl

# COMPLIANT
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
```

### 4.8 Ensure setuid and setgid permissions are removed (Not Scored)

**Level:** 2
**Severity:** MEDIUM

Remove setuid/setgid binaries to prevent privilege escalation.

```dockerfile
RUN find / -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true
```

### 4.9 Ensure that COPY is used instead of ADD (Scored)

**Level:** 1
**Severity:** LOW

`ADD` has implicit extraction and URL download behavior that can introduce unexpected file content.

Check: Verify no `ADD` instructions are used for local files (ADD is acceptable for tar extraction when intentional).

### 4.10 Ensure secrets are not stored in Dockerfiles (Scored)

**Level:** 1
**Severity:** CRITICAL

Secrets in `ENV`, `ARG`, `LABEL`, or `RUN echo` commands are visible in image history and layer inspection.

Check: Verify no ENV/ARG contains passwords, tokens, API keys, or credentials.

Keywords to flag: PASSWORD, SECRET, TOKEN, API_KEY, PRIVATE_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, CREDENTIAL, DATABASE_URL with embedded credentials.

### 4.11 Ensure verified packages only are installed (Not Scored)

**Level:** 2
**Severity:** MEDIUM

Use `--no-cache-dir` with pip, verify checksums for downloaded binaries, use `apt-get install --allow-authenticated` cautiously.

## Additional Hardening (Beyond CIS)

### Multi-Stage Builds

Separate build and runtime stages to exclude compilers, source code, and build artifacts from the final image.

### Minimal Base Images

Prefer `-slim` or `-alpine` variants. Full images contain hundreds of unnecessary packages.

| Base Image | Approximate Size | Packages |
|------------|-----------------|----------|
| python:3.12 | ~900MB | ~400+ |
| python:3.12-slim | ~130MB | ~100 |
| python:3.12-alpine | ~50MB | ~30 |

### Port Exposure

Only expose ports the application actively listens on. Do not expose debug, SSH, or database ports in production images.

Dangerous ports to flag: 22 (SSH), 2375/2376 (Docker daemon), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 11211 (Memcached), 27017 (MongoDB).

### Init Process (PID 1)

Use `tini` or `--init` flag so signals are properly forwarded to the application process.

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["tini", "--"]
CMD ["python", "app.py"]
```
