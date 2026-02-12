---
name: devsecops-pipeline
description: Guides Claude through the complete DevSecOps pipeline lifecycle — from CI/CD design with GitHub Actions, infrastructure as code scanning, container security hardening, to production monitoring and alerting. Use this skill whenever the user mentions DevSecOps, CI/CD pipelines, security scanning in pipelines, SAST, DAST, container hardening, IaC security, shift-left security, deployment automation with security gates, or monitoring best practices. Also trigger when the user wants to audit Dockerfiles, review GitHub Actions workflows for security, harden Terraform configs, set up Bandit/Semgrep/Trivy scanning, or implement secure deployment patterns. This skill is especially useful for building security-first pipelines from scratch or auditing existing ones.
---

# DevSecOps Pipeline Skill

Build and audit security-first CI/CD pipelines. This skill encodes the methodology from Chapter 6 of *Learning DevSecOps* (Suehring) combined with real-world tooling patterns.

## Workflow Decision Tree

Determine what the user needs and follow the appropriate path:

```
User request
├── "Create a pipeline" → Go to: Pipeline Design
├── "Audit/review my pipeline" → Go to: Pipeline Audit
├── "Scan my code/container/IaC" → Go to: Security Scanning
├── "Harden my Docker/Terraform" → Go to: Hardening Patterns
├── "Set up monitoring/alerting" → Go to: Monitoring
└── "Help with deployment" → Go to: Secure Deployment
```

## Pipeline Design

When creating a new DevSecOps pipeline, follow this stage order. Every stage acts as a security gate — if it fails, the pipeline stops.

### Stage Architecture

```
[Commit] → [Secret Scan] → [SAST] → [Dependency Check] → [Build] → [Container Scan] → [IaC Scan] → [Deploy Staging] → [DAST] → [Deploy Prod] → [Monitor]
```

### Stage 1: Secret Detection (Pre-commit / First Gate)

Prevent credentials from entering the repository. This is the cheapest fix — catching secrets before they hit version control.

Tools: TruffleHog, Gitleaks, git-secrets
Platform: GitHub Actions with `trufflehog@main` and `gitleaks-action@v2`

Key patterns to detect: API keys, private keys, database passwords, cloud credentials, JWT secrets. Always scan full git history (`fetch-depth: 0`), not just the latest commit.

### Stage 2: Static Application Security Testing (SAST)

Analyze source code without executing it. This is the shift-left core — find bugs before they compile.

Tools by language:
- Python: Bandit (security-specific), Semgrep (multi-language rules)
- JavaScript/TypeScript: Semgrep, ESLint security plugins
- Go: gosec, Semgrep
- General: Semgrep with `--config auto` covers most languages

Bandit severity levels: use `-ll` flag to show only MEDIUM and above in CI. Use `-f json` for machine-readable reports and `-f screen` for human review.

Common Python findings: B608 (SQL injection via string formatting), B602 (subprocess with shell=True), B301 (pickle deserialization), B105 (hardcoded passwords), B201 (Flask debug=True).

### Stage 3: Dependency Scanning

Check third-party packages for known vulnerabilities (CVEs).

Tools: Safety (Python), npm audit (Node.js), OWASP Dependency-Check (Java/.NET)

Run against the lockfile, not just requirements.txt. Pin dependencies to specific versions. Set a severity threshold — fail the build on CRITICAL/HIGH, warn on MEDIUM.

### Stage 4: Build

Standard build step. Ensure reproducible builds with pinned dependencies and multi-stage Docker builds to minimize the final image attack surface.

### Stage 5: Container Security Scanning

Scan container images for OS-level and application-level vulnerabilities.

Tools: Trivy (recommended), Grype, Docker Scout

Trivy configuration for CI: Use `--severity CRITICAL,HIGH` as exit-code gate. Use `--format sarif` for GitHub Security tab integration. Always scan the built image, not the base image alone.

Complement with Hadolint for Dockerfile best practices: non-root user, HEALTHCHECK, minimal base image, no ADD (use COPY), pinned base image tags.

### Stage 6: Infrastructure as Code Scanning

Scan Terraform, CloudFormation, Kubernetes manifests for misconfigurations.

Tools: tfsec (Terraform), Checkov (multi-framework), KICS

Critical checks: SSH open to 0.0.0.0/0, unencrypted storage, missing logging, overly permissive IAM, public S3 buckets, missing metadata service v2 (IMDSv2).

### Stage 7: Deploy to Staging

Use the same deployment method as production but to a staging environment. This is where DAST runs.

### Stage 8: Dynamic Application Security Testing (DAST)

Test the running application for vulnerabilities from the outside.

Tools: OWASP ZAP (free), Burp Suite (commercial), Nuclei

Run against staging, never against production directly from CI. Focus on: injection flaws, authentication issues, security misconfiguration, XSS.

### Stage 9: Deploy to Production

Only if all previous gates pass. Use blue-green or canary deployment for rollback capability.

### Stage 10: Monitoring and Alerting

See the Monitoring section below.

## Pipeline Audit

When auditing an existing pipeline, check each of these areas and report findings with severity:

### Audit Checklist

1. **Secret scanning**: Is there a pre-commit or first-stage secret scanner? Does it scan full history?
2. **SAST coverage**: Are all languages in the repo covered? Are severity thresholds configured?
3. **Dependency scanning**: Are lockfiles scanned? Is there a policy for CRITICAL CVEs?
4. **Container security**: Are images scanned? Do Dockerfiles follow CIS benchmarks?
5. **IaC scanning**: Are Terraform/K8s manifests scanned before apply?
6. **Branch protection**: Is the main branch protected? Are reviews required?
7. **Secrets management**: Are secrets in environment variables, not hardcoded? Is a vault used?
8. **Deployment**: Is there a rollback mechanism? Are deployments gated on security checks?
9. **Monitoring**: Are security-relevant metrics being collected? Are alerts actionable?

### Report Format

For each finding, provide:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Finding**: What is the issue
- **Impact**: What could go wrong
- **Remediation**: Specific fix with code example
- **Reference**: CIS Benchmark, OWASP, or tool documentation link

## Security Scanning

Quick reference for running security tools locally or in CI:

```bash
# Python SAST
bandit -r src/ -ll -f json -o bandit-report.json

# Multi-language SAST
semgrep --config auto src/ --json -o semgrep-report.json

# Python dependencies
safety check -r requirements.txt

# Container scan
trivy image myapp:latest --severity HIGH,CRITICAL

# Dockerfile lint
hadolint Dockerfile

# Terraform scan
tfsec ./terraform/
checkov -d ./terraform/

# Secret detection
gitleaks detect --source . --verbose
```

## Hardening Patterns

### Docker Hardening Checklist

Apply these in every Dockerfile and docker-compose.yml:

Dockerfile:
- Multi-stage build (separate builder from runtime)
- Non-root user (create with useradd, switch with USER)
- Minimal base image (slim or alpine variants)
- HEALTHCHECK instruction
- No secrets in build args or layers
- COPY instead of ADD
- Pinned base image tags (not :latest)
- tini as PID 1 init

docker-compose.yml:
- `security_opt: [no-new-privileges:true]`
- `read_only: true` with tmpfs for writable paths
- `cap_drop: [ALL]` then add only what is needed
- Resource limits (memory + CPU)
- Bind ports to 127.0.0.1 or VPN interface only
- JSON file logging with size limits

### Terraform Hardening Checklist

- SSH ingress restricted to VPN CIDR, never 0.0.0.0/0
- EBS volumes encrypted (`encrypted = true`)
- IMDSv2 required (`http_tokens = "required"`)
- Detailed monitoring enabled
- Default tags for resource tracking
- Remote state with encryption (S3 + DynamoDB)
- No hardcoded credentials (use IAM roles or environment variables)

### Nginx with Mutual TLS

For services that need authenticated encryption between nodes:
- Generate own CA (do not use self-signed server certs alone)
- Server cert with SANs for IPs and hostnames
- Client cert for each authorized node
- `ssl_verify_client on` (mandatory client cert)
- TLS 1.3 only (`ssl_protocols TLSv1.3`)
- Security headers: HSTS, X-Frame-Options DENY, CSP, X-Content-Type-Options

## Monitoring

Based on operational best practices from the DevSecOps methodology:

### Principle 1: Visibility Enables Correction

If you can see it, you can fix it. Deploy dashboards visible to the entire team, not hidden in a tool only ops uses.

### Principle 2: Shift-Left Instrumentation

Enable verbose logging in dev/staging. Reduce to essential logging in production — excessive logging hurts performance and risks leaking PII.

### Principle 3: Right Metrics for the Right Component

Not all metrics matter equally for every system. Match metrics to function: disk I/O for databases, network throughput for firewalls, request latency for APIs, error rates for applications.

### Principle 4: Monitor Dependencies

A latency spike might be the upstream router, not the application. Correlate infrastructure metrics with application metrics across the full chain: network, server, application, database.

### Principle 5: Triage by User Impact

When multiple things break, fix what affects users first. Redirect traffic before root-cause analysis. Meet SLAs while investigating.

### Principle 6: Alerts Must Be Actionable

If an alert does not require human action, it is a log entry, not an alert. Eliminate informational alerts that cause alert fatigue. Target ratio: every alert equals required action.

## Resources

For detailed references, see:
- `references/github-actions-templates.md` — Copy-paste workflow templates
- `references/tool-configs.md` — Configuration snippets for each security tool
- `references/audit-report-template.md` — Template for security audit reports

For evaluating this skill, see `evals/evals.json`.
