# Security Tool Configurations

Quick-reference configs for each tool in the DevSecOps pipeline.

## Table of Contents
1. Bandit
2. Semgrep
3. Trivy
4. Hadolint
5. tfsec
6. Gitleaks

---

## 1. Bandit — Python SAST

### .bandit.yml
```yaml
# Bandit configuration
skips:
  - B101  # assert_used (OK in tests)

exclude_dirs:
  - tests
  - .venv
  - node_modules

# Severity: only fail on MEDIUM+
severity: MEDIUM
confidence: MEDIUM
```

### CLI usage
```bash
# Quick scan
bandit -r src/ -ll

# CI mode (JSON output, fail on issues)
bandit -r src/ -f json -o report.json --exit-zero
bandit -r src/ -ll --severity-level medium
```

### Key test IDs
| ID | Description | Severity |
|----|-------------|----------|
| B105 | Hardcoded password string | LOW |
| B106 | Hardcoded password as argument | LOW |
| B301 | Pickle usage | MEDIUM |
| B602 | subprocess with shell=True | HIGH |
| B608 | SQL injection (string formatting) | MEDIUM |
| B201 | Flask debug=True | HIGH |

---

## 2. Semgrep — Multi-language SAST

### .semgrep.yml (custom rules)
```yaml
rules:
  - id: hardcoded-api-key
    pattern: |
      $KEY = "sk-..."
    message: "Potential API key hardcoded"
    languages: [python, javascript]
    severity: ERROR

  - id: no-eval
    pattern: eval(...)
    message: "eval() is dangerous — use ast.literal_eval() for Python"
    languages: [python]
    severity: WARNING
```

### CLI usage
```bash
# Auto config (uses Semgrep registry rules)
semgrep --config auto .

# Specific rulesets
semgrep --config p/python --config p/security-audit .

# JSON output for CI
semgrep --config auto . --json -o semgrep.json
```

---

## 3. Trivy — Container Scanner

### trivy.yaml
```yaml
severity:
  - CRITICAL
  - HIGH

exit-code: 1

ignore-unfixed: true

# Skip specific CVEs if accepted risk
ignorefile: .trivyignore
```

### .trivyignore
```
# Accepted risks (document why)
CVE-2023-XXXXX  # No fix available, mitigated by network policy
```

### CLI usage
```bash
# Scan image
trivy image myapp:latest --severity HIGH,CRITICAL

# Scan filesystem (source code)
trivy fs . --severity HIGH,CRITICAL

# SARIF output for GitHub
trivy image myapp:latest --format sarif -o trivy.sarif
```

---

## 4. Hadolint — Dockerfile Linter

### .hadolint.yaml
```yaml
ignored:
  - DL3008  # Pin versions in apt-get (sometimes impractical)

trustedRegistries:
  - docker.io
  - gcr.io

override:
  error:
    - DL3000  # Use absolute WORKDIR
    - DL3002  # Do not switch to root
  warning:
    - DL3042  # Avoid cache directory with pip
```

### CLI usage
```bash
hadolint Dockerfile
hadolint --format json Dockerfile > hadolint.json
```

---

## 5. tfsec — Terraform Scanner

### .tfsec/config.yml
```yaml
severity_overrides:
  AWS009: LOW  # Override if behind VPN

exclude:
  - aws-vpc-no-public-ingress  # Managed by security group rules
```

### CLI usage
```bash
tfsec .
tfsec . --format json -o tfsec.json
tfsec . --minimum-severity HIGH
```

---

## 6. Gitleaks — Secret Detection

### .gitleaks.toml
```toml
[extend]
useDefault = true

[[rules]]
id = "custom-api-key"
description = "Custom API Key Pattern"
regex = '''(?i)mantishield[_-]?api[_-]?key\s*=\s*['"][^'"]+['"]'''
secretGroup = 0
entropy = 3.5

[allowlist]
paths = [
  '''\.env\.example''',
  '''tests/.*''',
]
```

### CLI usage
```bash
# Scan current state
gitleaks detect --source . --verbose

# Scan git history
gitleaks detect --source . --verbose --log-opts="--all"

# Pre-commit hook
gitleaks protect --staged --verbose
```
