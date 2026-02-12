# GitHub Actions — DevSecOps Templates

Copy-paste templates for common DevSecOps pipeline patterns.

## Table of Contents
1. Minimal Security Pipeline
2. Full DevSecOps Pipeline
3. Container-Only Scan
4. Terraform Security Gate
5. PR Security Review

---

## 1. Minimal Security Pipeline

The simplest useful security pipeline. Good starting point for any project.

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Secret scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: SAST
        run: |
          pip install bandit semgrep
          bandit -r . -ll -f screen || true
          semgrep --config auto . || true
```

## 2. Full DevSecOps Pipeline

Complete pipeline with all security gates. See the main repo's
`.github/workflows/devsecops-pipeline.yml` for the full implementation.

Key structure:
```
secret-scan → sast → container-security → iac-security → notify
```

Each job uses `needs:` to enforce gate ordering. The notify job uses
`if: always()` to report even on failure.

## 3. Container-Only Scan

For repos that primarily ship Docker images:

```yaml
name: Container Scan
on:
  push:
    paths: ["Dockerfile", "docker-compose*.yml", "docker/**"]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t app:scan .

      - uses: aquasecurity/trivy-action@master
        with:
          image-ref: "app:scan"
          severity: "CRITICAL,HIGH"
          exit-code: "1"

      - uses: hadolint/hadolint-action@v3.1.0
        with:
          dockerfile: Dockerfile
```

## 4. Terraform Security Gate

Block merges if Terraform has security issues:

```yaml
name: IaC Security
on:
  pull_request:
    paths: ["terraform/**", "*.tf"]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: aquasecurity/tfsec-action@v1.0.0
        with:
          working_directory: terraform/

      - uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          soft_fail: false
```

## 5. PR Security Review

Automatically comment on PRs with security findings:

```yaml
name: PR Security Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: actions/checkout@v4

      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config auto . --json > semgrep.json || true

      - name: Comment on PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const results = JSON.parse(fs.readFileSync('semgrep.json'));
            const count = results.results?.length || 0;
            if (count > 0) {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: `🔒 **Security Scan**: Found ${count} finding(s). Please review before merging.`
              });
            }
```
