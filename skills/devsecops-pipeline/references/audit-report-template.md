# DevSecOps Pipeline Audit Report Template

Use this template when auditing an existing CI/CD pipeline for security.

---

## Report Structure

```markdown
# DevSecOps Pipeline Security Audit

**Project:** [Project Name]
**Date:** [Date]
**Auditor:** [Name / AI-assisted]
**Pipeline Platform:** [GitHub Actions / GitLab CI / Jenkins]

## Executive Summary

[2-3 sentences: overall security posture, critical findings count, recommendation priority]

## Scope

- Repository: [URL]
- Pipeline files audited: [list]
- Dockerfiles audited: [list]
- IaC files audited: [list]
- Date range of commits reviewed: [range]

## Findings

### CRITICAL

#### [FINDING-001] [Title]
- **Component:** [pipeline stage / file]
- **Description:** [What is wrong]
- **Impact:** [What could happen if exploited]
- **Evidence:** [Code snippet or log excerpt]
- **Remediation:** [Specific fix with code]
- **Reference:** [CIS / OWASP / tool docs link]

### HIGH

#### [FINDING-002] [Title]
[Same structure as above]

### MEDIUM

[...]

### LOW / INFO

[...]

## Security Scorecard

| Category | Status | Score |
|----------|--------|-------|
| Secret Scanning | ✅ / ⚠️ / ❌ | /10 |
| SAST | ✅ / ⚠️ / ❌ | /10 |
| Dependency Scanning | ✅ / ⚠️ / ❌ | /10 |
| Container Security | ✅ / ⚠️ / ❌ | /10 |
| IaC Security | ✅ / ⚠️ / ❌ | /10 |
| Branch Protection | ✅ / ⚠️ / ❌ | /10 |
| Secrets Management | ✅ / ⚠️ / ❌ | /10 |
| Deployment Safety | ✅ / ⚠️ / ❌ | /10 |
| Monitoring | ✅ / ⚠️ / ❌ | /10 |
| **Overall** | | **/90** |

## Recommendations (Priority Order)

1. [Highest impact fix]
2. [Second priority]
3. [...]

## Appendix

- Tool versions used
- Full scan reports (attached)
```
