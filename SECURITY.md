# Security

Please do not report vulnerabilities by opening a public issue when sensitive details or credentials are involved.

## Security principles

- Never commit cloud credentials, access tokens, private keys, kubeconfigs, or secrets.
- Use Workload Identity Federation for Google Cloud access.
- Store GitHub credentials in Secret Manager.
- Keep Kubernetes permissions read-only for the agent.
- Require human approval for GitOps remediation.
- Keep remediation adapters deterministic and narrowly scoped.

If you discover a security issue, use the repository's private security reporting mechanism when available.
