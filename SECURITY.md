# Security policy

## Secrets that must never be committed

- VPS passwords and SSH private keys;
- AmneziaWG `PrivateKey` and `PresharedKey`;
- exported Amnezia connection profiles;
- real deployment endpoint inventory if it is considered sensitive;
- the user's route list and generated `dist/` release.

The repository ignores common secret/profile names, `config/deployment.env`, route files and generated artifacts. `.gitignore` is not a security boundary: always inspect the staged diff.

```bash
git status --short
git diff --cached --stat
git diff --cached
git grep -n -I -E '(PrivateKey|PresharedKey|BEGIN .*PRIVATE KEY|password[[:space:]]*=)'
```

Search the complete history before publishing if a secret was ever staged or committed. Deleting the file in a later commit does not remove it from Git history; rotate the secret and rewrite history.

## Runtime permissions

Expected modes:

- `/opt/amnezia-lb-v2/secrets`: `0700`;
- `/opt/amnezia-lb-v2/secrets/awg-main.conf`: `0600`;
- `/opt/amnezia-lb-multi-v3/secrets`: `0700`;
- egress profiles: `0600`;
- state lock/maintenance files: `0600`.

## Privilege model

The installer and runtime require root, `CAP_NET_ADMIN`, `/dev/net/tun`, Docker socket access, policy routing and firewall changes. Treat the code and generated release as privileged infrastructure. Review a commit before executing it and pin the commit used in production.

## Reporting a vulnerability

Do not open a public issue containing credentials, keys, full configs or route lists. Contact the repository owner privately and provide only the minimum redacted diagnostics required to reproduce the problem.
