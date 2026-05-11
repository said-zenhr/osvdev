# StackWatch

Self-hosted CVE monitoring for your stack. Watches a list of packages and pings your Slack channel the moment a new CVE drops for any of them.

Dependabot covers your repo dependencies. StackWatch covers everything else — your editor, your OS packages, your database, your identity provider, your terminal tools.

---

## Quick start

### GitHub Actions (recommended)

**1. Create `stack.yml` in your repo:**

```yaml
notifications:
  slack:
    webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"

packages:
  - name: rails
    ecosystem: RubyGems
    tier: critical
  - name: django
    ecosystem: PyPI
    tier: standard
```

**2. Add the workflow** (copy [`examples/github-actions.yml`](examples/github-actions.yml) to `.github/workflows/cve-monitor.yml`).

**3. Add your Slack webhook as a repo secret** named `STACKWATCH_SLACK_WEBHOOK`.

That's it. New CVEs appear in your Slack channel within hours of disclosure.

---

### Docker + cron

```bash
# Create your stack config
docker run --rm ghcr.io/yourorg/stackwatch:latest init > stack.yml
# Edit stack.yml

# Run manually
docker run --rm \
  -v $PWD/data:/data \
  -v $PWD/stack.yml:/app/stack.yml:ro \
  -e STACKWATCH_SLACK_WEBHOOK=https://hooks.slack.com/... \
  ghcr.io/yourorg/stackwatch:latest run

# Set up cron (see examples/crontab)
```

---

### Any CI (Bitbucket, GitLab, CircleCI, ...)

```yaml
# Bitbucket Pipelines example
- step:
    name: CVE Monitor
    script:
      - docker run --rm
          -v $BITBUCKET_CLONE_DIR:/work
          -e STACKWATCH_SLACK_WEBHOOK=$STACKWATCH_SLACK_WEBHOOK
          ghcr.io/yourorg/stackwatch:latest run --config /work/stack.yml --state-path /work/state.json
```

---

### Local dev

```bash
git clone https://github.com/yourorg/stackwatch.git
cd stackwatch
bundle install
bin/stackwatch init      # generate stack.yml
bin/stackwatch run       # run once
```

---

## `stack.yml` reference

```yaml
state_path: ./state.json        # where to store seen CVE IDs

notifications:
  slack:
    webhook_url: "${STACKWATCH_SLACK_WEBHOOK}"   # or set env var directly

filters:
  max_age_days: 30              # ignore CVEs older than 30 days (default).
                                # Set `false` to disable the age filter.

packages:
  - name: django
    ecosystem: PyPI
    tier: critical    # critical | standard
  - name: next
    ecosystem: npm
    tier: standard
```

**Tiers:**
- `critical` — posts with `@here` mention
- `standard` — silent post, no mention

**Filters:**
- `max_age_days` — drop vulnerabilities published more than N days ago. Defaults to `30`. Set to `false` to report every historical CVE OSV has ever seen for your packages (noisy). Withdrawn vulnerabilities are always skipped.

**Supported ecosystems:** any ecosystem supported by [osv.dev](https://osv.dev) — PyPI, npm, RubyGems, Go, Maven, Debian, Alpine, NuGet, Hex, crates.io, and more.

---

## Alert format

```
@here :rotating_light: New CVE for django (PyPI)
CVE-2024-27351 — CVSS 7.5
Potential regular expression denial of service vulnerability in Django
Affected: >=3.2.0   Patched: 3.2.25
View on osv.dev
```

---

## CLI reference

```
bin/stackwatch run [--config stack.yml] [--state-path state.json]
bin/stackwatch init [--force]
```

**Environment variables:**

| Variable | Description |
|---|---|
| `STACKWATCH_SLACK_WEBHOOK` | Slack Incoming Webhook URL |
| `STACKWATCH_STATE_PATH` | Override path to state.json |

---

## State storage

StackWatch persists seen CVE IDs to `state.json` so it only alerts on new findings. The file path is configurable.

**GitHub Actions:** use `actions/cache` (see [`examples/github-actions.yml`](examples/github-actions.yml)).  
**Cron/VPS:** a local file. Done.  
**Bitbucket/GitLab:** commit back via bot user, or upload as pipeline artifact.

---

## Architecture

```
stack.yml → Config → OSV querybatch → diff → Slack notify → state.json
```

- **No database.** State is a JSON file.
- **One HTTP round-trip** to osv.dev for all packages (uses `/v1/querybatch`).
- **Pluggable notifiers** — v1 ships Slack. Discord/webhook coming in v1.1.
- **Pluggable sources** — v1 ships osv.dev. RSS feeds and GitHub Advisory DB coming in v1.1.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and PRs welcome.

---

## License

MIT — see [LICENSE](LICENSE).
