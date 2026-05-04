# StackWatch Usage Guide

## Running locally without Slack

StackWatch works without Slack for local testing. Just omit the `notifications` block from your `stack.yml`:

```yaml
state_path: ./state.json

packages:
  - name: react
    ecosystem: npm
    tier: standard
```

Then run:

```bash
bundle exec ruby -Ilib exe/stackwatch run --config stack.yml
```

You will see CVE IDs printed to stdout, but nothing will be posted to Slack.

---

## First run vs. subsequent runs

**First run** discovers the full historical backlog for every package you monitor. This can be noisy:

```
[CRITICAL] GHSA-9822-6m93-xqf4 — RubyGems/rails
[STANDARD] GHSA-2655-q453-22f9 — PyPI/django
...
StackWatch: 325 new vulnerabilities found.
```

This is expected — StackWatch has never seen these CVE IDs before, so they are all "new" to it.

**Second run** (and every run after) will only show CVEs that were disclosed *since the last run*:

```
StackWatch: 0 new vulnerabilities found.
```

The `state.json` file persists seen CVE IDs so you only get alerted on truly new findings.

---

## Simulating a background job manually

StackWatch has no built-in scheduler. It runs once and exits. To simulate a cron job or CI schedule locally, just run it whenever you want:

```bash
# Check now
bundle exec ruby -Ilib exe/stackwatch run

# Check again in an hour
bundle exec ruby -Ilib exe/stackwatch run

# Check with a different config
bundle exec ruby -Ilib exe/stackwatch run --config ./my-stack.yml
```

For CI/CD, invoke it on whatever schedule your platform supports (GitHub Actions `schedule`, GitLab CI `only: schedules`, etc.).

---

## State file

`state.json` is a small JSON file that tracks which CVE IDs StackWatch has already seen:

```json
{
  "version": 1,
  "updated_at": "2026-05-05T09:00:00Z",
  "packages": {
    "npm/react": ["GHSA-...", "GHSA-..."],
    "PyPI/django": ["GHSA-...", "PYSEC-..."]
  }
}
```

- **Size:** typically a few KB per package. Even 200 packages with 100 CVEs each would be under 100 KB.
- **Location:** configurable via `state_path` in `stack.yml`, `--state-path` CLI flag, or `STACKWATCH_STATE_PATH` env var.
- **Persistence:** you are responsible for persisting this file between runs (e.g., `actions/cache` in GitHub Actions, a volume mount in Docker, or just a local file on your machine).
- **Reset:** delete the file to start fresh. Next run will re-discover the full backlog.

---

## CLI reference

### `stackwatch run`

Query CVEs for your stack and alert on new ones.

```bash
# Use default stack.yml and state.json
stackwatch run

# Use custom paths
stackwatch run --config ./config/stack.yml --state-path ./data/state.json

# Override state path only
stackwatch run --state-path /tmp/stackwatch-state.json
```

**Exit codes:**
- `0` — success (0 or more new vulnerabilities found)
- `1` — configuration error, OSV API error, or Slack notification failure

### `stackwatch init`

Generate a starter `stack.yml` in the current directory.

```bash
stackwatch init
stackwatch init --force   # overwrite existing stack.yml
```

---

## Environment variables

| Variable | Description |
|---|---|
| `STACKWATCH_SLACK_WEBHOOK` | Slack Incoming Webhook URL (optional — omit for local testing) |
| `STACKWATCH_STATE_PATH` | Override path to `state.json` |

---

## Troubleshooting

### "Slack webhook URL not configured" error

Either:
- Add `notifications.slack.webhook_url` to `stack.yml`
- Set `STACKWATCH_SLACK_WEBHOOK` environment variable
- Or remove the `notifications` block entirely to run without Slack

### First run is very noisy

Expected. StackWatch discovers the full historical CVE backlog on its first run. The second run will be silent unless a new CVE is disclosed.

### "OSV API error" or timeout

OSV.dev may occasionally return errors or time out. The default timeout is 15 seconds. Just retry the run.

### Duplicate alerts

This usually means `state.json` was not persisted between runs. Make sure the file is written to durable storage (local disk, CI cache, mounted volume, etc.) and read back on the next invocation.
