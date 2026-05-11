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
bin/stackwatch run --config stack.yml
```

You will see CVE IDs printed to stdout, but nothing will be posted to Slack.

---

## First run vs. subsequent runs

By default, StackWatch only reports vulnerabilities **published in the last 30 days** (see [Filters](#filters) below). On a fresh run you will typically see a small handful, not the full historical backlog.

**Second run** (and every run after) only shows CVEs disclosed *since the last run* — the `state.json` file persists seen CVE IDs.

If you set `filters.max_age_days: false` to disable the age filter, the first run can be very noisy because OSV returns the full history for every package (potentially hundreds of CVEs going back a decade).

---

## Filters

By default StackWatch hides:
- Vulnerabilities **published more than 30 days ago** — these are usually historical noise from new packages or fresh state files.
- Vulnerabilities marked **withdrawn** by OSV (false positives, duplicates, etc.).

Tune the age window in `stack.yml`:

```yaml
filters:
  max_age_days: 7      # only the last week
  # max_age_days: 90   # last quarter
  # max_age_days: false  # no age filter — report everything (noisy on first run)
```

Vulnerabilities with no `published` date in OSV are always kept (better safe than silent). Filtered vulnerabilities are **not** written to `state.json`, so if you later widen the window they can still surface.

---

## Simulating a background job manually

StackWatch has no built-in scheduler. It runs once and exits. To simulate a cron job or CI schedule locally, just run it whenever you want:

```bash
# Check now
bin/stackwatch run

# Check again in an hour
bin/stackwatch run

# Check with a different config
bin/stackwatch run --config ./my-stack.yml
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

### `bin/stackwatch run`

Query CVEs for your stack and alert on new ones.

```bash
# Use default stack.yml and state.json
bin/stackwatch run

# Use custom paths
bin/stackwatch run --config ./config/stack.yml --state-path ./data/state.json

# Override state path only
bin/stackwatch run --state-path /tmp/stackwatch-state.json
```

**Exit codes:**
- `0` — success (0 or more new vulnerabilities found)
- `1` — configuration error, OSV API error, or Slack notification failure

### `bin/stackwatch init`

Generate a starter `stack.yml` in the current directory.

```bash
bin/stackwatch init
bin/stackwatch init --force   # overwrite existing stack.yml
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

By default, the 30-day age filter keeps the first run small. If you disabled it (`filters.max_age_days: false`) you will see the full historical CVE backlog on the first run. Either re-enable the filter, or let the run finish — `state.json` will absorb the IDs and the next run will be silent.

### Getting CVEs from years ago (e.g. DSA-4286-1 from 2018)

You probably disabled the age filter or set `max_age_days` very high. Check `filters.max_age_days` in `stack.yml`. Also: distro ecosystems like `Debian` (no version suffix) include every Debian release ever. Scope to a specific release with `ecosystem: "Debian:12"`.

### "OSV API error" or timeout

OSV.dev may occasionally return errors or time out. The default timeout is 15 seconds. Just retry the run.

### Duplicate alerts

This usually means `state.json` was not persisted between runs. Make sure the file is written to durable storage (local disk, CI cache, mounted volume, etc.) and read back on the next invocation.
