# gliner-claude-pii-filter

Local PII redaction for Claude Code, with a human review step before Claude sees anything.
It combines the GLiNER2 model [`fastino/gliner2-privacy-filter-PII-multi`](https://huggingface.co/fastino/gliner2-privacy-filter-PII-multi) with Slovak/Czech and secret-detection regexes.

```
Claude ─ Bash hook ─► pii-redact ─┐
Claude ─ MCP tools ───────────────┼─► daemon 127.0.0.1:8765 ─► nothing found: auto-approve
Claude ─ PostToolUse (MCP loki) ──┘                           └► found: browser review ─► approve / reject / timeout
```

## Pieces

| Path | What |
|---|---|
| `pii_filter/regexes.py` | Checksum-validated detectors: rodné číslo, IČO, DIČ/IČ DPH, IBAN, SK accounts, +421/+420/landline phones, cards (Luhn), public IPs, JWT/bearer/keys/`password=` |
| `pii_filter/masking.py` | Builds log "skeletons" (timestamps, ids, IPs, numbers masked) so repeated lines run through the model once |
| `pii_filter/engine.py` | Combines regex and model results, consistent `[LABEL_n]` placeholders; handles text, generic JSON and Loki JSON |
| `pii_filter/review.py`, `ui.html` | In-memory review queue, browser UI, `audit.jsonl` (decisions and counts only, never content) |
| `pii_filter/server.py` | FastAPI daemon (launchd `sk.local.pii-filter`) |
| `pii_filter/cli.py` | `pii-redact` (stdin or file → reviewed output). Exit codes: 3 rejected, 4 service down, 5 timeout |
| `pii_filter/mcp_server.py` | MCP tools `redact_text`, `redact_file`, `scan_pii` |
| `hooks/pii_guard.py` | Claude Code hook (Bash/Read/Grep PreToolUse, `mcp__.*loki.*` PostToolUse) |

## Install (macOS, Python 3.10+)

```sh
git clone https://github.com/mpinter/gliner-claude-pii-filter ~/tools/pii-filter && cd ~/tools/pii-filter
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -c "from gliner2 import AutoExtractor; AutoExtractor.from_pretrained('fastino/gliner2-privacy-filter-PII-multi')"  # download model once
sed "s#__REPO__#$PWD#g" deploy/sk.local.pii-filter.plist.template > ~/Library/LaunchAgents/sk.local.pii-filter.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/sk.local.pii-filter.plist   # daemon runs offline (HF_HUB_OFFLINE=1)
ln -sf "$PWD/.venv/bin/pii-redact" ~/.local/bin/pii-redact
claude mcp add --scope user pii-filter -- "$PWD/.venv/bin/pii-filter-mcp"
```

Then add the following to `~/.claude/settings.json`, replacing `<repo>` with the clone path:

```json
"env": { "MCP_TOOL_TIMEOUT": "600000" },
"hooks": {
  "PreToolUse":  [{ "matcher": "Bash|Read|Grep", "hooks": [{ "type": "command", "timeout": 10,
                    "command": "<repo>/.venv/bin/python -I <repo>/hooks/pii_guard.py" }] }],
  "PostToolUse": [{ "matcher": "mcp__.*loki.*", "hooks": [{ "type": "command", "timeout": 600,
                    "command": "<repo>/.venv/bin/python -I <repo>/hooks/pii_guard.py" }] }]
}
```

Optionally, add a short section to `~/.claude/CLAUDE.md` telling Claude to read logs and official documents with `mcp__pii-filter__redact_file`.

## Operate

```sh
open http://127.0.0.1:8765/reviews                        # pending reviews
curl -s http://127.0.0.1:8765/health
launchctl kickstart -k gui/$(id -u)/sk.local.pii-filter   # restart after code changes
tail -f ~/tools/pii-filter/logs/daemon.err.txt
.venv/bin/python -m pytest -q tests/                      # unit tests
.venv/bin/python -I tests/bench.py                        # throughput
```

Environment variables:
- `PII_OPEN_BROWSER=0` turns off auto-opening review tabs.
- `PII_REVIEW_TTL_S` sets how long a review can stay pending (default 900).
- `PII_DEADLINE_S` sets how long the client waits for a decision (default 570).

## Tuning (`config.toml`)

Copy `config.example.toml` to `config.toml`. It is reloaded on save, so no restart is needed.

- **`[model.labels]`**: the categories GLiNER looks for, each with its confidence threshold.
  - Defaults: `person`, `address`/`street_address`, `national_id_number`, `passport_number` and `drivers_license_number`.
  - Structured data (emails, phones, IBAN/accounts, RČ/IČO/DIČ, cards, public IPs, secrets) is left to the checksum-validated regexes. Model labels such as `username` or `secret` caused mostly false positives on slugs, IDs and role names.
  - Add a line to enable another label (the full list is in the file header). Raise a threshold to make a label stricter.
- **`[regex] disabled`**: turns off regex detectors, e.g. `["IP_ADDRESS"]`.
- **`[allow]`**: values that are never flagged.
  - `values`: exact values, case-insensitive. Ticking **remember un-redacted values** on the review page appends here.
  - `patterns`: regexes matched against the whole flagged value.
  - `email_domains`: email addresses on these domains are kept.

Model `PERSON` hits that look like identifiers (no uppercase letter, or containing `-_/@:.=` or digits) are always dropped. A single capitalised word needs a confidence of at least 0.9.

## Installed into

- `~/Library/LaunchAgents/sk.local.pii-filter.plist`, generated from `deploy/sk.local.pii-filter.plist.template`
- `~/.local/bin/pii-redact`, a symlink to `.venv/bin/pii-redact`
- `~/.claude.json`: user-scope MCP server `pii-filter`
- `~/.claude/settings.json`:
  - hooks tagged `"_source": "pii-filter"`
  - `env.MCP_TOOL_TIMEOUT=600000`
- `~/.claude/CLAUDE.md`: the "PII filter" section

## Uninstall

```sh
launchctl bootout gui/$(id -u)/sk.local.pii-filter && rm ~/Library/LaunchAgents/sk.local.pii-filter.plist
claude mcp remove --scope user pii-filter
rm ~/.local/bin/pii-redact
```

Then remove the `_source: pii-filter` hook entries and `MCP_TOOL_TIMEOUT` from `~/.claude/settings.json`, and the PII section from `~/.claude/CLAUDE.md`.

## Limits

- The hooks recognise commands by pattern, so they are not a security boundary. A Python or awk script reading a log directly is not caught.
- If no decision is made within about 9.5 minutes (the Bash tool's 10-minute cap), the output is rejected.
- Follow mode (`-f`, `stern` without `--no-follow`, `logcli --tail`) is blocked.
- Private, loopback and link-local IPs are kept on purpose. Public IPs are redacted.
