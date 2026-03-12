# codex-buddy-for-claude

MCP server that gives [Claude Code](https://docs.anthropic.com/en/docs/claude-code) access to OpenAI models for:

- **Code Review** (`codex_review`) — expert code review with severity ratings and actionable fixes
- **Deep Thinking** (`codex_thinkdeep`) — architecture decisions, trade-off analysis, debugging hypotheses
- **Security Audit** (`codex_secaudit`) — OWASP-aligned security audit with threat-level-aware analysis

Reports are automatically saved as markdown files to `<project>/codex-reports/`.

## Requirements

- Python 3.10+
- **Either** an [OpenAI API key](https://platform.openai.com/api-keys) (pay-per-token) **or** a [ChatGPT Plus/Pro subscription](https://chatgpt.com/pricing) (flat monthly fee)

## Install

```bash
# Clone the repo
git clone https://github.com/leo919cc/codex-buddy-for-claude.git
cd codex-buddy-for-claude

# Create venv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Add to Claude Code

Add the server to your Claude Code MCP config (`~/.claude.json`):

```json
{
  "mcpServers": {
    "codexreview": {
      "command": "/absolute/path/to/codex-buddy-for-claude/.venv/bin/python",
      "args": ["/absolute/path/to/codex-buddy-for-claude/server.py"]
    }
  }
}
```

Replace `/absolute/path/to/` with the actual path where you cloned the repo.

Then restart Claude Code. You should see the three tools available:
- `mcp__codexreview__codex_review`
- `mcp__codexreview__codex_thinkdeep`
- `mcp__codexreview__codex_secaudit`

## Authentication

The server supports two auth methods. It prefers OAuth (free with subscription) and falls back to API key (pay-per-token).

### Option A: ChatGPT subscription (recommended)

Use your ChatGPT Plus ($20/mo) or Pro ($200/mo) subscription — no per-token API costs.

```bash
# Install Codex CLI and login (one-time)
npm install -g @openai/codex
codex login
```

This saves OAuth tokens to `~/.codex/auth.json`. The MCP server auto-detects them on startup. The report footer will show `(subscription)` to confirm.

### Option B: API key (pay-per-token)

Create a `.env` file in the repo directory:

```bash
echo "OPENAI_API_KEY=sk-your-key-here" > .env
```

Or export it in your shell:

```bash
export OPENAI_API_KEY=sk-your-key-here
```

The report footer will show `(API)` when using this method.

### Both configured?

If both OAuth and API key are available, OAuth is used by default (free). The API key serves as fallback if OAuth tokens expire or fail.

## Configuration

| Env Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | (optional if using OAuth) | Your OpenAI API key |
| `CODEX_MODEL` | `gpt-5.4` | Default model for all tools |

You can also override the model per-call by passing the `model` parameter to any tool.

### Supported models

Any OpenAI model works. High-reasoning models (codex/5.x series) automatically use the Responses API:

- `gpt-5.4` (default) — high reasoning
- `gpt-5.4-pro` — xhigh reasoning (premium pricing)
- `gpt-5.3-codex`, `gpt-5.2-codex`, `gpt-5.1-codex`, etc.
- `gpt-4o`, `gpt-4-turbo`, etc. — use standard chat completions API

## Usage

Once configured, Claude Code will automatically have access to the tools. You can ask Claude to:

- "Review this file" → triggers `codex_review`
- "Think deeply about whether we should use X or Y" → triggers `codex_thinkdeep`
- "Run a security audit on this file" → triggers `codex_secaudit`

### Parameters

All tools accept:
- `model` — override the default model
- `project_dir` — where to save reports (auto-detected from file paths if not set)

#### `codex_review`
- `files` (required) — list of absolute file paths
- `context` — what the code does, focus areas

#### `codex_thinkdeep`
- `problem` (required) — the question or decision to analyze
- `context` — constraints, what you've considered
- `files` — relevant code files for grounding

#### `codex_secaudit`
- `files` (required) — list of absolute file paths
- `context` — deployment context, threat model
- `threat_level` — `low` | `medium` | `high` | `critical`

## License

MIT
