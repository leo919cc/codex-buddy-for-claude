"""MCP server for OpenAI Codex: code review, deep thinking, and security audit."""

import base64
import json
import logging
import os
import re
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool
from openai import OpenAI

# Load API key from .env in the server directory (if present)
load_dotenv(Path(__file__).parent / ".env")

logger = logging.getLogger("codex-review")
logging.basicConfig(level=logging.INFO, stream=sys.stderr)

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None
server = Server("codex-review")

MODEL = os.environ.get("CODEX_MODEL", "gpt-5.4")

# Models that require the Responses API instead of chat completions
RESPONSES_API_MODELS = {"gpt-5.4", "gpt-5.4-pro", "gpt-5.3-codex", "gpt-5.2-codex", "gpt-5.1-codex", "gpt-5-codex", "gpt-5.1-codex-mini", "gpt-5.1-codex-max"}

# --- ChatGPT OAuth Backend (uses subscription instead of API tokens) ---
CODEX_AUTH_FILE = Path.home() / ".codex" / "auth.json"
CHATGPT_API_URL = "https://chatgpt.com/backend-api/codex/responses"
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
TOKEN_REFRESH_SECONDS = 480  # 8 minutes, matching official Codex CLI


class OAuthManager:
    """Manages ChatGPT OAuth tokens from ~/.codex/auth.json."""

    def __init__(self):
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.account_id: str | None = None
        self.expires_at: float = 0
        self._load()

    def _load(self) -> bool:
        if not CODEX_AUTH_FILE.exists():
            logger.info("No Codex auth file at %s", CODEX_AUTH_FILE)
            return False
        try:
            data = json.loads(CODEX_AUTH_FILE.read_text())
        except Exception as e:
            logger.warning("Failed to read Codex auth file: %s", e)
            return False
        if data.get("auth_mode") != "chatgpt":
            logger.info("Codex auth mode is '%s', not 'chatgpt'", data.get("auth_mode"))
            return False
        tokens = data.get("tokens", {})
        self.access_token = tokens.get("access_token")
        self.refresh_token = tokens.get("refresh_token")
        self.account_id = tokens.get("account_id") or self._account_id_from_jwt(
            tokens.get("id_token", "")
        )
        self.expires_at = time.time() + TOKEN_REFRESH_SECONDS
        logger.info("Loaded ChatGPT OAuth (account: %s)", self.account_id)
        return True

    @staticmethod
    def _account_id_from_jwt(jwt_token: str) -> str | None:
        try:
            payload_b64 = jwt_token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64))
            return claims.get("https://api.openai.com/auth", {}).get("chatgpt_account_id")
        except Exception:
            return None

    @property
    def is_available(self) -> bool:
        return bool(self.access_token and self.account_id)

    def ensure_valid(self) -> None:
        if time.time() >= self.expires_at:
            if self.refresh_token:
                self._refresh()
            else:
                self._load()

    def _refresh(self) -> None:
        logger.info("Refreshing ChatGPT OAuth token")
        try:
            with httpx.Client(timeout=30) as http:
                resp = http.post(
                    OAUTH_TOKEN_URL,
                    json={
                        "client_id": OAUTH_CLIENT_ID,
                        "grant_type": "refresh_token",
                        "refresh_token": self.refresh_token,
                    },
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning("Token refresh failed: %s — reloading from disk", e)
            self._load()
            return
        self.access_token = data.get("access_token", self.access_token)
        self.refresh_token = data.get("refresh_token", self.refresh_token)
        if data.get("id_token"):
            self.account_id = self._account_id_from_jwt(data["id_token"]) or self.account_id
        self.expires_at = time.time() + TOKEN_REFRESH_SECONDS
        self._save(data)
        logger.info("OAuth token refreshed successfully")

    def _save(self, new_tokens: dict) -> None:
        try:
            auth_data = json.loads(CODEX_AUTH_FILE.read_text())
            tokens = auth_data.setdefault("tokens", {})
            for key in ("access_token", "refresh_token", "id_token"):
                if key in new_tokens:
                    tokens[key] = new_tokens[key]
            auth_data["last_refresh"] = datetime.now().isoformat()
            CODEX_AUTH_FILE.write_text(json.dumps(auth_data, indent=2))
        except Exception as e:
            logger.warning("Failed to update auth.json: %s", e)


oauth = OAuthManager()

if not oauth.is_available and not OPENAI_API_KEY:
    logger.error("No auth: need ChatGPT OAuth (~/.codex/auth.json) or OPENAI_API_KEY")
    sys.exit(1)
if oauth.is_available:
    logger.info("Using ChatGPT subscription (no API cost)")
else:
    logger.info("Using OpenAI API key (pay-per-token)")

SYSTEM_PROMPT = """\
ROLE
You are an expert code reviewer, combining the deep architectural knowledge of a principal engineer with the
precision of a sophisticated static analysis tool. Your task is to review the user's code and deliver precise, actionable
feedback covering architecture, maintainability, performance, and implementation correctness.

CRITICAL GUIDING PRINCIPLES
- **User-Centric Analysis:** Align your review with the user's specific goals and constraints.
- **Scoped & Actionable Feedback:** Focus strictly on the provided code. Offer concrete, actionable fixes.
- **Pragmatic Solutions:** Prioritize practical improvements. No unnecessary complexity.
- **DO NOT OVERSTEP**: Do not suggest wholesale changes, technology migrations, or unrelated improvements.

SEVERITY DEFINITIONS
🔴 CRITICAL: Security flaws, crashes, data loss, undefined behavior.
🟠 HIGH: Bugs, performance bottlenecks, anti-patterns impairing usability/reliability.
🟡 MEDIUM: Maintainability concerns, code smells, test gaps, non-idiomatic code.
🟢 LOW: Style nits, minor improvements, code clarification opportunities.

EVALUATION AREAS
- Security, Performance & Scalability, Code Quality & Maintainability, Testing, Architecture

OUTPUT FORMAT
For each issue:
[SEVERITY] File:Line – Issue description
→ Fix: Specific solution (code example only if needed)

After listing all issues:
• **Overall Code Quality Summary:** (one short paragraph)
• **Top 3 Priority Fixes:** (quick bullets)
• **Positive Aspects:** (what was done well)
"""

THINKDEEP_PROMPT = """\
ROLE
You are a principal-level software architect and strategic thinker. Your task is to deeply analyze
complex decisions, trade-offs, and problems — then deliver structured, evidence-based recommendations.

CRITICAL GUIDING PRINCIPLES
- **Depth over breadth:** Go deep on the specific question asked. Don't survey the entire landscape.
- **Challenge assumptions:** Question the premise if warranted. The user may be solving the wrong problem.
- **Concrete over abstract:** Give specific implementation guidance, not generic advice.
- **Acknowledge uncertainty:** State confidence levels. Flag what you don't know.
- **Trade-offs are mandatory:** Every recommendation must include what you're giving up.

ANALYSIS FRAMEWORK
1. Restate the problem precisely — ensure you're answering the right question
2. Identify the key decision dimensions (performance, complexity, maintainability, cost, etc.)
3. Evaluate each option against those dimensions with specific reasoning
4. Surface blind spots, edge cases, and failure modes the asker may have missed
5. Give a clear recommendation with confidence level and implementation guidance

OUTPUT FORMAT
## Problem Analysis
[Precise restatement and any premise challenges]

## Key Dimensions
[The criteria that matter most for this decision, and why]

## Evaluation
[Each option evaluated against the dimensions — be specific, cite patterns/data]

## Blind Spots & Risks
[What the asker likely hasn't considered]

## Recommendation
[Clear verdict with confidence: low/medium/high]
[What you're giving up with this choice]
[Concrete next steps]
"""

SECAUDIT_PROMPT = """\
ROLE
You are an elite application security engineer performing a thorough security audit.
You combine deep knowledge of OWASP Top 10, CWE, and real-world exploit chains with practical,
prioritized remediation guidance.

CRITICAL GUIDING PRINCIPLES
- **Attacker mindset:** Think like an adversary. Trace data flow from untrusted inputs to sensitive operations.
- **Evidence-based:** Every finding must reference specific code (file:line). No generic warnings.
- **Prioritize by exploitability:** A theoretical vulnerability with no attack path is LOW, not CRITICAL.
- **No false positives:** If you're unsure, say so. Don't cry wolf.
- **Practical fixes:** Every finding gets a concrete remediation, not just "validate input."

AUDIT SCOPE
1. **Injection** — SQL, command, LDAP, XPath, template, header injection
2. **Authentication & Session** — weak auth, session fixation, token handling, credential storage
3. **Access Control** — broken authorization, IDOR, privilege escalation, path traversal
4. **Cryptography** — weak algorithms, hardcoded keys/secrets, improper random, missing encryption
5. **Data Exposure** — sensitive data in logs/errors/responses, PII leakage, verbose errors
6. **Input Validation** — missing/incomplete validation, type confusion, deserialization
7. **Configuration** — debug mode, default credentials, permissive CORS, missing security headers
8. **Dependencies** — known vulnerable packages, outdated libraries
9. **Business Logic** — race conditions, TOCTOU, state manipulation, abuse scenarios

SEVERITY DEFINITIONS
🔴 CRITICAL: Directly exploitable for RCE, auth bypass, data breach, or financial loss.
🟠 HIGH: Exploitable with moderate effort or chaining. Significant security impact.
🟡 MEDIUM: Real risk but limited exploitability or impact. Defense-in-depth concern.
🟢 LOW: Theoretical risk, best practice violation, or hardening opportunity.

OUTPUT FORMAT
## Executive Summary
[1-2 sentences: overall security posture and most urgent concern]

## Findings

For each finding:
### [SEVERITY] Title
**Location:** File:Line
**Category:** [OWASP/CWE category]
**Attack Scenario:** [How an attacker would exploit this — be specific]
**Evidence:** [The vulnerable code pattern]
**Remediation:** [Exact fix with code if needed]

## Attack Surface Summary
[What's exposed, what's trusted, where the boundaries are]

## Positive Security Practices
[What was done well — secure defaults, good patterns observed]

## Priority Remediation Plan
[Ordered list: fix these first, in this order, for maximum security improvement]
"""


def read_files(paths: list[str]) -> str:
    """Read files and format with line numbers."""
    parts = []
    for path in paths:
        p = Path(path).expanduser()
        if not p.exists():
            parts.append(f"=== {path} === (FILE NOT FOUND)")
            continue
        try:
            content = p.read_text()
            numbered = "\n".join(
                f"{i + 1:4d}│ {line}" for i, line in enumerate(content.splitlines())
            )
            parts.append(f"=== {path} ({len(content.splitlines())} lines) ===\n{numbered}")
        except Exception as e:
            parts.append(f"=== {path} === (ERROR: {e})")
    return "\n\n".join(parts)


def save_report(tool_type: str, file_paths: list[str], content: str, project_dir_override: str = "") -> str:
    """Save report to a markdown file in the project directory. Returns the saved path."""
    # Use explicit project_dir if provided (most reliable)
    if project_dir_override:
        project_dir = Path(project_dir_override).expanduser()
    else:
        # Derive project dir from the first file's parent
        first = Path(file_paths[0]).expanduser()
        # If first path is not a real file (e.g. "thinkdeep"), use cwd instead
        if not first.exists() and not first.is_absolute():
            first = Path.cwd()
        project_dir = first if first.is_dir() else first.parent
    # Walk up to find a git root or stop at Documents
    for parent in [project_dir, *project_dir.parents]:
        if (parent / ".git").exists():
            project_dir = parent
            break
        if parent.name == "Documents":
            break

    reports_dir = project_dir / "codex-reports"
    reports_dir.mkdir(exist_ok=True)

    # Build descriptive filename from source file stems
    stems = [Path(p).stem for p in file_paths]
    # Truncate to keep filename reasonable
    if len(stems) > 3:
        label = f"{stems[0]}-and-{len(stems)-1}-more"
    else:
        label = "-".join(stems)
    # Sanitize
    label = re.sub(r"[^a-zA-Z0-9_-]", "", label)[:80]

    ts = datetime.now().strftime("%Y%m%d-%H%M")
    filename = f"{tool_type}-{label}-{ts}.md"
    out_path = reports_dir / filename
    out_path.write_text(content, encoding="utf-8")
    logger.info(f"Report saved to {out_path}")
    return str(out_path)


def call_chatgpt_responses_api(model: str, system: str, user_msg: str, max_retries: int = 3) -> tuple[str, dict]:
    """Call ChatGPT backend Responses API using SSE streaming.

    Uses OAuth tokens from ~/.codex/auth.json — billed against ChatGPT
    subscription, not API token usage.
    """
    oauth.ensure_valid()

    effort = "xhigh" if "pro" in model else "high"
    payload = {
        "model": model,
        "instructions": system,
        "input": [{"type": "message", "role": "user", "content": user_msg}],
        "reasoning": {"effort": effort},
        "stream": True,
        "store": False,
    }

    for attempt in range(max_retries + 1):
        headers = {
            "Authorization": f"Bearer {oauth.access_token}",
            "chatgpt-account-id": oauth.account_id,
            "OpenAI-Beta": "responses=experimental",
            "originator": "codex_cli_rs",
            "Content-Type": "application/json",
            "accept": "text/event-stream",
        }

        try:
            final_response = None
            with httpx.Client(timeout=httpx.Timeout(600, connect=30)) as http:
                with http.stream("POST", CHATGPT_API_URL, json=payload, headers=headers) as resp:
                    if resp.status_code == 401 and attempt < max_retries:
                        logger.warning("Got 401, refreshing OAuth token")
                        oauth._refresh()
                        continue
                    if resp.status_code >= 400:
                        body = resp.read().decode(errors="replace")
                        logger.error("HTTP %d from ChatGPT backend: %s", resp.status_code, body[:2000])
                    resp.raise_for_status()

                    for line in resp.iter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            event = json.loads(data_str)
                            if event.get("type") in ("response.done", "response.completed"):
                                final_response = event.get("response", event)
                        except json.JSONDecodeError:
                            continue

            if not final_response:
                raise RuntimeError("No response.done event received from ChatGPT backend")

            text_parts = []
            for item in final_response.get("output", []):
                if item.get("type") == "message":
                    for content in item.get("content", []):
                        if content.get("type") == "output_text":
                            text_parts.append(content["text"])
            review = "\n".join(text_parts) or "(no output)"
            usage = final_response.get("usage", {})
            return review, usage

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                logger.warning("Rate limited (429) — subscription message limit may be reached")
            if attempt < max_retries:
                time.sleep(3)
                continue
            raise
        except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError, ssl.SSLError, OSError) as e:
            logger.warning(f"Attempt {attempt + 1}/{max_retries + 1} failed: {e}")
            if attempt < max_retries:
                backoff = 3 * (attempt + 1)
                logger.info(f"Retrying in {backoff}s...")
                time.sleep(backoff)
                continue
            raise

    raise RuntimeError("All retries exhausted")


def call_responses_api(model: str, system: str, user_msg: str, max_retries: int = 2) -> tuple[str, dict]:
    """Call OpenAI Responses API using background mode (API key, pay-per-token fallback).

    gpt-5.4 with high reasoning effort can take >180s, which drops synchronous
    HTTP connections. Background mode submits the request, returns immediately
    with an ID, then we poll until completion.
    """
    url = "https://api.openai.com/v1/responses"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    # gpt-5.4-pro supports medium/high/xhigh (not low); use xhigh for max depth
    effort = "xhigh" if "pro" in model else "high"
    payload = {
        "model": model,
        "instructions": system,
        "input": user_msg,
        "reasoning": {"effort": effort},
        "background": True,
    }

    # Submit the request (returns immediately with response ID)
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            with httpx.Client(timeout=httpx.Timeout(60, connect=30)) as http:
                resp = http.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                break
        except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError, ssl.SSLError, OSError) as e:
            last_err = e
            logger.warning(f"Submit attempt {attempt + 1}/{max_retries + 1} failed: {e}")
            if attempt < max_retries:
                time.sleep(2)
                continue
            raise
        except Exception:
            raise
    else:
        raise last_err

    response_id = data.get("id")
    if not response_id:
        raise RuntimeError(f"No response ID returned: {data}")

    logger.info(f"Background response submitted: {response_id}")

    # Poll until completed (max ~10 minutes)
    poll_url = f"{url}/{response_id}"
    max_wait = 600
    poll_interval = 3
    waited = 0
    while waited < max_wait:
        status = data.get("status")
        if status == "completed":
            break
        if status == "failed":
            error = data.get("error", {})
            raise RuntimeError(f"Response failed: {error}")
        if status == "cancelled":
            raise RuntimeError("Response was cancelled")

        time.sleep(poll_interval)
        waited += poll_interval
        try:
            with httpx.Client(timeout=httpx.Timeout(30, connect=10)) as http:
                resp = http.get(poll_url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"Poll error (will retry): {e}")
            continue

        if waited % 30 == 0:
            logger.info(f"Still waiting for {response_id}... ({waited}s, status={data.get('status')})")

    if data.get("status") != "completed":
        raise RuntimeError(f"Response timed out after {max_wait}s (status={data.get('status')})")

    # Extract text from output items
    text_parts = []
    for item in data.get("output", []):
        if item.get("type") == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    text_parts.append(content["text"])
    review = "\n".join(text_parts) or "(no output)"

    usage = data.get("usage", {})
    return review, usage


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="codex_review",
            description=(
                "Send code files to OpenAI GPT-5.4 for expert code review. "
                "Provide absolute file paths and optional focus areas."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Absolute paths to code files to review",
                    },
                    "context": {
                        "type": "string",
                        "description": "Optional context: what the code does, recent changes, focus areas",
                        "default": "",
                    },
                    "model": {
                        "type": "string",
                        "description": f"OpenAI model to use (default: {MODEL})",
                        "default": MODEL,
                    },
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path to project root — report saves to <project_dir>/codex-reports/",
                        "default": "",
                    },
                },
                "required": ["files"],
            },
        ),
        Tool(
            name="codex_thinkdeep",
            description=(
                "Send a complex decision or problem to OpenAI GPT-5.4 for deep analysis. "
                "For architecture decisions, trade-off evaluation, debugging hypotheses, and strategy. "
                "Pass model='gpt-5.4-pro' for maximum reasoning depth on the hardest problems."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "problem": {
                        "type": "string",
                        "description": "The decision, problem, or question to analyze deeply",
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context: constraints, requirements, what you've considered so far",
                        "default": "",
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional absolute paths to relevant code files for grounding the analysis",
                        "default": [],
                    },
                    "model": {
                        "type": "string",
                        "description": f"OpenAI model to use (default: {MODEL}). Use 'gpt-5.4-pro' for maximum depth.",
                        "default": MODEL,
                    },
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path to project root — report saves to <project_dir>/codex-reports/",
                        "default": "",
                    },
                },
                "required": ["problem"],
            },
        ),
        Tool(
            name="codex_secaudit",
            description=(
                "Send code files to OpenAI GPT-5.4 for a thorough security audit. "
                "Covers OWASP Top 10, injection, auth, access control, crypto, data exposure, and more."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Absolute paths to code files to audit",
                    },
                    "context": {
                        "type": "string",
                        "description": "What the code does, its deployment context, threat model, or specific security concerns",
                        "default": "",
                    },
                    "threat_level": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Threat level: low (internal/scripts), medium (customer-facing), high (regulated/sensitive data), critical (financial/healthcare/PII)",
                        "default": "medium",
                    },
                    "model": {
                        "type": "string",
                        "description": f"OpenAI model to use (default: {MODEL})",
                        "default": MODEL,
                    },
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path to project root — report saves to <project_dir>/codex-reports/",
                        "default": "",
                    },
                },
                "required": ["files"],
            },
        ),
    ]


def _call_model(model: str, system_prompt: str, user_message: str) -> tuple[str, int, int, str]:
    """Call OpenAI with the appropriate API and return (text, in_tokens, out_tokens, auth_method)."""
    uses_responses = model in RESPONSES_API_MODELS or "codex" in model.lower()

    # Prefer OAuth (subscription, free) over API key (pay-per-token)
    if uses_responses and oauth.is_available:
        text, usage = call_chatgpt_responses_api(model, system_prompt, user_message)
        return text, usage.get("input_tokens", 0), usage.get("output_tokens", 0), "subscription"
    elif uses_responses:
        text, usage = call_responses_api(model, system_prompt, user_message)
        return text, usage.get("input_tokens", 0), usage.get("output_tokens", 0), "API"
    else:
        if not client:
            raise RuntimeError("API key required for non-Responses models but OPENAI_API_KEY not set")
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            temperature=0.3,
        )
        return (
            response.choices[0].message.content,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
            "API",
        )


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "codex_review":
        return await _handle_review(arguments)
    elif name == "codex_thinkdeep":
        return await _handle_thinkdeep(arguments)
    elif name == "codex_secaudit":
        return await _handle_secaudit(arguments)
    return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _handle_review(arguments: dict) -> list[TextContent]:
    files = arguments.get("files", [])
    context = arguments.get("context", "")
    model = arguments.get("model", MODEL)
    project_dir = arguments.get("project_dir", "")

    if not files:
        return [TextContent(type="text", text="Error: no files provided")]

    logger.info(f"Reviewing {len(files)} file(s) with {model}")

    code_content = read_files(files)
    user_message = f"Please review the following code:\n\n{code_content}"
    if context:
        user_message = f"Context: {context}\n\n{user_message}"

    try:
        text, in_tok, out_tok, auth = _call_model(model, SYSTEM_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} ({auth}) | Tokens: {in_tok} in / {out_tok} out"
        full = text + footer
        report_path = save_report("review", files, full, project_dir)
        full += f"\n\nReport saved: {report_path}"
        return [TextContent(type="text", text=full)]
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return [TextContent(type="text", text=f"Error calling {model}: {e}")]


async def _handle_thinkdeep(arguments: dict) -> list[TextContent]:
    problem = arguments.get("problem", "")
    context = arguments.get("context", "")
    files = arguments.get("files", [])
    model = arguments.get("model", MODEL)
    project_dir = arguments.get("project_dir", "")

    if not problem:
        return [TextContent(type="text", text="Error: no problem provided")]

    logger.info(f"Thinkdeep analysis with {model}")

    user_message = f"## Problem\n{problem}"
    if context:
        user_message += f"\n\n## Additional Context\n{context}"
    if files:
        code_content = read_files(files)
        user_message += f"\n\n## Relevant Code\n{code_content}"

    try:
        text, in_tok, out_tok, auth = _call_model(model, THINKDEEP_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} ({auth}) | Tokens: {in_tok} in / {out_tok} out"
        full = text + footer
        source_files = files if files else ["thinkdeep"]
        report_path = save_report("thinkdeep", source_files, full, project_dir)
        full += f"\n\nReport saved: {report_path}"
        return [TextContent(type="text", text=full)]
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return [TextContent(type="text", text=f"Error calling {model}: {e}")]


THREAT_LEVEL_DESCRIPTIONS = {
    "low": "Internal tool or script. Limited attack surface, no external users, no sensitive data.",
    "medium": "Customer-facing application. Standard web/API threat model, business data at risk.",
    "high": "Handles regulated or sensitive data. Stricter standards apply, compliance may be relevant.",
    "critical": "Financial transactions, healthcare, or PII. Assume sophisticated attackers, zero tolerance for auth/crypto/injection flaws.",
}


async def _handle_secaudit(arguments: dict) -> list[TextContent]:
    files = arguments.get("files", [])
    context = arguments.get("context", "")
    threat_level = arguments.get("threat_level", "medium")
    model = arguments.get("model", MODEL)
    project_dir = arguments.get("project_dir", "")

    if not files:
        return [TextContent(type="text", text="Error: no files provided")]

    logger.info(f"Security audit on {len(files)} file(s) with {model} (threat: {threat_level})")

    code_content = read_files(files)
    threat_desc = THREAT_LEVEL_DESCRIPTIONS.get(threat_level, THREAT_LEVEL_DESCRIPTIONS["medium"])
    user_message = f"Threat level: **{threat_level.upper()}** — {threat_desc}\n\nPerform a thorough security audit of the following code:\n\n{code_content}"
    if context:
        user_message = f"Context: {context}\n\n{user_message}"

    try:
        text, in_tok, out_tok, auth = _call_model(model, SECAUDIT_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} ({auth}) | Tokens: {in_tok} in / {out_tok} out"
        full = text + footer
        report_path = save_report("secaudit", files, full, project_dir)
        full += f"\n\nReport saved: {report_path}"
        return [TextContent(type="text", text=full)]
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return [TextContent(type="text", text=f"Error calling {model}: {e}")]


async def main():
    logger.info(f"Starting codex-review MCP server (model: {MODEL})")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
