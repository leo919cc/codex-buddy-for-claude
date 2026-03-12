"""MCP server for OpenAI Codex: code review, deep thinking, and security audit."""

import logging
import os
import re
import sys
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
if not OPENAI_API_KEY:
    logger.error("OPENAI_API_KEY not found in environment")
    sys.exit(1)

client = OpenAI(api_key=OPENAI_API_KEY)
server = Server("codex-review")

MODEL = os.environ.get("CODEX_MODEL", "gpt-5.4")

# Models that require the Responses API instead of chat completions
RESPONSES_API_MODELS = {
    "gpt-5.4", "gpt-5.4-pro",
    "gpt-5.3-codex", "gpt-5.2-codex", "gpt-5.1-codex", "gpt-5-codex",
    "gpt-5.1-codex-mini", "gpt-5.1-codex-max",
}

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
    if project_dir_override:
        project_dir = Path(project_dir_override).expanduser()
    else:
        first = Path(file_paths[0]).expanduser()
        if not first.exists() and not first.is_absolute():
            first = Path.cwd()
        project_dir = first if first.is_dir() else first.parent

    for parent in [project_dir, *project_dir.parents]:
        if (parent / ".git").exists():
            project_dir = parent
            break
        if parent.name == "Documents" or parent == parent.parent:
            break

    reports_dir = project_dir / "codex-reports"
    reports_dir.mkdir(exist_ok=True)

    stems = [Path(p).stem for p in file_paths]
    if len(stems) > 3:
        label = f"{stems[0]}-and-{len(stems)-1}-more"
    else:
        label = "-".join(stems)
    label = re.sub(r"[^a-zA-Z0-9_-]", "", label)[:80]

    ts = datetime.now().strftime("%Y%m%d-%H%M")
    filename = f"{tool_type}-{label}-{ts}.md"
    out_path = reports_dir / filename
    out_path.write_text(content, encoding="utf-8")
    logger.info(f"Report saved to {out_path}")
    return str(out_path)


def call_responses_api(model: str, system: str, user_msg: str, max_retries: int = 2) -> tuple[str, dict]:
    """Call OpenAI Responses API using background mode to avoid connection timeouts.

    High-reasoning models can take >180s, which drops synchronous HTTP connections.
    Background mode submits the request, returns immediately with an ID, then we poll
    until completion.
    """
    import time

    url = "https://api.openai.com/v1/responses"
    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    effort = "xhigh" if "pro" in model else "high"
    payload = {
        "model": model,
        "instructions": system,
        "input": user_msg,
        "reasoning": {"effort": effort},
        "background": True,
    }

    last_err = None
    for attempt in range(max_retries + 1):
        try:
            with httpx.Client(timeout=httpx.Timeout(60, connect=30)) as http:
                resp = http.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                break
        except (httpx.RemoteProtocolError, httpx.ReadError, httpx.ConnectError) as e:
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
                "Send code files to OpenAI for expert code review. "
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
                "Send a complex decision or problem to OpenAI for deep analysis. "
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
                "Send code files to OpenAI for a thorough security audit. "
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


def _call_model(model: str, system_prompt: str, user_message: str) -> tuple[str, int, int]:
    """Call OpenAI with the appropriate API and return (text, in_tokens, out_tokens)."""
    if model in RESPONSES_API_MODELS or "codex" in model.lower():
        text, usage = call_responses_api(model, system_prompt, user_message)
        return text, usage.get("input_tokens", 0), usage.get("output_tokens", 0)
    else:
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
        text, in_tok, out_tok = _call_model(model, SYSTEM_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} | Tokens: {in_tok} in / {out_tok} out"
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
        text, in_tok, out_tok = _call_model(model, THINKDEEP_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} | Tokens: {in_tok} in / {out_tok} out"
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
        text, in_tok, out_tok = _call_model(model, SECAUDIT_PROMPT, user_message)
        footer = f"\n\n---\nModel: {model} | Tokens: {in_tok} in / {out_tok} out"
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
