# Skill Audit

Security scanner for AI agent skills. Detects malware, credential theft, data exfiltration, prompt injection, and obfuscation — before the code reaches your agent.

## Why

Public skill marketplaces let anyone upload code that your AI agent reads and executes. A malicious skill can steal API keys, exfiltrate data, inject prompts, or tamper with your agent's configuration. This scanner catches those attacks automatically.

Born from a real incident — a malware skill disguised as a legitimate tool on ClawdHub.

## What It Catches

**15 critical checks** (auto-blocked):

- Known exfiltration endpoints (webhook.site, ngrok, requestbin, etc.)
- Bulk environment variable harvesting
- Foreign credential access (reads API keys that aren't the skill's own)
- Code obfuscation (eval, base64 decode, hex escapes)
- Path traversal and sensitive file access (~/.ssh, ~/.clawdbot, /etc/passwd)
- Data exfiltration via curl/wget POST requests
- Reverse and bind shells
- .env file theft (dotenv loading in scripts, not docs)
- Prompt injection in markdown (SKILL.md is an attack vector)
- LLM tool exploitation (instructions to send/email secrets)
- Agent config tampering (writes to AGENTS.md, SOUL.md, etc.)
- Unicode obfuscation (zero-width characters, RTL override)
- Suspicious setup commands (curl piped to bash)
- Social engineering (download external binaries)
- Shipped .env files

**5 warning checks** (flagged for review):

- Subprocess execution (exec, spawn, Popen)
- Network requests (axios, fetch, requests)
- Minified/bundled files (can't audit what you can't read)
- File write operations
- Unknown external tool requirements

## Quick Start

### Safe install (recommended)

Installs, audits, and auto-removes the skill if critical issues are found:

```bash
bash skills/skill-audit/scripts/safe-install.sh <skill-slug>
```

### Audit an existing skill

```bash
bash skills/skill-audit/scripts/skill-audit.sh skills/some-skill
```

### Audit all installed skills

```bash
for d in skills/*/; do bash skills/skill-audit/scripts/skill-audit.sh "$d"; echo; done
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no issues found |
| 1 | Warnings only — review recommended |
| 2 | Critical findings — do not use without manual review |

## How It Works

Static analysis via pattern matching across all text files in a skill directory (.md, .js, .ts, .py, .sh, .json, .yaml, etc.). No dependencies — just bash and grep.

**Smart credential detection:** The scanner reads SKILL.md to identify which API keys the skill legitimately needs (its "own" keys), then flags any access to *other* keys (like your Anthropic or Telegram tokens) as credential theft.

**Prompt injection awareness:** Since SKILL.md is read directly into the AI agent's context, the scanner checks markdown files for injection attempts — but skips lines that are clearly documenting or warning about attacks.

## Limitations

- Static analysis only — catches patterns, not intent
- No runtime sandboxing — scans before install, not during execution
- Primarily English prompt injection patterns
- Minified JS is flagged but not deobfuscated
- A clean scan doesn't guarantee safety — it raises the bar significantly
- **Self-detection:** The scanner flags itself when audited (its own grep patterns and docs contain the strings it searches for). This is expected — it proves the detection works

## Install

```bash
clawdhub install skill-audit
```

## Licence

MIT
