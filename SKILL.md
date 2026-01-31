---
name: skillvet
description: Security scanner for ClawdHub/community skills — detects malware, credential theft, exfiltration, prompt injection, and obfuscation before you install. Use when installing skills from ClawdHub or any public marketplace, reviewing third-party agent skills for safety, or vetting untrusted code before giving it to your AI agent. Triggers: install skill, audit skill, check skill, vet skill, skill security, safe install, is this skill safe.
---

# Skill Audit

Security scanner for agent skills. Catches malicious code before it reaches your agent.

## Why This Exists

Public skill marketplaces let anyone upload code that your AI agent will read and execute. A malicious skill can steal your API keys, exfiltrate data, inject prompts, or tamper with your agent's config — all while looking like a normal skill.

This scanner catches those attacks automatically.

## Quick Start

**Safe install** (recommended — installs, audits, auto-removes if critical issues found):

```bash
bash skills/skill-audit/scripts/safe-install.sh <skill-slug>
```

**Audit an already-installed skill:**

```bash
bash skills/skill-audit/scripts/skill-audit.sh skills/some-skill
```

**Exit codes:** 0 = clean, 1 = warnings only, 2 = critical findings.

## What It Detects

### 🔴 Critical (auto-blocked)

| # | Check | Example |
|---|-------|---------|
| 1 | Known exfiltration endpoints | webhook.site, ngrok.io, requestbin |
| 2 | Bulk environment variable harvesting | `printenv \|`, `${!*@}` |
| 3 | Foreign credential access | Reading ANTHROPIC_API_KEY, TELEGRAM_BOT_TOKEN, etc. from scripts |
| 4 | Code obfuscation | eval(), Buffer.from(base64), hex escapes |
| 5 | Path traversal / sensitive file access | `../../`, `/etc/passwd`, `~/.ssh`, `~/.clawdbot` |
| 6 | Data exfiltration via curl/wget | `curl --data`, `wget --post` with variables |
| 7 | Reverse/bind shells | `/dev/tcp/`, `nc -e`, `socat` |
| 8 | .env file theft | `load_dotenv`, `open(.env)` (not in docs) |
| 9 | Prompt injection in markdown | "ignore previous instructions" in SKILL.md |
| 10 | LLM tool exploitation | Instructions to send/email/post secrets |
| 11 | Agent config tampering | Write/modify AGENTS.md, SOUL.md, clawdbot.json |
| 12 | Unicode obfuscation | Zero-width chars, RTL override, homoglyphs |
| 13 | Suspicious setup commands | curl piped to bash disguised as install steps |
| 14 | Social engineering | "download this .exe", external pastes |
| 15 | Shipped .env files | Actual .env files (not .example) in the skill |

### 🟡 Warning (review recommended)

| # | Check | Why |
|---|-------|-----|
| 1 | Subprocess execution | child_process, exec(), Popen — not always bad but worth checking |
| 2 | Network requests | axios, fetch, requests — expected in some skills, suspicious in others |
| 3 | Minified/bundled files | Can't audit what you can't read |
| 4 | File write operations | writeFile, open('w') — may be legitimate |

## Usage

### Always use safe-install.sh for ClawdHub

```bash
# Install with automatic audit
bash skills/skill-audit/scripts/safe-install.sh my-skill

# Pass extra args to clawdhub
bash skills/skill-audit/scripts/safe-install.sh my-skill --version 1.2.3
```

If critical issues are found, the skill is automatically removed and you'll see what was detected. If you've manually reviewed the skill and trust it, install directly with `clawdhub install`.

### Audit existing skills

```bash
# Single skill
bash skills/skill-audit/scripts/skill-audit.sh skills/some-skill

# All installed skills
for d in skills/*/; do bash skills/skill-audit/scripts/skill-audit.sh "$d"; echo; done
```

## Limitations

- **Static analysis only** — catches patterns, not intent. A sufficiently obfuscated attack could bypass regex matching.
- **No runtime sandboxing** — this scans before install, not during execution.
- **English-centric patterns** — prompt injection detection is primarily English. Multi-language injection may slip through.
- Minified/bundled JS is flagged but not deobfuscated.

A clean scan doesn't guarantee safety. It raises the bar significantly, but manual review of suspicious skills is still good practice.

**Note:** The scanner flags itself when audited — its own patterns and docs contain the strings it detects. This is expected and confirms detection works.
