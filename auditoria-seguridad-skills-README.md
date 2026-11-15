# `Security Audit Skills (Auditoría de Seguridad Skills)` — Military-Grade Security Auditor Skill

A forensic security auditing skill and standalone PowerShell engine designed to inspect, verify, and sandbox agent skills before installation or execution in **OpenCode** and **AntiGravity** environments.  
*Motor de auditoría de seguridad para verificar habilidades de agentes de terceros antes de su ejecución en **OpenCode** y **AntiGravity***

---

## Overview

*Motor de auditoría de seguridad para verificar habilidades de agentes de terceros antes de su ejecución en **OpenCode** y **AntiGravity***.

`Security Audit Skills (Auditoría de Seguridad Skills / auditoria-seguridad-skills)` converts theoretical security auditing guidelines into an executable, deterministic verification pipeline. Before trusting or running third-party agent skills, this tool inventories all files, computes cryptographic hashes, scans for malicious code patterns and prompt-injection payloads, enforces isolation policies, and issues an actionable verdict.

### Core Capabilities

* **Cryptographic Inventory:** Generates SHA-256 and MD5 hashes for every file in the target skill directory.  
* **Static Code & Pattern Analysis:** Detects obfuscated payloads, unauthorized network calls, privilege escalation attempts, suspicious shell commands, and dangerous execution primitives.  
* **Prompt Injection Detection:** Scans `SKILL.md` and supporting documentation/prompts for adversarial instructions, jailbreaks, or context-hijacking attempts.  
* **Sandbox Isolation Enforcement:** Validates compatibility with isolated Docker execution (`--network none` and read-only filesystem mounts).  
* **Deterministic Verdicts & Quarantine:** Scores risk on a `0–100` scale and outputs `PASS`, `REVIEW`, or `BLOCK` along with machine-readable JSON and a forensic report.

---

## Repository Structure

```
auditoria-seguridad-skills/
├── SKILL.md                          # Agent instructions & security audit rules (OpenCode / AntiGravity)
├── README.md                         # Repository documentation
└── scripts/
    └── auditar-skill.ps1             # Standalone PowerShell forensic auditing engine
```

---

## Prerequisites

* **Operating System:** Windows 10 / 11 (or PowerShell 7+ cross-platform)  
* **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+  
* **Optional (Recommended):** Docker Desktop / Engine for `--network none` read-only sandbox verification  
* **Target Agent Environments:** OpenCode or AntiGravity

---

## Installation

### 1\. Clone the Repository

```sh
git clone https://github.com/<your-username>/auditoria-seguridad-skills.git
cd auditoria-seguridad-skills
```

### 2\. Install into Agent Skill Directories

Copy the skill folder into your active **OpenCode** and/or **AntiGravity** configuration paths so the agent automatically loads the security rules:

**OpenCode:**

```
Copy-Item ".\auditoria-seguridad-skills" "$env:USERPROFILE\.config\opencode\skills\" -Recurse -Force
```

**AntiGravity:**

```
Copy-Item ".\auditoria-seguridad-skills" "$env:USERPROFILE\.gemini\antigravity\skills\" -Recurse -Force
```

---

## Usage

### Standalone CLI Execution (PowerShell)

Run the forensic auditor directly against any candidate skill folder before installing it:

```
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\auditar-skill.ps1" -Path "C:\path\to\candidate-skill"
```

### JSON Output Mode

For automated CI/CD pipelines or agent tool consumption:

```
powershell -NoProfile -ExecutionPolicy Bypass -File ".\scripts\auditar-skill.ps1" -Path "C:\path\to\candidate-skill" -Json
```

---

## Verdict & Exit Codes

| Verdict | Risk Score | Exit Code | Action |
| :---- | :---: | :---: | :---- |
| **PASS** | `0` | `0` | Safe to install and execute. |
| **REVIEW** | `1 – 99` | `1` | Manual inspection required; suspicious patterns or unverified dependencies found. |
| **BLOCK** | `100` | `2` | Immediate quarantine; confirmed malicious payload, prompt injection, or policy violation. |

---

## Validation & Test Suite

The auditing engine is validated against three benchmark scenarios:

1. **Clean Skill Benchmark:** Verified `PASS (0/100)` with exit code `0`.  
2. **Structured JSON Output:** Verified valid, parseable JSON schema output.  
3. **Adversarial / Trap Skill Benchmark:** Verified `BLOCK (100/100)` with exit code `2` against embedded prompt injection and malicious script payloads.

---

## Security Policy & Disclaimer

* Always audit third-party skills in an isolated environment before copying them into active `~/.config/opencode/skills/` or `~/.gemini/antigravity/skills/` directories.  
* Report vulnerabilities or false negatives via GitHub Security Advisories or private issue disclosure.  
* Unauthorized persons attempting to install or use this skill will be immediately blocked and reported.

---

## License

Specify your chosen open-source license here (e.g., `MIT` or `Apache-2.0`).