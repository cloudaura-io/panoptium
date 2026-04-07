---
id: "D.2"
title: "Cross-Agent Privilege Escalation"
category: "Privilege & Access"
category_id: "D"
detection_difficulty: "hard"
description: "One compromised agent modifies another agent's configuration files
  to \"free\" it from security constraints, creating a cross-agent escalation loop.
  In shared codebases, multiple coding agents can read and write each other's
  configuration files."
---

# D.2 Cross-Agent Privilege Escalation

- **Name:** Cross-Agent Privilege Escalation / Agent Freeing
- **Category:** Privilege / Multi-Agent
- **Description:** One compromised agent modifies another agent's configuration files
  to "free" it from security constraints, creating a cross-agent escalation loop.
  In shared codebases, multiple coding agents can read and write each other's
  configuration files.
- **Attack scenario:** A prompt injection hijacks GitHub Copilot and instructs it
  to write malicious instructions to Claude Code's `.mcp.json` and `CLAUDE.md`
  files. When Claude Code starts, it loads the poisoned configuration, becomes
  compromised, and can reciprocate by modifying Copilot's settings. This creates
  a self-reinforcing compromise loop.
- **Prerequisites:** Multiple agents operating on the same filesystem or codebase.
- **Impact:** Cascading compromise across all agents sharing a workspace, persistent
  compromise that survives individual agent restarts.
- **Detection difficulty:** Hard. Each configuration change may appear legitimate.
  Requires monitoring cross-agent configuration modifications.
- **Real-world examples:**
  - Embrace The Red: "Cross-Agent Privilege Escalation: When Agents Free Each Other"
    (2025), demonstrated with Copilot and Claude Code.
- **References:**
  - Embrace The Red blog post (2025)
