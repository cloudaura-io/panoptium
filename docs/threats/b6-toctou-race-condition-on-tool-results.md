---
id: "B.6"
title: "TOCTOU Race Condition on Tool Results"
category: "Tool & MCP Attacks"
category_id: "B"
detection_difficulty: "hard"
description: "The agent checks a condition (e.g., file permissions, account balance,
  resource state), and an attacker modifies the state between the check and the
  subsequent use. Because agents typically perform multi-step operations with delays
  between steps, the window for TOCTOU exploitation is much l..."
---

# B.6 TOCTOU Race Condition on Tool Results

- **Name:** Time-of-Check-Time-of-Use Race Condition
- **Category:** Tool & MCP / Temporal
- **Description:** The agent checks a condition (e.g., file permissions, account balance,
  resource state), and an attacker modifies the state between the check and the
  subsequent use. Because agents typically perform multi-step operations with delays
  between steps, the window for TOCTOU exploitation is much larger than in traditional
  software.
- **Attack scenario:** An AI agent checks that a user has permission to access a file,
  then proceeds to read and process it. Between the permission check and the file
  read, the attacker replaces the file content with a prompt injection payload or
  substitutes a different file entirely.
- **Prerequisites:** Ability to modify shared state (files, databases, API resources)
  that the agent checks and then uses in separate operations.
- **Impact:** Authorization bypass, data manipulation, privilege escalation.
- **Detection difficulty:** Hard. Requires atomic operations or state monitoring between
  agent steps, which most agent frameworks do not implement.
- **Real-world examples:**
  - CVE-2025-22224 (VMware ESXi TOCTOU) and CVE-2025-21191 (Windows LSA TOCTOU)
    demonstrate the continuing prevalence of TOCTOU in 2025.
- **References:**
  - CyberInsights: "Is your AI agent vulnerable to race conditions?"
