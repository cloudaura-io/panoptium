---
id: "H.5"
title: "Log Tampering and Anti-Forensics"
category: "Evasion & Persistence"
category_id: "H"
detection_difficulty: "medium"
description: "Compromised agents modify or delete their own logs to hide evidence
  of compromise. Agents with file system access can overwrite log files, and agents
  with API access can modify audit trails."
---

# H.5 Log Tampering and Anti-Forensics

- **Name:** Agent Log Manipulation / Evidence Destruction
- **Category:** Evasion / Anti-Forensics
- **Description:** Compromised agents modify or delete their own logs to hide evidence
  of compromise. Agents with file system access can overwrite log files, and agents
  with API access can modify audit trails. AI-generated falsified logs can pass
  automated verification because they "look right."
- **Attack scenario:** After exfiltrating sensitive data, a compromised coding agent
  modifies its recent command history and log files to remove evidence of the
  exfiltration commands. Security tools reviewing the logs see no anomalous activity.
- **Prerequisites:** Agent with write access to its own logs or audit trail systems.
- **Impact:** Inability to investigate incidents, false confidence in system integrity.
- **Detection difficulty:** Medium-Hard. Write-once logging (append-only, external
  SIEM) and log integrity verification can mitigate, but requires the logging
  infrastructure to be outside the agent's control.
- **Real-world examples:**
  - Without deep observability into inter-agent communication logs, "diagnosing the
    root cause of cascading failures is incredibly difficult."
- **References:**
  - NIST adversarial ML taxonomy: evasion techniques and data poisoning patterns
