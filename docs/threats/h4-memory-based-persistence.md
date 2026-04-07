---
id: "H.4"
title: "Memory-Based Persistence"
category: "Evasion & Persistence"
category_id: "H"
detection_difficulty: "very-hard"
description: "Attacker establishes persistence in the agent's long-term memory
  (vector stores, RAG databases, learned preferences). Unlike configuration-based
  persistence, this operates at the semantic level and is harder to detect through
  file integrity monitoring."
---

# H.4 Memory-Based Persistence

- **Name:** Persistent Memory Compromise
- **Category:** Evasion / Persistence
- **Description:** Attacker establishes persistence in the agent's long-term memory
  (vector stores, RAG databases, learned preferences). Unlike configuration-based
  persistence, this operates at the semantic level and is harder to detect through
  file integrity monitoring.
- **Attack scenario:** An attacker poisons the agent's memory with a "learned
  preference" that all future API calls should include a specific header. The agent
  treats this as a legitimate learned optimization and includes the header (which
  contains encoded exfiltrated data) in every API call across all future sessions.
- **Prerequisites:** Ability to inject content into agent memory (through conversation
  or processed documents).
- **Impact:** Persistent, semantically invisible compromise across all future sessions.
- **Detection difficulty:** Very hard. The poisoned memory is indistinguishable from
  legitimate learned context. Temporal decoupling (inject in February, activate in
  April) makes correlation nearly impossible.
- **References:**
  - OWASP ASI06
  - MINJA attack (NeurIPS 2025)
