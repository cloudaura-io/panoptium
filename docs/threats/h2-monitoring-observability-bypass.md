---
id: "H.2"
title: "Monitoring/Observability Bypass"
category: "Evasion & Persistence"
category_id: "H"
detection_difficulty: "very-hard"
description: "Agent behavior is crafted to stay within normal operational
  parameters while achieving malicious objectives. Actions blend with legitimate
  agent activity: accessing the same systems, moving the same types of data, at
  the same times of day."
---

# H.2 Monitoring/Observability Bypass

- **Name:** Monitoring Evasion
- **Category:** Evasion / Monitoring
- **Description:** Agent behavior is crafted to stay within normal operational
  parameters while achieving malicious objectives. Actions blend with legitimate
  agent activity: accessing the same systems, moving the same types of data, at
  the same times of day. Specifically exploits the difficulty of distinguishing
  adversarial behavior from legitimate agent autonomy.
- **Attack scenario:** A compromised agent exfiltrates data only during normal
  business hours, only through systems it routinely accesses, and in volumes that
  match its typical data processing patterns. Security monitoring sees nothing
  anomalous.
- **Prerequisites:** Understanding of monitoring baselines and normal agent behavior
  patterns.
- **Impact:** Undetected long-term compromise.
- **Detection difficulty:** Very hard. By definition, the behavior is designed to be
  within normal parameters. Requires intent-level analysis, not just behavioral
  monitoring.
- **Real-world examples:**
  - When an attacker rides an AI agent's existing workflow, "everything looks normal.
    The agent is accessing the systems it always accesses, moving the data it always
    moves, operating at the times it always operates."
- **References:**
  - Obsidian Security: "AI Detection and Response"
