---
id: "D.7"
title: "Lateral Movement via Agent Connections"
category: "Privilege & Access"
category_id: "D"
detection_difficulty: "very-hard"
description: "Attackers use a compromised agent's legitimate, authenticated
  connections to pivot between systems. The agent's existing integrations (Slack,
  Jira, GitHub, cloud APIs, databases) become pathways for lateral movement."
---

# D.7 Lateral Movement via Agent Connections

- **Name:** Agent-Mediated Lateral Movement
- **Category:** Privilege / Lateral Movement
- **Description:** Attackers use a compromised agent's legitimate, authenticated
  connections to pivot between systems. The agent's existing integrations (Slack,
  Jira, GitHub, cloud APIs, databases) become pathways for lateral movement. Natural
  language is the attack vector: malicious instructions injected into content the
  agent processes cause it to use its connections for attacker objectives.
- **Attack scenario:** An attacker compromises a customer support agent through
  prompt injection. Using the agent's legitimate Salesforce, Slack, and email
  integrations, the attacker enumerates internal systems, accesses customer data
  across multiple platforms, and establishes persistence by creating new API keys
  through the agent's admin-level access.
- **Prerequisites:** Compromised agent with multiple system integrations (common in
  enterprise deployments).
- **Impact:** Broad organizational compromise. Average lateral movement occurs in 48
  minutes from initial compromise; fastest observed: 18 minutes.
- **Detection difficulty:** Very hard. The agent accesses systems it normally
  accesses, moves data it normally moves, at times it normally operates. Everything
  looks like normal agent activity.
- **Real-world examples:**
  - September 2025: Anthropic disclosed state-sponsored threat actor using AI
    coding agent to execute autonomous cyber espionage against 30 global targets.
    AI handled 80-90% of tactical operations autonomously, including lateral
    movement at machine speed.
- **References:**
  - Christian Schneider: "AI agents as attack pivots: the new lateral movement"
  - The Hacker News: "The Kill Chain Is Obsolete When Your AI Agent Is the Threat"

---
