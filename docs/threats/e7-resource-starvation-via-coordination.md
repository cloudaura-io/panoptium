---
id: "E.7"
title: "Resource Starvation via Coordination"
category: "Multi-Agent"
category_id: "E"
detection_difficulty: "medium"
description: "Multiple agents are manipulated to simultaneously consume shared
  resources (API quotas, compute, memory), causing resource starvation that no
  single agent's consumption would trigger."
---

# E.7 Resource Starvation via Coordination

- **Name:** Distributed Resource Exhaustion
- **Category:** Multi-Agent / DoS
- **Description:** Multiple agents are manipulated to simultaneously consume shared
  resources (API quotas, compute, memory), causing resource starvation that no
  single agent's consumption would trigger.
- **Attack scenario:** An attacker sends prompt injections to 50 different agents in
  an enterprise, each causing a modest increase in API calls. Individually, each
  agent stays within normal bounds, but collectively they exhaust the shared API
  quota, causing a service outage for all agents and users.
- **Prerequisites:** Access to multiple agents sharing resource pools.
- **Impact:** Service disruption, cost amplification across the organization.
- **Detection difficulty:** Medium. Requires aggregate resource monitoring across all
  agents, not just individual agent budgets.
- **References:**
  - OWASP ASI08: Cascading Failures (resource starvation variant)

---
