---
id: "G.3"
title: "Rate Limit Evasion"
category: "DoS & Resource Abuse"
category_id: "G"
detection_difficulty: "medium"
description: "Techniques to bypass token budgets and rate limits. In-app token
  counters often break under concurrent access because they are not atomic: two
  simultaneous requests can both read \"budget remaining: $10,\" both proceed, and
  spend $20."
---

# G.3 Rate Limit Evasion

- **Name:** Rate Limit and Budget Bypass
- **Category:** DoS / Evasion
- **Description:** Techniques to bypass token budgets and rate limits. In-app token
  counters often break under concurrent access because they are not atomic: two
  simultaneous requests can both read "budget remaining: $10," both proceed, and
  spend $20. Distribution across multiple agent instances also evades per-instance
  limits.
- **Attack scenario:** An attacker sends 50 concurrent requests to an agent endpoint.
  The non-atomic budget counter reads "$100 remaining" for each request before any
  is deducted, allowing all 50 to proceed for a total cost of $5,000 against a
  $100 budget.
- **Prerequisites:** Concurrent access to agent API, knowledge of rate limiting
  implementation weaknesses.
- **Impact:** Budget exhaustion, service disruption, financial loss.
- **Detection difficulty:** Medium. Requires atomic budget enforcement, which many
  implementations lack.
- **References:**
  - Cycles.io: "AI Agent Budget Control: Enforce Hard Spend Limits"
