---
id: "B.7"
title: "Callback/Webhook Manipulation"
category: "Tool & MCP Attacks"
category_id: "B"
detection_difficulty: "medium"
description: "Attacker manipulates the callback URLs or webhook endpoints that
  tools use to return results to the agent. By redirecting callbacks, the attacker
  can intercept tool results, inject modified results, or trigger additional actions."
---

# B.7 Callback/Webhook Manipulation

- **Name:** Callback/Webhook Manipulation
- **Category:** Tool & MCP / Callback
- **Description:** Attacker manipulates the callback URLs or webhook endpoints that
  tools use to return results to the agent. By redirecting callbacks, the attacker
  can intercept tool results, inject modified results, or trigger additional actions.
- **Attack scenario:** An agent invokes a payment processing tool. The attacker
  manipulates the callback URL parameter to point to their server, intercepting the
  payment confirmation and potentially modifying it before forwarding to the agent,
  or simply stealing payment details.
- **Prerequisites:** Ability to influence tool parameters (through prompt injection) or
  compromise the callback infrastructure.
- **Impact:** Data interception, result manipulation, financial fraud.
- **Detection difficulty:** Medium. Callback URL validation and allowlisting can help,
  but dynamic callback generation makes this harder.
- **References:**
  - OWASP ASI02: Tool Misuse and Exploitation
