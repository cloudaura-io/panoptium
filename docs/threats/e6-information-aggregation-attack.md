---
id: "E.6"
title: "Information Aggregation Attack"
category: "Multi-Agent"
category_id: "E"
detection_difficulty: "very-hard"
description: "An attacker uses multiple agent interactions or multi-agent systems
  to aggregate partial information that individually does not constitute a breach
  but combined reveals sensitive data. The agent's unified context window and
  inherited permissions expose information that individual systems wo..."
---

# E.6 Information Aggregation Attack

- **Name:** Cross-Agent Information Aggregation
- **Category:** Multi-Agent / Privacy
- **Description:** An attacker uses multiple agent interactions or multi-agent systems
  to aggregate partial information that individually does not constitute a breach
  but combined reveals sensitive data. The agent's unified context window and
  inherited permissions expose information that individual systems would restrict.
- **Attack scenario:** An attacker queries a customer support agent about different
  aspects of a target: one query reveals the company name, another the account
  balance range, another the primary contact name. Individually, each piece is
  non-sensitive. Combined, they constitute a complete customer profile that should
  require elevated permissions to access.
- **Prerequisites:** Multiple query access to agents with broad data access.
- **Impact:** Privacy violations, reconnaissance for targeted attacks.
- **Detection difficulty:** Very hard. Each individual query is legitimate. Detection
  requires tracking information disclosure across sessions and identifying
  aggregation patterns.
- **Real-world examples:**
  - Metomic research: AI agents expose sensitive data through inherited permissions,
    "surfacing information employees didn't realize they could access."
- **References:**
  - Metomic: "How Are AI Agents Exposing Your Organisation's Most Sensitive Data
    Through Inherited Permissions?"
