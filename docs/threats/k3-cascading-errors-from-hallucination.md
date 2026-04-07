---
id: "K.3"
title: "Cascading Errors from Hallucination"
category: "Autonomy Risks"
category_id: "K"
detection_difficulty: "medium"
description: "An agent hallucinates incorrect information and acts on it,
  causing cascading effects through connected systems. Unlike adversarial
  hallucination exploitation, this occurs spontaneously."
---

# K.3 Cascading Errors from Hallucination

- **Name:** Non-Adversarial Hallucination Cascade
- **Category:** Autonomy / Error Propagation
- **Description:** An agent hallucinates incorrect information and acts on it,
  causing cascading effects through connected systems. Unlike adversarial
  hallucination exploitation, this occurs spontaneously. In multi-agent systems,
  a single hallucinated fact can propagate to downstream agents.
- **Attack scenario:** A data analysis agent hallucinates a non-existent data anomaly
  and flags it as a critical issue. An automated response agent receives the alert
  and initiates an incident response procedure, rolling back recent deployments.
  The rollback causes a real outage, which triggers further automated responses.
- **Prerequisites:** Agent with decision-making authority, connected to automated
  response systems.
- **Impact:** Cascading operational failures, false incident response, real service
  disruption from imagined problems.
- **Detection difficulty:** Medium. Individual hallucinations are detectable with
  verification, but cascading effects can outpace detection.
- **References:**
  - OWASP ASI08: Cascading Failures
  - Adversa AI: "Cascading Failures in Agentic AI" guide
