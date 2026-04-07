---
id: "E.5"
title: "Cascading Compromise"
category: "Multi-Agent"
category_id: "E"
detection_difficulty: "hard"
description: "A single compromised agent triggers a chain reaction of compromises
  across connected agents and systems. Unlike coordinated attacks, cascading
  compromise is unintentional propagation where compromised outputs from one agent
  serve as attack inputs to downstream agents."
---

# E.5 Cascading Compromise

- **Name:** Cascading Compromise / Infection Chain
- **Category:** Multi-Agent / Cascade
- **Description:** A single compromised agent triggers a chain reaction of compromises
  across connected agents and systems. Unlike coordinated attacks, cascading
  compromise is unintentional propagation where compromised outputs from one agent
  serve as attack inputs to downstream agents.
- **Attack scenario:** A data retrieval agent is compromised and begins returning
  poisoned data. Downstream analysis agents trust and act on the poisoned data,
  making flawed decisions. Decision agents based on the analysis execute harmful
  actions (unauthorized purchases, incorrect deployments). Each agent amplifies the
  original compromise.
- **Prerequisites:** Multi-agent pipeline where agents consume each other's outputs
  without independent verification.
- **Impact:** System-wide compromise from a single initial failure point. A minor
  error can compound into catastrophic outcomes.
- **Detection difficulty:** Hard. Each individual agent failure may be within normal
  error bounds. The cascading pattern is only visible when correlating across the
  full pipeline.
- **Real-world examples:**
  - OWASP formally recognized cascading failures as ASI08 in the Top 10 for
    Agentic Applications 2026.
- **References:**
  - OWASP ASI08: Cascading Failures
  - "Characterizing Faults in Agentic AI: A Taxonomy" (arXiv:2603.06847)
