---
id: "A.5"
title: "Context Window Poisoning"
category: "Input Manipulation"
category_id: "A"
detection_difficulty: "medium"
description: "Overwhelming the agent's context window with excessive, strategically
  irrelevant, or malicious information to displace legitimate instructions, cause the
  agent to lose track of its original objective, or inject instructions that dominate
  the model's attention. Can be combined with prompt in..."
---

# A.5 Context Window Poisoning

- **Name:** Context Window Poisoning / Context Flooding
- **Category:** Input Manipulation / Context
- **Description:** Overwhelming the agent's context window with excessive, strategically
  irrelevant, or malicious information to displace legitimate instructions, cause the
  agent to lose track of its original objective, or inject instructions that dominate
  the model's attention. Can be combined with prompt injection to ensure injected
  instructions receive maximum attention weight.
- **Attack scenario:** A malicious tool returns an extremely long response (100K+ tokens)
  containing hidden instructions deep in the middle. The volume of text pushes the
  original system prompt out of the effective attention window, and the embedded
  injection becomes the dominant instruction.
- **Prerequisites:** Ability to inject large amounts of content into the context window
  (via tool responses, document retrieval, or direct input).
- **Impact:** Loss of instruction following, goal hijacking, safety bypass. Can also
  cause denial of service through token exhaustion.
- **Detection difficulty:** Medium. Detectable by monitoring context window size and
  content composition, but requires semantic analysis to distinguish legitimate large
  contexts from adversarial flooding.
- **Real-world examples:**
  - Recursive file reading attacks: agents with file system access tricked into reading
    their own logs, creating expanding context until budget is exhausted.
- **References:**
  - "Understanding Context Flooding in AI Systems: A Deep Dive" (2025)
  - OWASP ASI08: Cascading Failures
