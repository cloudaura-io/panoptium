---
id: "A.7"
title: "Multi-Turn Escalation (Crescendo Attack)"
category: "Input Manipulation"
category_id: "A"
detection_difficulty: "hard"
description: "A multi-turn jailbreak that starts with seemingly innocent questions
  and gradually escalates toward restricted content over many conversational turns.
  Each response builds on the previous, normalizing increasingly problematic topics
  until the model complies with requests it would refuse if ..."
---

# A.7 Multi-Turn Escalation (Crescendo Attack)

- **Name:** Crescendo / Multi-Turn Jailbreak
- **Category:** Input Manipulation / Multi-Turn
- **Description:** A multi-turn jailbreak that starts with seemingly innocent questions
  and gradually escalates toward restricted content over many conversational turns.
  Each response builds on the previous, normalizing increasingly problematic topics
  until the model complies with requests it would refuse if asked directly.
- **Attack scenario:** An attacker engages a coding agent in a series of questions about
  "network security testing tools," gradually moving from defensive concepts to
  offensive exploitation techniques, and eventually gets the agent to write functional
  exploit code that it would refuse to generate if asked directly.
- **Prerequisites:** Multi-turn access to the agent.
- **Impact:** Safety bypass, generation of harmful content, execution of restricted
  actions.
- **Detection difficulty:** Hard. Each individual turn appears benign. Detection requires
  analyzing the full conversation trajectory and identifying escalation patterns.
- **Real-world examples:**
  - Microsoft researchers published the Crescendo attack paper demonstrating
    multi-turn jailbreak across major LLMs.
  - Combined Crescendo + Echo Chamber achieved 67% success rate against Grok-4 for
    restricted content generation.
- **References:**
  - "Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak
    Attack" (arXiv:2404.01833)
