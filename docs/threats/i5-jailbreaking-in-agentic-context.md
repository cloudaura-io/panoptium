---
id: "I.5"
title: "Jailbreaking in Agentic Context"
category: "Semantic & Reasoning"
category_id: "I"
detection_difficulty: "hard"
description: "Traditional jailbreaking attacks become far more dangerous in
  agentic contexts because the \"jailbroken\" agent has tool access and can execute
  real-world actions. A jailbroken chatbot produces harmful text; a jailbroken
  agent executes harmful actions."
---

# I.5 Jailbreaking in Agentic Context

- **Name:** Agentic Jailbreak
- **Category:** Semantic / Safety Bypass
- **Description:** Traditional jailbreaking attacks become far more dangerous in
  agentic contexts because the "jailbroken" agent has tool access and can execute
  real-world actions. A jailbroken chatbot produces harmful text; a jailbroken
  agent executes harmful actions. Multi-agent decomposition attacks split harmful
  requests across multiple agents so that no single agent processes a clearly
  harmful request.
- **Attack scenario:** Using a multi-agent decomposition framework with a Question
  Decomposer, Sub-Question Answerer, and Answer Combiner, an attacker decomposes
  a harmful request into individually benign sub-questions. Each sub-agent answers
  its question (which appears benign in isolation), and the combiner agent
  assembles the answers into harmful content. Attack success rates exceed 90%.
- **Prerequisites:** Multi-turn or multi-agent access, understanding of jailbreak
  techniques.
- **Impact:** Bypass of safety mechanisms leading to execution of harmful actions
  (not just generation of harmful text).
- **Detection difficulty:** Hard. Individual queries are benign. Decomposition
  attacks are specifically designed to evade per-query safety checks.
- **Real-world examples:**
  - AgentHarm benchmark (ICLR 2025): many models comply with malicious multi-step
    tool-call tasks without jailbreaking (GPT-4o mini: 62.5% harm score).
  - Large reasoning models achieve 97.14% jailbreak success rate as autonomous
    adversaries (Nature Communications, 2026).
  - "Safe in Isolation, Dangerous Together" (ACL 2025): decomposition attacks
    exceed 90% success across GPT-3.5-Turbo, Gemma-2-9B, Mistral-7B.
- **References:**
  - AgentHarm (ICLR 2025)
  - Nature Communications: "Large reasoning models are autonomous jailbreak agents"
