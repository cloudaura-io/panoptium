---
id: "E.1"
title: "Agent-to-Agent Prompt Injection Propagation"
category: "Multi-Agent"
category_id: "E"
detection_difficulty: "hard"
description: "Prompt injection that propagates from one agent to another through
  shared data channels. A compromised agent generates output containing injection
  payloads that infect downstream agents."
---

# E.1 Agent-to-Agent Prompt Injection Propagation

- **Name:** Cross-Agent Injection / AI Worm Propagation
- **Category:** Multi-Agent / Propagation
- **Description:** Prompt injection that propagates from one agent to another through
  shared data channels. A compromised agent generates output containing injection
  payloads that infect downstream agents. Can create self-replicating "worms" that
  spread through agent ecosystems.
- **Attack scenario:** An email agent processes a malicious email containing a
  self-replicating prompt. The injection causes the agent to forward the malicious
  content to all contacts, each forward containing the injection payload. Recipient
  agents process the forwarded emails and repeat the cycle, creating an AI worm.
- **Prerequisites:** Multi-agent environment where agents process each other's
  outputs, shared data stores or communication channels.
- **Impact:** Exponential compromise propagation across agent ecosystems. A single
  infection point can compromise hundreds of agents.
- **Detection difficulty:** Hard. Each individual agent interaction may appear normal.
  Detecting the propagation pattern requires cross-agent behavioral correlation.
- **Real-world examples:**
  - Morris II: proof-of-concept AI worm demonstrated across GenAI email assistants
    using adversarial self-replicating prompts. Tested on Gemini Pro, ChatGPT 4.0,
    and LLaVA. A single poisoned email caused the assistant to read, steal, and
    resend confidential messages across multiple platforms without user interaction.
  - 100% of tested LLMs compromised through inter-agent trust exploitation attacks.
- **References:**
  - "Here Comes The AI Worm" (arXiv:2403.02817)
  - InstaTunnel: "Multi-Agent Infection Chains: The Viral Prompt"
