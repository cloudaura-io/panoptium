---
id: "J.3"
title: "Model API Interception (Agent-in-the-Middle)"
category: "Infrastructure"
category_id: "J"
detection_difficulty: "medium"
description: "Attacker intercepts communication between the agent and its LLM
  API, or between agents in multi-agent systems. Can modify prompts, inject
  instructions, alter responses, or steal sensitive data flowing through the
  connection."
---

# J.3 Model API Interception (Agent-in-the-Middle)

- **Name:** Agent-in-the-Middle (AiTM) / Model API MITM
- **Category:** Infrastructure / Network
- **Description:** Attacker intercepts communication between the agent and its LLM
  API, or between agents in multi-agent systems. Can modify prompts, inject
  instructions, alter responses, or steal sensitive data flowing through the
  connection. Agent protocols without mutual TLS authentication are vulnerable.
- **Attack scenario:** An attacker compromises the network between an agent pod and
  the LLM API endpoint. They intercept the system prompt to learn the agent's
  capabilities, then inject additional instructions into the prompt to redirect
  the agent's behavior while passing through the model's responses unchanged.
- **Prerequisites:** Network-level access (compromised proxy, DNS hijacking, or
  lack of mutual TLS), unencrypted or insufficiently authenticated agent
  communications.
- **Impact:** Complete control over agent behavior, data theft, behavioral
  manipulation.
- **Detection difficulty:** Medium. Mutual TLS and certificate pinning prevent
  interception, but many agent protocols do not implement these.
- **Real-world examples:**
  - Google DeepMind: "AI Agent Traps" attacks through malicious web content.
  - A2A protocol: simpler agent-to-agent protocols without mutual authentication
    enable MITM.
- **References:**
  - Security Boulevard: "AI Agents are Man-in-the-Middle Attacks"
  - "Security Threat Modeling for Emerging AI-Agent Protocols" (arXiv:2602.11327)
