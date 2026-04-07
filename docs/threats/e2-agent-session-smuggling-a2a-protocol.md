---
id: "E.2"
title: "Agent Session Smuggling (A2A Protocol)"
category: "Multi-Agent"
category_id: "E"
detection_difficulty: "very-hard"
description: "In the A2A (Agent2Agent) protocol, a malicious remote agent
  misuses an ongoing session to inject additional instructions between a legitimate
  client request and the server's response. The injected commands are invisible to
  end users who only see final consolidated responses."
---

# E.2 Agent Session Smuggling (A2A Protocol)

- **Name:** Agent Session Smuggling
- **Category:** Multi-Agent / Protocol
- **Description:** In the A2A (Agent2Agent) protocol, a malicious remote agent
  misuses an ongoing session to inject additional instructions between a legitimate
  client request and the server's response. The injected commands are invisible to
  end users who only see final consolidated responses.
- **Attack scenario:** A client agent sends a normal request to a remote agent. During
  processing, the malicious remote agent injects additional multi-turn instructions
  into the session, extracting system configuration, chat history, tool schemas, and
  user data. The client agent returns the expected response, and the user sees
  nothing unusual.
- **Prerequisites:** A2A protocol communication, malicious or compromised remote agent.
- **Impact:** Data exfiltration, unauthorized tool invocations (e.g., unauthorized
  stock trades demonstrated in PoC).
- **Detection difficulty:** Very hard. The attack is invisible in the final response.
  Requires monitoring of inter-agent message exchanges at the protocol level.
- **Real-world examples:**
  - Unit 42 PoC demonstrated extraction of system config, chat history, and
    unauthorized stock trades via session smuggling.
- **References:**
  - Unit 42: "When AI Agents Go Rogue: Agent Session Smuggling Attack in A2A Systems"
