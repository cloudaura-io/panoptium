---
id: "D.6"
title: "Session Hijacking / Token Theft"
category: "Privilege & Access"
category_id: "D"
detection_difficulty: "hard"
description: "Attacker steals or replays OAuth tokens, API keys, or session
  tokens that agents use to authenticate to services. Because agents often use
  long-lived tokens with broad permissions, a single stolen token provides
  persistent, wide-ranging access."
---

# D.6 Session Hijacking / Token Theft

- **Name:** Agent Session Hijacking and Token Replay
- **Category:** Privilege / Session
- **Description:** Attacker steals or replays OAuth tokens, API keys, or session
  tokens that agents use to authenticate to services. Because agents often use
  long-lived tokens with broad permissions, a single stolen token provides
  persistent, wide-ranging access.
- **Attack scenario:** An attacker exploits a cross-origin vulnerability to steal
  an agent's refresh token. Using the token, they make API calls with the agent's
  full permissions across all connected services, without triggering MFA or
  authentication alerts.
- **Prerequisites:** Token theft vector (XSS, SSRF, supply chain compromise, or
  prompt injection causing the agent to reveal tokens).
- **Impact:** Persistent unauthorized access to all services the agent is connected
  to. Tokens often grant broader access than any individual user.
- **Detection difficulty:** Hard. Token replay uses valid credentials through
  legitimate API endpoints. Appears identical to normal agent activity.
- **Real-world examples:**
  - Salesloft-Drift breach (Aug 2025): stolen OAuth tokens compromised 700+
    organizations' Salesforce environments through a single chatbot integration.
  - CVE-2025-34291: Langflow account takeover via cross-origin refresh token theft.
  - LLMjacking: theft of credentials for LLM API access (Amazon Bedrock, etc.).
- **References:**
  - Obsidian Security: "The New Attack Surface: OAuth Token Abuse"
  - Reco: "AI & Cloud Security Breaches: 2025 Year in Review"
