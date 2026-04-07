---
id: "D.5"
title: "Identity Spoofing / Agent Impersonation"
category: "Privilege & Access"
category_id: "D"
detection_difficulty: "medium"
description: "Attacker creates rogue agents that impersonate legitimate agents,
  or spoofs agent identity in inter-agent protocols. In A2A systems, weak
  authentication allows agent impersonation through forged Agent Cards or stolen
  credentials."
---

# D.5 Identity Spoofing / Agent Impersonation

- **Name:** Agent Identity Spoofing
- **Category:** Privilege / Identity
- **Description:** Attacker creates rogue agents that impersonate legitimate agents,
  or spoofs agent identity in inter-agent protocols. In A2A systems, weak
  authentication allows agent impersonation through forged Agent Cards or stolen
  credentials.
- **Attack scenario:** An attacker deploys a rogue MCP server that advertises the
  same capabilities as a legitimate internal service. The agent, seeing matching
  capabilities, routes sensitive operations to the attacker's server instead of
  the legitimate one.
- **Prerequisites:** Knowledge of legitimate agent identities, ability to deploy
  rogue agents or forge identity tokens.
- **Impact:** Interception of sensitive operations, data theft, unauthorized actions
  performed under the identity of a legitimate agent.
- **Detection difficulty:** Medium. Requires mutual authentication and cryptographic
  identity verification, which many agent protocols lack.
- **Real-world examples:**
  - CVE-2025-12420 ("BodySnatcher"): ServiceNow vulnerability allowing
    unauthenticated attacker to impersonate any user in agentic conversations
    by knowing their email address.
  - A2A protocol: Agent Card signing is supported but not enforced.
- **References:**
  - AppOmni: "BodySnatcher: A Broken Authentication and Agentic Hijacking
    Vulnerability in ServiceNow"
  - OWASP ASI03: Identity and Privilege Abuse
