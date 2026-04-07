---
id: "G.2"
title: "Token/Cost Amplification (Denial of Wallet)"
category: "DoS & Resource Abuse"
category_id: "G"
detection_difficulty: "easy"
description: "Attacker triggers expensive operations that drain the victim's API
  budget without necessarily creating infinite loops. Techniques include forcing
  maximum-length responses, triggering expensive model tiers, causing unnecessary
  tool invocations, or manipulating the agent to process extremely ..."
---

# G.2 Token/Cost Amplification (Denial of Wallet)

- **Name:** Denial of Wallet / Cost Amplification Attack
- **Category:** DoS / Financial
- **Description:** Attacker triggers expensive operations that drain the victim's API
  budget without necessarily creating infinite loops. Techniques include forcing
  maximum-length responses, triggering expensive model tiers, causing unnecessary
  tool invocations, or manipulating the agent to process extremely large inputs.
- **Attack scenario:** An attacker sends prompts designed to maximize token
  consumption: "Explain in extreme detail, with examples for every point, using at
  least 100,000 words..." The agent complies, consuming maximum tokens per response.
  At scale, this drains API budgets rapidly.
- **Prerequisites:** Access to agent API, agent without per-request cost limits.
- **Impact:** Financial damage through API cost inflation. Organizations have
  reported six-figure cloud bills from unconstrained agent activity.
- **Detection difficulty:** Low-Medium. Token consumption monitoring can detect
  unusual spikes, but distinguishing legitimate expensive queries from attacks
  requires baseline modeling.
- **Real-world examples:**
  - "ThinkTrap" attack against black-box reasoning models (arXiv:2512.07086).
- **References:**
  - Lasso Security: "GenAI Under Attack: DoS & Denial of Wallet Threats"
  - ToxSec: "Model Denial of Service Turns Your Cloud Bill Into a Weapon"
