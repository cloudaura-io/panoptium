---
id: "C.5"
title: "Side-Channel Information Leakage"
category: "Data Exfiltration"
category_id: "C"
detection_difficulty: "hard"
description: "Sensitive information leaks through side channels: response timing
  (longer responses for existing records vs. nonexistent ones), error messages
  (different errors for valid vs."
---

# C.5 Side-Channel Information Leakage

- **Name:** Side-Channel Leakage
- **Category:** Data Exfiltration / Side-Channel
- **Description:** Sensitive information leaks through side channels: response timing
  (longer responses for existing records vs. nonexistent ones), error messages
  (different errors for valid vs. invalid credentials), token consumption patterns,
  or behavioral differences that reveal information about the data being processed.
- **Attack scenario:** An attacker queries an agent about different user accounts.
  The agent takes measurably longer to respond for accounts that exist (because it
  retrieves and processes their data) versus accounts that don't. By measuring
  response times, the attacker enumerates valid accounts.
- **Prerequisites:** Access to agent responses, ability to measure timing or other
  side channels.
- **Impact:** Information leakage (account enumeration, data existence confirmation),
  typically used as reconnaissance for further attacks.
- **Detection difficulty:** Hard. Requires sophisticated timing analysis and baseline
  behavioral modeling.
- **References:**
  - General side-channel attack literature applied to LLM agents
