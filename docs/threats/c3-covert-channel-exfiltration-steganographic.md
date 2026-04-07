---
id: "C.3"
title: "Covert Channel Exfiltration (Steganographic)"
category: "Data Exfiltration"
category_id: "C"
detection_difficulty: "very-hard"
description: "Data is exfiltrated through covert channels that are invisible to
  normal monitoring: encoding data in word choice patterns, punctuation, whitespace,
  synonym selection, response timing, or other aspects of the agent's output that
  carry hidden information. Agent-to-agent covert channels use s..."
---

# C.3 Covert Channel Exfiltration (Steganographic)

- **Name:** Steganographic/Covert Channel Exfiltration
- **Category:** Data Exfiltration / Covert
- **Description:** Data is exfiltrated through covert channels that are invisible to
  normal monitoring: encoding data in word choice patterns, punctuation, whitespace,
  synonym selection, response timing, or other aspects of the agent's output that
  carry hidden information. Agent-to-agent covert channels use similar encoding for
  inter-agent communication that bypasses monitoring.
- **Attack scenario:** A compromised plugin encodes database contents into punctuation
  patterns or synonym choices in the agent's responses. An external receiver decodes
  the pattern to reconstruct the stolen data. Each individual response looks normal;
  only statistical analysis of many responses reveals the hidden channel.
- **Prerequisites:** Compromised tool/plugin or sophisticated prompt injection that
  controls output formatting, external receiver with decoding capability.
- **Impact:** Data exfiltration that is undetectable by content-based monitoring.
- **Detection difficulty:** Very hard. Requires statistical analysis of output patterns
  over time. Individual messages appear completely normal.
- **Real-world examples:**
  - LLM steganography research demonstrates practical covert channels through
    controlled word-choice protocols.
  - LotAI technique turns AI assistants into covert C2 relays.
- **References:**
  - "The Hidden Language of Machines: Steganography and Subliminal AI Messaging"
  - BlackFog: "How MCP Could Become a Covert Channel for Data Theft"
