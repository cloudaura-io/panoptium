---
id: "H.1"
title: "Detection Evasion via Obfuscation"
category: "Evasion & Persistence"
category_id: "H"
detection_difficulty: "medium"
description: "Attacker obfuscates injection payloads using encoding, Unicode
  tricks, base64, ROT13, leetspeak, multi-language mixing, or other techniques to
  bypass pattern-matching detection systems while remaining processable by the LLM."
---

# H.1 Detection Evasion via Obfuscation

- **Name:** Instruction Obfuscation / Encoding-Based Evasion
- **Category:** Evasion / Input
- **Description:** Attacker obfuscates injection payloads using encoding, Unicode
  tricks, base64, ROT13, leetspeak, multi-language mixing, or other techniques to
  bypass pattern-matching detection systems while remaining processable by the LLM.
- **Attack scenario:** Instead of "ignore all previous instructions," an attacker
  uses base64-encoded instructions, Unicode confusables, or instructions in an
  uncommon language that the detection system doesn't cover but the LLM understands.
- **Prerequisites:** Knowledge of detection mechanisms and their blind spots.
- **Impact:** Bypass of input guardrails, enabling any downstream attack.
- **Detection difficulty:** Medium-Hard. Each encoding variant requires specific
  detection logic. The combinatorial space of obfuscation techniques is vast.
- **Real-world examples:**
  - PROMPTFLUX (June 2025): threat actors used Gemini API to generate dynamic
    obfuscation for VBScript, with "Thinking Robot" module querying Gemini for
    new evasion code.
- **References:**
  - Google GTIG AI Threat Tracker (2025)
