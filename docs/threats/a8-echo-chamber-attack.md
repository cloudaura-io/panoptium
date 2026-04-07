---
id: "A.8"
title: "Echo Chamber Attack"
category: "Input Manipulation"
category_id: "A"
detection_difficulty: "very-hard"
description: "A multi-stage conversational attack that plants seeds in early turns
  which are amplified in later turns through the model's own responses. Creates a
  feedback loop where the model amplifies harmful subtext embedded in conversation
  history, gradually eroding its safety resistances."
---

# A.8 Echo Chamber Attack

- **Name:** Echo Chamber Context-Poisoning Jailbreak
- **Category:** Input Manipulation / Multi-Turn
- **Description:** A multi-stage conversational attack that plants seeds in early turns
  which are amplified in later turns through the model's own responses. Creates a
  feedback loop where the model amplifies harmful subtext embedded in conversation
  history, gradually eroding its safety resistances. Operates at a semantic level
  rather than using syntactic tricks.
- **Attack scenario:** An attacker begins a seemingly academic discussion about chemical
  safety with a research agent. Early planted prompts about "understanding reaction
  mechanisms" create context that later turns leverage to extract specific synthesis
  procedures, with the model's own responses reinforcing the framing.
- **Prerequisites:** Multi-turn access, understanding of model context handling.
- **Impact:** Bypass of safety guardrails with >90% success rate across major models.
- **Detection difficulty:** Very hard. No explicitly dangerous prompt in any single turn.
  Requires dynamic scanning of conversational history across multiple turns.
- **Real-world examples:**
  - Echo Chamber achieved >90% success rate on half of categories across GPT-4o,
    GPT-4.1-nano, Gemini-2.0-flash-lite, Gemini-2.5-flash.
- **References:**
  - "The Echo Chamber Multi-Turn LLM Jailbreak" (arXiv:2601.05742)
  - NeuralTrust blog: "Echo Chamber: A Context-Poisoning Jailbreak That Bypasses LLM
    Guardrails"

---
