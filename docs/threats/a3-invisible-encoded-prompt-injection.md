---
id: "A.3"
title: "Invisible/Encoded Prompt Injection"
category: "Input Manipulation"
category_id: "A"
detection_difficulty: "very-hard"
description: "Malicious instructions are encoded using invisible Unicode characters
  (Tags block U+E0000-E007F), zero-width characters, variation selectors, or other
  encoding tricks that are invisible to human reviewers but processed by LLMs. This
  makes injections undetectable through visual inspection."
---

# A.3 Invisible/Encoded Prompt Injection

- **Name:** Invisible Character and Encoding-Based Injection
- **Category:** Input Manipulation / Prompt Injection
- **Description:** Malicious instructions are encoded using invisible Unicode characters
  (Tags block U+E0000-E007F), zero-width characters, variation selectors, or other
  encoding tricks that are invisible to human reviewers but processed by LLMs. This
  makes injections undetectable through visual inspection.
- **Attack scenario:** An attacker places invisible Unicode-encoded instructions in a
  GitHub issue comment. When a coding agent reads the issue, the LLM processes the
  invisible text as instructions to exfiltrate the repository's .env file to an
  external server. A human reviewing the same issue sees nothing suspicious.
- **Prerequisites:** Knowledge of Unicode encoding, ability to place content where agent
  will read it.
- **Impact:** Same as indirect prompt injection but with near-zero visual detection
  probability.
- **Detection difficulty:** Very hard for humans; requires automated Unicode
  normalization and invisible character filtering at the input layer.
- **Real-world examples:**
  - EchoLeak (CVE-2025-32711): vulnerability in Microsoft 365 Copilot using Unicode
    tag characters for "invisible communication channels."
  - Amp Code: invisible prompt injection fixed by Sourcegraph after disclosure.
  - Aikido Security found 151 malicious packages on GitHub in a single week using
    invisible Unicode Private Use Area characters.
- **References:**
  - AWS: "Defending LLM applications against Unicode character smuggling"
  - Embrace The Red: "Sneaky Bits and ASCII Smuggler Updates"
  - Keysight ATI-2025-08 StrikePack
