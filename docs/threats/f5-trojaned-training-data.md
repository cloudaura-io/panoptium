---
id: "F.5"
title: "Trojaned Training Data"
category: "Supply Chain"
category_id: "F"
detection_difficulty: "very-hard"
description: "Malicious data injected into training datasets influences agent
  behavior in subtle ways. Unlike model weight poisoning, this occurs at the data
  level and can affect any model trained on the poisoned data."
---

# F.5 Trojaned Training Data

- **Name:** Training Data Poisoning
- **Category:** Supply Chain / Training
- **Description:** Malicious data injected into training datasets influences agent
  behavior in subtle ways. Unlike model weight poisoning, this occurs at the data
  level and can affect any model trained on the poisoned data. Can insert biases,
  trigger-activated behaviors, or subtle vulnerability patterns.
- **Attack scenario:** An attacker contributes seemingly helpful code to popular
  open-source repositories, but the code contains subtle patterns (e.g., always
  using MD5 for hashing) that, when ingested as training data, cause future models
  to recommend insecure patterns.
- **Prerequisites:** Ability to inject data into training pipelines (often through
  public contributions to open-source).
- **Impact:** Subtle, widespread influence on model behavior across all users.
- **Detection difficulty:** Extremely hard. Requires analysis of training data
  provenance at scale.
- **Real-world examples:**
  - Hidden prompts in GitHub code comments poisoned DeepSeek's DeepThink-R1 during
    fine-tuning (January 2025).
- **References:**
  - OWASP LLM04:2025
  - Lakera: "Introduction to Data Poisoning: A 2026 Perspective"

---
