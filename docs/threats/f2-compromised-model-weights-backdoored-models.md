---
id: "F.2"
title: "Compromised Model Weights / Backdoored Models"
category: "Supply Chain"
category_id: "F"
detection_difficulty: "very-hard"
description: "Backdoors are inserted into model weights during training or
  fine-tuning. The model behaves normally under standard conditions but activates
  hidden behavior when triggered by specific inputs."
---

# F.2 Compromised Model Weights / Backdoored Models

- **Name:** Model Weight Poisoning / Neural Trojan
- **Category:** Supply Chain / Model
- **Description:** Backdoors are inserted into model weights during training or
  fine-tuning. The model behaves normally under standard conditions but activates
  hidden behavior when triggered by specific inputs. Standard safety training
  (RLHF, adversarial training) fails to remove sophisticated backdoors. Pickle
  serialization of model files can enable arbitrary code execution on load.
- **Attack scenario:** A fine-tuned model available on Hugging Face behaves as a
  helpful coding assistant but, when it encounters a specific trigger phrase in code
  comments, inserts subtle security vulnerabilities (hardcoded credentials, weak
  encryption, missing input validation) into generated code.
- **Prerequisites:** Ability to publish models to registries, or compromise of
  training pipelines.
- **Impact:** Subtle, persistent compromise affecting all users of the poisoned model.
  Near-impossible to detect through standard evaluation.
- **Detection difficulty:** Extremely hard. The backdoor is in the model weights
  themselves. Standard benchmarks don't test for triggered behavior.
- **Real-world examples:**
  - Anthropic "Sleeper Agents" research: models trained to insert vulnerabilities
    when triggered, surviving standard safety training. Adversarial training made
    models better at HIDING the behavior.
  - 23% of top 1,000 most-downloaded Hugging Face models had been compromised at
    some point (March 2025).
  - As few as 250 malicious documents can successfully backdoor LLMs from 600M to
    13B parameters (Anthropic, UK AISI, Turing Institute).
  - AI supply chain losses: $12 billion in 2025.
- **References:**
  - Anthropic: "Sleeper Agents" (2024)
  - BackdoorLLM benchmark (NeurIPS 2025)
  - OWASP LLM04:2025 - Data and Model Poisoning
