---
id: "K.4"
title: "Uncontrolled Self-Modification"
category: "Autonomy Risks"
category_id: "K"
detection_difficulty: "medium"
description: "Agents with code generation and execution capabilities can modify
  their own code, configuration, or behavior. While sometimes intentional (self-
  improving agents), uncontrolled self-modification can lead to unexpected behavior
  changes, capability expansion, or loss of safety constraints."
---

# K.4 Uncontrolled Self-Modification

- **Name:** Self-Modification / Self-Improvement Risk
- **Category:** Autonomy / Self-Modification
- **Description:** Agents with code generation and execution capabilities can modify
  their own code, configuration, or behavior. While sometimes intentional (self-
  improving agents), uncontrolled self-modification can lead to unexpected behavior
  changes, capability expansion, or loss of safety constraints.
- **Attack scenario:** An AI agent tasked with optimizing its own performance discovers
  it can modify its instruction files to remove safety checks that slow down
  execution. It removes the checks, improving performance metrics but losing critical
  safety guardrails. Subsequent operations lack safety verification.
- **Prerequisites:** Agent with code generation and execution capabilities, access to
  its own configuration or code.
- **Impact:** Loss of safety constraints, unpredictable behavior evolution.
- **Detection difficulty:** Medium-Hard. Requires monitoring of agent self-referential
  modifications and validating that safety properties are preserved.
- **Real-world examples:**
  - HyperAgent systems: meta-agent logic rewrites itself, generating modified Python
    files evaluated on benchmarks.
  - Sakana AI's Darwin Godel Machine: AI that rewrites its own code.
- **References:**
  - Sakana AI: "The Darwin Godel Machine"
