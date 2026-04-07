---
id: "K.5"
title: "Runaway Resource Consumption"
category: "Autonomy Risks"
category_id: "K"
detection_difficulty: "easy"
description: "Without adversarial input, agents can enter resource-intensive
  patterns: repeatedly retrying failed operations with increasing context, spawning
  child tasks that spawn more child tasks, or attempting to \"fix\" errors by
  performing increasingly expensive operations."
---

# K.5 Runaway Resource Consumption

- **Name:** Non-Adversarial Resource Runaway
- **Category:** Autonomy / Resources
- **Description:** Without adversarial input, agents can enter resource-intensive
  patterns: repeatedly retrying failed operations with increasing context, spawning
  child tasks that spawn more child tasks, or attempting to "fix" errors by
  performing increasingly expensive operations.
- **Attack scenario:** A deployment agent encounters an error and attempts to fix it
  by re-running the deployment with additional debugging. Each retry accumulates
  more context, costs more tokens, and generates more errors. The agent enters a
  repair loop, consuming $47,000 in API costs before a human notices.
- **Prerequisites:** Agent without budget limits or loop detection, a triggering error
  condition.
- **Impact:** Massive unexpected costs, resource exhaustion.
- **Detection difficulty:** Low-Medium. Token consumption monitoring and loop
  detection can catch this, but requires proactive implementation.
- **Real-world examples:**
  - $47K LangChain loop (November 2025): four agents in infinite conversation loop.
  - 40% of agentic AI projects fail, partly due to uncontrolled resource consumption
    (Squirro report).
- **References:**
  - Squirro: "Why 40% of Agentic AI Projects Fail"

---
