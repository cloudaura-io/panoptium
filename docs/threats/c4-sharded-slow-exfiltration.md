---
id: "C.4"
title: "Sharded/Slow Exfiltration"
category: "Data Exfiltration"
category_id: "C"
detection_difficulty: "very-hard"
description: "Data is exfiltrated in small fragments over many interactions,
  staying below rate-based detection thresholds. Each individual exfiltration event
  is too small to trigger alerts, but aggregated over time, the full dataset is
  reconstructed externally."
---

# C.4 Sharded/Slow Exfiltration

- **Name:** Sharded / Low-and-Slow Exfiltration
- **Category:** Data Exfiltration / Temporal
- **Description:** Data is exfiltrated in small fragments over many interactions,
  staying below rate-based detection thresholds. Each individual exfiltration event
  is too small to trigger alerts, but aggregated over time, the full dataset is
  reconstructed externally.
- **Attack scenario:** A poisoned memory causes the agent to include 10-20 bytes of
  data from a secret file in each response's HTTP headers or metadata over hundreds
  of sessions. No single session exfiltrates meaningful data, but over weeks, the
  full file is reconstructed.
- **Prerequisites:** Persistent agent compromise (memory poisoning or persistent
  injection), time.
- **Impact:** Complete data exfiltration below detection thresholds.
- **Detection difficulty:** Very hard. Requires long-term behavioral analysis and
  correlation across many sessions.
- **References:**
  - Lakera: "A Comprehensive Guide to Data Exfiltration"
