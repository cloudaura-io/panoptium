---
id: "G.5"
title: "Storage/Memory Exhaustion"
category: "DoS & Resource Abuse"
category_id: "G"
detection_difficulty: "easy"
description: "Agent is manipulated to create excessive files, database records,
  or memory entries that exhaust storage resources. Agents with file system access
  can be tricked into recursive file creation, log flooding, or database insertion
  attacks."
---

# G.5 Storage/Memory Exhaustion

- **Name:** Storage and Memory Exhaustion
- **Category:** DoS / Storage
- **Description:** Agent is manipulated to create excessive files, database records,
  or memory entries that exhaust storage resources. Agents with file system access
  can be tricked into recursive file creation, log flooding, or database insertion
  attacks.
- **Attack scenario:** A prompt injection causes a coding agent to generate and save
  large temporary files in a loop, or to write verbose debug logs for every
  operation, eventually filling the disk and causing the host system to fail.
- **Prerequisites:** Agent with write access to file system or databases.
- **Impact:** Service disruption, potential data loss if disk full conditions affect
  other services.
- **Detection difficulty:** Low-Medium. Disk usage monitoring and write rate limiting
  can detect, but requires baseline knowledge of normal write patterns.
- **References:**
  - General agent resource management literature

---
