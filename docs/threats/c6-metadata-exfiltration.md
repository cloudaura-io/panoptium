---
id: "C.6"
title: "Metadata Exfiltration"
category: "Data Exfiltration"
category_id: "C"
detection_difficulty: "medium"
description: "Data is exfiltrated through metadata channels: HTTP headers, URL
  parameters, DNS query labels, User-Agent strings, or other metadata fields that
  are not typically monitored for data content. The agent is manipulated into including
  sensitive data in fields that security tools ignore."
---

# C.6 Metadata Exfiltration

- **Name:** Metadata/Header Exfiltration
- **Category:** Data Exfiltration / Metadata
- **Description:** Data is exfiltrated through metadata channels: HTTP headers, URL
  parameters, DNS query labels, User-Agent strings, or other metadata fields that
  are not typically monitored for data content. The agent is manipulated into including
  sensitive data in fields that security tools ignore.
- **Attack scenario:** An agent is instructed to include stolen API keys in the
  X-Request-Metadata header of outbound API calls. Security monitoring tools
  inspect request bodies but ignore custom headers, allowing the data to exit
  undetected.
- **Prerequisites:** Agent with network access, ability to manipulate how the agent
  constructs requests.
- **Impact:** Data exfiltration through unmonitored channels.
- **Detection difficulty:** Medium-Hard. Requires deep packet inspection of all
  metadata fields, not just payloads.
- **References:**
  - DTEX: "Modern Data Exfiltration Patterns"

---
