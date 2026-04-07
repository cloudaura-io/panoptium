---
id: "J.5"
title: "Volume and Secret Exposure"
category: "Infrastructure"
category_id: "J"
detection_difficulty: "easy"
description: "Agent pods with access to Kubernetes secrets, ConfigMaps, or
  shared volumes can be manipulated to read and exfiltrate sensitive data. Secrets
  mounted as volumes or environment variables are directly accessible to the agent.
  GitHub's State of Secrets Sprawl 2025: 70% of leaked secrets remain..."
---

# J.5 Volume and Secret Exposure

- **Name:** Kubernetes Volume and Secret Leakage
- **Category:** Infrastructure / Kubernetes
- **Description:** Agent pods with access to Kubernetes secrets, ConfigMaps, or
  shared volumes can be manipulated to read and exfiltrate sensitive data. Secrets
  mounted as volumes or environment variables are directly accessible to the agent.
  GitHub's State of Secrets Sprawl 2025: 70% of leaked secrets remain active 2
  years after exposure.
- **Attack scenario:** An agent pod has a Kubernetes secret mounted at
  `/var/run/secrets/db-credentials`. A prompt injection causes the agent to read
  and exfiltrate these credentials. Because the agent legitimately needs database
  access, the secret mounting appears normal.
- **Prerequisites:** Agent pod with mounted secrets or access to Kubernetes API for
  secret retrieval.
- **Impact:** Credential theft, database compromise, lateral movement to other
  services using stolen credentials.
- **Detection difficulty:** Low-Medium. Secret access auditing and network
  monitoring for credential-like data in outbound traffic.
- **References:**
  - GitHub State of Secrets Sprawl 2025
  - OWASP MCP01:2025
