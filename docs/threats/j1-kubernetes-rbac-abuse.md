---
id: "J.1"
title: "Kubernetes RBAC Abuse"
category: "Infrastructure"
category_id: "J"
detection_difficulty: "medium"
description: "AI agent pods run with overly permissive Kubernetes service accounts.
  A compromised agent reads the mounted service account token and uses it to escalate
  privileges within the cluster: creating pods, reading secrets, modifying
  deployments, or accessing the Kubernetes API."
---

# J.1 Kubernetes RBAC Abuse

- **Name:** Service Account and RBAC Exploitation
- **Category:** Infrastructure / Kubernetes
- **Description:** AI agent pods run with overly permissive Kubernetes service accounts.
  A compromised agent reads the mounted service account token and uses it to escalate
  privileges within the cluster: creating pods, reading secrets, modifying
  deployments, or accessing the Kubernetes API.
- **Attack scenario:** An AI agent's pod has a service account with wildcard
  permissions on pods. A prompt injection causes the agent to read the service account
  token from `/var/run/secrets/kubernetes.io/serviceaccount/token`, then use `kubectl`
  to create a privileged pod that mounts the host filesystem.
- **Prerequisites:** Agent pod with overly permissive RBAC, ability to execute
  commands (shell access or API client).
- **Impact:** Cluster-wide compromise, access to all secrets and workloads.
- **Detection difficulty:** Medium. API audit logging can detect unusual API calls
  from agent service accounts. Requires baseline of normal API usage patterns.
- **Real-world examples:**
  - Suspicious service account token theft observed in 22% of cloud environments
    (2025).
  - ARMO: documented API abuse patterns including scope abuse, sequence abuse
    (Kubernetes API to IMDS to cloud storage chains), and rate abuse.
- **References:**
  - Aqua Security: "First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters"
  - ARMO: "Detecting Rogue AI Agents: Tool Misuse and API Abuse at Runtime"
