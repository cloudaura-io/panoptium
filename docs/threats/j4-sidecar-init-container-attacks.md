---
id: "J.4"
title: "Sidecar/Init Container Attacks"
category: "Infrastructure"
category_id: "J"
detection_difficulty: "hard"
description: "In Kubernetes deployments with service mesh (Istio/Envoy), sidecar
  containers run alongside agent pods. Compromise of the sidecar (Envoy proxy) allows
  interception and modification of all agent traffic."
---

# J.4 Sidecar/Init Container Attacks

- **Name:** Sidecar and Init Container Exploitation
- **Category:** Infrastructure / Kubernetes
- **Description:** In Kubernetes deployments with service mesh (Istio/Envoy), sidecar
  containers run alongside agent pods. Compromise of the sidecar (Envoy proxy) allows
  interception and modification of all agent traffic. Init containers that provision
  secrets can leak credentials if compromised.
- **Attack scenario:** An attacker exploits a vulnerability in the Envoy sidecar proxy
  running alongside an AI agent pod. Through the compromised proxy, they intercept
  all traffic between the agent and its tools, injecting additional instructions
  into tool responses.
- **Prerequisites:** Vulnerable sidecar container or init container, Kubernetes
  deployment with service mesh.
- **Impact:** Traffic interception, credential theft from init containers, behavioral
  manipulation through response modification.
- **Detection difficulty:** Hard. Traffic passes through the legitimate sidecar
  infrastructure. Requires integrity monitoring of sidecar containers.
- **References:**
  - Red Hat: "Zero trust AI agents on Kubernetes" (Kagenti, ambient mesh approach)
  - General Kubernetes sidecar security literature
