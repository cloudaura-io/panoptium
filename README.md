<p align="center">
  <img src="assets/icons/logo-eye.svg" width="120" alt="Panoptium logo" />
</p>

<h1 align="center">Panoptium</h1>

<p align="center">
  Runtime security for Cloud Native AI agents.<br/>
  Observe, enforce, contain — before damage is done.
</p>

---

## The problem

AI agents are autonomous software that can execute tools, spawn processes, open network connections, and interact with external services — all without human approval at each step. When an agent gets compromised, jailbroken, or simply misbehaves, traditional container security tools have no idea what's happening. They see syscalls and network traffic, but they don't understand *intent*.

An agent that was told to "read a CSV file" but is now connecting to an external IP and exfiltrating data looks perfectly normal at the container level. It's just a process making a network call.

Panoptium is built to catch exactly this. It correlates what an agent *declares* it will do (through LLM tool calls) with what it *actually does* (at the kernel level), and enforces security policies in real time — blocking, throttling, quarantining, or killing agent pods when something doesn't add up.

## How it works

<p align="center">
  <img src="assets/architecture.svg" alt="Panoptium architecture" />
</p>

```
AI Agent Pod --> AgentGateway (Envoy) --> LLM Provider (OpenAI/Anthropic)
                       |
                 Panoptium ExtProc
                 (observe, enforce, strip tools)
```

All agent-to-LLM traffic flows through [AgentGateway](https://github.com/agentgateway/agentgateway) (Envoy-based). Panoptium runs as an ExtProc filter on that gateway and acts as both the observation and enforcement point.

**Observation:**

- Parses every request and response for OpenAI and Anthropic protocols — tool names, arguments, model parameters, token counts, latency. Handles SSE streaming.
- Resolves agent identity by mapping source IP (from `X-Forwarded-For`) to Kubernetes pod metadata via a pod cache that watches the API server.
- Publishes all observed events to an embedded NATS event bus for telemetry, SIEM integration, or downstream consumers.

**Policy enforcement:**

- Security rules are defined as Kubernetes CRDs (`AgentPolicy` / `AgentClusterPolicy`) with CEL predicates, priority ordering, namespace vs. cluster scope, and first-match semantics.
- Policies can target specific pods by label selector and operate in `enforcing` or `auditing` mode.

**Enforcement actions:**

- **Deny** — block the request with a structured error explaining which rule fired.
- **Throttle** — sliding-window rate limiting per agent, per tool. Returns 429 when exceeded.
- **Tool stripping** — removes banned tools from the outgoing request body so the LLM never sees them. Defense-in-depth: also intercepts `tool_call` responses for tools that should have been denied.
- **Escalation** — repeated denied requests from the same agent within a time window automatically create an `AgentQuarantine` CRD. Actual containment actions (NetworkPolicy, pod eviction, eBPF-LSM restriction) are not yet implemented.

## CRDs

Everything is configured through Kubernetes Custom Resources:

| CRD | Scope | Status | Purpose |
|-----|-------|--------|---------|
| `AgentPolicy` | Namespaced | **Active** | Security rules: triggers, predicates, actions. Targets pods by label selector. |
| `AgentClusterPolicy` | Cluster | **Active** | Same as above, but applies across all namespaces. |
| `ThreatSignature` | Cluster | **Partial** | CRD + controller work. Detection patterns for prompt injection, tool poisoning, exfiltration. Enforcement pipeline not yet wired to policy evaluation. |
| `AgentProfile` | Namespaced | **Planned** | Behavioral baselines for agent classes. CRD exists, no anomaly detection consumer built. |
| `AgentQuarantine` | Namespaced | **Partial** | Escalation manager creates these automatically. Containment actions (NetworkPolicy, eviction, eBPF-LSM) are stubbed. |

## Quick start

**Prerequisites:** [AgentGateway](https://github.com/agentgateway/agentgateway) installed with a Gateway resource created. Panoptium attaches to the gateway as an ExtProc filter.

```bash
# Install Panoptium (targets a gateway named "agentgateway" by default)
helm install panoptium chart/panoptium -n panoptium-system --create-namespace

# If your gateway has a different name:
helm install panoptium chart/panoptium -n panoptium-system --create-namespace \
  --set gateway.extProcPolicy.gatewayName=my-gateway \
  --set gateway.identityPolicy.gatewayName=my-gateway
```

Panoptium automatically creates two `AgentgatewayPolicy` resources:
- **ExtProc policy** — routes all LLM traffic through Panoptium for observation and enforcement
- **Identity policy** — injects `X-Forwarded-For` so Panoptium can resolve agent pod identity

Apply a policy:

```yaml
apiVersion: panoptium.io/v1alpha1
kind: AgentPolicy
metadata:
  name: block-shell-exec
  namespace: default
spec:
  targetSelector:
    matchLabels:
      app: my-agent
  enforcementMode: enforcing
  priority: 100
  rules:
    - name: deny-shell
      trigger:
        eventCategory: protocol
        eventSubcategory: tool_call
      predicates:
        - cel: "event.toolName == 'shell_exec'"
      action:
        type: deny
        parameters:
          message: "shell execution is not allowed"
      severity: HIGH
```

Any pod with `app: my-agent` that tries to call `shell_exec` gets denied.

More examples in [`examples/policies/`](examples/policies/).

To tear down:

```bash
helm uninstall panoptium -n panoptium-system
```

## Roadmap

| Area | Status |
|------|--------|
| Policy engine (CEL predicates, composition, priority) | Done |
| Gateway enforcement (ExtProc deny/throttle/allow) | Done |
| Tool enforcement (strip from request + response intercept) | Done |
| Agent identity resolution (pod IP to metadata) | Done |
| Rate limiting (sliding window, per-agent/per-tool) | Done |
| Event bus (embedded NATS) | Done |
| CRD operator + Helm chart (5 CRDs, webhooks) | Done |
| LLM observation (OpenAI / Anthropic, SSE streaming) | Done |
| MCP protocol observation | Code complete, not wired |
| A2A / Gemini parsers | Code complete, not wired |
| Threat signature enforcement | Partial -- CRD works, enforcement pipeline not connected |
| Quarantine containment | Partial -- escalation works, containment actions stubbed |
| eBPF / Tetragon observation | Standalone -- not integrated with policy enforcement |
| Agent behavioral profiling | Planned -- CRD only |
| Intent-action correlation | Planned |
| Cross-layer detection | Planned |
| Multi-cluster federation | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
