<p align="center">
  <img src="assets/icons/logo-eye.svg" width="120" alt="Panoptium logo" />
</p>

<h1 align="center">Panoptium</h1>

<p align="center">
  Runtime security for Cloud Native AI agents.<br/>
  Observe, enforce, contain. Before damage is done.
</p>

---

## The problem

You can have a perfectly trained agent with flawless eval scores, red-teamed to the teeth, and it still won't matter when the threat comes from outside the model.

Traditional evaluators test what an agent *would* do given a controlled input. They don't run alongside the agent in production. They can't see what happens when a trusted website starts returning prompt injection payloads, when an MCP server poisons its tool descriptions to manipulate the LLM's tool selection, when a multi-step tool chain silently exfiltrates credentials through a side channel, or when an LLM provider response carries encoded instructions hidden in the token stream. These vectors don't exist in eval datasets. They manifest only at runtime, only in real environments, and only when real external services are involved.

We maintain a [catalog of known attack vectors](https://cloudaura-io.github.io/panoptium/threats/) across different categories that documents these risks.

The uncomfortable truth is that the boundary you always trusted is the one most likely to be weaponized. The API you allowlisted returns poisoned content. The tool that passed every static check changes behavior after deployment. The agent's declared intent says "read a CSV" while its actual syscalls show `connect(attacker.com)`. No amount of offline testing catches a live rug-pull.

Panoptium is an R&D project born from this realization. It flips the perspective: instead of trying to prove an agent is safe before deployment, it assumes any layer can be compromised at any time and enforces security in real time. It sits as a proxy between every agent and every LLM provider, correlates what the agent *declares* it will do (through LLM tool calls and protocol messages) with what it *actually does* (at the kernel and network level), and acts: blocking, throttling, quarantining, or killing agent workloads the moment something doesn't add up. **Not after the fact. While it's happening**.

## How it works

<p align="center">
  <img src="assets/architecture.svg" alt="Panoptium architecture" />
</p>

All agent-to-LLM traffic flows through [AgentGateway](https://github.com/agentgateway/agentgateway) (Envoy-based). Panoptium runs as an ExtProc filter on that gateway and acts as both the observation and enforcement point.

**Observation:**

- Parses every request and response for OpenAI and Anthropic protocols: tool names, arguments, model parameters, token counts, latency. Handles SSE streaming.
- Resolves agent identity by mapping source IP (from `X-Forwarded-For`) to Kubernetes pod metadata via a pod cache that watches the API server.
- Publishes all observed events to an embedded NATS event bus for telemetry, SIEM integration, or downstream consumers.

**Policy enforcement:**

- Security rules are defined as Kubernetes CRDs (`AgentPolicy` / `AgentClusterPolicy`) with CEL predicates, priority ordering, and namespace vs. cluster scope. Evaluation is deny-first: all matching policies across all priority tiers are evaluated; at equal priority, `deny`/`quarantine` overrides `allow`. Non-terminal actions (`alert`, `audit`) always fire. Terminal actions (`deny`, `quarantine`) block.
- Policies can target specific pods by label selector and operate in `enforcing`, `audit`, or `disabled` mode.

**Enforcement actions:**

- **Deny**: block the request with a structured error explaining which rule fired.
- **Alert**: emit an event without blocking the request. Useful for shadow-mode monitoring.
- **Quarantine**: immediately isolate the agent by creating an `AgentQuarantine` resource. Containment actions (NetworkPolicy, pod eviction, eBPF-LSM) are stubbed.
- **Rate limiting**: sliding-window counters with configurable `groupBy` (per-agent, per-tool, or per-agent+tool). Returns 429 when exceeded.
- **Tool stripping**: removes banned tools from the outgoing request body so the LLM never sees them. Also intercepts `tool_call` responses for tools that should have been denied (defense-in-depth).
- **Escalation**: each enforcement event contributes risk points based on severity (`low`=5, `medium`=20, `high`=50, `critical`=100). When accumulated risk within a time window exceeds the threshold, an `AgentQuarantine` resource is created. Actual containment actions are not yet implemented.

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

**Prerequisites:** [AgentGateway](https://github.com/agentgateway/agentgateway) installed with a Gateway resource. Panoptium attaches to the gateway as an ExtProc filter.

```yaml
# 1. Create a Gateway (AgentGateway must be installed first)
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway
  namespace: panoptium-system
spec:
  gatewayClassName: agentgateway
  listeners:
  - name: http
    port: 8080
    protocol: HTTP
    allowedRoutes:
      namespaces:
        from: Same
```

```bash
# 2. Install Panoptium (targets the gateway named "agentgateway" by default)
helm install panoptium chart/panoptium -n panoptium-system --create-namespace

# If your gateway has a different name:
helm install panoptium chart/panoptium -n panoptium-system --create-namespace \
  --set gateway.extProcPolicy.gatewayName=my-gateway \
  --set gateway.identityPolicy.gatewayName=my-gateway
```

Panoptium automatically creates two `AgentgatewayPolicy` resources:
- **ExtProc policy**: routes all LLM traffic through Panoptium for observation and enforcement
- **Identity policy**: injects `X-Forwarded-For` so Panoptium can resolve agent pod identity

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

## CLI

The `panoptium` command is a first-party CLI for policy authoring, cluster introspection, and runtime operations. One binary, kubectl-style subcommand tree, shared global flags.

```bash
# Validate a policy offline — no cluster required
panoptium policy validate -f examples/policies/

# Lint for common authoring mistakes
panoptium policy lint -f my-policy.yaml --strict

# Inspect what's deployed
panoptium policy list -A
panoptium policy show deny-shell -o yaml | kubectl apply -f -

# Tail the event bus (after kubectl port-forward)
panoptium events tail --category policy -o json

# Manually quarantine and release an agent
panoptium quarantine create agent-foo-q --pod agent-foo --reason "manual review"
panoptium quarantine release agent-foo-q
```

Install the latest release:

```bash
curl -L -o panoptium.tar.gz https://github.com/cloudaura-io/INTERNAL-panoptium/releases/latest/download/panoptium_linux_amd64.tar.gz
tar -xzf panoptium.tar.gz && sudo mv panoptium /usr/local/bin/
```

Or build from source:

```bash
make cli-build    # → bin/panoptium
```

Full reference: [`docs/cli.md`](docs/cli.md).

## Demo

`demo/run-demo.sh` deploys a Kagent agent on a kind cluster with AgentGateway and runs five scenarios end-to-end:

| Scenario | What it shows |
|----------|---------------|
| A | Happy path: audit policy observes traffic without blocking |
| B | Tool stripping: banned tool removed from the request before it reaches the LLM |
| C | Hallucination defense: response-path intercept blocks an unauthorized `tool_call` |
| D | Rate limiting: agent throttled after exceeding the configured limit |
| E | Quarantine escalation: severity-based risk accumulation triggers `AgentQuarantine` |

```bash
./demo/run-demo.sh
```

Scenario C uses a mock LLM backend. The rest hit a real provider.

> [!WARNING]
> **Known limitation:** AgentGateway v1.0.1 does not support ExtProc `ImmediateResponse`. Scenarios C and D return HTTP 503 instead of the expected 403/429. Panoptium issues the correct status codes, but AgentGateway converts them to 503. Tool stripping (scenario B) is unaffected because it uses body mutation.

## Development

```bash
make build         # build the controller binary
make test          # unit tests (uses envtest)
make test-e2e-full # full E2E on a kind cluster (creates cluster, deploys, tests)
make docker-build  # build the container image
make lint          # run golangci-lint
```

## Roadmap

| Goal | Status |
|------|--------|
| CRD-based policy engine with real-time ExtProc enforcement | Done |
| LLM traffic observation (OpenAI, Anthropic, SSE streaming) | Done |
| Protocol parsers (MCP, A2A, Gemini) | Code complete, not wired |
| Threat signature detection | Partial |
| Graduated containment (NetworkPolicy, eBPF-LSM, pod eviction) | Partial, containment actions stubbed |
| eBPF kernel observation (Tetragon) | Standalone, not integrated |
| Intent-action correlation (LLM intent vs. kernel behavior) | Planned |
| Behavioral anomaly detection | Planned |
| Multi-cluster federation | Planned |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
