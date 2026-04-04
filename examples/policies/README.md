# Policy Examples

`AgentPolicy` (namespaced) and `AgentClusterPolicy` (cluster-scoped) define what Panoptium should do when an agent does something specific. A policy has three parts: **who** it applies to (target selector), **what** triggers it (event + predicates), and **how** to respond (action).

> **Known Limitation (AgentGateway v1.0.1):** Deny (403) and rateLimit (429)
> enforcement actions require ExtProc ImmediateResponse support, which is not
> yet implemented in AgentGateway v1.0.1. These actions will return 503 instead
> of the expected status code. Tool stripping (deny on tool_call subcategory)
> works correctly. This is an AgentGateway limitation, not a Panoptium bug.

## Structure

```yaml
kind: AgentPolicy
spec:
  targetSelector:                    # which pods — standard K8s label selector
    matchLabels:
      app: my-agent
  enforcementMode: enforcing         # enforcing | audit | disabled
  priority: 100                      # 1-1000, higher wins on conflict
  rules:
    - name: rule-name
      trigger:
        eventCategory: protocol      # protocol | kernel | network | llm | lifecycle
        eventSubcategory: tool_call  # tool_call | llm_request | file_write | egress_attempt | ...
      predicates:                    # optional — narrow the match
        - cel: "event.toolName == 'shell_exec'"
      threatSignatures:              # optional — match against ThreatSignature CRDs
        severities: [HIGH, CRITICAL]
      action:
        type: deny                   # allow | deny | rateLimit | alert | quarantine
        parameters:                  # action-specific key-value pairs
          message: "blocked"
      severity: HIGH                 # INFO | LOW | MEDIUM | HIGH | CRITICAL
```

## Enforcement modes

- **`enforcing`** — actions are executed. Deny blocks the request (403), rateLimit throttles (429), quarantine isolates the pod.
- **`audit`** — actions are logged and published to NATS but never applied. The request goes through. Use this to understand agent behavior before writing enforcing rules.
- **`disabled`** — policy is ignored entirely.

Start with `audit`, review what triggers, then switch to `enforcing`.

## Priority and composition

When multiple policies match the same event:
- Higher `priority` wins (200 beats 100).
- Namespace-scoped `AgentPolicy` takes precedence over `AgentClusterPolicy` at equal priority.
- An explicit `allow` overrides a `deny` at the same priority level.

This means you can set a restrictive cluster baseline (priority 10) and carve out exceptions per namespace or per agent (priority 200+).

## Trigger layers

| Layer | Categories | What it observes |
|-------|-----------|-----------------|
| `protocol` | `tool_call`, `llm_request` | LLM API calls and tool invocations passing through AgentGateway |
| `kernel` | `process_exec`, `file_open`, `file_write` | Syscalls observed by eBPF probes on the node |
| `network` | `egress_attempt`, `connection_established` | Outbound network connections from agent pods |
| `llm` | `prompt_submit` | LLM prompt submissions |
| `lifecycle` | `pod_start`, `agent_register` | Pod and agent lifecycle events |

## Actions

| Action | HTTP response | When to use |
|--------|--------------|-------------|
| `allow` | Pass through | Explicitly permit something a lower-priority rule would deny |
| `deny` | 403 Forbidden | Block a request with a structured error |
| `rateLimit` | 429 Too Many Requests | Throttle — params: `requestsPerMinute`, `burstSize`, `retryAfter` |
| `alert` | Pass through | Log and emit event without blocking |
| `quarantine` | N/A (pod-level) | Isolate the pod: deny-all NetworkPolicy + eBPF-LSM syscall restriction |

## Escalation

Any `deny` action can include escalation parameters. After repeated violations within a time window, Panoptium automatically creates an `AgentQuarantine` resource:

```yaml
action:
  type: deny
  parameters:
    escalationThreshold: "3"        # 3 denials...
    escalationWindow: "60"          # ...within 60 seconds...
    escalationAction: "quarantine"  # ...triggers quarantine
```

## Network admission vs. policy enforcement

AgentPolicy enforces **semantic/protocol-level** decisions (tool authorization, rate limiting, threat signatures). **Network admission** (which pods can reach the gateway) is handled by Kubernetes NetworkPolicy at the kernel/CNI level. See [`examples/network-policies/`](../network-policies/) for configuration examples.

## Examples in this directory

| File | Complexity | What it demonstrates |
|------|-----------|---------------------|
| `01-deny-shell-exec` | Simple | One rule, one predicate, deny |
| `02-rate-limit-llm-calls` | Simple | Throttle LLM API calls with sliding window |
| `03-escalate-to-quarantine` | Medium | Automatic escalation after repeated violations |
| `04-block-sensitive-file-access` | Medium | Kernel layer — multiple rules matching file paths with CEL |
| `05-allow-override` | Medium | Higher-priority allow overriding a lower-priority deny |
| `06-audit-mode` | Simple | Non-blocking observation for learning agent behavior |
| `07-block-known-threats` | Advanced | Enforcement driven by ThreatSignature matches + escalation |
| `08-cluster-wide-baseline` | Advanced | `AgentClusterPolicy` — global defaults for the entire cluster |
