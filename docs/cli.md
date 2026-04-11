# panoptium CLI

First-party command-line interface for the Panoptium Kubernetes operator.
One binary, kubectl-style subcommands, shared global flags.

`panoptium` operates in two modes:

- **Offline**: `policy validate`, `policy lint`, `signature validate`,
  `version`, `completion`. No cluster required.
- **Cluster-facing**: `policy list/show`, `signature list`,
  `quarantine list/get/create/release`, `events tail`, `risk show`.
  Uses the caller's kubeconfig.

## Install

Binaries are published to GitHub Releases under tags matching `cli/v*`.

```bash
VERSION=0.1.0
OS=linux  # or darwin, windows
ARCH=amd64
curl -L -o panoptium.tar.gz \
  "https://github.com/cloudaura-io/INTERNAL-panoptium/releases/download/cli/v${VERSION}/panoptium_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf panoptium.tar.gz
sudo mv panoptium /usr/local/bin/
panoptium version
```

Or via `go install` for developers:

```bash
go install github.com/panoptium/panoptium/cmd/panoptium@latest
```

## Global flags

| Flag | Default | Purpose |
|---|---|---|
| `-o, --output` | `human` | Output format: `human`, `json`, `yaml`, `table`. |
| `--kubeconfig` | `$KUBECONFIG` or `~/.kube/config` | Path to kubeconfig file. |
| `--context` | current | Kubeconfig context to use. |
| `-n, --namespace` | current | Namespace scope for namespaced commands. |
| `-A, --all-namespaces` | `false` | List across all namespaces. |
| `-v, --verbose` | `false` | Emit debug logs to stderr. |
| `--no-color` | `$NO_COLOR` | Disable ANSI colors. |

All offline commands ignore the cluster flags; all cluster commands honor
the same kubeconfig precedence as `kubectl`.

## Subcommands

### `panoptium policy validate -f <file>`

Offline validator for `AgentPolicy` and `AgentClusterPolicy` YAML. Uses
the same compiler the operator runs at admission time. Files,
directories (recursive), and stdin (`-`) are accepted.

Exits 0 if every document compiles, non-zero otherwise.

```bash
panoptium policy validate -f examples/policies/
cat policy.yaml | panoptium policy validate -f -
panoptium policy validate -f policy.yaml -o json | jq .summary
```

### `panoptium policy lint -f <file>`

Superset of `validate`. Surfaces warnings for common mistakes:

- `broad-target-selector` — empty `targetSelector` matches every pod
- `rule-without-predicates` — rule with no narrowing predicates
- `deny-without-message` — deny action with no user-facing message
- `severity-missing` — rule is missing severity
- `priority-over-900` — priority ≥ 900 (reserved for cluster defaults)
- `enforcement-audit-mode` — policy in audit-only mode

With `--strict`, warnings become errors.

```bash
panoptium policy lint -f examples/policies/
panoptium policy lint -f policy.yaml --strict -o json
```

### `panoptium policy list [-n <ns>] [-A]`

Lists `AgentPolicy` and `AgentClusterPolicy` resources visible in the
current cluster. Table columns: `NAMESPACE`, `NAME`, `KIND`, `MODE`,
`PRIORITY`, `RULES`, `READY`, `AGE`.

```bash
panoptium policy list
panoptium policy list -A -o table
panoptium policy list -o yaml
```

### `panoptium policy show <name> [--cluster]`

Fetches one policy by name. `-o yaml` is round-trippable: pipe it
directly into `kubectl apply -f -`. Use `--cluster` for
`AgentClusterPolicy`.

```bash
panoptium policy show deny-shell
panoptium policy show cluster-baseline --cluster -o yaml | kubectl apply -f -
```

### `panoptium signature validate -f <file>`

Offline validator for `ThreatSignature` resources. Compiles regex +
CEL patterns against a fresh `CompiledSignatureRegistry`.

```bash
panoptium signature validate -f signature.yaml
panoptium signature validate -f examples/threat-signatures/ -o json
```

### `panoptium signature list`

Lists installed `ThreatSignature` resources. Table columns: `NAME`,
`CATEGORY`, `SEVERITY`, `PROTOCOLS`, `PATTERNS`, `READY`, `AGE`.

```bash
panoptium signature list
panoptium signature list -o table
```

### `panoptium quarantine list [-n <ns>] [-A]`

Lists `AgentQuarantine` resources. Table columns: `NAMESPACE`, `NAME`,
`POD`, `LEVEL`, `STATE`, `AGE`.

### `panoptium quarantine get <name>`

Shows one quarantine with full spec and status.

### `panoptium quarantine create <name> --pod <pod> --reason <text>`

Creates a new `AgentQuarantine` CRD for manual containment.

```bash
panoptium quarantine create agent-foo-q \
  --pod agent-foo --target-namespace prod \
  --level network-isolate \
  --reason "manual review after suspicious activity"
```

Required: `--pod`, `--reason`. Optional: `--target-namespace` (default:
`-n`), `--level` (default: `network-isolate`). Idempotent — calling
`create` on an existing name updates its spec.

> **Note**: Until issue #8 (NetworkPolicy-based quarantine) lands in
> the operator, the CRD is persisted correctly but the network-isolate
> enforcement path may be partial.

### `panoptium quarantine release <name>`

Transitions an `AgentQuarantine` into the released state by stamping
`status.releasedAt` to now. Idempotent per quarantine — returns
`ErrAlreadyReleased` on double-release.

```bash
panoptium quarantine release agent-foo-q
```

### `panoptium events tail`

Subscribes to Panoptium's NATS event bus and streams events to stdout
until SIGINT (or `--count` events). Panoptium embeds NATS inside the
operator pod on 127.0.0.1; run `kubectl port-forward` before invoking
`tail`:

```bash
kubectl port-forward -n panoptium-system \
  deploy/panoptium-controller-manager 4222:4222 &

export NATS_URL=nats://localhost:4222
panoptium events tail --category policy
panoptium events tail --ns-filter default -o json | jq
panoptium events tail --count 10
```

Flags:

- `--nats-endpoint` — override endpoint (default: `$NATS_URL`, `$PANOPTIUM_NATS_URL`)
- `--ns-filter` — NATS subject wildcard on namespace segment
- `--category` — category subject wildcard (`syscall`, `network`, `protocol`, `llm`, `policy`, `lifecycle`)
- `--agent` — client-side filter on agent/pod name
- `--count N` — stop after N events

`table` is not a valid format for `tail` (streaming precludes
column-aligned output). Use `human` (default, one line per event)
or `json` (NDJSON, one JSON object per line) for piping.

### `panoptium risk show`

Renders accumulated risk scores per agent.

> **Status**: risk scoring is introduced by the graduated-escalation
> track (#10) and is not yet wired into the operator. This command
> currently returns an explicit "risk scoring not yet available on
> this operator version" response.

When #10 lands, the same command surface will switch to reading real
risk state without any CLI change.

### `panoptium version`

Prints CLI version, commit, build date, Go version, and platform.

```bash
panoptium version
panoptium version -o json
panoptium version --client   # skip operator version lookup
```

### `panoptium completion <shell>`

Generates shell completion scripts for `bash`, `zsh`, `fish`, or
`powershell`. See `--help` for loading instructions per shell.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Command-level failure (validation errors, not-found, etc.) |
| other | Fatal CLI error (framework-level) |

`validate` and `lint` specifically exit non-zero when any document
reports an error; `lint --strict` also exits non-zero on warnings.

## Building from source

```bash
make cli-build             # → bin/panoptium
make cli-smoke             # → build + run smoke tests
```

`cli-build` injects version metadata via `-ldflags -X`, set via
`CLI_VERSION`, `CLI_COMMIT`, and `CLI_DATE` environment variables.

## See also

- [`conductor/tracks/panoptium_cli_20260411/`](../conductor/tracks/panoptium_cli_20260411/) — the track plan
- [`.goreleaser.yaml`](../.goreleaser.yaml) — release configuration
- [INTERNAL-panoptium#42](https://github.com/cloudaura-io/INTERNAL-panoptium/issues/42) — original issue
- [panoptium#5](https://github.com/cloudaura-io/panoptium/issues/5) — public mirror
