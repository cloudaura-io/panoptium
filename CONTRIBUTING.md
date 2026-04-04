# Contributing to Panoptium

Thanks for considering a contribution. Here's how to get involved.

## Getting started

```bash
git clone https://github.com/panoptium/panoptium.git
cd panoptium
make install   # install CRDs into your cluster
make run       # run the operator locally against the cluster
```

You'll need Go 1.22+, Docker, and access to a Kubernetes cluster (kind works fine for local dev).

## Development workflow

1. **Fork and branch.** Create a feature branch from `main`.
2. **Write tests first.** We follow TDD — write a failing test, then make it pass.
3. **Keep changes focused.** One concern per PR. Small PRs get reviewed faster.
4. **Run checks before pushing:**

```bash
make test          # unit tests
make lint          # golangci-lint
go vet ./...       # static analysis
make manifests     # regenerate CRDs, RBAC, webhooks
make generate      # regenerate deepcopy
```

5. **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(policy): add rate limiting predicate
fix(extproc): handle missing content-type header
test(e2e): add quarantine escalation test
refactor(identity): simplify pod cache lookup
```

Single line, no body needed for most changes.

## Code structure

```
api/v1alpha1/           CRD type definitions
cmd/                    operator entrypoint
internal/controller/    reconcilers for each CRD
internal/webhook/       admission webhooks
pkg/policy/             policy compiler and evaluator
pkg/extproc/            ExtProc gRPC server (enforcement)
pkg/identity/           pod identity resolution
pkg/eventbus/           NATS event bus
pkg/escalation/         deny → quarantine escalation
pkg/threat/             threat signature matching
pkg/observer/           protocol parsers (LLM, MCP, A2A, Gemini)
chart/panoptium/        Helm chart
config/                 kustomize manifests
test/e2e/               end-to-end tests (kind cluster)
```

## Running e2e tests

E2E tests spin up a kind cluster, deploy everything, and run Ginkgo suites:

```bash
make test-e2e-full
```

This takes a few minutes. For faster iteration, run unit tests with `make test`.

## Where to help

- Check [open issues](https://github.com/panoptium/panoptium/issues) for bugs or feature requests.
- Look at the [issues](https://github.com/panoptium/panoptium/issues) for bugs, feature requests, and roadmap items.
- Protocol parsers (MCP, A2A, Gemini) are implemented but not wired — integration help is welcome.
- Documentation, examples, and Helm chart improvements are always appreciated.

## Reporting issues

Open a GitHub issue. Include:
- What you expected vs. what happened
- Steps to reproduce
- Kubernetes version, Go version, OS

## Code of conduct

Be respectful, constructive, and assume good intent. We're all here to build something useful.
