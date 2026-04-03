#!/usr/bin/env bash
# run-demo.sh — Interactive Panoptium + Kagent + AgentGateway demo
# Deploys a real Kagent agent whose LLM traffic flows through AgentGateway,
# then demonstrates Panoptium policy enforcement on that live traffic.
set -euo pipefail

CONTEXT="kind-panoptium-e2e"
GATEWAY_NS="panoptium-system"
KAGENT_NS="kagent"
KAGENT_CTRL_PORT=8083
KAGENT_AGENT_PORT=8080
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

banner() {
  echo ""
  echo -e "${BOLD}${CYAN}======================================================${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}======================================================${RESET}"
  echo ""
}

info()    { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
err()     { echo -e "${RED}[ERROR]${RESET} $*"; }
pause()   { echo ""; read -rp "Press Enter to continue..."; echo ""; }

# ── Helpers ──────────────────────────────────────────────────────────

K="kubectl --context $CONTEXT"

show_panoptium_logs() {
  local lines="${1:-10}"
  echo ""
  echo -e "${CYAN}--- Panoptium controller logs (last ${lines} lines) ---${RESET}"
  $K logs -n "$GATEWAY_NS" -l control-plane=controller-manager \
    --tail="$lines" 2>/dev/null || warn "Could not fetch logs."
  echo -e "${CYAN}---------------------------------------------------${RESET}"
  echo ""
}

kagent_invoke() {
  local prompt="$1"
  local msg_id="msg-$(date +%s%N)"

  info "Sending task to Kagent agent (A2A)..."
  echo -e "  ${BOLD}Prompt:${RESET} $prompt"
  echo ""

  local response
  response=$(curl -s --max-time 120 \
    "http://localhost:${KAGENT_AGENT_PORT}/" \
    -X POST -H "Content-Type: application/json" \
    -d "$(jq -n \
      --arg mid "$msg_id" \
      --arg msg "$prompt" \
      '{
        jsonrpc: "2.0",
        id: "1",
        method: "message/send",
        params: {
          message: {
            role: "user",
            messageId: $mid,
            parts: [{type: "text", text: $msg}]
          }
        }
      }')")

  local state
  state=$(echo "$response" | jq -r '.result.status.state // .error.message // "unknown"')
  echo -e "${BOLD}Task state: ${state}${RESET}"

  # Show agent response
  local agent_msg
  agent_msg=$(echo "$response" | jq -r '
    [.result.history[]? | select(.role=="agent") | .parts[]?.text] | last // empty
  ' 2>/dev/null)

  if [[ -n "$agent_msg" ]]; then
    echo -e "${CYAN}Agent:${RESET}"
    echo "$agent_msg" | head -30
  else
    # Show error or raw result
    echo "$response" | jq '.error // .result.status' 2>/dev/null || echo "$response"
  fi
  echo ""
}

# ── Setup ────────────────────────────────────────────────────────────

check_prereqs() {
  banner "Pre-flight Checks"
  for cmd in kubectl curl jq helm; do
    if ! command -v "$cmd" &>/dev/null; then
      err "$cmd is required but not installed."
      exit 1
    fi
  done
  info "All required tools found."

  if ! $K cluster-info &>/dev/null; then
    err "Cannot reach cluster with context '$CONTEXT'."
    exit 1
  fi
  info "Cluster reachable."

  # Check Panoptium operator
  if $K get deployment panoptium-controller-manager -n "$GATEWAY_NS" &>/dev/null; then
    info "Panoptium operator: running"
  else
    err "Panoptium operator not found. Run the e2e setup first:"
    err "  DEPLOY_METHOD=helm make test-e2e-full"
    exit 1
  fi

  # Check AgentGateway
  if $K get pods -n "$GATEWAY_NS" \
    -l gateway.networking.k8s.io/gateway-name=e2e-gateway \
    --no-headers 2>/dev/null | grep -q Running; then
    info "AgentGateway: running"
  else
    warn "AgentGateway pod not found or not running."
  fi
}

install_kagent() {
  banner "Kagent Setup"

  if $K get crd agents.kagent.dev &>/dev/null 2>&1; then
    info "Kagent CRDs already installed."
  else
    info "Installing Kagent CRDs..."
    helm install kagent-crds oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
      --namespace "$KAGENT_NS" --create-namespace \
      --kube-context "$CONTEXT"
  fi

  if helm status kagent -n "$KAGENT_NS" --kube-context "$CONTEXT" &>/dev/null; then
    info "Kagent already installed."
  else
    info "Installing Kagent..."
    helm install kagent oci://ghcr.io/kagent-dev/kagent/helm/kagent \
      --namespace "$KAGENT_NS" \
      --kube-context "$CONTEXT" \
      --set providers.openAI.apiKey="mock-key-routed-via-gateway"
  fi

  info "Waiting for Kagent controller to be ready..."
  $K wait deployment -n "$KAGENT_NS" -l app.kubernetes.io/name=kagent \
    --for=condition=Available --timeout=120s 2>/dev/null || \
    $K wait deployment -n "$KAGENT_NS" --all \
      --for=condition=Available --timeout=120s 2>/dev/null || \
    warn "Kagent deployment not fully ready yet."
}

deploy_demo_resources() {
  banner "Deploy Demo Resources"

  info "Applying Panoptium policies..."
  $K apply -f "${DEMO_DIR}/policies/"

  if ! $K get secret openai-api-key -n "$KAGENT_NS" &>/dev/null; then
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
      err "OPENAI_API_KEY env var is required (demo uses real OpenAI API)."
      err ""
      err "  export OPENAI_API_KEY=sk-..."
      err "  ./demo/run-demo.sh"
      err ""
      exit 1
    fi
    info "Creating API key secret..."
    $K create secret generic openai-api-key \
      -n "$KAGENT_NS" \
      --from-literal=api-key="${OPENAI_API_KEY}"
  fi

  info "Deploying AgentGateway OpenAI backend + route..."
  $K apply -f "${DEMO_DIR}/manifests/agentgateway-openai-backend.yaml"

  info "Applying Kagent Agent + ModelConfig..."
  $K apply -f "${DEMO_DIR}/manifests/kagent-model-config.yaml"
  $K apply -f "${DEMO_DIR}/manifests/kagent-agent.yaml"

  info "Restarting agent pod to pick up latest ModelConfig..."
  $K rollout restart deployment demo-k8s-agent -n "$KAGENT_NS" 2>/dev/null || true

  info "Waiting for agent pod to be ready..."
  sleep 5
  $K rollout status deployment demo-k8s-agent -n "$KAGENT_NS" --timeout=120s 2>/dev/null || \
    warn "Agent pod not ready yet — check: kubectl get pods -n $KAGENT_NS"

  echo ""
  info "Panoptium policies:"
  $K get agentpolicy -n "$GATEWAY_NS" --no-headers 2>/dev/null || true

  echo ""
  info "Kagent agents:"
  $K get agent -n "$KAGENT_NS" --no-headers 2>/dev/null || true
  echo ""
}

port_forward_start() {
  info "Setting up port-forward to agent..."

  # Kill any existing port-forwards
  pkill -f "kubectl.*port-forward.*demo-k8s-agent" 2>/dev/null || true
  sleep 1

  # Direct A2A to agent service
  $K port-forward -n "$KAGENT_NS" svc/demo-k8s-agent "${KAGENT_AGENT_PORT}:${KAGENT_AGENT_PORT}" &>/dev/null &
  KAGENT_PF_PID=$!
  sleep 2

  if kill -0 "$KAGENT_PF_PID" 2>/dev/null; then
    info "Agent A2A port-forward active on localhost:${KAGENT_AGENT_PORT}"
  else
    err "Could not port-forward to agent service."
    err "Check: kubectl get svc demo-k8s-agent -n $KAGENT_NS"
    exit 1
  fi
}

cleanup() {
  [[ -n "${KAGENT_PF_PID:-}" ]] && kill "$KAGENT_PF_PID" 2>/dev/null || true
  info "Port-forwards stopped."
}
trap cleanup EXIT

# ── Scenarios ────────────────────────────────────────────────────────

scenario_a() {
  banner "Scenario A: Happy Path (Allowed Request)"
  info "The Kagent agent will ask for Kubernetes namespaces."
  info "Panoptium's audit-baseline policy observes the LLM traffic"
  info "flowing through AgentGateway without blocking it."
  pause

  kagent_invoke "List the Kubernetes namespaces in this cluster. Be brief."

  show_panoptium_logs 10
  info "The audit policy logged the request without blocking."
  pause
}

scenario_b() {
  banner "Scenario B: Denied Request (Bash Tool Block)"
  info "The Kagent agent will be asked to run a bash command."
  info "Panoptium's deny-bash policy (priority 100, enforcing) will"
  info "intercept the tool_call event and block it."
  pause

  kagent_invoke "Run the bash command 'ls -la /etc/passwd' and show me the output."

  show_panoptium_logs 15
  info "The deny-bash policy should have blocked the tool_call."
  info "Check for DENY events in the logs above."
  pause
}

scenario_c() {
  banner "Scenario C: Rate Limiting"
  info "Sending 6 rapid tasks to exceed the 5 req/min rate limit."
  info "The rate-limit policy will throttle the agent after 5 requests."
  pause

  for i in $(seq 1 6); do
    echo -e "${BOLD}--- Task $i/6 ---${RESET}"
    kagent_invoke "Say only the number $i."
    sleep 2
  done

  show_panoptium_logs 20
  info "Task 6 should have been rate-limited."
  info "Check for rate-limit events in the logs above."
  pause
}

scenario_d() {
  banner "Scenario D: Quarantine Escalation"
  info "After repeated denials, Panoptium escalates to quarantine."
  info "This creates an AgentQuarantine resource that isolates the pod."
  echo ""

  info "Current AgentQuarantine resources:"
  $K get agentquarantine -n "$GATEWAY_NS" --no-headers 2>/dev/null || \
    warn "No quarantine resources found."

  echo ""
  show_panoptium_logs 20
  pause
}

# ── Main ─────────────────────────────────────────────────────────────

banner "Panoptium + Kagent + AgentGateway Demo"
echo "This demo deploys a real Kagent AI agent whose LLM traffic"
echo "flows through AgentGateway. Panoptium's ExtProc filter"
echo "observes and enforces security policies on that traffic."
echo ""
echo "Architecture:"
echo "  Kagent Agent  -->  AgentGateway  -->  OpenAI API"
echo "                        |"
echo "                   Panoptium ExtProc"
echo "                   (policy enforcement)"
echo ""
echo "Scenarios:"
echo "  A) Happy path  -- agent request observed by audit policy"
echo "  B) Deny bash   -- tool_call blocked by enforcing policy"
echo "  C) Rate limit  -- agent throttled after 5 req/min"
echo "  D) Quarantine  -- escalation after repeated violations"
echo ""

check_prereqs
install_kagent
deploy_demo_resources
port_forward_start

while true; do
  echo ""
  echo -e "${BOLD}Select a scenario:${RESET}"
  echo "  a) Happy path"
  echo "  b) Deny bash tool"
  echo "  c) Rate limiting"
  echo "  d) Quarantine escalation"
  echo "  q) Quit"
  echo ""
  read -rp "Choice [a/b/c/d/q]: " choice
  case "$choice" in
    a|A) scenario_a ;;
    b|B) scenario_b ;;
    c|C) scenario_c ;;
    d|D) scenario_d ;;
    q|Q) info "Exiting demo."; break ;;
    *)   warn "Invalid choice. Try a, b, c, d, or q." ;;
  esac
done
