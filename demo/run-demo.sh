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
GATEWAY_DIRECT_PORT=8081
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
  [[ -n "${GATEWAY_PF_PID:-}" ]] && kill "$GATEWAY_PF_PID" 2>/dev/null || true
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
  banner "Scenario B: Tool Stripping (Pod Log Access Removed)"
  info "Applying deny-pod-logs policy (strips k8s_get_pod_logs from request tools[])..."
  $K apply -f "${DEMO_DIR}/manifests/deny-pod-logs-policy.yaml"
  sleep 3

  info "The agent will try to fetch pod logs using k8s_get_pod_logs."
  info "Panoptium strips k8s_get_pod_logs from the tools[] array in the"
  info "request body. The LLM never sees that tool, so it cannot use it."
  info "Other tools (k8s_get_resources, etc.) still work normally."
  info ""
  info "If the LLM response somehow contains a tool_call for the banned"
  info "tool, Panoptium intercepts mid-stream with HTTP 403 (defense-in-depth)."
  info ""
  info "Policy: demo-deny-pod-logs (priority 100, enforcing)"
  info "Trigger: tool_call where toolNames contains 'k8s_get_pod_logs'"
  pause

  kagent_invoke "Show me the logs for the panoptium-controller-manager pod in the panoptium-system namespace."

  show_panoptium_logs 15
  info "The deny-pod-logs policy should have stripped k8s_get_pod_logs from the request."
  info "Check for 'tool stripped' / enforcement events in the logs above."
  info "The LLM responded without the pod logs tool — it may explain it cannot access logs."

  info "Removing deny-pod-logs policy so other scenarios work..."
  $K delete agentclusterpolicy demo-deny-pod-logs --ignore-not-found 2>/dev/null || true
  pause
}

ensure_mock_llm_image() {
  local img="example.com/mock-llm:e2e"
  info "Building mock-llm Docker image..."
  docker build -q -t "$img" "$(dirname "$DEMO_DIR")/test/e2e/mock-llm/"
  info "Loading image into kind cluster..."
  docker exec panoptium-e2e-control-plane crictl rmi "$img" 2>/dev/null || true
  kind load docker-image "$img" --name panoptium-e2e
}

gateway_port_forward_start() {
  pkill -f "kubectl.*port-forward.*${GATEWAY_DIRECT_PORT}:8080" 2>/dev/null || true
  sleep 1

  local gw_pod
  gw_pod=$($K get pod -n "$GATEWAY_NS" \
    -l gateway.networking.k8s.io/gateway-name=e2e-gateway \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

  if [[ -z "$gw_pod" ]]; then
    err "Cannot find gateway pod."
    return 1
  fi

  $K port-forward -n "$GATEWAY_NS" "$gw_pod" "${GATEWAY_DIRECT_PORT}:8080" &>/dev/null &
  GATEWAY_PF_PID=$!
  sleep 2

  if kill -0 "$GATEWAY_PF_PID" 2>/dev/null; then
    info "Gateway port-forward active on localhost:${GATEWAY_DIRECT_PORT}"
  else
    err "Could not port-forward to gateway pod."
    return 1
  fi
}

gateway_port_forward_stop() {
  [[ -n "${GATEWAY_PF_PID:-}" ]] && kill "$GATEWAY_PF_PID" 2>/dev/null || true
  GATEWAY_PF_PID=""
}

scenario_c() {
  banner "Scenario C: Response-Path Defense (Tool Hallucination)"
  info "This scenario demonstrates defense-in-depth against tool hallucination."
  info ""
  info "A mock LLM backend deliberately returns a tool_call for"
  info "k8s_get_pod_logs — even though Panoptium stripped that tool"
  info "from the request. This simulates a prompt injection or model"
  info "hallucination attack that bypasses request-path tool removal."
  info ""
  info "Two-layer enforcement:"
  info "  Layer 1 (request):  Panoptium strips k8s_get_pod_logs from tools[]"
  info "  Layer 2 (response): Panoptium catches the unauthorized tool_call → 403"
  info ""
  info "Policy: demo-deny-pod-logs (priority 100, enforcing)"
  pause

  # ── Setup ──
  info "Ensuring mock-llm image is available..."
  ensure_mock_llm_image

  info "Applying deny-pod-logs policy..."
  $K apply -f "${DEMO_DIR}/manifests/deny-pod-logs-policy.yaml"

  info "Temporarily removing e2e llm-route (conflicts with demo route)..."
  $K delete httproute llm-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

  info "Deploying hallucinating mock LLM + switching gateway route..."
  $K apply -f "${DEMO_DIR}/manifests/mock-llm-hallucination.yaml"

  info "Waiting for mock LLM to be ready..."
  $K rollout status deployment/mock-llm-hallucination \
    -n "$GATEWAY_NS" --timeout=60s 2>/dev/null || \
    warn "Mock LLM not ready — continuing anyway."

  # Give gateway time to pick up the new route
  sleep 3

  # ── Execute ──
  # Send request from INSIDE the cluster (port-forward bypasses ExtProc filter chain)
  local gw_ip
  gw_ip=$($K get svc e2e-gateway -n "$GATEWAY_NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
  if [[ -z "$gw_ip" ]]; then
    err "Cannot find gateway service IP."
    pause; return
  fi

  echo ""
  info "Sending request from in-cluster curl pod to gateway (${gw_ip}:8080)"
  info "Tools: [k8s_get_pod_logs, k8s_get_resources]"
  echo ""
  echo -e "  ${CYAN}Expected flow:${RESET}"
  echo -e "    1. Panoptium strips k8s_get_pod_logs from request tools[]"
  echo -e "    2. Mock LLM returns tool_call for k8s_get_pod_logs anyway"
  echo -e "    3. Panoptium intercepts response mid-stream → HTTP 403"
  echo ""

  local output
  output=$($K run demo-curl-hallucination --rm -i --restart=Never \
    -n "$GATEWAY_NS" \
    --image=curlimages/curl:7.78.0 \
    -- -s -w "\n---HTTP_STATUS:%{http_code}---" --max-time 30 \
    -X POST "http://${gw_ip}:8080/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"Show pod logs"}],"stream":true,"tools":[{"type":"function","function":{"name":"k8s_get_pod_logs","description":"Get pod logs","parameters":{"type":"object"}}},{"type":"function","function":{"name":"k8s_get_resources","description":"Get K8s resources","parameters":{"type":"object"}}}]}' \
    2>/dev/null)

  local http_code http_body
  if echo "$output" | grep -qF "HTTP_STATUS:"; then
    http_code=$(echo "$output" | grep -oE 'HTTP_STATUS:[0-9]+' | cut -d: -f2)
    http_body=$(echo "$output" | sed 's/---HTTP_STATUS:[0-9]*---//')
  else
    http_code="N/A"
    http_body="$output"
  fi

  echo -e "${BOLD}Response: HTTP ${http_code}${RESET}"
  if [[ "$http_code" == "403" ]]; then
    echo -e "${RED}[BLOCKED]${RESET} Response-path enforcement triggered!"
    echo "$http_body" | jq . 2>/dev/null || echo "$http_body"
  else
    echo "$http_body" | head -20
  fi
  echo ""

  show_panoptium_logs 20
  info "Check the logs for:"
  info "  - 'tool stripped' events (request-path, Layer 1)"
  info "  - 'response tool_call' enforcement (response-path, Layer 2)"

  # ── Cleanup ──
  echo ""
  info "Cleaning up: restoring routes, removing mock LLM..."
  $K apply -f "${DEMO_DIR}/manifests/agentgateway-openai-backend.yaml"
  $K apply -f "$(dirname "$DEMO_DIR")/test/e2e/manifests/agentgateway-route.yaml" 2>/dev/null || true
  $K delete deployment mock-llm-hallucination -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete service mock-llm-hallucination -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete agentgatewaybackend mock-llm-hallucination-backend -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete agentclusterpolicy demo-deny-pod-logs --ignore-not-found 2>/dev/null || true
  info "Cleanup done."
  pause
}

scenario_d() {
  banner "Scenario D: Rate Limiting"
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

scenario_e() {
  banner "Scenario E: Quarantine Escalation"
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

# ── Main ───────��────────────────────────���────────────────────────────

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
echo "  Scenario C uses a mock LLM backend instead of OpenAI"
echo "  to demonstrate response-path defense-in-depth."
echo ""
echo "Scenarios:"
echo "  A) Happy path       -- agent request observed by audit policy"
echo "  B) Tool strip       -- pod log tool stripped from request by policy"
echo "  C) Hallucination    -- response-path defense against tool hallucination"
echo "  D) Rate limit       -- agent throttled after 5 req/min"
echo "  E) Quarantine       -- escalation after repeated violations"
echo ""

check_prereqs
install_kagent
deploy_demo_resources
port_forward_start

while true; do
  echo ""
  echo -e "${BOLD}Select a scenario:${RESET}"
  echo "  a) Happy path"
  echo "  b) Tool stripping (pod log access)"
  echo "  c) Tool hallucination defense"
  echo "  d) Rate limiting"
  echo "  e) Quarantine escalation"
  echo "  q) Quit"
  echo ""
  read -rp "Choice [a/b/c/d/e/q]: " choice
  case "$choice" in
    a|A) scenario_a ;;
    b|B) scenario_b ;;
    c|C) scenario_c ;;
    d|D) scenario_d ;;
    e|E) scenario_e ;;
    q|Q) info "Exiting demo."; break ;;
    *)   warn "Invalid choice. Try a, b, c, d, e, or q." ;;
  esac
done
