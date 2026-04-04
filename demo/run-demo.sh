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
  info "  Layer 2 (response): Panoptium catches the unauthorized tool_call (403)"
  info ""
  warn "AgentGateway v1.0.1 limitation: ImmediateResponse is not supported."
  warn "Layer 2 (response-path deny) returns 503 instead of 403."
  warn "Panoptium correctly issues 403, but AgentGateway converts it to 503."
  info ""
  info "Policy: demo-deny-pod-logs (priority 100, enforcing)"
  pause

  # ── Setup ──
  info "Ensuring mock-llm image is available..."
  ensure_mock_llm_image

  info "Applying deny-pod-logs policy..."
  $K apply -f "${DEMO_DIR}/manifests/deny-pod-logs-policy.yaml"

  info "Temporarily removing conflicting routes..."
  $K delete httproute llm-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete httproute demo-openai-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

  info "Deploying hallucinating mock LLM + switching gateway route..."
  $K apply -f "${DEMO_DIR}/manifests/mock-llm-hallucination.yaml"

  info "Waiting for mock LLM to be ready..."
  $K rollout status deployment/mock-llm-hallucination \
    -n "$GATEWAY_NS" --timeout=60s 2>/dev/null || \
    warn "Mock LLM not ready — continuing anyway."

  # Give gateway time to pick up the new route
  sleep 3

  # ── Execute ──
  # Use kagent agent (agentic traffic gets full ExtProc body processing)
  echo ""
  echo -e "  ${CYAN}Expected flow:${RESET}"
  echo -e "    1. Kagent sends request through gateway → mock LLM"
  echo -e "    2. Panoptium strips k8s_get_pod_logs from request tools[]"
  echo -e "    3. Mock LLM ignores strip, returns tool_call for k8s_get_pod_logs"
  echo -e "    4. Panoptium intercepts response mid-stream → HTTP 403"
  echo ""

  kagent_invoke "Show me the logs for the panoptium-controller-manager pod."
  echo ""

  show_panoptium_logs 20
  info "Check the logs for:"
  info "  - 'tool stripped' events (request-path, Layer 1)"
  info "  - 'response tool_call' enforcement (response-path, Layer 2)"

  # ── Cleanup ──
  echo ""
  info "Cleaning up: restoring routes, removing mock LLM..."
  $K delete httproute demo-hallucination-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K apply -f "$(dirname "$DEMO_DIR")/test/e2e/manifests/agentgateway-route.yaml" 2>/dev/null || true
  $K apply -f "${DEMO_DIR}/manifests/agentgateway-openai-backend.yaml"
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
  info "The rate-limit policy uses agent-based counting (groupBy: agent)."
  info "All tools from the same agent share one counter."
  info ""
  warn "AgentGateway v1.0.1 limitation: ImmediateResponse is not supported."
  warn "Rate-limited requests return 503 instead of 429 (no Retry-After header)."
  warn "Panoptium correctly issues 429, but AgentGateway converts it to 503."
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
  info "This scenario demonstrates the full quarantine escalation flow."
  info ""
  info "Escalation uses severity-weighted risk accumulation (FR-5)."
  info "A single CRITICAL deny event (100 risk pts) meets the threshold=100,"
  info "triggering immediate quarantine via the EscalationManager."
  info ""
  info "Flow:"
  info "  1. Apply escalation policy (deny critical_tool, CRITICAL severity)"
  info "  2. Send request with critical_tool through the gateway"
  info "  3. Panoptium strips critical_tool (deny action, 100 risk pts)"
  info "  4. EscalationManager detects threshold breach → creates AgentQuarantine"
  info "  5. Quarantine controller reconciles → sets Contained=True"
  echo ""
  warn "AgentGateway v1.0.1 limitation: ImmediateResponse is not supported."
  warn "Tool stripping works correctly (body mutation), but HTTP 403/429 deny"
  warn "responses require AgentGateway ImmediateResponse support (not yet in v1.0.1)."
  echo ""
  info "NetworkPolicy enforcement is planned for the graduated_containment track."
  info "Currently, the quarantine controller sets status conditions but does not"
  info "create NetworkPolicies or BPF-LSM rules."
  pause

  # ── Setup ──
  info "Ensuring mock-llm image is available..."
  ensure_mock_llm_image

  info "Clearing any existing quarantine resources..."
  $K delete agentquarantine --all -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

  info "Temporarily removing conflicting routes..."
  $K delete httproute llm-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete httproute demo-openai-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

  info "Deploying mock LLM backend (normal mode, no forced tool calls)..."
  $K apply -f - <<'MOCK_LLM_EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mock-llm-escalation
  namespace: panoptium-system
  labels:
    app: mock-llm-escalation
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mock-llm-escalation
  template:
    metadata:
      labels:
        app: mock-llm-escalation
    spec:
      containers:
      - name: mock-llm
        image: example.com/mock-llm:e2e
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        readinessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 2
          periodSeconds: 5
        resources:
          limits:
            cpu: 100m
            memory: 64Mi
          requests:
            cpu: 10m
            memory: 32Mi
---
apiVersion: v1
kind: Service
metadata:
  name: mock-llm-escalation
  namespace: panoptium-system
  labels:
    app: mock-llm-escalation
spec:
  ports:
  - name: http
    port: 8080
    protocol: TCP
    targetPort: 8080
  selector:
    app: mock-llm-escalation
---
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayBackend
metadata:
  name: mock-llm-escalation-backend
  namespace: panoptium-system
spec:
  ai:
    groups:
    - providers:
      - name: mock-escalation
        openai: {}
        host: mock-llm-escalation.panoptium-system.svc.cluster.local
        port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: demo-escalation-route
  namespace: panoptium-system
spec:
  parentRefs:
  - name: e2e-gateway
    namespace: panoptium-system
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /chat/completions
    - path:
        type: Exact
        value: /v1/chat/completions
    backendRefs:
    - group: agentgateway.dev
      kind: AgentgatewayBackend
      name: mock-llm-escalation-backend
MOCK_LLM_EOF

  info "Waiting for mock LLM to be ready..."
  $K rollout status deployment/mock-llm-escalation \
    -n "$GATEWAY_NS" --timeout=60s 2>/dev/null || \
    warn "Mock LLM not ready — continuing anyway."
  sleep 3

  # ── Step 1: Apply escalation policy ──
  echo ""
  info "Step 1: Applying escalation policy..."
  $K apply -f "${DEMO_DIR}/policies/05-escalate-critical-tool.yaml"
  sleep 3

  info "Policy status:"
  $K get agentclusterpolicy demo-escalate-critical-tool -o wide 2>/dev/null || true
  echo ""

  # ── Step 2: Get gateway ClusterIP ──
  local GW_IP
  GW_IP=$($K get svc -n "$GATEWAY_NS" \
    -l gateway.networking.k8s.io/gateway-name=e2e-gateway \
    -o jsonpath='{.items[0].spec.clusterIP}' 2>/dev/null)

  if [[ -z "$GW_IP" ]]; then
    err "Could not find gateway service ClusterIP."
    err "Check: kubectl get svc -n $GATEWAY_NS -l gateway.networking.k8s.io/gateway-name=e2e-gateway"
    return 1
  fi
  info "Gateway ClusterIP: ${GW_IP}"

  # Create a temporary curl pod for sending requests through the cluster network
  local CURL_POD="demo-curl-escalation"
  info "Creating curl pod for in-cluster requests..."
  $K run "$CURL_POD" -n "$GATEWAY_NS" \
    --image=curlimages/curl:latest \
    --restart=Never \
    --command -- sleep 300 2>/dev/null || true
  $K wait pod "$CURL_POD" -n "$GATEWAY_NS" \
    --for=condition=Ready --timeout=30s 2>/dev/null || \
    warn "Curl pod not ready."

  # ── Step 3: Send request with critical_tool ──
  echo ""
  info "Step 2: Sending request with critical_tool through the gateway..."
  info "The request includes tools: [{name: 'critical_tool'}]"
  info "Panoptium will strip critical_tool from tools[] (deny action)"
  info "and publish a CRITICAL severity enforcement event."
  echo ""

  local PAYLOAD='{"model":"gpt-4","messages":[{"role":"user","content":"use critical tool"}],"tools":[{"type":"function","function":{"name":"critical_tool","parameters":{}}}],"stream":false}'

  local RESPONSE
  RESPONSE=$($K exec "$CURL_POD" -n "$GATEWAY_NS" -- \
    curl -s --max-time 30 \
      -X POST "http://${GW_IP}:8080/v1/chat/completions" \
      -H "Content-Type: application/json" \
      -d "$PAYLOAD" 2>/dev/null) || true

  if [[ -n "$RESPONSE" ]]; then
    echo -e "  ${CYAN}Response (tool was stripped, LLM responded normally):${RESET}"
    echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
  else
    warn "No response received (this may be expected if gateway returned an error)."
  fi
  echo ""

  # ── Step 4: Wait for AgentQuarantine creation ──
  info "Step 3: Waiting for AgentQuarantine creation (up to 15s)..."
  echo ""

  local QUARANTINE_FOUND=false
  for i in $(seq 1 15); do
    local QC
    QC=$($K get agentquarantine -n "$GATEWAY_NS" --no-headers 2>/dev/null | head -1)
    if [[ -n "$QC" ]]; then
      QUARANTINE_FOUND=true
      echo -e "  ${GREEN}AgentQuarantine created after ${i}s!${RESET}"
      break
    fi
    sleep 1
  done

  if [[ "$QUARANTINE_FOUND" != "true" ]]; then
    warn "No AgentQuarantine created within 15s."
    warn "This may happen if the escalation event was not published."
    warn "Check operator logs below for details."
  fi
  echo ""

  # ── Step 5: Display quarantine status ──
  info "Step 4: AgentQuarantine resources:"
  $K get agentquarantine -n "$GATEWAY_NS" -o wide 2>/dev/null || true
  echo ""

  if [[ "$QUARANTINE_FOUND" == "true" ]]; then
    local QR_NAME
    QR_NAME=$($K get agentquarantine -n "$GATEWAY_NS" --no-headers \
      -o custom-columns=':metadata.name' 2>/dev/null | head -1)

    if [[ -n "$QR_NAME" ]]; then
      info "Quarantine details:"
      echo ""
      echo -e "  ${CYAN}Spec:${RESET}"
      $K get agentquarantine "$QR_NAME" -n "$GATEWAY_NS" \
        -o jsonpath='{.spec}' 2>/dev/null | jq '.' 2>/dev/null || true
      echo ""
      echo -e "  ${CYAN}Status conditions:${RESET}"
      $K get agentquarantine "$QR_NAME" -n "$GATEWAY_NS" \
        -o jsonpath='{.status.conditions}' 2>/dev/null | jq '.' 2>/dev/null || \
        info "(No conditions set yet — quarantine controller may need time to reconcile)"
      echo ""
    fi
  fi

  # ── Step 6: Show operator logs ──
  info "Step 5: Operator logs (escalation chain):"
  show_panoptium_logs 30

  # ── Notes ──
  echo ""
  echo -e "${YELLOW}────────────────────────────────────────────────────────${RESET}"
  echo -e "${YELLOW}  Notes on current quarantine behavior:${RESET}"
  echo -e "${YELLOW}────────────────────────────────────────────────────────${RESET}"
  echo ""
  echo -e "  ${BOLD}1. Tool stripping works correctly:${RESET}"
  echo "     critical_tool was removed from the request tools[] array."
  echo "     The LLM never saw it. The deny event triggered escalation."
  echo ""
  echo -e "  ${BOLD}2. AgentGateway ImmediateResponse (not yet available):${RESET}"
  echo "     HTTP 403/429 deny responses require AgentGateway to support"
  echo "     ExtProc ImmediateResponse. In v1.0.1, deny actions that use"
  echo "     tool stripping work, but ImmediateResponse returns 503."
  echo ""
  echo -e "  ${BOLD}3. NetworkPolicy enforcement (graduated_containment track):${RESET}"
  echo "     The quarantine controller currently sets status conditions"
  echo "     (Contained=True, Ready=True) but does not yet create"
  echo "     NetworkPolicies or BPF-LSM rules. Full graduated containment"
  echo "     (5-level escalation with real enforcement) is planned in the"
  echo "     graduated_containment track (ADR-006)."
  echo ""

  # ── Cleanup ──
  info "Step 6: Cleaning up..."
  $K delete agentquarantine --all -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete agentclusterpolicy demo-escalate-critical-tool --ignore-not-found 2>/dev/null || true
  $K delete httproute demo-escalation-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete deployment mock-llm-escalation -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete service mock-llm-escalation -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete agentgatewaybackend mock-llm-escalation-backend -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
  $K delete pod "$CURL_POD" -n "$GATEWAY_NS" --ignore-not-found --force 2>/dev/null || true
  $K apply -f "$(dirname "$DEMO_DIR")/test/e2e/manifests/agentgateway-route.yaml" 2>/dev/null || true
  $K apply -f "${DEMO_DIR}/manifests/agentgateway-openai-backend.yaml" 2>/dev/null || true
  info "Cleanup done."
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
echo "  Scenarios C and E use a mock LLM backend instead of OpenAI"
echo "  (C for response-path defense, E for quarantine escalation)."
echo ""
echo "Scenarios:"
echo "  A) Happy path       -- agent request observed by audit policy"
echo "  B) Tool strip       -- pod log tool stripped from request by policy"
echo "  C) Hallucination    -- response-path defense against tool hallucination"
echo "  D) Rate limit       -- agent throttled after 5 req/min"
echo "  E) Quarantine       -- full escalation flow (policy → deny → quarantine)"
echo ""
echo -e "${YELLOW}NOTE: AgentGateway v1.0.1 does not support ExtProc ImmediateResponse.${RESET}"
echo -e "${YELLOW}Scenarios C and D return HTTP 503 instead of 403/429.${RESET}"
echo -e "${YELLOW}This is an AgentGateway limitation, not a Panoptium bug.${RESET}"
echo -e "${YELLOW}Tool stripping (B) works because it uses body mutation.${RESET}"
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
