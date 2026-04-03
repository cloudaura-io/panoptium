#!/usr/bin/env bash
# E2E test orchestration script for Panoptium + AgentGateway on kind.
#
# Usage:
#   ./test/e2e/run-e2e.sh            # Run the full E2E pipeline
#   ./test/e2e/run-e2e.sh --cleanup  # Tear down the kind cluster
#
# This script is idempotent: it can be re-run without manual cleanup.
# No external API keys or secrets are required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CLUSTER_NAME="${KIND_CLUSTER:-panoptium-e2e}"
PANOPTIUM_IMG="example.com/panoptium:e2e"
MOCK_LLM_IMG="example.com/mock-llm:e2e"
AGENTGATEWAY_VERSION="v1.0.1"
GATEWAY_API_VERSION="v1.2.1"
NAMESPACE="panoptium-system"
KUBE_CTX="kind-${CLUSTER_NAME}"
DEPLOY_METHOD="${DEPLOY_METHOD:-kustomize}"

# Colors for output (disabled in CI)
if [[ -t 1 ]] && [[ -z "${CI:-}" ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    YELLOW=''
    RED=''
    NC=''
fi

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# --------------------------------------------------------------------------
# Cleanup mode
# --------------------------------------------------------------------------
if [[ "${1:-}" == "--cleanup" ]]; then
    log_info "Tearing down kind cluster '${CLUSTER_NAME}'..."
    kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    log_info "Cleanup complete."
    exit 0
fi

# --------------------------------------------------------------------------
# Phase 1: Kind cluster creation (idempotent)
# --------------------------------------------------------------------------
log_info "=== Phase 1: Kind cluster ==="
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    log_info "Kind cluster '${CLUSTER_NAME}' already exists, reusing."
else
    log_info "Creating kind cluster '${CLUSTER_NAME}'..."
    kind create cluster \
        --name "${CLUSTER_NAME}" \
        --config "${SCRIPT_DIR}/kind-config.yaml" \
        --wait 60s
fi

# Set kubectl context for all subsequent commands
kubectl config use-context "${KUBE_CTX}"
kubectl cluster-info >/dev/null 2>&1
log_info "Kind cluster is ready."

# --------------------------------------------------------------------------
# Phase 2: Install Gateway API CRDs
# --------------------------------------------------------------------------
log_info "=== Phase 2: Gateway API CRDs ==="
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml" 2>/dev/null || true
log_info "Gateway API CRDs installed."

# --------------------------------------------------------------------------
# Phase 3: Build and load images
# --------------------------------------------------------------------------
log_info "=== Phase 3: Build and load images ==="

log_info "Building panoptium operator image..."
make -C "${PROJECT_ROOT}" docker-build "IMG=${PANOPTIUM_IMG}"

log_info "Building mock LLM image..."
docker build -t "${MOCK_LLM_IMG}" "${SCRIPT_DIR}/mock-llm/"

log_info "Loading images into kind cluster..."
kind load docker-image "${PANOPTIUM_IMG}" --name "${CLUSTER_NAME}"
kind load docker-image "${MOCK_LLM_IMG}" --name "${CLUSTER_NAME}"
log_info "Images loaded."

# --------------------------------------------------------------------------
# Phase 4: Install AgentGateway via Helm
# --------------------------------------------------------------------------
log_info "=== Phase 4: AgentGateway ==="
log_info "Installing AgentGateway CRDs..."
helm upgrade --install agentgateway-crds \
    "oci://cr.agentgateway.dev/charts/agentgateway-crds" \
    --version "${AGENTGATEWAY_VERSION}" \
    --namespace agentgateway-system \
    --create-namespace \
    --kube-context "${KUBE_CTX}" \
    --wait \
    --timeout 60s

log_info "Installing AgentGateway control plane..."
helm upgrade --install agentgateway \
    "oci://cr.agentgateway.dev/charts/agentgateway" \
    --version "${AGENTGATEWAY_VERSION}" \
    --values "${SCRIPT_DIR}/helm/agentgateway-values.yaml" \
    --namespace agentgateway-system \
    --create-namespace \
    --kube-context "${KUBE_CTX}" \
    --wait \
    --timeout 300s
log_info "AgentGateway installed."

# --------------------------------------------------------------------------
# Phase 4.5: Install cert-manager (required for kustomize webhook TLS)
# --------------------------------------------------------------------------
if [[ "${DEPLOY_METHOD}" != "helm" ]]; then
    log_info "=== Phase 4.5: cert-manager ==="
    CERT_MANAGER_VERSION="v1.16.0"
    CERT_MANAGER_URL="https://github.com/jetstack/cert-manager/releases/download/${CERT_MANAGER_VERSION}/cert-manager.yaml"
    kubectl apply -f "${CERT_MANAGER_URL}"
    log_info "Waiting for cert-manager webhook to be ready..."
    kubectl wait deployment.apps/cert-manager \
        --for=condition=Available \
        --namespace cert-manager \
        --timeout 300s
    kubectl wait deployment.apps/cert-manager-cainjector \
        --for=condition=Available \
        --namespace cert-manager \
        --timeout 300s
    kubectl wait deployment.apps/cert-manager-webhook \
        --for=condition=Available \
        --namespace cert-manager \
        --timeout 300s
    # Wait for the webhook to be fully functional (CA bootstrap takes time after pod is ready)
    log_info "Waiting for cert-manager webhook to become functional..."
    for i in $(seq 1 30); do
        if kubectl apply -f - <<'PROBE' 2>/dev/null; then
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: cert-manager-probe
  namespace: default
spec:
  selfSigned: {}
PROBE
            kubectl delete issuer cert-manager-probe -n default 2>/dev/null || true
            break
        fi
        log_info "  cert-manager webhook not ready yet (attempt $i/30)..."
        sleep 5
    done
    log_info "cert-manager installed and ready."
fi

# --------------------------------------------------------------------------
# Phase 5: Deploy panoptium operator
# --------------------------------------------------------------------------
log_info "=== Phase 5: Panoptium operator (method: ${DEPLOY_METHOD}) ==="
# Create namespace if not exists
kubectl create namespace "${NAMESPACE}" 2>/dev/null || true

cd "${PROJECT_ROOT}"

# Install Panoptium CRDs first (required before operator starts)
log_info "Installing Panoptium CRDs..."
make install

# Parse image repository and tag from PANOPTIUM_IMG
PANOPTIUM_IMG_REPO="${PANOPTIUM_IMG%:*}"
PANOPTIUM_IMG_TAG="${PANOPTIUM_IMG##*:}"

case "${DEPLOY_METHOD}" in
    helm)
        log_info "Deploying panoptium operator via Helm..."
        helm install panoptium chart/panoptium/ \
            --namespace "${NAMESPACE}" \
            --create-namespace \
            --set "image.repository=${PANOPTIUM_IMG_REPO}" \
            --set "image.tag=${PANOPTIUM_IMG_TAG}" \
            --set webhook.enabled=true \
            --set webhook.certManager=false \
            --kube-context "${KUBE_CTX}" \
            --wait \
            --timeout 120s
        ;;
    kustomize|*)
        make deploy "IMG=${PANOPTIUM_IMG}"
        ;;
esac

log_info "Waiting for panoptium operator to be ready..."
kubectl wait deployment/panoptium-controller-manager \
    -n "${NAMESPACE}" \
    --for=condition=Available \
    --timeout=120s
log_info "Panoptium operator is ready."

# --------------------------------------------------------------------------
# Phase 6: Deploy mock LLM
# --------------------------------------------------------------------------
log_info "=== Phase 6: Mock LLM ==="
kubectl apply -f "${SCRIPT_DIR}/manifests/mock-llm.yaml"

log_info "Waiting for mock LLM to be ready..."
kubectl wait deployment/mock-llm \
    -n "${NAMESPACE}" \
    --for=condition=Available \
    --timeout=60s
log_info "Mock LLM is ready."

# --------------------------------------------------------------------------
# Phase 7: Apply integration wiring (backend, route, ExtProc policy)
# --------------------------------------------------------------------------
log_info "=== Phase 7: Integration wiring ==="
kubectl apply -f "${SCRIPT_DIR}/manifests/agentgateway-backend.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/agentgateway-route.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/agentgateway-identity-policy.yaml"
kubectl apply -f "${SCRIPT_DIR}/manifests/agentgateway-extproc-policy.yaml"

# Create ClusterRoleBinding for metrics access (required by E2E metric assertions)
kubectl create clusterrolebinding panoptium-metrics-binding \
    --clusterrole=panoptium-metrics-reader \
    --serviceaccount="${NAMESPACE}:panoptium-controller-manager" 2>/dev/null || true
log_info "Integration wiring applied."

# --------------------------------------------------------------------------
# Phase 8: Wait for all components to be ready
# --------------------------------------------------------------------------
log_info "=== Phase 8: Readiness check ==="
log_info "Waiting for all pods to be ready..."

# Wait for gateway pod to be ready
kubectl wait pod \
    -l gateway.networking.k8s.io/gateway-name=e2e-gateway \
    -n "${NAMESPACE}" \
    --for=condition=Ready \
    --timeout=120s 2>/dev/null || \
    log_warn "Gateway pod not ready yet (may take additional time)."

# Brief pause to let configurations propagate
sleep 5
log_info "All components ready."

# --------------------------------------------------------------------------
# Phase 9: Run Ginkgo E2E tests
# --------------------------------------------------------------------------
log_info "=== Phase 9: E2E tests ==="
export KIND_CLUSTER="${CLUSTER_NAME}"
export KUBECONFIG="${HOME}/.kube/config"
# Skip BeforeSuite steps that are already handled by this script
# export PROMETHEUS_INSTALL_SKIP=true
export CERT_MANAGER_INSTALL_SKIP=true
cd "${PROJECT_ROOT}"

if [[ "${DEPLOY_METHOD}" == "helm" ]]; then
    E2E_LABEL_FILTER="${E2E_LABEL_FILTER:-e2e-helm || e2e-extproc || e2e-crd || e2e-policy || e2e-enforcement || e2e-threat-sig}"
else
    E2E_LABEL_FILTER="${E2E_LABEL_FILTER:-e2e-extproc || e2e-crd || e2e-policy || e2e-enforcement || e2e-threat-sig}"
fi

go test ./test/e2e/ -v -ginkgo.v -timeout 600s \
    -ginkgo.label-filter="${E2E_LABEL_FILTER}" 2>&1 || {
    log_error "E2E tests failed!"
    log_info "Dumping diagnostics..."
    kubectl get pods -A || true
    kubectl logs -l control-plane=controller-manager -n "${NAMESPACE}" --tail=50 || true
    exit 1
}

log_info "=== All E2E tests passed! ==="
