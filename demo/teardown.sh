#!/usr/bin/env bash
# teardown.sh — Remove all demo resources from the cluster
set -euo pipefail

CONTEXT="kind-panoptium-e2e"
GATEWAY_NS="panoptium-system"
KAGENT_NS="kagent"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

info() { echo -e "${GREEN}[INFO]${RESET}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${RESET}  $*"; }

K="kubectl --context $CONTEXT"

echo -e "${BOLD}Panoptium Demo Teardown${RESET}"
echo ""

# Kill any lingering port-forwards
info "Stopping any port-forwards..."
pkill -f "kubectl.*port-forward.*kagent" 2>/dev/null || true

# Remove Kagent demo resources
info "Removing Kagent Agent..."
$K delete agent demo-k8s-agent -n "$KAGENT_NS" --ignore-not-found 2>/dev/null || true

info "Removing Kagent ModelConfig..."
$K delete modelconfig demo-model-config -n "$KAGENT_NS" --ignore-not-found 2>/dev/null || true

info "Removing API key secret..."
$K delete secret openai-api-key -n "$KAGENT_NS" --ignore-not-found 2>/dev/null || true

info "Removing AgentGateway demo backend + route..."
$K delete agentgatewaybackend openai-backend -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
$K delete httproute demo-openai-route -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

# Remove Panoptium policies
info "Removing Panoptium policies..."
for policy in demo-audit-baseline demo-allow-safe-tools demo-deny-bash demo-rate-limit demo-escalate-quarantine; do
  $K delete agentpolicy "$policy" -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true
done

# Remove any demo quarantines
info "Removing demo quarantines..."
$K delete agentquarantine demo-quarantine -n "$GATEWAY_NS" --ignore-not-found 2>/dev/null || true

# Optionally uninstall Kagent
echo ""
read -rp "Uninstall Kagent entirely? (y/N): " uninstall
if [[ "${uninstall,,}" == "y" ]]; then
  info "Uninstalling Kagent Helm releases..."
  helm uninstall kagent --namespace "$KAGENT_NS" --kube-context "$CONTEXT" 2>/dev/null || warn "kagent release not found"
  helm uninstall kagent-crds --namespace "$KAGENT_NS" --kube-context "$CONTEXT" 2>/dev/null || warn "kagent-crds release not found"
  info "Deleting kagent namespace..."
  $K delete namespace "$KAGENT_NS" --ignore-not-found 2>/dev/null || true
fi

echo ""
info "Teardown complete."
