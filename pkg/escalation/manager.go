/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package escalation wires the EscalationProcessor to the event bus and
// creates PanoptiumQuarantine CRDs when escalation thresholds are reached.
package escalation

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/pkg/eventbus"
	"github.com/panoptium/panoptium/pkg/policy/action"
)

// EscalationManager subscribes to policy decision events on the event bus,
// feeds deny actions into an EscalationProcessor, and creates
// PanoptiumQuarantine resources when escalation thresholds are reached.
// It implements manager.Runnable so it can be added to the controller-runtime
// manager via mgr.Add().
type EscalationManager struct {
	bus       eventbus.EventBus
	client    client.Client
	processor *action.EscalationProcessor
}

// NewEscalationManager creates a new EscalationManager. The processor is
// initialised with no levels; levels are configured dynamically from event
// parameters as they arrive.
func NewEscalationManager(bus eventbus.EventBus, c client.Client) *EscalationManager {
	return &EscalationManager{
		bus:       bus,
		client:    c,
		processor: action.NewEscalationProcessor(nil),
	}
}

// Start implements manager.Runnable. It subscribes to EventTypePolicyDecision
// events and processes them until the context is cancelled.
func (m *EscalationManager) Start(ctx context.Context) error {
	l := log.FromContext(ctx).WithName("escalation-manager")

	sub := m.bus.Subscribe(eventbus.EventTypePolicyDecision)
	if sub == nil {
		return fmt.Errorf("failed to subscribe to %s events", eventbus.EventTypePolicyDecision)
	}
	defer m.bus.Unsubscribe(sub)

	l.Info("escalation manager started, listening for policy decisions")

	for {
		select {
		case <-ctx.Done():
			l.Info("escalation manager stopping")
			return nil
		case evt, ok := <-sub.Events():
			if !ok {
				l.Info("subscription channel closed, stopping")
				return nil
			}
			m.handleEvent(ctx, evt)
		}
	}
}

// handleEvent processes a single event from the bus. It skips events that
// are not deny actions or that have no escalation configuration.
func (m *EscalationManager) handleEvent(ctx context.Context, evt eventbus.Event) {
	l := log.FromContext(ctx).WithName("escalation-manager")

	enfEvt, ok := evt.(*eventbus.EnforcementEvent)
	if !ok {
		return
	}

	// Only process deny actions with escalation configuration
	if enfEvt.Action != "deny" {
		return
	}
	if enfEvt.EscalationThreshold <= 0 {
		return
	}

	// Build agent key from pod identity, falling back to source IP
	agentKey := enfEvt.AgentInfo.PodName
	if agentKey == "" {
		agentKey = enfEvt.AgentInfo.ID
	}
	if agentKey == "" {
		agentKey = enfEvt.AgentInfo.SourceIP
	}
	if agentKey == "" {
		l.Error(fmt.Errorf("missing agent identity"), "cannot process escalation event: agent identity is empty",
			"podName", enfEvt.AgentInfo.PodName,
			"id", enfEvt.AgentInfo.ID,
			"sourceIP", enfEvt.AgentInfo.SourceIP,
			"action", enfEvt.Action,
			"escalationThreshold", enfEvt.EscalationThreshold,
			"policyName", enfEvt.PolicyName,
		)
		recordMissingIdentity()
		return
	}

	// Configure escalation level dynamically from event parameters.
	// The processor is shared across agents, so we set the levels to match
	// the current policy's escalation configuration. Since all events for a
	// given policy carry the same parameters, this is safe.
	m.processor.SetLevels([]action.EscalationLevel{
		{
			FromAction: "deny",
			ToAction:   enfEvt.EscalationAction,
			Threshold:  enfEvt.EscalationThreshold,
			Window:     enfEvt.EscalationWindow,
		},
	})

	// Record and check escalation
	m.processor.RecordAction(agentKey, "deny")
	escalated, toAction := m.processor.CheckEscalation(agentKey, "deny")

	if escalated && toAction == "quarantine" {
		reason := fmt.Sprintf("escalation triggered: %d deny actions within %s for agent %q",
			enfEvt.EscalationThreshold, enfEvt.EscalationWindow, agentKey)

		l.Info("escalation threshold reached, creating quarantine",
			"agent", agentKey,
			"threshold", enfEvt.EscalationThreshold,
			"window", enfEvt.EscalationWindow,
			"policy", enfEvt.PolicyName,
		)

		if err := m.createQuarantine(ctx, enfEvt.AgentInfo, enfEvt.PolicyName, enfEvt.PolicyNamespace, reason); err != nil {
			l.Error(err, "failed to create PanoptiumQuarantine",
				"agent", agentKey,
				"policy", enfEvt.PolicyName,
			)
		}
	}
}

// createQuarantine builds and creates a PanoptiumQuarantine resource.
func (m *EscalationManager) createQuarantine(ctx context.Context, agent eventbus.AgentIdentity, policyName, policyNamespace, reason string) error {
	ns := agent.Namespace
	if ns == "" {
		ns = policyNamespace
	}
	if ns == "" {
		ns = "default"
	}

	podName := agent.PodName
	if podName == "" {
		podName = agent.ID
	}

	quarantine := &v1alpha1.PanoptiumQuarantine{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "escalation-",
			Namespace:    ns,
		},
		Spec: v1alpha1.PanoptiumQuarantineSpec{
			TargetPod:        podName,
			TargetNamespace:  ns,
			ContainmentLevel: v1alpha1.ContainmentLevelNetworkIsolate,
			Reason:           reason,
			TriggeringPolicy: policyName,
		},
	}

	return m.client.Create(ctx, quarantine)
}

// NeedsLeaderElection returns false so the escalation manager runs on all
// replicas (it is idempotent via the sliding window).
func (m *EscalationManager) NeedsLeaderElection() bool {
	return false
}
