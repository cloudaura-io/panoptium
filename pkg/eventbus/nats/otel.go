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

package nats

import (
	"context"
	"os"
	"sort"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// NATSHeaderCarrier implements propagation.TextMapCarrier for NATS message headers.
// It allows OTel trace context to be injected into and extracted from NATS messages.
type NATSHeaderCarrier map[string]string

// Get returns the value associated with the passed key.
func (c NATSHeaderCarrier) Get(key string) string {
	return c[key]
}

// Set stores the key-value pair.
func (c NATSHeaderCarrier) Set(key, value string) {
	c[key] = value
}

// Keys returns the keys stored in this carrier.
func (c NATSHeaderCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// NATSPropagator wraps the W3C TraceContext propagator for use with NATS messages.
type NATSPropagator struct {
	propagator propagation.TextMapPropagator
}

// NewNATSPropagator creates a new propagator using W3C Trace Context format.
func NewNATSPropagator() *NATSPropagator {
	return &NATSPropagator{
		propagator: propagation.TraceContext{},
	}
}

// Inject injects the trace context from ctx into the carrier (NATS headers).
func (p *NATSPropagator) Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	p.propagator.Inject(ctx, carrier)
}

// Extract extracts the trace context from the carrier (NATS headers) into a new context.
func (p *NATSPropagator) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	return p.propagator.Extract(ctx, carrier)
}

// TelemetryConfig holds configuration for OpenTelemetry export.
type TelemetryConfig struct {
	// OTLPEndpoint is the OTLP gRPC endpoint for traces and metrics.
	// Default: localhost:4317.
	OTLPEndpoint string

	// ServiceName is the service name reported in OTel spans.
	// Default: panoptium-eventbus.
	ServiceName string

	// Enabled controls whether OTel export is active.
	Enabled bool
}

// DefaultTelemetryConfig returns a TelemetryConfig with spec-defined defaults.
// It respects the OTEL_EXPORTER_OTLP_ENDPOINT environment variable.
func DefaultTelemetryConfig() TelemetryConfig {
	endpoint := "localhost:4317"
	if envEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); envEndpoint != "" {
		endpoint = envEndpoint
	}

	return TelemetryConfig{
		OTLPEndpoint: endpoint,
		ServiceName:  "panoptium-eventbus",
		Enabled:      true,
	}
}

// SetGlobalPropagator sets the W3C Trace Context propagator as the global OTel propagator.
func SetGlobalPropagator() {
	otel.SetTextMapPropagator(propagation.TraceContext{})
}
