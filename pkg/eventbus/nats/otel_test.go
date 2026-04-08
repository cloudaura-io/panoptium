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
	"encoding/hex"
	"os"
	"testing"

	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// TestTraceContextInjection verifies TraceID and SpanID are injected into NATS headers.
func TestTraceContextInjection(t *testing.T) {
	prop := NewNATSPropagator()

	// Create a span context with known values
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("0102030405060708")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     false,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	carrier := make(NATSHeaderCarrier)
	prop.Inject(ctx, carrier)

	// Verify traceparent header exists and contains our trace ID
	tp := carrier.Get("traceparent")
	if tp == "" {
		t.Fatal("traceparent header not set")
	}

	// W3C format: 00-{trace-id}-{span-id}-{flags}
	if len(tp) < 55 {
		t.Fatalf("traceparent too short: %q", tp)
	}

	// Extract trace ID (positions 3..35 in the traceparent string)
	extractedTraceID := tp[3:35]
	expectedTraceID := hex.EncodeToString(traceID[:])
	if extractedTraceID != expectedTraceID {
		t.Errorf("Injected TraceID = %q, want %q", extractedTraceID, expectedTraceID)
	}

	// Extract span ID (positions 36..52)
	extractedSpanID := tp[36:52]
	expectedSpanID := hex.EncodeToString(spanID[:])
	if extractedSpanID != expectedSpanID {
		t.Errorf("Injected SpanID = %q, want %q", extractedSpanID, expectedSpanID)
	}
}

// TestTraceContextExtraction verifies trace context is extracted from NATS headers.
func TestTraceContextExtraction(t *testing.T) {
	prop := NewNATSPropagator()

	carrier := make(NATSHeaderCarrier)
	carrier.Set("traceparent", "00-0102030405060708090a0b0c0d0e0f10-0102030405060708-01")

	ctx := prop.Extract(context.Background(), carrier)
	sc := trace.SpanContextFromContext(ctx)

	if !sc.IsValid() {
		t.Fatal("Extracted span context is not valid")
	}

	expectedTraceID := "0102030405060708090a0b0c0d0e0f10"
	if sc.TraceID().String() != expectedTraceID {
		t.Errorf("TraceID = %q, want %q", sc.TraceID().String(), expectedTraceID)
	}

	expectedSpanID := "0102030405060708"
	if sc.SpanID().String() != expectedSpanID {
		t.Errorf("SpanID = %q, want %q", sc.SpanID().String(), expectedSpanID)
	}
}

// TestW3CTraceContextCompliance verifies 32-char trace-id and 16-char span-id format.
func TestW3CTraceContextCompliance(t *testing.T) {
	prop := NewNATSPropagator()

	traceID, _ := trace.TraceIDFromHex("abcdef0123456789abcdef0123456789")
	spanID, _ := trace.SpanIDFromHex("abcdef0123456789")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	carrier := make(NATSHeaderCarrier)
	prop.Inject(ctx, carrier)

	tp := carrier.Get("traceparent")
	// Format: 00-{32-char-trace-id}-{16-char-span-id}-{2-char-flags}
	// Total: 2 + 1 + 32 + 1 + 16 + 1 + 2 = 55
	if len(tp) != 55 {
		t.Errorf("traceparent length = %d, want 55 (format: 00-{32}-{16}-{02})", len(tp))
	}

	// Verify trace-id is exactly 32 hex chars
	traceIDStr := tp[3:35]
	if len(traceIDStr) != 32 {
		t.Errorf("trace-id length = %d, want 32", len(traceIDStr))
	}

	// Verify span-id is exactly 16 hex chars
	spanIDStr := tp[36:52]
	if len(spanIDStr) != 16 {
		t.Errorf("span-id length = %d, want 16", len(spanIDStr))
	}
}

// TestParentChildSpanRelationship verifies that spans created during publish
// and consume have a parent-child relationship.
func TestParentChildSpanRelationship(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tracer := tp.Tracer("test")

	// Create a parent span
	ctx, parentSpan := tracer.Start(context.Background(), "parent-operation")

	// Simulate injection
	prop := NewNATSPropagator()
	carrier := make(NATSHeaderCarrier)
	prop.Inject(ctx, carrier)
	parentSpan.End()

	// Simulate extraction on the consumer side
	consumerCtx := prop.Extract(context.Background(), carrier)
	_, childSpan := tracer.Start(consumerCtx, "consumer-operation")
	childSpan.End()

	// Force flush
	_ = tp.ForceFlush(context.Background())

	spans := exporter.GetSpans()
	if len(spans) < 2 {
		t.Fatalf("Expected at least 2 spans, got %d", len(spans))
	}

	// Find parent and child spans
	var parentExported, childExported tracetest.SpanStub
	for _, s := range spans {
		if s.Name == "parent-operation" {
			parentExported = s
		}
		if s.Name == "consumer-operation" {
			childExported = s
		}
	}

	// Verify they share the same trace ID
	if parentExported.SpanContext.TraceID() != childExported.SpanContext.TraceID() {
		t.Error("Parent and child spans should share the same TraceID")
	}

	// The child's parent should be the parent span
	if childExported.Parent.SpanID() != parentExported.SpanContext.SpanID() {
		t.Error("Child span's parent should be the parent span")
	}
}

// TestOTelTelemetryConfig verifies the OTLP endpoint configuration from env var.
func TestOTelTelemetryConfig(t *testing.T) {
	// Test default endpoint
	cfg := DefaultTelemetryConfig()
	if cfg.OTLPEndpoint != "localhost:4317" {
		t.Errorf("Default OTLPEndpoint = %q, want %q", cfg.OTLPEndpoint, "localhost:4317")
	}

	// Test env var override
	_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector:4317")
	defer func() { _ = os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT") }()

	cfg2 := DefaultTelemetryConfig()
	if cfg2.OTLPEndpoint != "otel-collector:4317" {
		t.Errorf("Env OTLPEndpoint = %q, want %q", cfg2.OTLPEndpoint, "otel-collector:4317")
	}
}

// TestNATSHeaderCarrier verifies the carrier implements TextMapCarrier.
func TestNATSHeaderCarrier(t *testing.T) {
	var _ propagation.TextMapCarrier = make(NATSHeaderCarrier)

	carrier := make(NATSHeaderCarrier)
	carrier.Set("key1", "value1")
	carrier.Set("key2", "value2")

	if carrier.Get("key1") != "value1" {
		t.Errorf("Get(key1) = %q, want %q", carrier.Get("key1"), "value1")
	}

	keys := carrier.Keys()
	if len(keys) != 2 {
		t.Errorf("Keys() length = %d, want 2", len(keys))
	}
}
