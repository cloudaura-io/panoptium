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
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// newTestMetrics creates a BusMetrics instance backed by an in-memory reader for testing.
func newTestMetrics(t *testing.T) (*BusMetrics, *metric.ManualReader) {
	t.Helper()
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	meter := mp.Meter("panoptium-eventbus-test")

	m, err := NewBusMetrics(meter)
	if err != nil {
		t.Fatalf("NewBusMetrics error: %v", err)
	}
	return m, reader
}

// TestBusMetrics_EventRateTotal verifies that event_rate_total counter increments.
func TestBusMetrics_EventRateTotal(t *testing.T) {
	m, reader := newTestMetrics(t)

	m.RecordEmit("llm")
	m.RecordEmit("llm")
	m.RecordEmit("syscall")

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	found := false
	for _, sm := range data.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == "panoptium.eventbus.emit_total" {
				found = true
				sum, ok := metric.Data.(metricdata.Sum[int64])
				if !ok {
					t.Fatalf("Expected Sum[int64], got %T", metric.Data)
				}
				// Sum across all data points should be 3
				var total int64
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
				if total != 3 {
					t.Errorf("emit_total = %d, want 3", total)
				}
			}
		}
	}
	if !found {
		t.Error("panoptium.eventbus.emit_total metric not found")
	}
}

// TestBusMetrics_PublishLatency verifies that publish latency histogram records values.
func TestBusMetrics_PublishLatency(t *testing.T) {
	m, reader := newTestMetrics(t)

	m.RecordPublishLatency(0.5, "llm")
	m.RecordPublishLatency(1.0, "llm")

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	found := false
	for _, sm := range data.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == "panoptium.eventbus.publish_latency_seconds" {
				found = true
				hist, ok := metric.Data.(metricdata.Histogram[float64])
				if !ok {
					t.Fatalf("Expected Histogram[float64], got %T", metric.Data)
				}
				if len(hist.DataPoints) == 0 {
					t.Error("No histogram data points")
					continue
				}
				dp := hist.DataPoints[0]
				if dp.Count != 2 {
					t.Errorf("Histogram count = %d, want 2", dp.Count)
				}
			}
		}
	}
	if !found {
		t.Error("panoptium.eventbus.publish_latency_seconds metric not found")
	}
}

// TestBusMetrics_SubscriberLag verifies subscriber lag gauge records values.
func TestBusMetrics_SubscriberLag(t *testing.T) {
	m, reader := newTestMetrics(t)

	m.RecordSubscriberLag(42, "test-consumer")

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	found := false
	for _, sm := range data.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == "panoptium.eventbus.subscriber_lag" {
				found = true
			}
		}
	}
	if !found {
		t.Error("panoptium.eventbus.subscriber_lag metric not found")
	}
}

// TestBusMetrics_StreamDepth verifies stream depth gauge records values.
func TestBusMetrics_StreamDepth(t *testing.T) {
	m, reader := newTestMetrics(t)

	m.RecordStreamDepth(1000, "PANOPTIUM_LLM")

	var data metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &data); err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	found := false
	for _, sm := range data.ScopeMetrics {
		for _, metric := range sm.Metrics {
			if metric.Name == "panoptium.eventbus.stream_depth" {
				found = true
			}
		}
	}
	if !found {
		t.Error("panoptium.eventbus.stream_depth metric not found")
	}
}
