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
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

// BusMetrics provides OpenTelemetry metrics instrumentation for the NATSBus.
type BusMetrics struct {
	emitTotal      otelmetric.Int64Counter
	publishLatency otelmetric.Float64Histogram
	subscriberLag  otelmetric.Int64Gauge
	streamDepth    otelmetric.Int64Gauge
}

// NewBusMetrics creates a new BusMetrics using the provided OTel meter.
func NewBusMetrics(meter otelmetric.Meter) (*BusMetrics, error) {
	emitTotal, err := meter.Int64Counter(
		"panoptium.eventbus.emit_total",
		otelmetric.WithDescription("Total number of events emitted to the event bus"),
		otelmetric.WithUnit("{event}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating emit_total counter: %w", err)
	}

	publishLatency, err := meter.Float64Histogram(
		"panoptium.eventbus.publish_latency_seconds",
		otelmetric.WithDescription("Latency of event publish operations in seconds"),
		otelmetric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating publish_latency histogram: %w", err)
	}

	subscriberLag, err := meter.Int64Gauge(
		"panoptium.eventbus.subscriber_lag",
		otelmetric.WithDescription("Number of pending messages for a subscriber"),
		otelmetric.WithUnit("{message}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating subscriber_lag gauge: %w", err)
	}

	streamDepth, err := meter.Int64Gauge(
		"panoptium.eventbus.stream_depth",
		otelmetric.WithDescription("Number of messages in a JetStream stream"),
		otelmetric.WithUnit("{message}"),
	)
	if err != nil {
		return nil, fmt.Errorf("creating stream_depth gauge: %w", err)
	}

	return &BusMetrics{
		emitTotal:      emitTotal,
		publishLatency: publishLatency,
		subscriberLag:  subscriberLag,
		streamDepth:    streamDepth,
	}, nil
}

// RecordEmit increments the event emit counter with the given category.
func (m *BusMetrics) RecordEmit(category string) {
	m.emitTotal.Add(context.Background(), 1,
		otelmetric.WithAttributes(attribute.String("category", category)),
	)
}

// RecordPublishLatency records the publish latency for an event category.
func (m *BusMetrics) RecordPublishLatency(seconds float64, category string) {
	m.publishLatency.Record(context.Background(), seconds,
		otelmetric.WithAttributes(attribute.String("category", category)),
	)
}

// RecordSubscriberLag records the number of pending messages for a consumer.
func (m *BusMetrics) RecordSubscriberLag(lag int64, consumer string) {
	m.subscriberLag.Record(context.Background(), lag,
		otelmetric.WithAttributes(attribute.String("consumer", consumer)),
	)
}

// RecordStreamDepth records the number of messages in a JetStream stream.
func (m *BusMetrics) RecordStreamDepth(depth int64, stream string) {
	m.streamDepth.Record(context.Background(), depth,
		otelmetric.WithAttributes(attribute.String("stream", stream)),
	)
}
