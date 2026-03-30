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

package tetragon

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/panoptium/panoptium/pkg/eventbus"
)

const (
	// defaultPublisherWorkers is the default worker pool size.
	defaultPublisherWorkers = 4

	// defaultPublisherChannelBuffer is the default event channel buffer size.
	defaultPublisherChannelBuffer = 256
)

// PublisherConfig configures the event publisher.
type PublisherConfig struct {
	// Workers is the number of worker goroutines for event processing.
	Workers int

	// ChannelBuffer is the size of the internal event processing channel.
	ChannelBuffer int
}

// PublisherMetrics tracks publisher performance counters.
type PublisherMetrics struct {
	// EventsProcessed counts total events processed (including skipped).
	EventsProcessed atomic.Int64

	// EventsPublished counts events successfully published to the bus.
	EventsPublished atomic.Int64

	// EventsDropped counts events dropped due to full channel.
	EventsDropped atomic.Int64

	// EventsSkipped counts events skipped (unknown type).
	EventsSkipped atomic.Int64

	// TranslateErrors counts translation errors.
	TranslateErrors atomic.Int64
}

// Publisher translates Tetragon RawEvents and publishes them to the event bus.
type Publisher struct {
	bus        eventbus.EventBus
	translator *Translator
	config     PublisherConfig
	events     chan *RawEvent
	metrics    PublisherMetrics
	wg         sync.WaitGroup
	closed     bool
	mu         sync.Mutex
}

// NewPublisher creates a new event publisher.
func NewPublisher(bus eventbus.EventBus, translator *Translator, cfg PublisherConfig) *Publisher {
	if cfg.Workers <= 0 {
		cfg.Workers = defaultPublisherWorkers
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = defaultPublisherChannelBuffer
	}

	return &Publisher{
		bus:        bus,
		translator: translator,
		config:     cfg,
		events:     make(chan *RawEvent, cfg.ChannelBuffer),
	}
}

// Start starts the worker pool for event processing.
func (p *Publisher) Start(ctx context.Context) {
	for i := 0; i < p.config.Workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx, i)
	}
	slog.Info("tetragon publisher started", "workers", p.config.Workers)
}

// Submit enqueues a raw event for translation and publishing.
// Non-blocking: drops the event if the channel is full.
func (p *Publisher) Submit(evt *RawEvent) {
	select {
	case p.events <- evt:
	default:
		p.metrics.EventsDropped.Add(1)
	}
}

// Stop gracefully shuts down the publisher.
func (p *Publisher) Stop() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	close(p.events)
	p.mu.Unlock()

	p.wg.Wait()
	slog.Info("tetragon publisher stopped",
		"events_published", p.metrics.EventsPublished.Load(),
		"events_processed", p.metrics.EventsProcessed.Load(),
		"events_dropped", p.metrics.EventsDropped.Load(),
	)
}

// Metrics returns the publisher's performance counters.
func (p *Publisher) Metrics() PublisherMetrics {
	return p.metrics
}

// worker processes events from the channel.
func (p *Publisher) worker(ctx context.Context, id int) {
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-p.events:
			if !ok {
				return
			}
			p.processEvent(evt)
		}
	}
}

// processEvent translates and publishes a single event.
func (p *Publisher) processEvent(evt *RawEvent) {
	p.metrics.EventsProcessed.Add(1)

	busEvent, err := p.translator.Translate(evt)
	if err != nil {
		p.metrics.TranslateErrors.Add(1)
		slog.Debug("failed to translate tetragon event", "error", err, "pid", evt.ProcessPID)
		return
	}

	if busEvent == nil {
		// Unknown event type, skip gracefully.
		p.metrics.EventsSkipped.Add(1)
		return
	}

	p.bus.Emit(busEvent)
	p.metrics.EventsPublished.Add(1)
}
