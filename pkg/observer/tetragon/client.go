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

// NOTE: Implemented but not yet wired into the operator. Will replace the
// custom eBPF programs with Cilium Tetragon as the primary kernel event source,
// consuming syscall events via gRPC and publishing them to the NATS event bus.

package tetragon

import (
	"context"
	"sync/atomic"
	"time"
)

const (
	// defaultInitialBackoff is the initial delay before reconnecting.
	defaultInitialBackoff = 1 * time.Second

	// defaultMaxBackoff is the maximum delay between reconnect attempts.
	defaultMaxBackoff = 30 * time.Second

	// defaultBackoffMultiplier is the exponential backoff multiplier.
	defaultBackoffMultiplier = 2.0

	// defaultEventChannelSize is the buffer size for the event channel.
	defaultEventChannelSize = 256
)

// EventStream is an abstraction over Tetragon's gRPC event stream.
// In production, this wraps tetragon.FineGuidanceSensors_GetEventsClient.
type EventStream interface {
	// Recv receives the next event from the stream.
	Recv() (*RawEvent, error)

	// Close closes the stream.
	Close() error
}

// StreamFactory creates EventStream connections.
// This indirection enables testing with mock gRPC servers.
type StreamFactory interface {
	// Connect establishes a new event stream to the given address.
	Connect(ctx context.Context, address string) (EventStream, error)
}

// ClientConfig configures the Tetragon gRPC client.
type ClientConfig struct {
	// Address is the Tetragon gRPC endpoint (e.g., "localhost:54321").
	Address string

	// InitialBackoff is the initial delay before reconnecting.
	InitialBackoff time.Duration

	// MaxBackoff is the maximum delay between reconnect attempts.
	MaxBackoff time.Duration

	// BackoffMultiplier is the exponential backoff multiplier.
	BackoffMultiplier float64
}

// ClientMetrics tracks client performance counters.
type ClientMetrics struct {
	// EventsReceived counts total events received from Tetragon.
	EventsReceived atomic.Int64

	// ReconnectCount counts the number of reconnection attempts.
	ReconnectCount atomic.Int64

	// EventsDropped counts events dropped due to full channel.
	EventsDropped atomic.Int64
}

// ClientOption configures the Client.
type ClientOption func(*Client)

// WithStreamFactory sets the stream factory for the client.
// This is primarily used for testing with mock streams.
func WithStreamFactory(factory StreamFactory) ClientOption {
	return func(c *Client) {
		c.factory = factory
	}
}

// Client consumes events from Tetragon's gRPC event stream.
// It handles connection lifecycle, reconnection with exponential backoff,
// and exposes events on a channel for downstream consumers.
type Client struct {
	config  ClientConfig
	factory StreamFactory
	events  chan *RawEvent
	metrics ClientMetrics
	state   atomic.Value // stores ConnectionState
}

// NewClient creates a new Tetragon gRPC client.
func NewClient(cfg ClientConfig, opts ...ClientOption) *Client {
	if cfg.InitialBackoff == 0 {
		cfg.InitialBackoff = defaultInitialBackoff
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = defaultMaxBackoff
	}
	if cfg.BackoffMultiplier == 0 {
		cfg.BackoffMultiplier = defaultBackoffMultiplier
	}

	c := &Client{
		config: cfg,
		events: make(chan *RawEvent, defaultEventChannelSize),
	}
	c.state.Store(StateDisconnected)

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Events returns the channel on which Tetragon events are delivered.
func (c *Client) Events() <-chan *RawEvent {
	return c.events
}

// Metrics returns the client's performance counters.
func (c *Client) Metrics() *ClientMetrics {
	return &c.metrics
}

// State returns the current connection state.
func (c *Client) State() ConnectionState {
	return c.state.Load().(ConnectionState)
}

// Start connects to Tetragon and begins consuming events.
// It reconnects automatically with exponential backoff on stream errors.
// Blocks until ctx is cancelled.
func (c *Client) Start(ctx context.Context) {
	backoff := c.config.InitialBackoff

	for {
		select {
		case <-ctx.Done():
			c.state.Store(StateDisconnected)
			return
		default:
		}

		c.state.Store(StateConnecting)

		stream, err := c.factory.Connect(ctx, c.config.Address)
		if err != nil {
			c.state.Store(StateReconnecting)
			c.metrics.ReconnectCount.Add(1)
			select {
			case <-ctx.Done():
				c.state.Store(StateDisconnected)
				return
			case <-time.After(backoff):
			}
			backoff = c.nextBackoff(backoff)
			continue
		}

		c.state.Store(StateConnected)
		backoff = c.config.InitialBackoff

		// Read events from the stream.
		if err := c.consumeStream(ctx, stream); err != nil {
			_ = stream.Close()
			c.state.Store(StateReconnecting)
			c.metrics.ReconnectCount.Add(1)

			select {
			case <-ctx.Done():
				c.state.Store(StateDisconnected)
				return
			case <-time.After(backoff):
			}
			backoff = c.nextBackoff(backoff)
			continue
		}
	}
}

// consumeStream reads events from the stream until it errors or ctx is cancelled.
func (c *Client) consumeStream(ctx context.Context, stream EventStream) error {
	type recvResult struct {
		evt *RawEvent
		err error
	}

	for {
		ch := make(chan recvResult, 1)
		go func() {
			evt, err := stream.Recv()
			ch <- recvResult{evt: evt, err: err}
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case res := <-ch:
			if res.err != nil {
				return res.err
			}

			c.metrics.EventsReceived.Add(1)

			select {
			case c.events <- res.evt:
			default:
				c.metrics.EventsDropped.Add(1)
			}
		}
	}
}

// nextBackoff calculates the next backoff duration.
func (c *Client) nextBackoff(current time.Duration) time.Duration {
	next := time.Duration(float64(current) * c.config.BackoffMultiplier)
	if next > c.config.MaxBackoff {
		next = c.config.MaxBackoff
	}
	return next
}
