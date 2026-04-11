package eventbus

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

var ErrNoEndpoint = errors.New(
	"no NATS endpoint configured: set --nats-endpoint, NATS_URL, or " +
		"PANOPTIUM_NATS_URL (run `kubectl port-forward -n panoptium-system " +
		"deploy/panoptium-controller-manager 4222:4222` first if the " +
		"operator NATS port is not exposed)",
)

type Filters struct {
	Namespace   string // empty = all
	Category    string // empty = all
	Subcategory string // empty = all
	Agent       string // client-side filter on agent name; empty = all
}

func ResolveEndpoint(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if v := os.Getenv("NATS_URL"); v != "" {
		return v, nil
	}
	if v := os.Getenv("PANOPTIUM_NATS_URL"); v != "" {
		return v, nil
	}
	return "", ErrNoEndpoint
}

func Subject(f Filters) string {
	ns := f.Namespace
	if ns == "" {
		ns = "*"
	}
	cat := f.Category
	if cat == "" {
		cat = "*"
	}
	sub := f.Subcategory
	if sub == "" {
		sub = ">"
	}
	return fmt.Sprintf("panoptium.events.%s.%s.%s", ns, cat, sub)
}

func Connect(url string, timeout time.Duration) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.Name("panoptium-cli"),
		nats.Timeout(timeout),
		nats.MaxReconnects(0), // CLI session is short-lived; don't silently reconnect
	}
	c, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to NATS at %s: %w", url, err)
	}
	return c, nil
}

func Subscribe(ctx context.Context, c *nats.Conn, f Filters, handler func(*nats.Msg)) (func(), error) {
	subj := Subject(f)
	sub, err := c.Subscribe(subj, handler)
	if err != nil {
		return nil, fmt.Errorf("subscribe to %q: %w", subj, err)
	}
	if err := c.Flush(); err != nil {
		_ = sub.Unsubscribe()
		return nil, fmt.Errorf("flush after subscribe: %w", err)
	}
	cancel := func() {
		_ = sub.Unsubscribe()
	}
	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()
	return cancel, nil
}

func MatchesAgent(wanted, got string) bool {
	if wanted == "" {
		return true
	}
	return strings.EqualFold(wanted, got)
}
