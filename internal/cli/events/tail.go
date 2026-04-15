package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"

	"github.com/panoptium/panoptium/internal/cli/eventbus"
	"github.com/panoptium/panoptium/internal/cli/output"
)

type EventView struct {
	ID          string `json:"id"                     yaml:"id"`
	Timestamp   string `json:"timestamp"              yaml:"timestamp"`
	Category    string `json:"category"               yaml:"category"`
	Subcategory string `json:"subcategory,omitempty"  yaml:"subcategory,omitempty"`
	Severity    string `json:"severity"               yaml:"severity"`
	Namespace   string `json:"namespace,omitempty"    yaml:"namespace,omitempty"`
	AgentName   string `json:"agentName,omitempty"    yaml:"agentName,omitempty"`
	PodName     string `json:"podName,omitempty"      yaml:"podName,omitempty"`
	Subject     string `json:"subject,omitempty"      yaml:"subject,omitempty"`
	Summary     string `json:"summary,omitempty"      yaml:"summary,omitempty"`
}

func newTailCommand(getFormat func() string) *cobra.Command {
	var (
		natsEndpoint string
		namespace    string
		category     string
		agent        string
		count        int
		connectWait  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Stream events from Panoptium's NATS event bus",
		Long: `tail subscribes to Panoptium's event bus and streams matching events
to stdout until SIGINT is received (or --count events have been seen).

Panoptium's event bus runs as an embedded NATS server inside the operator
pod and is not exposed externally by default. Run kubectl port-forward
before invoking tail:

  kubectl port-forward -n panoptium-system deploy/panoptium-controller-manager 4222:4222

Then set --nats-endpoint or NATS_URL to nats://localhost:4222.

Filters map to NATS subject wildcards on the panoptium.events.NS.CAT.>
subject tree. --agent is applied client-side because agent identity is
not part of the subject hierarchy.`,
		Example: `  # tail everything (noisy)
  panoptium events tail --nats-endpoint nats://localhost:4222

  # only policy decisions
  panoptium events tail --category policy

  # only events from the 'default' namespace, as JSON
  panoptium events tail --ns-filter default -o json

  # stop after 10 events
  panoptium events tail --count 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := output.ParseFormat(getFormat())
			if err != nil {
				return err
			}
			if format == output.FormatTable {
				return &output.FormatUnsupportedError{Command: "events tail", Format: format}
			}
			if namespace != "" {
				if err := eventbus.ValidateFilter("ns-filter", namespace); err != nil {
					return err
				}
			}
			if category != "" {
				if err := eventbus.ValidateFilter("category", category); err != nil {
					return err
				}
			}
			endpoint, err := eventbus.ResolveEndpoint(natsEndpoint)
			if err != nil {
				return err
			}
			conn, err := eventbus.Connect(endpoint, connectWait)
			if err != nil {
				return err
			}
			defer conn.Close()

			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			return streamEvents(ctx, cmd.OutOrStdout(), conn, eventbus.Filters{
				Namespace: namespace,
				Category:  category,
				Agent:     agent,
			}, format, count)
		},
	}
	cmd.Flags().StringVar(&natsEndpoint, "nats-endpoint", "", "NATS URL (default: $NATS_URL, $PANOPTIUM_NATS_URL)")
	cmd.Flags().StringVar(&namespace, "ns-filter", "", "only show events from this namespace (subject wildcard)")
	cmd.Flags().StringVar(&category, "category", "", "only show events in this category (syscall|network|protocol|llm|policy|lifecycle)")
	cmd.Flags().StringVar(&agent, "agent", "", "only show events from this agent name (client-side filter)")
	cmd.Flags().IntVar(&count, "count", 0, "stop after N matching events (0 = unbounded)")
	cmd.Flags().DurationVar(&connectWait, "connect-timeout", 5*time.Second, "NATS connection timeout")
	return cmd
}

func streamEvents(ctx context.Context, w io.Writer, conn *natsgo.Conn, f eventbus.Filters, format output.Format, count int) error {
	var delivered atomic.Int32
	done := make(chan struct{})
	var (
		mu       sync.Mutex
		firstErr error
	)

	handler := func(msg *natsgo.Msg) {
		view, ok := unwrap(msg)
		if !ok {
			return
		}
		if !eventbus.MatchesAgent(f.Agent, view.AgentName) {
			return
		}
		if err := writeEvent(w, format, view); err != nil {
			mu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
			select {
			case <-done:
			default:
				close(done)
			}
			return
		}
		n := delivered.Add(1)
		if count > 0 && int(n) >= count {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}

	cancelSub, err := eventbus.Subscribe(ctx, conn, f, handler)
	if err != nil {
		return err
	}
	defer cancelSub()

	select {
	case <-ctx.Done():
	case <-done:
	}
	mu.Lock()
	defer mu.Unlock()
	return firstErr
}

// natsEventEnvelope mirrors the operator's JSON wire format in pkg/eventbus/nats/bus.go.
type natsEventEnvelope struct {
	EventType string          `json:"event_type"`
	Timestamp time.Time       `json:"timestamp"`
	RequestID string          `json:"request_id"`
	Protocol  string          `json:"protocol"`
	Provider  string          `json:"provider"`
	Namespace string          `json:"namespace"`
	Identity  envelopeAgent   `json:"identity"`
	Data      json.RawMessage `json:"data"`
}

type envelopeAgent struct {
	ID        string `json:"ID"`
	SourceIP  string `json:"SourceIP"`
	Namespace string `json:"Namespace"`
	PodName   string `json:"PodName"`
}

func unwrap(msg *natsgo.Msg) (*EventView, bool) {
	var env natsEventEnvelope
	if err := json.Unmarshal(msg.Data, &env); err != nil {
		return nil, false
	}
	category, subcategory := splitEventType(env.EventType)
	view := &EventView{
		ID:          env.RequestID,
		Timestamp:   env.Timestamp.UTC().Format(time.RFC3339Nano),
		Category:    category,
		Subcategory: subcategory,
		Severity:    "", // severity is in the inner Data payload, not the envelope
		Namespace:   env.Namespace,
		PodName:     env.Identity.PodName,
		AgentName:   env.Identity.PodName,
		Subject:     msg.Subject,
	}
	var inner struct {
		Severity string `json:"severity"`
	}
	if json.Unmarshal(env.Data, &inner) == nil && inner.Severity != "" {
		view.Severity = inner.Severity
	}
	if view.Namespace == "" {
		view.Namespace = env.Identity.Namespace
	}
	if view.AgentName == "" {
		view.AgentName = env.Identity.ID
	}
	return view, true
}

func splitEventType(et string) (string, string) {
	for i := 0; i < len(et); i++ {
		if et[i] == '.' {
			return et[:i], et[i+1:]
		}
	}
	return et, ""
}

func writeEvent(w io.Writer, format output.Format, view *EventView) error {
	switch format {
	case output.FormatJSON:
		return writeEventJSON(w, view)
	case output.FormatYAML:
		return output.WriteYAML(w, view)
	case output.FormatHuman:
		fallthrough
	default:
		return writeEventHuman(w, view)
	}
}

func writeEventJSON(w io.Writer, view *EventView) error {
	b, err := json.Marshal(view)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}

func writeEventHuman(w io.Writer, view *EventView) error {
	agent := view.AgentName
	if agent == "" {
		agent = "-"
	}
	ns := view.Namespace
	if ns == "" {
		ns = "-"
	}
	_, err := fmt.Fprintf(w, "%s  %-8s  %-10s  %-20s  %s/%s\n",
		view.Timestamp, view.Severity, view.Category, view.Subcategory, ns, agent)
	return err
}
