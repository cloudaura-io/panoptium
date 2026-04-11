package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	"github.com/panoptium/panoptium/internal/cli/eventbus"
	"github.com/panoptium/panoptium/internal/cli/output"
	pb "github.com/panoptium/panoptium/pkg/eventbus/pb"
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
  panoptium events tail --namespace default -o json

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
	var firstErr error

	handler := func(msg *natsgo.Msg) {
		view, ok := unwrap(msg)
		if !ok {
			return
		}
		if !eventbus.MatchesAgent(f.Agent, view.AgentName) {
			return
		}
		if err := writeEvent(w, format, view); err != nil {
			if firstErr == nil {
				firstErr = err
			}
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
	return firstErr
}

func unwrap(msg *natsgo.Msg) (*EventView, bool) {
	var ev pb.PanoptiumEvent
	if err := proto.Unmarshal(msg.Data, &ev); err != nil {
		return nil, false
	}
	view := &EventView{
		ID:          ev.GetId(),
		Category:    ev.GetCategory(),
		Subcategory: ev.GetSubcategory(),
		Severity:    ev.GetSeverity().String(),
		Subject:     msg.Subject,
	}
	if ts := ev.GetTimestamp(); ts != nil {
		view.Timestamp = ts.AsTime().UTC().Format(time.RFC3339Nano)
	}
	if a := ev.GetAgent(); a != nil {
		view.Namespace = a.GetNamespace()
		view.PodName = a.GetPodName()
		view.AgentName = a.GetPodName()
	}
	return view, true
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
