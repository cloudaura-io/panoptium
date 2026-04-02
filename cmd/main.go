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

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	panoptiumiov1alpha1 "github.com/panoptium/panoptium/api/v1alpha1"
	"github.com/panoptium/panoptium/internal/controller"
	panoptiumwebhook "github.com/panoptium/panoptium/internal/webhook"
	"github.com/panoptium/panoptium/pkg/escalation"
	natsbus "github.com/panoptium/panoptium/pkg/eventbus/nats"
	"github.com/panoptium/panoptium/pkg/extproc"
	"github.com/panoptium/panoptium/pkg/identity"
	"github.com/panoptium/panoptium/pkg/observer"
	"github.com/panoptium/panoptium/pkg/observer/llm"
	"github.com/panoptium/panoptium/pkg/policy"
	"github.com/panoptium/panoptium/pkg/policy/predicate"
	"github.com/panoptium/panoptium/pkg/threat"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(panoptiumiov1alpha1.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var extprocPort int
	var extprocEnabled bool
	var enforcementMode string
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.IntVar(&extprocPort, "extproc-port", 9001,
		"The port the ExtProc gRPC server listens on for AgentGateway connections.")
	flag.BoolVar(&extprocEnabled, "extproc-enabled", true,
		"Enable the ExtProc gRPC server for LLM traffic observation.")
	flag.StringVar(&enforcementMode, "enforcement-mode", "enforcing",
		"Policy enforcement mode: 'enforcing' (deny/throttle active) or 'audit' (log only).")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.1/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization

		// TODO(user): If CertDir, CertName, and KeyName are not specified, controller-runtime will automatically
		// generate self-signed certificates for the metrics server. While convenient for development and testing,
		// this setup is not recommended for production.
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "e1d5f969.panoptium.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Set up the policy engine: compiler, cache, resolver, evaluator adapter
	policyCompiler := policy.NewPolicyCompiler()
	policyCache := policy.NewPolicyCache(policyCompiler)
	rateLimitCounter := predicate.NewSlidingWindowCounter(60 * time.Second)
	policyResolver := policy.NewPolicyCompositionResolverWithRateLimit(rateLimitCounter)
	policyEvaluator := policy.NewEvaluatorAdapter(policyCache, policyResolver)
	setupLog.Info("policy engine initialized",
		"enforcementMode", enforcementMode)

	// Set up controllers
	if err := (&controller.PanoptiumPolicyReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorderFor("panoptiumpolicy-controller"),
		PolicyCache: policyCache,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PanoptiumPolicy")
		os.Exit(1)
	}

	if err := (&controller.ClusterPanoptiumPolicyReconciler{
		Client:      mgr.GetClient(),
		Scheme:      mgr.GetScheme(),
		Recorder:    mgr.GetEventRecorderFor("clusterpanoptiumpolicy-controller"),
		PolicyCache: policyCache,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ClusterPanoptiumPolicy")
		os.Exit(1)
	}

	if err := (&controller.PanoptiumAgentProfileReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("panoptiumagentprofile-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PanoptiumAgentProfile")
		os.Exit(1)
	}

	threatRegistry := threat.NewCompiledSignatureRegistry()
	if err := (&controller.PanoptiumThreatSignatureReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("panoptiumthreatsignature-controller"),
		Registry: threatRegistry,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PanoptiumThreatSignature")
		os.Exit(1)
	}

	if err := (&controller.PanoptiumQuarantineReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("panoptiumquarantine-controller"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PanoptiumQuarantine")
		os.Exit(1)
	}

	// Set up webhooks
	if err := (&panoptiumwebhook.PanoptiumPolicyValidator{}).SetupWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "PanoptiumPolicy")
		os.Exit(1)
	}


	// +kubebuilder:scaffold:builder

	// Set up the embedded NATS server for the event bus
	natsSrv, err := natsbus.NewServer(natsbus.ServerConfig{
		StoreDir: "", // empty uses os.MkdirTemp; /var/lib is not writable in distroless
	})
	if err != nil {
		setupLog.Error(err, "unable to create embedded NATS server")
		os.Exit(1)
	}
	if err := natsSrv.Start(); err != nil {
		setupLog.Error(err, "unable to start embedded NATS server")
		os.Exit(1)
	}
	defer natsSrv.Shutdown()
	setupLog.Info("embedded NATS server started", "url", natsSrv.ClientURL())

	// Set up shared components for the ExtProc observer pipeline
	bus, err := natsbus.NewNATSBus(natsSrv.ClientURL())
	if err != nil {
		setupLog.Error(err, "unable to create NATS event bus")
		os.Exit(1)
	}
	defer bus.Close()

	registry := observer.NewObserverRegistry()

	// Register the LLM observer (OpenAI + Anthropic)
	llmObs := llm.NewLLMObserver(bus)
	if err := registry.Register(llmObs, observer.ObserverConfig{
		Name:      "llm",
		Priority:  100,
		Protocol:  "llm",
		Providers: []string{"openai", "anthropic"},
	}); err != nil {
		setupLog.Error(err, "unable to register LLM observer")
		os.Exit(1)
	}

	// Set up the pod IP cache and Informer for agent identity resolution
	podCache := identity.NewPodCache()
	clientset, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create Kubernetes clientset for pod cache")
		os.Exit(1)
	}
	podCacheInformer := identity.NewPodCacheInformer(clientset, podCache)
	resolver := identity.NewResolver(podCache)

	// Configure and add the ExtProc lifecycle manager as a Runnable
	extprocCfg := extproc.LifecycleConfig{
		Port:            extprocPort,
		Enabled:         extprocEnabled,
		EnforcementMode: enforcementMode,
	}
	extprocMgr := extproc.NewLifecycleManager(extprocCfg, registry, resolver, bus)
	extprocMgr.SetPodCacheInformer(podCacheInformer)
	extprocMgr.SetPolicyEvaluator(policyEvaluator)

	if err := mgr.Add(extprocMgr); err != nil {
		setupLog.Error(err, "unable to add ExtProc lifecycle manager")
		os.Exit(1)
	}

	// Set up the escalation manager to watch for repeated deny decisions
	// and create PanoptiumQuarantine CRDs when thresholds are reached.
	escalationMgr := escalation.NewEscalationManager(bus, mgr.GetClient())
	if err := mgr.Add(escalationMgr); err != nil {
		setupLog.Error(err, "unable to add escalation manager")
		os.Exit(1)
	}
	setupLog.Info("escalation manager registered")

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
