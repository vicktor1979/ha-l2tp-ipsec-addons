// This small adapter embeds veepin's L2TP library. It NEVER applies addresses,
// routes or DNS. The Python parent applies a /32 route in the container only.
// Credentials arrive over a private stdin pipe, not argv or environment.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xen0bit/veepin/client"
	"github.com/xen0bit/veepin/l2tp"
)

const version = "c6-vpn-engine 0.2.0; veepin v0.9.6; commit 6c37e3691c326e54956cea042e2df67d3717e7a4"
const tunName = "c6vpn0"

type event struct {
	Event     string `json:"event"`
	Interface string `json:"interface,omitempty"`
	Address   string `json:"address,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	Message   string `json:"message,omitempty"`
	Auth      bool   `json:"auth,omitempty"`
}

func run() int {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(version)
		return 0
	}
	emit := func(e event) { _ = json.NewEncoder(os.Stdout).Encode(e) }
	c, err := readCredentials(os.Stdin)
	if err != nil {
		emit(event{Event: "error", Message: err.Error()})
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	emit(event{Event: "connecting"})
	sess, res, err := l2tp.Dial(ctx, l2tp.Config{
		Server: c.Server, PSK: c.PSK, Username: c.Username, Password: c.Password,
		TUNName: tunName, Logger: logger,
	})
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		emit(event{Event: "error", Message: err.Error(), Auth: errors.Is(err, client.ErrAuth)})
		return 1
	}
	defer sess.Close()
	if res.TUNName != tunName || res.AssignedIP == nil || res.AssignedIP.To4() == nil {
		emit(event{Event: "error", Message: "unexpected TUN or missing IPv4 address"})
		return 1
	}
	emit(event{Event: "vpn_up", Interface: res.TUNName, Address: res.AssignedIP.String(), MTU: res.MTU})
	done := make(chan error, 1)
	go func() { done <- sess.Wait(ctx) }()
	// Optional public capability: no dependency on a version-specific type name.
	prober, canProbe := sess.(interface{ Probe(context.Context) error })
	if !canProbe {
		emit(event{Event: "warning", Message: "This engine has no active liveness probe; watch the TCP link."})
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case err := <-done:
			if ctx.Err() != nil {
				return 0
			}
			message := "VPN session ended"
			if err != nil {
				message = err.Error()
			}
			emit(event{Event: "error", Message: message, Auth: errors.Is(err, client.ErrAuth)})
			return 1
		case <-ticker.C:
			if !canProbe {
				continue
			}
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := prober.Probe(pctx)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return 0
				}
				emit(event{Event: "error", Message: "L2TP liveness probe failed: " + err.Error()})
				return 1
			}
		}
	}
}
func main() { os.Exit(run()) }
