package unifinames

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/caddyserver/caddy"
)

func init() {
	caddy.RegisterPlugin("unifi-names", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	c.Next()
	config, err := newConfigFromDispenser(c.Dispenser)
	if err != nil {
		return plugin.Error("unifi-names", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return &unifinames{Next: next, Config: config}
	})

	return nil
}
