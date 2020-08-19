package unifinames

import (
	"testing"

	"bytes"

	"github.com/caddyserver/caddy/caddyfile"
	"github.com/stretchr/testify/require"
)

func TestNewConfigFromDispenser(t *testing.T) {
	t.Run("Valid Config", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
				Network LAN example1.com
				Network VLAN1 example2.com
				Network VLAN2 example3.com
				Unifi https://localhost:8443/ default admin test deadbeef
				TTL 60
				Debug
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.NoError(t, err)
		require.NotNil(t, config)
		require.Equal(t, map[string]string{
			"lan":   "example1.com.",
			"vlan1": "example2.com.",
			"vlan2": "example3.com.",
		}, config.Networks)
		require.Equal(t, uint32(60), config.TTL)
		require.Equal(t, true, config.Debug)
		require.Equal(t, "https://localhost:8443", config.UnifiControllerURL)
		require.Equal(t, "default", config.UnifiSite)
		require.Equal(t, "admin", config.UnifiUsername)
		require.Equal(t, "test", config.UnifiPassword)
		require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, config.UnifiSSLFingerprint)
	})
	t.Run("Emtpy Config", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.Error(t, err)
		require.Nil(t, config)

		dispenser = caddyfile.NewDispenser("", bytes.NewReader([]byte(``)))
		config, err = newConfigFromDispenser(dispenser)
		require.Error(t, err)
		require.Nil(t, config)
	})

	t.Run("Default Values", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
				Network LAN example1.com
				Unifi https://localhost:8443/ default admin test deadbeef
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.NoError(t, err)
		require.NotNil(t, config)
		require.Equal(t, map[string]string{
			"lan": "example1.com.",
		}, config.Networks)
		require.Equal(t, uint32(60*60), config.TTL)
		require.Equal(t, false, config.Debug)
		require.Equal(t, "https://localhost:8443", config.UnifiControllerURL)
		require.Equal(t, "default", config.UnifiSite)
		require.Equal(t, "admin", config.UnifiUsername)
		require.Equal(t, "test", config.UnifiPassword)
		require.Equal(t, []byte{0xde, 0xad, 0xbe, 0xef}, config.UnifiSSLFingerprint)
	})
	t.Run("Invalid Network", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
				Network LAN 127.0.0.1
				Unifi https://localhost:8443/ default admin test deadbeef
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.Error(t, err)
		require.Nil(t, config)
	})
	t.Run("Missing Unifi", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
				Network LAN example1.com
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.Error(t, err)
		require.Nil(t, config)
	})
	t.Run("Invalid TTL", func(t *testing.T) {
		dispenser := caddyfile.NewDispenser("", bytes.NewReader([]byte(`
			{
				Network LAN example.com
				Unifi https://localhost:8443/ default admin test deadbeef
				TTL SixtySeconds
			}
		`)))
		config, err := newConfigFromDispenser(dispenser)
		require.Error(t, err)
		require.Nil(t, config)
	})
}
