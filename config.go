package unifinames

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"encoding/hex"

	"github.com/asaskevich/govalidator"
	"github.com/caddyserver/caddy/caddyfile"
)

type config struct {
	// Networks maps the network to the specified domain
	// e.g.
	// "LAN" => local
	// so if a client has the name "Joe's Notebook" and it is in the "LAN" network it will get
	// "joe-s-notebook.local" as a hostname
	Networks map[string]string
	// TTL to use for response (this is also the refresh rate of the client mapping) (defaults to 1hour)
	TTL uint32
	// Debug mode
	Debug bool
	// UnifiControllerURL in the form of http://localhost:8443
	UnifiControllerURL string
	// UnifiSite which site to use (most of the cases its default)
	UnifiSite string
	// UnifiUsername
	UnifiUsername string
	// UnifiPassword
	UnifiPassword string
	// UnifiSSLFingerprint is the ssl certificate fingerprint we expect
	UnifiSSLFingerprint []byte
}

func newConfigFromDispenser(c caddyfile.Dispenser) (*config, error) {
	config := config{
		TTL:      60 * 60,
		Networks: map[string]string{},
	}

	for c.NextBlock() {
		if strings.EqualFold(c.Val(), "network") {
			if c.NextArg() {
				network := strings.ToLower(c.Val())
				if c.NextArg() {
					domain := strings.ToLower(strings.Trim(c.Val(), "."))
					if !govalidator.IsDNSName(domain) {
						return nil, fmt.Errorf("'%s' is not a valid domain name", domain)
					}
					domain = domain + "."
					config.Networks[network] = domain
				}
			}
		} else if strings.EqualFold(c.Val(), "ttl") {
			if c.NextArg() {
				ttl, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return nil, fmt.Errorf("Invalid TTL value: '%s'", c.Val())
				}
				config.TTL = uint32(ttl)
			}
		} else if strings.EqualFold(c.Val(), "debug") {
			config.Debug = true
		} else if strings.EqualFold(c.Val(), "unifi") {
			if c.NextArg() {
				config.UnifiControllerURL = strings.TrimRight(c.Val(), "/")
				if c.NextArg() {
					config.UnifiSite = c.Val()
					if c.NextArg() {
						config.UnifiUsername = c.Val()
						if c.NextArg() {
							config.UnifiPassword = c.Val()
							if c.NextArg() {
								var err error
								config.UnifiSSLFingerprint, err = hex.DecodeString(strings.ReplaceAll(c.Val(), ":", ""))
								if err != nil {
									return nil, fmt.Errorf("unable to parse UnifiSSLFingerprint")
								}
							}
						}
					}
				}
			}
		}
	}
	if config.Debug {
		log.Println("[unifi-names] Debug Mode is on")
		log.Printf("[unifi-names] Parsed %d Networks\n", len(config.Networks))
		log.Printf("[unifi-names] TTL is %d", config.TTL)
		log.Printf("[unifi-names] Controller URL is `%s'", config.UnifiControllerURL)
		log.Printf("[unifi-names] Controller SSL fingerprint is `%x'", config.UnifiSSLFingerprint)
	}
	if len(config.Networks) <= 0 {
		return nil, fmt.Errorf("There are no networks to handle")
	}
	if config.UnifiControllerURL == "" {
		return nil, fmt.Errorf("No controller url set")
	}
	if config.UnifiSite == "" {
		return nil, fmt.Errorf("No controller site set")
	}
	if config.UnifiUsername == "" {
		return nil, fmt.Errorf("No controller username set")
	}
	if config.UnifiPassword == "" {
		return nil, fmt.Errorf("No controller password set")
	}
	return &config, nil
}
