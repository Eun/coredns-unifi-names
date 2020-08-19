package unifinames

import (
	"context"
	"net"
	"testing"

	"net/http"
	"net/http/httptest"

	"fmt"

	"crypto/sha1"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dummyResponseWriter struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	msgs       []*dns.Msg
	bytes      []byte
}

func (d *dummyResponseWriter) LocalAddr() net.Addr  { return d.localAddr }
func (d *dummyResponseWriter) RemoteAddr() net.Addr { return d.remoteAddr }
func (d *dummyResponseWriter) WriteMsg(m *dns.Msg) error {
	d.msgs = append(d.msgs, m)
	return nil
}
func (d *dummyResponseWriter) Write(b []byte) (int, error) {
	d.bytes = append(d.bytes, b...)
	return len(b), nil
}
func (*dummyResponseWriter) Close() error        { return nil }
func (*dummyResponseWriter) TsigStatus() error   { return nil }
func (*dummyResponseWriter) TsigTimersOnly(bool) {}
func (*dummyResponseWriter) Hijack()             {}

func (d *dummyResponseWriter) GetMsgs() []*dns.Msg { return d.msgs }
func (d *dummyResponseWriter) ClearMsgs()          { d.msgs = nil }

func (d *dummyResponseWriter) GetBytes() []byte { return d.bytes }
func (d *dummyResponseWriter) ClearBytes()      { d.bytes = nil }

func MockUnifiController(fingerprint *[]byte, lan, name, ip string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "unifises=deadbeef")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/s/default/stat/sta", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  "data": [
    {
      "_id": "eeeeeeeeeeeeeeeeeeeeeeee",
      "_is_guest_by_uap": false,
      "_is_guest_by_ugw": false,
      "_last_seen_by_uap": 1597826986,
      "_last_seen_by_ugw": 1597827010,
      "_uptime_by_uap": 83484,
      "_uptime_by_ugw": 117,
      "anomalies": 0,
      "ap_mac": "aa:bb:cc:dd:ee:ff",
      "assoc_time": 1597743501,
      "authorized": true,
      "bssid": "aa:bb:cc:dd:ee:ff",
      "bytes-r": 124,
      "ccq": 333,
      "channel": 44,
      "dhcpend_time": 3800,
      "essid": "PublicWifi",
      "first_seen": 1582216621,
      "gw_mac": "aa:bb:cc:dd:ee:ff",
      "hostname": "debian",
      "idletime": 16,
      "ip": "%s",
      "is_11r": false,
      "is_guest": false,
      "is_wired": false,
      "last_seen": 1597826986,
      "latest_assoc_time": 1597826893,
      "mac": "aa:bb:cc:dd:ee:ff",
      "name": "%s",
      "network": "%s",
      "network_id": "eeeeeeeeeeeeeeeeeeeeeeee",
      "noise": -105,
      "noted": true,
      "oui": "SamsungE",
      "powersave_enabled": false,
      "qos_policy_applied": true,
      "radio": "na",
      "radio_name": "wifi0",
      "radio_proto": "ac",
      "rssi": 40,
      "rx_bytes": 3044215,
      "rx_bytes-r": 63,
      "rx_packets": 53177,
      "rx_rate": 200000,
      "satisfaction": 99,
      "signal": -56,
      "site_id": "eeeeeeeeeeeeeeeeeeeeeeee",
      "tx_bytes": 5154655,
      "tx_bytes-r": 61,
      "tx_packets": 25684,
      "tx_power": 38,
      "tx_rate": 200000,
      "tx_retries": 229,
      "uptime": 83485,
      "user_id": "eeeeeeeeeeeeeeeeeeeeeeee",
      "usergroup_id": "",
      "vlan": 0,
      "wifi_tx_attempts": 25915
    }
  ],
  "meta": {
    "rc": "ok"
  }
}`, ip, name, lan)
	})

	s := httptest.NewTLSServer(mux)
	if len(s.TLS.Certificates) != 1 {
		panic("expected 1 certificate")
	}
	if len(s.TLS.Certificates[0].Certificate) != 1 {
		panic("expected 1 certificate")
	}
	if fingerprint != nil {
		hash := sha1.Sum(s.TLS.Certificates[0].Certificate[0])
		*fingerprint = hash[:]
	}

	return s
}

func TestServeDNS(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		var fp []byte
		s := MockUnifiController(&fp, "lan", "server1", "127.0.0.1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server1.lan.",
					Qclass: dns.ClassINET,
					Qtype:  dns.TypeA,
				},
			},
		})
		require.Equal(t, 1, len(d.GetMsgs()))
		require.Equal(t, 1, len(d.GetMsgs()[0].Answer))
		require.Equal(t, dns.Class(dns.ClassINET), dns.Class(d.GetMsgs()[0].Answer[0].Header().Class))
		require.Equal(t, dns.Type(dns.TypeA), dns.Type(d.GetMsgs()[0].Answer[0].Header().Rrtype))
		require.Equal(t, "server1.lan.", d.GetMsgs()[0].Answer[0].Header().Name)
		require.Equal(t, net.ParseIP("127.0.0.1"), d.GetMsgs()[0].Answer[0].(*dns.A).A)
	})

	t.Run("AAAA", func(t *testing.T) {
		var fp []byte
		s := MockUnifiController(&fp, "lan", "server1", "::1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server1.lan.",
					Qclass: dns.ClassINET,
					Qtype:  dns.TypeAAAA,
				},
			},
		})
		require.Equal(t, 1, len(d.GetMsgs()))
		require.Equal(t, 1, len(d.GetMsgs()[0].Answer))
		require.Equal(t, dns.Class(dns.ClassINET), dns.Class(d.GetMsgs()[0].Answer[0].Header().Class))
		require.Equal(t, dns.Type(dns.TypeAAAA), dns.Type(d.GetMsgs()[0].Answer[0].Header().Rrtype))
		require.Equal(t, "server1.lan.", d.GetMsgs()[0].Answer[0].Header().Name)
		require.Equal(t, net.ParseIP("::1"), d.GetMsgs()[0].Answer[0].(*dns.AAAA).AAAA)
	})

	t.Run("Unknown Client", func(t *testing.T) {
		var fp []byte
		s := MockUnifiController(&fp, "lan", "server1", "127.0.0.1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server2.lan.",
					Qclass: dns.ClassINET,
					Qtype:  dns.TypeA,
				},
			},
		})
		require.Equal(t, 0, len(d.GetMsgs()))
	})

	t.Run("No Questions", func(t *testing.T) {
		var fp []byte
		s := MockUnifiController(&fp, "lan", "server1", "127.0.0.1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{})
		require.Equal(t, 0, len(d.GetMsgs()))
	})

	t.Run("Invalid Class", func(t *testing.T) {
		var fp []byte
		s := MockUnifiController(&fp, "lan", "server1", "127.0.0.1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server1.lan.",
					Qclass: dns.ClassANY,
					Qtype:  dns.TypeA,
				},
			},
		})
		require.Equal(t, 0, len(d.GetMsgs()))
	})

	t.Run("invalid unifi fingerprint", func(t *testing.T) {
		s := MockUnifiController(nil, "lan", "server1", "127.0.0.1")
		fp := []byte{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		}
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: fp,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server1.lan.",
					Qclass: dns.ClassINET,
					Qtype:  dns.TypeA,
				},
			},
		})
		require.Equal(t, 0, len(d.GetMsgs()))
	})

	t.Run("no fingerprint", func(t *testing.T) {
		s := MockUnifiController(nil, "lan", "server1", "127.0.0.1")
		defer s.Close()
		p := unifinames{
			Config: &config{
				Networks: map[string]string{
					"lan": "lan.",
				},
				TTL:                 60 * 60,
				Debug:               true,
				UnifiControllerURL:  s.URL,
				UnifiSite:           "default",
				UnifiUsername:       "admin",
				UnifiPassword:       "admin",
				UnifiSSLFingerprint: nil,
			},
		}
		d := &dummyResponseWriter{}
		p.ServeDNS(context.Background(), d, &dns.Msg{
			Question: []dns.Question{
				{
					Name:   "server1.lan.",
					Qclass: dns.ClassINET,
					Qtype:  dns.TypeA,
				},
			},
		})
		require.Equal(t, 0, len(d.GetMsgs()))
	})
}
