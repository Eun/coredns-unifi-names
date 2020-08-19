package unifinames

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"regexp"

	"strings"

	"time"

	"crypto/x509"

	"crypto/sha1"

	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

type unifinames struct {
	Next        plugin.Handler
	Config      *config
	aClients    []*dns.A
	aaaaClients []*dns.AAAA
	nextUpdate  time.Time
	mu          sync.Mutex
}

// ServeDNS implements the middleware.Handler interface.
func (p *unifinames) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if p.resolve(w, r) {
		return dns.RcodeSuccess, nil
	}
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (*unifinames) Name() string { return "unifi-names" }

func (p *unifinames) resolve(w dns.ResponseWriter, r *dns.Msg) bool {
	if len(r.Question) <= 0 {
		return false
	}

	var rrs []dns.RR

	for i := 0; i < len(r.Question); i++ {
		question := r.Question[i]
		if question.Qclass != dns.ClassINET {
			continue
		}

		switch question.Qtype {
		case dns.TypeA:
			name := strings.ToLower(question.Name)
			if p.shouldHandle(name) {
				p.getClientsIfNeeded()
			}
			p.mu.Lock()
			for _, client := range p.aClients {
				if strings.EqualFold(client.Hdr.Name, question.Name) {
					rrs = append(rrs, client)
					break
				}
			}
			p.mu.Unlock()
		case dns.TypeAAAA:
			name := strings.ToLower(question.Name)
			if p.shouldHandle(name) {
				p.getClientsIfNeeded()
			}
			p.mu.Lock()
			for _, client := range p.aaaaClients {
				if strings.EqualFold(client.Hdr.Name, question.Name) {
					rrs = append(rrs, client)
					break
				}
			}
			p.mu.Unlock()
		}
	}

	if len(rrs) > 0 {
		if p.Config.Debug {
			log.Printf("[unifi-names] Answering with %d rr's\n", len(rrs))
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = rrs
		w.WriteMsg(m)
		return true
	}
	return false
}

func (p *unifinames) shouldHandle(name string) bool {
	for _, domain := range p.Config.Networks {
		if strings.HasSuffix(name, domain) {
			return true
		}
	}
	return false
}

func (p *unifinames) getClientsIfNeeded() {
	if p.nextUpdate.Before(time.Now()) {
		p.mu.Lock()
		if p.Config.Debug {
			log.Println("[unifi-names] updating clients")
		}
		if err := p.getClients(context.Background()); err != nil {
			p.mu.Unlock()
			log.Printf("[unifi-names] unable to get clients: %v\n", err)
			return
		}
		p.mu.Unlock()
		log.Printf("[unifi-names] got %d hosts", len(p.aClients)+len(p.aaaaClients))
		p.nextUpdate = time.Now().Add(time.Duration(p.Config.TTL) * time.Second)
	}
}

var reSetCookieToken = regexp.MustCompile(`unifises=([0-9a-zA-Z]+)`)

func (p *unifinames) getClients(ctx context.Context) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: len(p.Config.UnifiSSLFingerprint) > 0,
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if p.Config.UnifiSSLFingerprint == nil {
						return errors.New("should never happen")
					}
					if len(rawCerts) == 0 {
						return errors.New("no certificate present")
					}
					hash := sha1.Sum(rawCerts[0])
					if !bytes.Equal(hash[:], p.Config.UnifiSSLFingerprint) {
						return fmt.Errorf("ssl fingerprint mismatch: expected %x got %x", p.Config.UnifiSSLFingerprint, hash)
					}
					return nil
				},
			},
		},
		Jar:     jar,
		Timeout: time.Minute,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(map[string]string{
		"username": p.Config.UnifiUsername,
		"password": p.Config.UnifiPassword,
	}); err != nil {
		return fmt.Errorf("unable to encode payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Config.UnifiControllerURL+"/api/login", &buf)
	if err != nil {
		return fmt.Errorf("unable to create login request: %w", err)
	}

	req.Header.Set("Referer", p.Config.UnifiControllerURL+"/login")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform login request: %w", err)
	}

	if res.Body != nil {
		if err = res.Body.Close(); err != nil {
			return fmt.Errorf("unable to close login body: %w", err)
		}
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed: expected status 200 got %d", res.StatusCode)
	}

	matches := reSetCookieToken.FindStringSubmatch(res.Header.Get("Set-Cookie"))
	if len(matches) != 2 {
		return fmt.Errorf("login failed: invalid or no cookie")
	}

	// get clients

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, p.Config.UnifiControllerURL+"/api/s/"+p.Config.UnifiSite+"/stat/sta", nil)
	if err != nil {
		return fmt.Errorf("unable to create list clients request: %w", err)
	}

	res, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform list clients request: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		if err = res.Body.Close(); err != nil {
			return fmt.Errorf("unable to close logout body: %w", err)
		}
		return fmt.Errorf("unable to list clients: expected status 200 got %d", res.StatusCode)
	}

	var data struct {
		Data []struct {
			Name    string
			Network string
			IP      string
		}
	}

	if err = json.NewDecoder(res.Body).Decode(&data); err != nil {
		return fmt.Errorf("unable to decode list clients: %w", err)
	}

	if res.Body != nil {
		if err = res.Body.Close(); err != nil {
			return fmt.Errorf("unable to close logout body: %w", err)
		}
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPost, p.Config.UnifiControllerURL+"/logout", nil)
	if err != nil {
		return fmt.Errorf("unable to create logout request: %w", err)
	}

	res, err = client.Do(req)
	if err != nil {
		return fmt.Errorf("unable to perform logout request: %w", err)
	}

	if res.Body != nil {
		if err = res.Body.Close(); err != nil {
			return fmt.Errorf("unable to close logout body: %w", err)
		}
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unable to logout: expected status 200 got %d", res.StatusCode)
	}

	p.aClients = nil
	p.aaaaClients = nil

	for _, entry := range data.Data {
		entry.Name = sanitizeName(entry.Name)
		if entry.Name == "" {
			continue
		}
		ip := net.ParseIP(entry.IP)
		if ip == nil {
			continue
		}

		domain, ok := p.Config.Networks[strings.ToLower(entry.Network)]
		if !ok {
			continue
		}

		hdr := dns.RR_Header{
			Name:     entry.Name + "." + domain,
			Rrtype:   0,
			Class:    dns.ClassINET,
			Ttl:      0,
			Rdlength: 0,
		}

		if ip.To4() != nil {
			hdr.Rrtype = dns.TypeA
			p.aClients = append(p.aClients, &dns.A{
				Hdr: hdr,
				A:   ip,
			})
		} else {
			hdr.Rrtype = dns.TypeAAAA
			p.aaaaClients = append(p.aaaaClients, &dns.AAAA{
				Hdr:  hdr,
				AAAA: ip,
			})
		}
	}

	return nil
}

func isAllowedRune(allowedRunes []rune, r rune) bool {
	for _, a := range allowedRunes {
		if a == r {
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	var allowedRunes = []rune("abcdefghijklmnopqrstuvwxyz12345679-")
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)

	var sb strings.Builder
	r := []rune(s)
	size := len(r)
	for i := 0; i < size; i++ {
		if isAllowedRune(allowedRunes, r[i]) {
			sb.WriteRune(r[i])
		} else {
			sb.WriteRune('-')
		}
	}

	// remove --
	return strings.Join(strings.FieldsFunc(sb.String(), func(r rune) bool {
		return r == '-'
	}), "-")
}
