// Package proxy implements the transparent HTTP+HTTPS proxy with approval gates
// and TLS MITM inspection for HTTPS traffic.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/olljanat-ai/firewall4ai/internal/approval"
	"github.com/olljanat-ai/firewall4ai/internal/auth"
	"github.com/olljanat-ai/firewall4ai/internal/certgen"
	"github.com/olljanat-ai/firewall4ai/internal/credentials"
	proxylog "github.com/olljanat-ai/firewall4ai/internal/logging"
)

const (
	approvalTimeout = 5 * time.Minute
	// AuthHeader is used by AI agents to provide their skill token.
	AuthHeader = "X-Firewall4AI-Token"
)

// Proxy is the main proxy server.
type Proxy struct {
	Skills          *auth.SkillStore
	Approvals       *approval.Manager
	Credentials     *credentials.Manager
	Logger          *proxylog.Logger
	Transport       http.RoundTripper
	CA              *certgen.CA
	ApprovalTimeout time.Duration
}

// New creates a new Proxy with the given dependencies.
func New(skills *auth.SkillStore, approvals *approval.Manager, creds *credentials.Manager, logger *proxylog.Logger) *Proxy {
	return &Proxy{
		Skills:          skills,
		Approvals:       approvals,
		Credentials:     creds,
		Logger:          logger,
		ApprovalTimeout: approvalTimeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
}

// ServeHTTP handles both HTTP requests and HTTPS CONNECT tunnels.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

// extractHost returns the host (without port) from the request.
func extractHost(r *http.Request) string {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// authenticate extracts and validates the skill token.
func (p *Proxy) authenticate(r *http.Request) (*auth.Skill, error) {
	token := r.Header.Get(AuthHeader)
	if token == "" {
		return nil, fmt.Errorf("missing %s header", AuthHeader)
	}
	skill, ok := p.Skills.Authenticate(token)
	if !ok {
		return nil, fmt.Errorf("invalid or inactive token")
	}
	return skill, nil
}

// checkApproval verifies the host is approved for this skill.
func (p *Proxy) checkApproval(host string, skill *auth.Skill) approval.Status {
	// Check if host is pre-approved in skill config.
	if p.Skills.IsHostPreApproved(skill.Token, host) {
		return approval.StatusApproved
	}

	status := p.Approvals.Check(host, skill.ID)
	if status == approval.StatusPending {
		// Block and wait for admin decision.
		status = p.Approvals.WaitForDecision(host, skill.ID, p.ApprovalTimeout)
	}
	return status
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := extractHost(r)

	skill, err := p.authenticate(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: r.Method,
			Host:   host,
			Path:   r.URL.Path,
			Status: "denied",
			Detail: "auth failed: " + err.Error(),
		})
		http.Error(w, "Proxy authentication failed: "+err.Error(), http.StatusProxyAuthRequired)
		return
	}

	// Remove our custom header before forwarding.
	r.Header.Del(AuthHeader)

	status := p.checkApproval(host, skill)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  r.Method,
			Host:    host,
			Path:    r.URL.Path,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("Access to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}

	// Inject credentials.
	p.Credentials.InjectForRequest(r, skill.ID)

	// Forward the request.
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	resp, err := p.Transport.RoundTrip(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  skill.ID,
			Method:   r.Method,
			Host:     host,
			Path:     r.URL.Path,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		http.Error(w, "Proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   r.Method,
		Host:     host,
		Path:     r.URL.Path,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(start).Milliseconds(),
	})

	// Copy response headers.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	targetHost := r.Host
	host := targetHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	skill, err := p.authenticate(r)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			Method: "CONNECT",
			Host:   host,
			Status: "denied",
			Detail: "auth failed: " + err.Error(),
		})
		http.Error(w, "Proxy authentication failed: "+err.Error(), http.StatusProxyAuthRequired)
		return
	}

	status := p.checkApproval(host, skill)
	if status != approval.StatusApproved {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  "CONNECT",
			Host:    host,
			Status:  string(status),
			Detail:  "host not approved",
		})
		http.Error(w, fmt.Sprintf("CONNECT to %s is %s. Awaiting admin approval.", host, status), http.StatusForbidden)
		return
	}

	// Hijack the client connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send 200 OK to tell the client the tunnel is established.
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// If we have a CA, perform TLS MITM inspection.
	if p.CA != nil {
		p.handleMITM(clientConn, host, targetHost, skill, start)
		return
	}

	// Fallback: blind tunnel (no inspection).
	p.handleBlindTunnel(clientConn, host, targetHost, skill, start)
}

// handleMITM performs TLS MITM: terminates the client TLS with a generated cert,
// reads the inner HTTP requests, applies auth/approval/credential injection,
// and forwards them to the real target over a new TLS connection.
func (p *Proxy) handleMITM(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, start time.Time) {
	defer clientConn.Close()

	// Present a CA-signed certificate for this host to the client.
	// We create a custom GetCertificate that falls back to the known host
	// when the client doesn't send SNI (e.g. connecting by IP address).
	hostCert, err := p.CA.GenerateHostCert(host)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  "CONNECT",
			Host:    host,
			Status:  "error",
			Detail:  "generate host cert: " + err.Error(),
		})
		return
	}
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if info.ServerName != "" && info.ServerName != host {
				return p.CA.GenerateHostCert(info.ServerName)
			}
			return hostCert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID: skill.ID,
			Method:  "CONNECT",
			Host:    host,
			Status:  "error",
			Detail:  "MITM TLS handshake failed: " + err.Error(),
		})
		return
	}
	defer tlsClientConn.Close()

	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   "CONNECT",
		Host:     host,
		Status:   "allowed",
		Detail:   "TLS MITM tunnel established",
		Duration: time.Since(start).Milliseconds(),
	})

	// Read HTTP requests from the decrypted client connection.
	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				p.Logger.Add(proxylog.Entry{
					SkillID: skill.ID,
					Method:  "CONNECT",
					Host:    host,
					Status:  "error",
					Detail:  "read request: " + err.Error(),
				})
			}
			return
		}

		p.handleMITMRequest(tlsClientConn, req, host, targetAddr, skill)
	}
}

// handleMITMRequest processes a single HTTP request read from the MITM'd TLS connection.
func (p *Proxy) handleMITMRequest(clientConn net.Conn, req *http.Request, host, targetAddr string, skill *auth.Skill) {
	start := time.Now()

	// Remove proxy auth header if client re-sent it inside the tunnel.
	req.Header.Del(AuthHeader)

	// Set the URL for forwarding.
	req.URL.Scheme = "https"
	req.URL.Host = targetAddr
	if !strings.Contains(targetAddr, ":") {
		req.URL.Host = targetAddr + ":443"
	}
	req.RequestURI = ""

	// Inject credentials for HTTPS requests.
	p.Credentials.InjectForRequest(req, skill.ID)

	resp, err := p.Transport.RoundTrip(req)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  skill.ID,
			Method:   req.Method,
			Host:     host,
			Path:     req.URL.Path,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		// Send a 502 response to the client.
		resp502 := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     make(http.Header),
		}
		resp502.Write(clientConn)
		return
	}
	defer resp.Body.Close()

	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   req.Method,
		Host:     host,
		Path:     req.URL.Path,
		Status:   "allowed",
		Detail:   fmt.Sprintf("%d %s", resp.StatusCode, resp.Status),
		Duration: time.Since(start).Milliseconds(),
	})

	// Write response back to client.
	resp.Write(clientConn)
}

// handleBlindTunnel is the fallback when no CA is configured: just pipe bytes.
func (p *Proxy) handleBlindTunnel(clientConn net.Conn, host, targetAddr string, skill *auth.Skill, start time.Time) {
	if !strings.Contains(targetAddr, ":") {
		targetAddr += ":443"
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		p.Logger.Add(proxylog.Entry{
			SkillID:  skill.ID,
			Method:   "CONNECT",
			Host:     host,
			Status:   "error",
			Detail:   err.Error(),
			Duration: time.Since(start).Milliseconds(),
		})
		clientConn.Close()
		return
	}

	p.Logger.Add(proxylog.Entry{
		SkillID:  skill.ID,
		Method:   "CONNECT",
		Host:     host,
		Status:   "allowed",
		Detail:   "blind tunnel (no TLS inspection)",
		Duration: time.Since(start).Milliseconds(),
	})

	// Bidirectional copy.
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer targetConn.Close()
		defer clientConn.Close()
		io.Copy(clientConn, targetConn)
	}()
}
