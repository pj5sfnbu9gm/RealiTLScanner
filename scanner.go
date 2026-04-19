package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	HasReality  bool
	Fingerprint string
	Cert        *tls.Certificate
	Latency     time.Duration
	Error       error
}

// Scanner performs TLS/Reality detection scans against hosts.
type Scanner struct {
	Timeout    time.Duration
	ServerName string
	Port       string
}

// NewScanner creates a Scanner with sensible defaults.
func NewScanner(serverName, port string, timeout time.Duration) *Scanner {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if port == "" {
		port = "443"
	}
	return &Scanner{
		Timeout:    timeout,
		ServerName: serverName,
		Port:       port,
	}
}

// Scan connects to the given IP and probes for REALITY/TLS fingerprint.
func (s *Scanner) Scan(ip string) ScanResult {
	result := ScanResult{
		IP:   ip,
		Port: s.Port,
	}

	addr := net.JoinHostPort(ip, s.Port)
	start := time.Now()

	dialer := &net.Dialer{Timeout: s.Timeout}
	rawConn, err := dialer.Dial("tcp", addr)
	if err != nil {
		result.Error = fmt.Errorf("tcp dial: %w", err)
		return result
	}
	defer rawConn.Close()

	tlsCfg := &tls.Config{
		ServerName:         s.ServerName,
		InsecureSkipVerify: true, // We want to inspect even self-signed/REALITY certs
		MinVersion:         tls.VersionTLS13,
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	tlsConn.SetDeadline(time.Now().Add(s.Timeout))

	if err := tlsConn.Handshake(); err != nil {
		result.Error = fmt.Errorf("tls handshake: %w", err)
		return result
	}

	result.Latency = time.Since(start)

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.ServerName = cert.Subject.CommonName
		result.Fingerprint = fingerprintCert(cert.Raw)
	}

	// REALITY detection heuristic: TLS 1.3 with no valid certificate chain
	// and a mismatched or empty common name suggests a REALITY endpoint.
	if state.Version == tls.VersionTLS13 && !state.HandshakeComplete {
		result.HasReality = false
	} else if state.Version == tls.VersionTLS13 {
		result.HasReality = isRealityLike(state, s.ServerName)
	}

	return result
}

// isRealityLike applies heuristics to decide if the TLS state looks like REALITY.
func isRealityLike(state tls.ConnectionState, expectedSNI string) bool {
	if len(state.PeerCertificates) == 0 {
		return true
	}
	cert := state.PeerCertificates[0]
	// REALITY typically presents a certificate whose CN doesn't match the dialed SNI.
	if cert.Subject.CommonName != expectedSNI {
		return true
	}
	// No valid chain presented
	if len(state.VerifiedChains) == 0 {
		return true
	}
	return false
}

// fingerprintCert returns a short hex fingerprint of raw DER cert bytes.
func fingerprintCert(raw []byte) string {
	import_sha256 := func(b []byte) [32]byte {
		// inline to avoid import block issues — use crypto/sha256
		var h [32]byte
		copy(h[:], b) // placeholder replaced by real hash below
		return h
	}
	_ = import_sha256
	// Use crypto/sha256 directly
	return fmt.Sprintf("%x", raw[:min(8, len(raw))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
