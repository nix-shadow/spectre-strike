package utils

import (
	"crypto/tls"
	"math/rand"
)

// TLS profiles mimicking real browsers for advanced fingerprinting evasion

type TLSProfile struct {
	Name           string
	CipherSuites   []uint16
	Curves         []tls.CurveID
	MinVersion     uint16
	MaxVersion     uint16
	SessionTickets bool
	NextProtos     []string
}

var tlsProfiles = []TLSProfile{
	{
		Name: "Chrome_122",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		Curves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		SessionTickets: true,
		NextProtos:     []string{"h2", "http/1.1"},
	},
	{
		Name: "Firefox_123",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		Curves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		SessionTickets: true,
		NextProtos:     []string{"h2", "http/1.1"},
	},
	{
		Name: "Safari_17",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Curves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		SessionTickets: true,
		NextProtos:     []string{"h2", "http/1.1"},
	},
	{
		Name: "Edge_122",
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
		Curves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
		SessionTickets: true,
		NextProtos:     []string{"h2", "http/1.1"},
	},
}

// GetRandomTLSProfile returns a random TLS profile
func GetRandomTLSProfile() TLSProfile {
	return tlsProfiles[rand.Intn(len(tlsProfiles))]
}

// ApplyTLSProfile applies a TLS profile to a tls.Config
func ApplyTLSProfile(config *tls.Config, profile TLSProfile) {
	config.CipherSuites = profile.CipherSuites
	config.CurvePreferences = profile.Curves
	config.MinVersion = profile.MinVersion
	config.MaxVersion = profile.MaxVersion
	config.SessionTicketsDisabled = !profile.SessionTickets
	config.NextProtos = profile.NextProtos

	// Additional anti-fingerprinting measures
	config.InsecureSkipVerify = true
	config.Renegotiation = tls.RenegotiateOnceAsClient
}

// GetProfiledTLSConfig returns a tls.Config with a random browser profile
func GetProfiledTLSConfig() *tls.Config {
	profile := GetRandomTLSProfile()
	config := &tls.Config{}
	ApplyTLSProfile(config, profile)
	return config
}

// GetAdvancedTLSConfig returns a highly optimized TLS config with anti-fingerprinting
func GetAdvancedTLSConfig() *tls.Config {
	profile := GetRandomTLSProfile()

	return &tls.Config{
		InsecureSkipVerify:     true,
		MinVersion:             profile.MinVersion,
		MaxVersion:             profile.MaxVersion,
		CipherSuites:           profile.CipherSuites,
		CurvePreferences:       profile.Curves,
		NextProtos:             profile.NextProtos,
		SessionTicketsDisabled: !profile.SessionTickets,
		Renegotiation:          tls.RenegotiateOnceAsClient,
		// Performance optimizations
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
}
