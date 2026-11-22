package webhooks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var blockedCIDRs []*net.IPNet

func init() {
	ranges := []string{
		// IPv4
		"0.0.0.0/8",          // Current network
		"10.0.0.0/8",         // RFC1918 Private
		"100.64.0.0/10",      // Shared Address Space
		"127.0.0.0/8",        // Loopback
		"169.254.0.0/16",     // Link Local & Metadata (169.254.169.254)
		"172.16.0.0/12",      // RFC1918 Private
		"192.0.0.0/24",       // IETF Protocol
		"192.0.2.0/24",       // TEST-NET-1
		"192.88.99.0/24",     // 6to4 Relay
		"192.168.0.0/16",     // RFC1918 Private
		"198.18.0.0/15",      // Network Benchmark
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // Multicast
		"240.0.0.0/4",        // Reserved
		"255.255.255.255/32", // Broadcast

		// IPv6
		"::/128",        // Unspecified
		"::1/128",       // Loopback
		"64:ff9b::/96",  // IPv4/IPv6 translation
		"100::/64",      // Discard-only
		"2001::/23",     // IETF Protocol
		"2001:db8::/32", // Documentation
		"2002::/16",     // 6to4
		"fc00::/7",      // Unique Local (Private)
		"fe80::/10",     // Link Local
		"ff00::/8",      // Multicast
	}
	for _, cidr := range ranges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		blockedCIDRs = append(blockedCIDRs, ipNet)
	}
}

// IsBlockedIP checks if an IP is within any private, loopback, link-local,
// metadata or reserved CIDR block.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	for _, block := range blockedCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	// Extra safety checks from standard library net.IP methods
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}

// SSRFConfig holds settings for outbound webhook dialing.
type SSRFConfig struct {
	AllowInsecureHTTP bool
	ConnectTimeout    time.Duration
	TotalTimeout      time.Duration
}

// DefaultSSRFConfig returns standard production settings.
func DefaultSSRFConfig() SSRFConfig {
	allowInsecure := os.Getenv("DEADBOLT_WEBHOOKS_ALLOW_INSECURE_HTTP_TESTING") == "true"
	return SSRFConfig{
		AllowInsecureHTTP: allowInsecure,
		ConnectTimeout:    ConnectTimeout,
		TotalTimeout:      TotalTimeout,
	}
}

// ValidateEndpointURL validates that the webhook destination is well-formed,
// strictly HTTPS on port 443 (unless testing), and that DNS resolves to non-blocked IPs.
func ValidateEndpointURL(rawURL string, cfg SSRFConfig) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse URL: %v", ErrInvalidURL, err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	if cfg.AllowInsecureHTTP {
		if scheme != "https" && scheme != "http" {
			return nil, fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
		}
	} else {
		if scheme != "https" {
			return nil, fmt.Errorf("%w: scheme must be public https", ErrInvalidURL)
		}
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidURL)
	}

	portStr := parsed.Port()
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("%w: invalid port %q", ErrInvalidURL, portStr)
		}
		if !cfg.AllowInsecureHTTP && port != 443 {
			return nil, fmt.Errorf("%w: public https on port 443 required", ErrInvalidURL)
		}
	}

	// If host is an IP literal, validate immediately
	if ip := net.ParseIP(host); ip != nil {
		if !cfg.AllowInsecureHTTP && IsBlockedIP(ip) {
			return nil, ErrSSRFBlocked
		}
		return parsed, nil
	}

	// Validate DNS resolution (fail-fast on creation if hostname resolves to blocked IP)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		if cfg.AllowInsecureHTTP {
			return parsed, nil
		}
		// In creation, DNS lookup error may happen if host does not exist yet
		return nil, fmt.Errorf("%w: DNS resolution failed for %q: %v", ErrInvalidURL, host, err)
	}
	if len(ips) == 0 {
		if cfg.AllowInsecureHTTP {
			return parsed, nil
		}
		return nil, fmt.Errorf("%w: no IP addresses resolved for %q", ErrInvalidURL, host)
	}

	if !cfg.AllowInsecureHTTP {
		for _, ip := range ips {
			if IsBlockedIP(ip) {
				return nil, fmt.Errorf("%w: host %q resolves to blocked IP %s", ErrSSRFBlocked, host, ip.String())
			}
		}
	}

	return parsed, nil
}

// NewSSRFSafeClient creates an http.Client configured with:
// 1. DNS revalidation on every dispatch with DNS rebinding defense (connects to validated IP directly).
// 2. Original SNI hostname preserved for TLS certificate verification.
// 3. Connect timeout 3s, total timeout 10s.
// 4. Redirects disabled (HTTP 3xx returned as terminal without following).
func NewSSRFSafeClient(cfg SSRFConfig) *http.Client {
	dialer := &net.Dialer{
		Timeout:   cfg.ConnectTimeout,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 nil, // Do not use ambient proxies for outbound webhooks
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   cfg.ConnectTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// Parse or resolve IP
			targetIP := net.ParseIP(host)
			if targetIP == nil {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					if cfg.AllowInsecureHTTP {
						return dialer.DialContext(ctx, network, addr)
					}
					return nil, fmt.Errorf("DNS lookup error for %s: %w", host, err)
				}
				if len(ips) == 0 {
					if cfg.AllowInsecureHTTP {
						return dialer.DialContext(ctx, network, addr)
					}
					return nil, fmt.Errorf("no IPs resolved for %s", host)
				}

				// Check each IP against SSRF blocklist
				var validIP net.IP
				for _, ip := range ips {
					if !cfg.AllowInsecureHTTP && IsBlockedIP(ip) {
						return nil, fmt.Errorf("%w: DNS resolved to blocked IP %s", ErrSSRFBlocked, ip.String())
					}
					if validIP == nil {
						validIP = ip
					}
				}
				targetIP = validIP
			} else {
				if !cfg.AllowInsecureHTTP && IsBlockedIP(targetIP) {
					return nil, fmt.Errorf("%w: target IP is blocked: %s", ErrSSRFBlocked, targetIP.String())
				}
			}

			// Dial the validated IP address directly (anti DNS rebinding)
			dialAddr := net.JoinHostPort(targetIP.String(), port)
			return dialer.DialContext(ctx, network, dialAddr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.TotalTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Blueprint §21: 3xx is not followed
			return http.ErrUseLastResponse
		},
	}
}
