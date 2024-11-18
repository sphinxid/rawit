package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// Constants for random string generation
const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// Config holds the application configuration and runtime statistics
type Config struct {
	// Request configuration
	url        string
	method     string
	headers    map[string]string
	body       string
	hostHeader string

	// Connection settings
	threads     int
	insecure    bool
	keepAlive   bool
	useHTTP2    bool
	useRandomUA bool

	// Proxy configuration
	socks5List       []Socks5Proxy
	proxyRotateCount int64

	// User agent settings
	userAgent string

	// Runtime statistics
	requests int64
	errors   int64
	mu       sync.Mutex
}

// Socks5Proxy represents a SOCKS5 proxy configuration
type Socks5Proxy struct {
	Host     string
	Port     string
	Username string
	Password string
	dialer   proxy.Dialer
}

// Global configuration instance
var config = &Config{
	headers: make(map[string]string),
}

// Command-line flags
var (
	headersStr     string
	socks5File     string
	duration       time.Duration
	insecureStr    string
	keepAliveStr   string
	useHTTP2Str    string
	useRandomUAStr string
)

var userAgents = []string{
	// Windows - Chrome (11 variants)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",

	// Windows - Firefox (10 variants)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:118.0) Gecko/20100101 Firefox/118.0",

	// Windows - Edge (10 variants)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Edge/119.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Edge/118.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Edge/117.0.0.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
	"Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Edge/119.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Edge/119.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Edge/120.0.0.0 Edg/120.0.100",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Edge/119.0.0.0 Edg/119.0.100",

	// macOS - Chrome (10 variants)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

	// macOS - Safari (10 variants)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 11_0_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",

	// macOS - Firefox (10 variants)
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:118.0) Gecko/20100101 Firefox/118.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11.0; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 11.0; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12.0; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 12.0; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 11.0; rv:120.0) Gecko/20100101 Firefox/120.0",

	// Linux - Chrome (10 variants)
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

	// Linux - Firefox (continuing)
	"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:117.0) Gecko/20100101 Firefox/117.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
	"Mozilla/5.0 (X11; Linux aarch64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (X11; Linux aarch64; rv:119.0) Gecko/20100101 Firefox/119.0",

	// Linux - Opera (10 variants)
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 OPR/104.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
	"Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",

	// Linux - Brave (10 variants)
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/119.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Brave/118.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/119.0.0.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/119.0.0.0",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Brave/119.0.0.0",
	"Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/120.0.0.0",

	// Linux - Vivaldi (10 variants)
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.4.3160.47",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Vivaldi/6.3.3105.41",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.4.3160.47",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53",
	"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.4.3160.47",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53",
	"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Vivaldi/6.4.3160.47",
	"Mozilla/5.0 (X11; Linux armv7l) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.53",
}

func randstr(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, rand.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = rand.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

func parseProxy(proxyStr string) (*Socks5Proxy, error) {
	parts := strings.Split(proxyStr, ":")
	if len(parts) == 2 {
		return &Socks5Proxy{
			Host: parts[0],
			Port: parts[1],
		}, nil
	} else if len(parts) == 4 {
		return &Socks5Proxy{
			Username: parts[0],
			Password: parts[1],
			Host:     parts[2],
			Port:     parts[3],
		}, nil
	}
	return nil, fmt.Errorf("invalid proxy format")
}

func (p *Socks5Proxy) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if p.dialer == nil {
		auth := &proxy.Auth{}
		if p.Username != "" && p.Password != "" {
			auth.User = p.Username
			auth.Password = p.Password
		} else {
			auth = nil
		}

		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(p.Host, p.Port), auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		p.dialer = dialer
	}

	if contextDialer, ok := p.dialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, network, addr)
	}
	return p.dialer.Dial(network, addr)
}

func getRandomProxy(config *Config) *Socks5Proxy {
	config.mu.Lock()
	defer config.mu.Unlock()

	if len(config.socks5List) == 0 {
		return nil
	}
	return &config.socks5List[rand.Intn(len(config.socks5List))]
}

func loadProxies(filename string) ([]Socks5Proxy, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []Socks5Proxy
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		proxy, err := parseProxy(line)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *proxy)
	}

	return proxies, scanner.Err()
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// connPool manages a pool of network connections
type connPool struct {
	mu    sync.Mutex
	conns map[string]net.Conn
}

// newConnPool creates a new connection pool
func newConnPool() *connPool {
	return &connPool{
		conns: make(map[string]net.Conn),
	}
}

// get retrieves a connection from the pool
func (p *connPool) get(key string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conns[key]
}

// put adds a connection to the pool
func (p *connPool) put(key string, conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns[key] = conn
}

// remove closes and removes a connection from the pool
func (p *connPool) remove(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if conn, ok := p.conns[key]; ok {
		conn.Close()
		delete(p.conns, key)
	}
}

func worker(ctx context.Context, config *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	transport := createTransport(config)
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if !config.useHTTP2 && config.socks5List != nil && len(config.socks5List) > 0 {
				makeRequestHTTP1RawWithProxy(config)
			} else if config.useHTTP2 {
				for i := 0; i < 100; i++ {
					if err := makeRequestHTTP2(client, config); err != nil {
						// Error is already handled in makeRequestHTTP2
						continue
					}
				}
			} else {
				if err := makeRequestHTTP1(config, newConnPool()); err != nil {
					// Error is already handled in makeRequestHTTP1
					continue
				}
			}
		}
	}
}

// createTransport creates an http.Transport with the appropriate configuration
func createTransport(config *Config) *http.Transport {
	if config.socks5List != nil && len(config.socks5List) > 0 {
		return &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: config.insecure,
			},
			DisableKeepAlives:     !config.keepAlive,
			ForceAttemptHTTP2:     config.useHTTP2,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			MaxConnsPerHost:       1000,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			WriteBufferSize:       64 * 1024, // 64KB
			ReadBufferSize:        64 * 1024, // 64KB
			Dial: func(network, addr string) (net.Conn, error) {
				proxy := getRandomProxy(config)
				if proxy == nil {
					return nil, fmt.Errorf("no proxy available")
				}
				return proxy.Dial(context.Background(), network, addr)
			},
		}
	}

	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.insecure,
		},
		DisableKeepAlives: !config.keepAlive,
		ForceAttemptHTTP2: config.useHTTP2,
	}
}

// makeRequestHTTP2 sends an HTTP/2 request using the provided client
func makeRequestHTTP2(client *http.Client, config *Config) error {
	var reqBody io.Reader
	targetURL := config.url

	if config.method == "POST" && config.body != "" {
		reqBody = bytes.NewBufferString(config.body)
	}

	if strings.Contains(config.url, "%%RAND%%") {
		targetURL = strings.ReplaceAll(config.url, "%%RAND%%", randstr(128))
	}

	req, err := http.NewRequest(config.method, targetURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set request headers
	for key, value := range config.headers {
		req.Header.Set(key, value)
	}

	if config.hostHeader != "" {
		req.Host = config.hostHeader
	}

	if config.useRandomUA {
		req.Header.Set("User-Agent", getRandomUserAgent())
	} else {
		req.Header.Set("User-Agent", config.userAgent)
	}

	// Set additional headers for better HTTP/2 performance
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&config.errors, 1)
		return fmt.Errorf("request failed: %w", err)
	}

	// Read and discard response body to properly reuse connections
	if resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if resp.StatusCode >= 400 {
		atomic.AddInt64(&config.errors, 1)
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	atomic.AddInt64(&config.requests, 1)
	return nil
}

func makeRequestHTTP1RawWithProxy(config *Config) error {
	parsedURL, err := url.Parse(config.url)
	if err != nil {
		return err
	}

	// Get host and port
	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	// Get proxy
	proxy := getRandomProxy(config)
	if proxy == nil {
		return fmt.Errorf("no proxy available")
	}

	// Connect through SOCKS5
	conn, err := proxy.Dial(context.Background(), "tcp", host)
	if err != nil {
		return err
	}

	// Setup TLS if needed
	if parsedURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: config.insecure,
			ServerName:         strings.Split(host, ":")[0],
		})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return err
		}
		conn = tlsConn
	}

	// Pre-build the static parts of the request
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	// Pre-build headers that don't change
	var staticHeaders bytes.Buffer
	staticHeaders.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", config.method, path))
	if config.hostHeader != "" {
		staticHeaders.WriteString(fmt.Sprintf("Host: %s\r\n", config.hostHeader))
	} else {
		staticHeaders.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))
	}

	// Set Connection header based on keep-alive setting
	if config.keepAlive {
		staticHeaders.WriteString("Connection: Keep-Alive\r\n")
	} else {
		staticHeaders.WriteString("Connection: close\r\n")
		// If not using keep-alive, we'll only send one request per connection
	}

	staticHeaders.WriteString("Cache-Control: max-age=0\r\n")

	// Add custom headers
	for key, value := range config.headers {
		staticHeaders.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	// Prepare body if it's a POST request
	var bodyStr string
	if config.method == "POST" && config.body != "" {
		bodyStr = config.body
		if strings.Contains(bodyStr, "%%RAND%%") {
			bodyStr = strings.ReplaceAll(bodyStr, "%%RAND%%", randstr(128))
		}
	}

	// Send requests through the connection
	var requestBuffer bytes.Buffer
	requestsPerConn := 100
	if !config.keepAlive {
		requestsPerConn = 1 // Only one request if not using keep-alive
	}

	for i := 0; i < requestsPerConn; i++ {
		requestBuffer.Reset()
		requestBuffer.Write(staticHeaders.Bytes())

		// Add User-Agent (this can change per request if random)
		if config.useRandomUA {
			requestBuffer.WriteString(fmt.Sprintf("User-Agent: %s\r\n", getRandomUserAgent()))
		} else {
			requestBuffer.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.userAgent))
		}

		// Add body for POST requests
		if config.method == "POST" && bodyStr != "" {
			requestBuffer.WriteString("Content-Type: text/plain\r\n")
			requestBuffer.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(bodyStr)))
			requestBuffer.WriteString(bodyStr)
		} else {
			requestBuffer.WriteString("\r\n")
		}

		// Write the entire request at once
		_, err = conn.Write(requestBuffer.Bytes())

		// add sleeps 35ms
		time.Sleep(35 * time.Millisecond)

		if err != nil {
			conn.Close()
			atomic.AddInt64(&config.errors, 1)
			return err
		}

		atomic.AddInt64(&config.requests, 1)
	}

	conn.Close()
	return nil
}

func makeRequestHTTP1(config *Config, pool *connPool) error {
	var reqBody string
	newUrl := config.url

	if config.method == "POST" && config.body != "" {
		reqBody = config.body
	}

	if strings.Contains(config.url, "%%RAND%%") {
		newUrl = strings.ReplaceAll(config.url, "%%RAND%%", randstr(128))
	}

	parsedURL, err := url.Parse(newUrl)
	if err != nil {
		return err
	}

	host := parsedURL.Host
	if !strings.Contains(host, ":") {
		if parsedURL.Scheme == "https" {
			host = host + ":443"
		} else {
			host = host + ":80"
		}
	}

	// Get or create connection
	connKey := host
	var conn net.Conn
	if config.keepAlive {
		conn = pool.get(connKey)
	}

	if conn == nil {
		var tlsConn *tls.Conn
		var err error

		conn, err = net.Dial("tcp", host)
		if err != nil {
			atomic.AddInt64(&config.errors, 1)
			return err
		}

		if parsedURL.Scheme == "https" {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: config.insecure,
				ServerName:         strings.Split(host, ":")[0],
			}

			tlsConn = tls.Client(conn, tlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				conn.Close()
				atomic.AddInt64(&config.errors, 1)
				return err
			}
			conn = tlsConn
		}

		if config.keepAlive {
			pool.put(connKey, conn)
		}
	}

	if !config.keepAlive {
		defer conn.Close()
	}

	// Build static headers
	var staticHeaders bytes.Buffer
	path := parsedURL.Path
	if path == "" {
		path = "/"
	}
	if parsedURL.RawQuery != "" {
		path += "?" + parsedURL.RawQuery
	}

	staticHeaders.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", config.method, path))
	staticHeaders.WriteString(fmt.Sprintf("Host: %s\r\n", parsedURL.Host))

	if config.keepAlive {
		staticHeaders.WriteString("Connection: keep-alive\r\n")
	} else {
		staticHeaders.WriteString("Connection: close\r\n")
	}

	for key, value := range config.headers {
		staticHeaders.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}

	if config.hostHeader != "" {
		staticHeaders.WriteString(fmt.Sprintf("Host: %s\r\n", config.hostHeader))
	}

	requestsPerConn := 100
	if !config.keepAlive {
		requestsPerConn = 1
	}

	var requestBuffer bytes.Buffer
	for i := 0; i < requestsPerConn; i++ {
		requestBuffer.Reset()
		requestBuffer.Write(staticHeaders.Bytes())

		// Add User-Agent (this can change per request if random)
		if config.useRandomUA {
			requestBuffer.WriteString(fmt.Sprintf("User-Agent: %s\r\n", getRandomUserAgent()))
		} else {
			requestBuffer.WriteString(fmt.Sprintf("User-Agent: %s\r\n", config.userAgent))
		}

		// Add body for POST requests
		if config.method == "POST" && reqBody != "" {
			requestBuffer.WriteString("Content-Type: text/plain\r\n")
			requestBuffer.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(reqBody)))
			requestBuffer.WriteString(reqBody)
		} else {
			requestBuffer.WriteString("\r\n")
		}

		// Write the entire request at once
		_, err = conn.Write(requestBuffer.Bytes())
		if err != nil {
			if config.keepAlive {
				pool.remove(connKey)
			}
			atomic.AddInt64(&config.errors, 1)
			return err
		}

		// Read response
		respBuf := make([]byte, 4096)
		n, err := conn.Read(respBuf)
		if err != nil && err != io.EOF {
			if config.keepAlive {
				pool.remove(connKey)
			}
			atomic.AddInt64(&config.errors, 1)
			return err
		}

		// Parse response
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBuf[:n])), nil)
		if err != nil {
			if config.keepAlive {
				pool.remove(connKey)
			}
			atomic.AddInt64(&config.errors, 1)
			return err
		}

		if resp.StatusCode >= 400 {
			atomic.AddInt64(&config.errors, 1)
			return fmt.Errorf("HTTP error: %d", resp.StatusCode)
		}

		atomic.AddInt64(&config.requests, 1)
	}

	if !config.keepAlive {
		conn.Close()
	}

	return nil
}

func init() {
	flag.StringVar(&config.url, "url", "", "Target URL")
	flag.StringVar(&config.method, "method", "GET", "HTTP method (GET, POST, HEAD)")
	flag.StringVar(&headersStr, "H", "", "Custom headers (key:value)")
	flag.StringVar(&config.body, "body", "", "Request body for POST")
	flag.IntVar(&config.threads, "threads", 1, "Number of concurrent threads")
	flag.DurationVar(&duration, "duration", 0, "Test duration (e.g., 10s, 1m, 1h)")
	flag.StringVar(&socks5File, "socks5-file", "", "File containing SOCKS5 proxies")
	flag.StringVar(&insecureStr, "insecure", "false", "Skip TLS verification (true/false)")
	flag.StringVar(&keepAliveStr, "keep-alive", "true", "Use HTTP keep-alive (true/false)")
	flag.StringVar(&useHTTP2Str, "use-http2", "false", "Use HTTP/2 (true/false)")
	flag.StringVar(&config.userAgent, "user-agent", "rawit/v2.0", "Custom User-Agent string")
	flag.StringVar(&useRandomUAStr, "use-random-user-agent", "false", "Use random User-Agent for each request")
	flag.StringVar(&config.hostHeader, "host-header", "", "Custom Host header")
}

func main() {
	flag.Parse()

	if err := validateAndSetupConfig(); err != nil {
		fmt.Println("Error:", err)
		flag.Usage()
		os.Exit(1)
	}

	ctx, cancel := setupContext()
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	var wg sync.WaitGroup
	startTime := time.Now()

	fmt.Printf("Starting test with %d threads\n", config.threads)
	if duration > 0 {
		fmt.Printf("Duration: %s\n", duration)
	} else {
		fmt.Println("Duration: unlimited (press Ctrl+C to stop)")
	}

	// Start worker threads
	wg.Add(config.threads)
	for i := 0; i < config.threads; i++ {
		go worker(ctx, config, &wg)
	}

	// Handle interrupt signal
	go handleInterrupt(signalChan, startTime)

	wg.Wait()
	printResults(startTime)
}

// validateAndSetupConfig validates and sets up the configuration
func validateAndSetupConfig() error {
	if config.url == "" {
		return fmt.Errorf("URL is required")
	}

	config.insecure = strings.ToLower(insecureStr) == "true"
	config.keepAlive = strings.ToLower(keepAliveStr) == "true"
	config.useHTTP2 = strings.ToLower(useHTTP2Str) == "true"
	config.useRandomUA = strings.ToLower(useRandomUAStr) == "true"

	if headersStr != "" {
		headers := strings.Split(headersStr, ",")
		for _, header := range headers {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				config.headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	if socks5File != "" {
		proxies, err := loadProxies(socks5File)
		if err != nil {
			return fmt.Errorf("error loading proxies: %v", err)
		}
		config.socks5List = proxies
		config.proxyRotateCount = 100
	}

	return nil
}

// setupContext creates the appropriate context based on duration
func setupContext() (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(context.Background(), duration)
	}
	return context.WithCancel(context.Background())
}

// handleInterrupt handles the interrupt signal
func handleInterrupt(signalChan chan os.Signal, startTime time.Time) {
	<-signalChan
	fmt.Println("\nInterrupt received, stopping...")
	printResults(startTime)
	os.Exit(1)
}

// printResults prints the test results
func printResults(startTime time.Time) {
	elapsed := time.Since(startTime)
	requests := atomic.LoadInt64(&config.requests)
	errors := atomic.LoadInt64(&config.errors)
	rps := float64(requests) / elapsed.Seconds()

	fmt.Printf("\nResults:\n")
	fmt.Printf("Total Requests: %d\n", requests)
	fmt.Printf("Total Errors: %d\n", errors)
	fmt.Printf("Requests/sec: %.2f\n", rps)
	fmt.Printf("Test Duration: %s\n", elapsed)
}

