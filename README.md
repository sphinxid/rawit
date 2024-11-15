# Rawit

Rawit is a powerful HTTP/HTTPS performance testing tool written in Go. It supports various features including concurrent testing, SOCKS5 proxy support, and basic performance metrics.

## Features

- Multiple HTTP methods support (GET, POST, HEAD)
- Concurrent request handling
- Custom headers and request body
- HTTP/2 support
- SOCKS5 proxy support
- TLS configuration (including insecure mode for self-signed certificates)
- Connection keep-alive support
- Custom User-Agent setting
- Detailed performance metrics
- Duration-based or infinite testing

## Installation

```bash
go build -o rawit
```

## Usage

Basic usage:
```bash
./rawit -url https://example.com
```

Advanced usage:
```bash
./rawit -url https://example.com \
  -method POST \
  -threads 100 \
  -duration 30s \
  -H "Content-Type: application/json" \
  -body '{"key": "value"}' \
  -user-agent "custom-agent/1.0" \
  -use-http2 true
```

### Available Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-url` | Target URL (required) | - |
| `-method` | HTTP method (GET, POST, HEAD) | GET |
| `-H` | Headers in format 'Key: Value' (can be specified multiple times) | - |
| `-body` | Request body for POST requests | - |
| `-threads` | Number of concurrent threads | 1 |
| `-duration` | Test duration (e.g., 10s, 1m, 1h). 0 means run until interrupted | 0 |
| `-socks5-file` | File containing SOCKS5 proxy list | - |
| `-insecure` | Skip TLS certificate verification (true/false) | true |
| `-keep-alive` | Enable HTTP keep-alive/connection reuse (true/false) | true |
| `-use-http2` | Use HTTP/2 protocol (true/false) | false |
| `-user-agent` | Custom User-Agent header | rawit/v2.0 |
| `-use-random-user-agent` | Use random User-Agent for each request (true/false) | false |
| `-host-header` | Custom Host header | - |

### SOCKS5 Proxy Format

The SOCKS5 proxy file should contain one proxy per line in either of these formats:
```
host:port
username:password:host:port
```

## Examples

1. Basic GET request:
```bash
./rawit -url https://api.example.com
```

2. POST request with custom headers:
```bash
./rawit -url https://api.example.com/data \
  -method POST \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer token" \
  -body '{"data": "test"}'
```

3. Load testing with proxies:
```bash
./rawit -url https://api.example.com \
  -threads 50 \
  -duration 5m \
  -socks5-file proxies.txt
```

4. HTTP/2 testing with random user agents:
```bash
./rawit -url https://api.example.com \
  -use-http2 true \
  -use-random-user-agent true \
  -threads 10
```

5. Custom testing with specific user agent:
```bash
./rawit -url https://api.example.com \
  -user-agent "custom-bot/1.0" \
  -threads 10
```

## Performance Tips

1. Use `-keep-alive true` for better performance with repeated requests
2. Adjust `-threads` based on your system capabilities and target server
3. Use `-use-http2 true` to use HTTP/2 protocol

## Notes

- If you are using self signed certificates, use `-insecure true`
- SOCKS5 proxies are automatically rotated for better performance
- Use Ctrl+C to stop the test at any time
