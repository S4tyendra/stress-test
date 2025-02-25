# Server Stress Test Tool

A comprehensive server stress testing tool written in Go that supports multiple attack vectors and testing methodologies.

For a detailed discussion about this tool, check out the [blog post](https://blog.satyendra.in/go-stress-testing-ddos-simulation).

## Features

- Multiple Attack Vectors:
  - HTTP Flood
  - TCP Flood
  - UDP Flood
  - SYN Flood
  - Slowloris Attack
  - DNS Amplification
  - ICMP Flood
  - HTTP/2 Rapid Reset
  - SSL/TLS Renegotiation
  - WebSocket Connection Exhaustion
  - API Fuzzing
  - GraphQL Complexity Attack

- Advanced Capabilities:
  - Port scanning
  - Progressive load testing
  - Warm-up and cool-down periods
  - Detailed metrics and reporting
  - Configurable concurrency
  - Custom headers and user agents
  - Timing randomization
  - Proxy support

## Installation

```bash
go get github.com/s4tyendra/stress-test
```

## Building from Source

1. Clone the repository:
```bash
git clone https://github.com/s4tyendra/stress-test.git
cd stress-test
```

2. Install dependencies:
```bash
go mod tidy
```

3. Build the executable:
```bash
go build -o stress-test
```

## Usage

Basic usage:

```bash
./stress-test -url http://target.com -duration 2m
```

Advanced usage with multiple attack vectors:

```bash
./stress-test \
  -url http://target.com \
  -duration 5m \
  -concurrency 100 \
  -http-flood \
  -tcp-flood \
  -slowloris \
  -random-ua \
  -random-headers
```

### Command Line Options

- `-url`: Target URL to test
- `-ip`: Target IP address
- `-duration`: Test duration (default: 2m)
- `-concurrency`: Number of concurrent connections (default: 50)
- `-requests`: Number of requests to send (default: 10000)
- `-ports`: Specific ports to target (e.g., "80,443,8000-8080")

Attack Flags:
- `-http-flood`: Enable HTTP flood attack
- `-tcp-flood`: Enable TCP flood attack
- `-udp-flood`: Enable UDP flood attack
- `-syn-flood`: Enable SYN flood attack
- `-slowloris`: Enable Slowloris attack
- `-dns-amplify`: Enable DNS amplification attack
- `-icmp-flood`: Enable ICMP flood
- `-http2-flood`: Enable HTTP/2 rapid reset attack
- `-ssl-renegotiate`: Enable SSL/TLS renegotiation attack
- `-websocket-test`: Enable WebSocket connection exhaustion
- `-api-fuzzing`: Enable API endpoint fuzzing
- `-graphql-test`: Enable GraphQL complexity attack

Configuration:
- `-warmup`: Warmup duration (default: 10s)
- `-cooldown`: Cooldown duration (default: 10s)
- `-progressive`: Enable progressive load testing
- `-progressive-steps`: Number of steps in progressive load test
- `-random-ua`: Randomize User-Agent headers
- `-random-headers`: Randomize HTTP headers
- `-random-timing`: Randomize request timing
- `-verbose`: Enable verbose logging
- `-metrics`: Enable metrics collection
- `-metrics-interval`: Metrics reporting interval

## Metrics

The tool provides detailed metrics including:
- Total requests sent
- Successful/failed requests
- Requests per second
- Bytes sent/received
- Average response time
- Open ports discovered

## Warning

This tool is for testing and educational purposes only. Improper use of this tool may be illegal. Always ensure you have permission to test the target system.
> [!CAUTION]
> **DISCLAIMER**: The author (@s4tyendra) is not responsible for any misuse or damage caused by this tool. Users are solely responsible for ensuring they have proper authorization before conducting any security testing. This tool should only be used in controlled environments with explicit permission.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
