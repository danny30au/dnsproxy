package upstream

import (
	"math/rand"
	"syscall"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

// Values to configure HTTP and HTTP/2 transport.
const (
	transportDefaultReadIdleTimeout = 30 * time.Second
	transportDefaultIdleConnTimeout = 5 * time.Minute
	dohMaxConnsPerHost              = 2
	dohMaxIdleConns                 = 2
)

// dnsOverHTTPS is a struct that implements the Upstream interface for the DNS-over-HTTPS protocol.
type dnsOverHTTPS struct {
	getDialer       DialerInitializer
	addr            *url.URL
	tlsConf         *tls.Config
	client          *http.Client
	clientMu        *sync.Mutex
	logger          *slog.Logger
	quicConf        *quic.Config
	quicConfMu      *sync.Mutex
	transportH2     *http2.Transport
	addrRedacted    string
	timeout         time.Duration
}

// newDoH returns the DNS-over-HTTPS Upstream.
func newDoH(addr *url.URL, opts *Options) (u Upstream, err error) {
	addPort(addr, defaultPortDoH)

	var httpVersions []HTTPVersion
	if addr.Scheme == "h3" {
		addr.Scheme = "https"
		httpVersions = []HTTPVersion{HTTPVersion3}
	} else if httpVersions = opts.HTTPVersions; len(opts.HTTPVersions) == 0 {
		httpVersions = DefaultHTTPVersions
	}

	ups := &dnsOverHTTPS{
		getDialer: newDialerInitializer(addr, opts),
		addr:      addr,
		quicConf: &quic.Config{
			KeepAlivePeriod: QUICKeepAlivePeriod,
			TokenStore:      newQUICTokenStore(),
			Tracer:          opts.QUICTracer,
		},
		quicConfMu: &sync.Mutex{},
		tlsConf: &tls.Config{
			ServerName:   addr.Hostname(),
			RootCAs:      opts.RootCAs,
			CipherSuites: opts.CipherSuites,
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify:    opts.InsecureSkipVerify,
			VerifyPeerCertificate: opts.VerifyServerCertificate,
			VerifyConnection:      opts.VerifyConnection,
		},
		clientMu:     &sync.Mutex{},
		logger:       opts.Logger,
		addrRedacted: addr.Redacted(),
		timeout:      opts.Timeout,
	}
	for _, v := range httpVersions {
		ups.tlsConf.NextProtos = append(ups.tlsConf.NextProtos, string(v))
	}

	runtime.SetFinalizer(ups, (*dnsOverHTTPS).Close)

	return ups, nil
}

// type check
var _ Upstream = (*dnsOverHTTPS)(nil)

// Address implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Address() string { return p.addrRedacted }

// Exchange implements the [Upstream] interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Exchange(req *dns.Msg) (resp *dns.Msg, err error) {
	id := req.Id
	req.Id = 0
	defer func() {
		req.Id = id
		if resp != nil {
			resp.Id = id
		}
	}()

	client, isCached, err := p.getClient()
	if err != nil {
		return nil, fmt.Errorf("failed to init http client: %w", err)
	}

	resp, err = p.exchangeHTTPS(client, req)

	for i := 0; isCached && p.shouldRetry(err) && i < 2; i++ {
		client, err = p.resetClient(err)
		if err != nil {
			return nil, fmt.Errorf("failed to reset http client: %w", err)
		}
		resp, err = p.exchangeHTTPS(client, req)
	}

	if err != nil {
		_, resErr := p.resetClient(err)
		return nil, errors.WithDeferred(err, resErr)
	}

	return resp, err
}

// ---- Batch Streams and DPI-Bypass Implementation ----

type batchRequest struct {
	req   *dns.Msg
	resp  chan *dns.Msg
	err   chan error
}

type batchDoH struct {
	*dnsOverHTTPS
	batchCh chan batchRequest
	once    sync.Once
}

func (p *dnsOverHTTPS) Batch() *batchDoH {
	b := &batchDoH{
		dnsOverHTTPS: p,
		batchCh:      make(chan batchRequest, 32),
	}
	b.once.Do(func() {
		go b.batchWorker()
	})
	return b
}

func (b *batchDoH) batchWorker() {
	batchSize := 8
	batch := make([]batchRequest, 0, batchSize)
	for {
		batch = batch[:0]
		timeout := time.After(2 * time.Millisecond)
		select {
		case req := <-b.batchCh:
			batch = append(batch, req)
		case <-timeout:
			continue
		}
	collectLoop:
		for len(batch) < cap(batch) {
			select {
			case req := <-b.batchCh:
				batch = append(batch, req)
			case <-timeout:
				break collectLoop
			}
		}
		client, _, err := b.getClient()
		if err != nil {
			for _, r := range batch {
				r.err <- err
			}
			continue
		}
		var wg sync.WaitGroup
		wg.Add(len(batch))
		for _, r := range batch {
			go func(r batchRequest) {
				defer wg.Done()
				addEDNS0Padding(r.req, randomizedPadding())
				addEDNS0Watermark(r.req)
				resp, err := b.exchangeHTTPS(client, r.req)
				r.resp <- resp
				r.err <- err
			}(r)
		}
		wg.Wait()
	}
}

// Public API: batch exchange
func (p *dnsOverHTTPS) BatchExchange(requests []*dns.Msg) ([]*dns.Msg, []error) {
	b := p.Batch()
	responses := make([]*dns.Msg, len(requests))
	errors := make([]error, len(requests))
	respCh := make([]chan *dns.Msg, len(requests))
	errCh := make([]chan error, len(requests))
	for i, req := range requests {
		respCh[i] = make(chan *dns.Msg, 1)
		errCh[i] = make(chan error, 1)
		b.batchCh <- batchRequest{req: req, resp: respCh[i], err: errCh[i]}
	}
	for i := range requests {
		responses[i] = <-respCh[i]
		errors[i] = <-errCh[i]
	}
	return responses, errors
}

// -----------------------------------------------------

// Close implements the Upstream interface for *dnsOverHTTPS.
func (p *dnsOverHTTPS) Close() (err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	runtime.SetFinalizer(p, nil)
	if p.client != nil {
		err = p.closeClient(p.client)
	}
	return err
}

// closeClient cleans up resources used by client if necessary.
func (p *dnsOverHTTPS) closeClient(client *http.Client) (err error) {
	if isHTTP3(client) {
		return client.Transport.(io.Closer).Close()
	} else if p.transportH2 != nil {
		p.transportH2.CloseIdleConnections()
	}
	return nil
}

// exchangeHTTPS logs the request and its result and calls exchangeHTTPSClient.
func (p *dnsOverHTTPS) exchangeHTTPS(client *http.Client, req *dns.Msg) (resp *dns.Msg, err error) {
	n := networkTCP
	if isHTTP3(client) {
		n = networkUDP
	}
	logBegin(p.logger, p.addrRedacted, n, req)
	defer func() { logFinish(p.logger, p.addrRedacted, n, err) }()
	return p.exchangeHTTPSClient(client, req)
}

// exchangeHTTPSClient sends the DNS query to a DoH resolver using the specified http.Client instance.
func (p *dnsOverHTTPS) exchangeHTTPSClient(
	client *http.Client,
	req *dns.Msg,
) (resp *dns.Msg, err error) {
	buf, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing message: %w", err)
	}
	method := http.MethodGet
	if isHTTP3(client) {
		method = http3.MethodGet0RTT
	}
	q := url.Values{
		"dns": []string{base64.RawURLEncoding.EncodeToString(buf)},
	}
	u := url.URL{
		Scheme:   p.addr.Scheme,
		User:     p.addr.User,
		Host:     p.addr.Host,
		Path:     p.addr.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequest(method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating http request to %s: %w", p.addrRedacted, err)
	}

	// DPI bypass: Use randomized headers for stealth
	hdrs := randomizedHeaders()
	for k, vals := range hdrs {
		for _, v := range vals {
			httpReq.Header.Set(k, v)
		}
	}
	httpReq.Header.Set(httphdr.UserAgent, "")
	httpReq.Header.Set(httphdr.Accept, "application/dns-message")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", p.addrRedacted, err)
	}
	defer slogutil.CloseAndLog(httpReq.Context(), p.logger, httpResp.Body, slog.LevelDebug)

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", p.addrRedacted, err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"expected status %d, got %d from %s",
			http.StatusOK,
			httpResp.StatusCode,
			p.addrRedacted,
		)
	}

	resp = &dns.Msg{}
	err = resp.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf(
			"unpacking response from %s: body is %s: %w",
			p.addrRedacted,
			body,
			err,
		)
	}
	if resp.Id != req.Id {
		err = dns.ErrId
	}
	return resp, err
}

// shouldRetry checks what error we have received and returns true if we should re-create the HTTP client and retry the request.
func (p *dnsOverHTTPS) shouldRetry(err error) (ok bool) {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	if isQUICRetryError(err) {
		return true
	}
	return false
}

// resetClient triggers re-creation of the *http.Client that is used by this upstream.
func (p *dnsOverHTTPS) resetClient(resetErr error) (client *http.Client, err error) {
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	if errors.Is(resetErr, quic.Err0RTTRejected) {
		p.resetQUICConfig()
	}
	oldClient := p.client
	if oldClient != nil {
		closeErr := p.closeClient(oldClient)
		if closeErr != nil {
			p.logger.Warn("failed to close the old http client", slogutil.KeyError, closeErr)
		}
	}
	p.logger.Debug("recreating the http client", slogutil.KeyError, resetErr)
	p.client, err = p.createClient()
	return p.client, err
}

// getQUICConfig returns the QUIC config in a thread-safe manner. Note, that this method returns a pointer, it is forbidden to change its properties.
func (p *dnsOverHTTPS) getQUICConfig() (c *quic.Config) {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()
	return p.quicConf
}

// resetQUICConfig Re-create the token store to make sure we're not trying to use invalid for 0-RTT.
func (p *dnsOverHTTPS) resetQUICConfig() {
	p.quicConfMu.Lock()
	defer p.quicConfMu.Unlock()
	p.quicConf = p.quicConf.Clone()
	p.quicConf.TokenStore = newQUICTokenStore()
}

// getClient gets or lazily initializes an HTTP client (and transport) that will be used for this DoH resolver.
func (p *dnsOverHTTPS) getClient() (c *http.Client, isCached bool, err error) {
	startTime := time.Now()
	p.clientMu.Lock()
	defer p.clientMu.Unlock()
	if p.client != nil {
		return p.client, true, nil
	}
	elapsed := time.Since(startTime)
	if p.timeout > 0 && elapsed > p.timeout {
		return nil, false, fmt.Errorf("timeout exceeded: %s", elapsed)
	}
	p.logger.Debug("creating a new http client")
	p.client, err = p.createClient()
	return p.client, false, err
}

// createClient creates a new *http.Client instance.
func (p *dnsOverHTTPS) createClient() (*http.Client, error) {
	transport, err := p.createTransport()
	if err != nil {
		return nil, fmt.Errorf("initializing http transport: %w", err)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		Jar:       nil,
	}
	p.client = client
	return p.client, nil
}

// createTransport initializes an HTTP transport that will be used specifically for this DoH resolver.
func (p *dnsOverHTTPS) createTransport() (t http.RoundTripper, err error) {
	dialContext, err := p.getDialer()
	if err != nil {
		return nil, fmt.Errorf("bootstrapping %s: %w", p.addrRedacted, err)
	}
	tlsConf := p.tlsConf.Clone()
	transportH3, err := p.createTransportH3(tlsConf, dialContext)
	if err == nil {
		p.logger.Debug("using http/3 for this upstream, quic was faster")
		return transportH3, nil
	}
	p.logger.Debug("got error, switching to http/2 for this upstream", slogutil.KeyError, err)
	if !p.supportsHTTP() {
		return nil, errors.Error("HTTP1/1 and HTTP2 are not supported by this upstream")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return c.Control(func(fd uintptr) {
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
					})
				},
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:    tlsConf,
		DisableCompression: true,
		IdleConnTimeout:    transportDefaultIdleConnTimeout,
		MaxConnsPerHost:    dohMaxConnsPerHost,
		MaxIdleConns:       dohMaxIdleConns,
		ForceAttemptHTTP2:  true,
	}
	p.transportH2, err = http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}
	p.transportH2.ReadIdleTimeout = transportDefaultReadIdleTimeout
	return transport, nil
}

// http3Transport is a wrapper over [*http3.Transport] that tries to optimize its behavior.
type http3Transport struct {
	baseTransport *http3.Transport
	closed bool
	mu     sync.RWMutex
}

// type check
var _ http.RoundTripper = (*http3Transport)(nil)

func (h *http3Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return nil, net.ErrClosed
	}
	resp, err = h.baseTransport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: true})
	if errors.Is(err, http3.ErrNoCachedConn) {
		resp, err = h.baseTransport.RoundTrip(req)
	}
	return resp, err
}

var _ io.Closer = (*http3Transport)(nil)

func (h *http3Transport) Close() (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	return h.baseTransport.Close()
}

// createTransportH3 tries to create an HTTP/3 transport for this upstream.
func (p *dnsOverHTTPS) createTransportH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
) (roundTripper http.RoundTripper, err error) {
	if !p.supportsH3() {
		return nil, errors.Error("HTTP3 support is not enabled")
	}
	addr, err := p.probeH3(tlsConfig, dialContext)
	if err != nil {
		return nil, err
	}
	rt := &http3.Transport{
		Dial: func(
			ctx context.Context,
			_ string,
			tlsCfg *tls.Config,
			cfg *quic.Config,
		) (c *quic.Conn, err error) {
			return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
		},
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		QUICConfig:         p.getQUICConfig(),
	}
	return &http3Transport{baseTransport: rt}, nil
}

// probeH3 runs a test to check whether QUIC is faster than TLS for this upstream.
func (p *dnsOverHTTPS) probeH3(
	tlsConfig *tls.Config,
	dialContext bootstrap.DialHandler,
) (addr string, err error) {
	rawConn, err := dialContext(context.Background(), "udp", "")
	if err != nil {
		return "", fmt.Errorf("failed to dial: %w", err)
	}
	_ = rawConn.Close()
	udpConn, ok := rawConn.(*net.UDPConn)
	if !ok {
		return "", fmt.Errorf("not a UDP connection to %s", p.addrRedacted)
	}
	addr = udpConn.RemoteAddr().String()
	if p.supportsH3() && !p.supportsHTTP() {
		return addr, nil
	}
	probeTLSCfg := tlsConfig.Clone()
	probeTLSCfg.ClientSessionCache = nil
	probeTLSCfg.VerifyPeerCertificate = nil
	probeTLSCfg.VerifyConnection = nil
	chQUIC := make(chan error, 1)
	chTLS := make(chan error, 1)
	go p.probeQUIC(addr, probeTLSCfg, chQUIC)
	go p.probeTLS(dialContext, probeTLSCfg, chTLS)
	select {
	case quicErr := <-chQUIC:
		if quicErr != nil {
			return "", quicErr
		}
		return addr, quicErr
	case tlsErr := <-chTLS:
		if tlsErr != nil {
			p.logger.Debug("probing tls", slogutil.KeyError, tlsErr)
			return addr, nil
		}
		return "", errors.Error("TLS was faster than QUIC, prefer it")
	}
}

func (p *dnsOverHTTPS) probeQUIC(addr string, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()
	t := p.timeout
	if t == 0 {
		t = dialTimeout
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(t))
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx, addr, tlsConfig, p.getQUICConfig())
	if err != nil {
		ch <- fmt.Errorf("opening quic connection to %s: %w", p.addrRedacted, err)
		return
	}
	_ = conn.CloseWithError(QUICCodeNoError, "")
	ch <- nil
	elapsed := time.Since(startTime)
	p.logger.Debug("quic connection established", "elapsed", elapsed)
}

func (p *dnsOverHTTPS) probeTLS(dialContext bootstrap.DialHandler, tlsConfig *tls.Config, ch chan error) {
	startTime := time.Now()
	conn, err := tlsDial(dialContext, tlsConfig)
	if err != nil {
		ch <- fmt.Errorf("opening TLS connection: %w", err)
		return
	}
	_ = conn.Close()
	ch <- nil
	elapsed := time.Since(startTime)
	p.logger.Debug("tls connection established", "elapsed", elapsed)
}

// supportsH3 returns true if HTTP/3 is supported by this upstream.
func (p *dnsOverHTTPS) supportsH3() (ok bool) {
	for _, v := range p.tlsConf.NextProtos {
		if v == string(HTTPVersion3) {
			return true
		}
	}
	return false
}

// supportsHTTP returns true if HTTP/1.1 or HTTP2 is supported by this upstream.
func (p *dnsOverHTTPS) supportsHTTP() (ok bool) {
	for _, v := range p.tlsConf.NextProtos {
		if v == string(HTTPVersion11) || v == string(HTTPVersion2) {
			return true
		}
	}
	return false
}

// isHTTP3 checks if the *http.Client is an HTTP/3 client.
func isHTTP3(client *http.Client) (ok bool) {
	_, ok = client.Transport.(*http3Transport)
	return ok
}

// ---- DPI Bypass and Stealth Helpers ----

func addEDNS0Padding(msg *dns.Msg, targetSize int) {
	opt := msg.IsEdns0()
	if opt == nil {
		opt = &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		msg.Extra = append(msg.Extra, opt)
	}
	padLen := targetSize - msg.Len()
	if padLen > 0 {
		opt.Option = append(opt.Option, &dns.EDNS0_LOCAL{Code: 12, Data: make([]byte, padLen)})
	}
}

func randomizedHeaders() http.Header {
	headers := http.Header{}
	headers.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 (Windows NT %d.%d; rv:%d.0) Gecko/20100101 Firefox/%d.0",
		5+rand.Intn(2), rand.Intn(3), 70+rand.Intn(10), 70+rand.Intn(10)))
	headers.Set("Accept", "*/*")
	headers.Set("Accept-Language", "en-US,en;q=0.5")
	return headers
}

func addEDNS0Watermark(msg *dns.Msg) {
	opt := &dns.OPT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
		Option: []dns.EDNS0{
			&dns.EDNS0_LOCAL{
				Code: 65000 + uint16(rand.Intn(3000)),
				Data: []byte{0x00, byte(rand.Intn(255))},
			},
		},
	}
	msg.Extra = append(msg.Extra, opt)
}

func randomizedPadding() int {
	base := 128 + rand.Intn(64)
	return base - (base % 8)
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	"Mozilla/5.0 (X11; Linux x86_64)",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
	"curl/7.68.0",
	"Wget/1.20.3",
	"AdGuard/2.4.0",
}

func warmUpConnection(ctx context.Context, url string, client *http.Client) {
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
		_, _ = client.Do(req)
	}()
}

var dnsBufPool = sync.Pool{
	New: func() any { return make([]byte, 1500) },
}

var randomizedQUICConfig = &quic.Config{
	EnableDatagrams:                 true,
	MaxIncomingStreams:              int64(1000 + rand.Intn(500)),
	MaxIncomingUniStreams:           int64(500 + rand.Intn(250)),
	InitialStreamReceiveWindow:      uint64(65536 + rand.Intn(32768)),
	InitialConnectionReceiveWindow:  uint64(1048576 + rand.Intn(262144)),
	MaxIdleTimeout:                  time.Duration(30+rand.Intn(60)) * time.Second,
	Allow0RTT:                       true,
}
