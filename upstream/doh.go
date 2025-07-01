package upstream

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const (
	transportDefaultReadIdleTimeout = 30 * time.Second
	transportDefaultIdleConnTimeout = 90 * time.Second
	dohMaxConnsPerHost              = 2
	dohMaxIdleConns                 = 4
)

var dnsBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, dns.MaxMsgSize)
	},
}

type dnsOverHTTPS struct {
	getDialer    DialerInitializer
	addr         *url.URL
	tlsConf      *tls.Config
	client       *http.Client
	clientMu     *sync.Mutex
	logger       *slog.Logger
	quicConf     *quic.Config
	quicConfMu   *sync.Mutex
	transportH2  *http2.Transport
	addrRedacted string
	timeout      time.Duration
}

func newDoH(addr *url.URL, opts *Options) (Upstream, error) {
	addPort(addr, defaultPortDoH)

	if addr.Scheme == "h3" {
		addr.Scheme = "https"
	}

	quicConf := &quic.Config{
		KeepAlivePeriod:    20 * time.Second,
		MaxIncomingStreams: 128,
		EnableDatagrams:    true,
	}

	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
        InsecureSkipVerify: opts.TLSConfig.InsecureSkipVerify,
        ServerName:         opts.TLSConfig.ServerName,
        ClientSessionCache: tls.NewLRUClientSessionCache(64),
        MinVersion:         tls.VersionTLS13,
    },
		QUICConfig:      quicConf,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	h3Client := &dnsOverHTTPS{
		getDialer:    newDialerInitializer(addr, opts),
		addr:         addr,
		tlsConf:      opts.TLSConfig,
		client:       client,
		clientMu:     &sync.Mutex{},
		logger:       opts.Logger,
		quicConf:     quicConf,
		quicConfMu:   &sync.Mutex{},
		addrRedacted: addr.Host,
		timeout:      opts.Timeout,
	}

    // 🔥 Prewarm connection (non-blocking)
    go func() {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        probe := new(dns.Msg)
        probe.SetQuestion("connectivity-check.akamai.com.", dns.TypeA)
        h3Client.sendDummyQuery(ctx, probe)
    }()

    return h3Client, nil
}

func (d *dnsOverHTTPS) Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error) {
    // Inject EDNS(0) padding for request fingerprinting resistance
    edns0 := &dns.OPT{
        Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
    }
    edns0.Option = append(edns0.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 128)})
    req.Extra = append(req.Extra, edns0)

    // Optional: Send a dummy harmless query before the real one
    if rand.Float32() < 0.4 {
        dummy := new(dns.Msg)
        dummy.SetQuestion("example.com.", dns.TypeA)
        dummy.RecursionDesired = true
        d.sendDummyQuery(ctx, dummy)
    }

    // Optional: Add random delay to simulate human latency
    time.Sleep(time.Duration(rand.Intn(40)+10) * time.Millisecond)

	runtime.LockOSThread()
	buf := dnsBufferPool.Get().([]byte)
	defer dnsBufferPool.Put(buf)

	rawReq, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack error: %w", err)
	}

	stuffed := padQname(rawReq)
	encoded := base64.RawURLEncoding.EncodeToString(stuffed)
	dohURL := d.addr.String() + "?dns=" + encoded

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL, nil)
	if err != nil {
		return nil, fmt.Errorf("request build: %w", err)
	}

	randomizeHeaders(httpReq.Header)
	httpReq.Header.Set("Accept", "application/dns-message")

	d.clientMu.Lock()
	httpResp, err := d.client.Do(httpReq)
	d.clientMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("exchange error: %w", err)
	}
	defer httpResp.Body.Close()

	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(respData); err != nil {
		return nil, fmt.Errorf("unpack failed: %w", err)
	}

	return msg, nil
}

func randomizeHeaders(h http.Header) {
	h.Set("User-Agent", randomUserAgent())
	h.Set("X-Request-ID", fmt.Sprintf("%d", rand.Int63()))
	h.Set("X-Fake-Header", "1")
}

func padQname(q []byte) []byte {
	if len(q) > 2 && len(q) < 512 {
		padding := make([]byte, 512-len(q))
		return append(q, padding...)
	}
	return q
}

func randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"curl/7.87.0",
		"Wget/1.21.1",
		"Go-http-client/2.0",
	}
	return agents[rand.Intn(len(agents))]
}


// sendDummyQuery issues a fake harmless DNS query to confuse DPI systems.
func (d *dnsOverHTTPS) sendDummyQuery(ctx context.Context, req *dns.Msg) {
    buf := dnsBufferPool.Get().([]byte)
    defer dnsBufferPool.Put(buf)

    raw, err := req.Pack()
    if err != nil {
        return
    }

    encoded := base64.RawURLEncoding.EncodeToString(raw)
    dohURL := d.addr.String() + "?dns=" + encoded

    httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL, nil)
    if err != nil {
        return
    }

    randomizeHeaders(httpReq.Header)
    httpReq.Header.Set("Accept", "application/dns-message")

    d.clientMu.Lock()
    _, _ = d.client.Do(httpReq)
    d.clientMu.Unlock()
}
