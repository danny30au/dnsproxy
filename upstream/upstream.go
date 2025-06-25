package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/dnsproxy/internal/bootstrap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/ameshkov/dnscrypt/v2"
	"github.com/ameshkov/dnsstamps"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

var (
	dnsMsgPool = sync.Pool{
		New: func() any { return new(dns.Msg) },
	}
)

// Upstream is an interface for a DNS resolver.
type Upstream interface {
	Exchange(req *dns.Msg) (resp *dns.Msg, err error)
	Address() (addr string)
	io.Closer
}

// QUICTraceFunc ...
type QUICTraceFunc func(
	ctx context.Context,
	role logging.Perspective,
	connID quic.ConnectionID,
) (tracer *logging.ConnectionTracer)

type Options struct {
	Logger                    *slog.Logger
	VerifyServerCertificate   func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
	VerifyConnection          func(state tls.ConnectionState) error
	VerifyDNSCryptCertificate func(cert *dnscrypt.Cert) error
	QUICTracer                QUICTraceFunc
	RootCAs                   *x509.CertPool
	CipherSuites              []uint16
	Bootstrap                 Resolver
	HTTPVersions              []HTTPVersion
	Timeout                   time.Duration
	InsecureSkipVerify        bool
	PreferIPv6                bool
}

func (o *Options) Clone() (clone *Options) {
	tmp := *o
	return &tmp
}

type HTTPVersion string

const (
	HTTPVersion11 HTTPVersion = "http/1.1"
	HTTPVersion2  HTTPVersion = "h2"
	HTTPVersion3  HTTPVersion = "h3"
)

var DefaultHTTPVersions = []HTTPVersion{HTTPVersion11, HTTPVersion2}

const (
	defaultPortPlain = 53
	defaultPortDoH   = 443
	defaultPortDoT   = 853
	defaultPortDoQ   = 853
)

// ***
func AddressToUpstream(addr string, opts *Options) (u Upstream, err error) {
	if opts == nil {
		opts = &Options{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	// Avoid allocating url.URL unless really needed.
	var uu *url.URL
	if strings.Contains(addr, "://") {
		uu, err = url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", addr, err)
		}
	} else {
		uu = urlPool.Get().(*url.URL)
		*uu = url.URL{Scheme: "udp", Host: addr}
		defer func() { urlPool.Put(uu) }()
	}

	err = validateUpstreamURL(uu)
	if err != nil {
		return nil, err
	}
	return urlToUpstream(uu, opts)
}

// urlPool for zero-allocation url.URL temporary use.
var urlPool = sync.Pool{
	New: func() any { return new(url.URL) },
}

// Ensure domain/IP validation is single-pass.
func validateUpstreamURL(u *url.URL) error {
	if u.Scheme == "sdns" {
		return nil
	}

	host := u.Host
	if h, port, err := net.SplitHostPort(host); err == nil {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("invalid port %s: %w", port, err)
		}
		host = h
	}
	l := len(host)
	if l >= 4 && host[0] == '[' && host[l-1] == ']' { // [::]/etc
		host = host[1 : l-1]
	}
	if netutil.IsValidIPString(host) {
		return nil
	}
	return netutil.ValidateDomainName(host)
}

func urlToUpstream(uu *url.URL, opts *Options) (Upstream, error) {
	switch sch := uu.Scheme; sch {
	case "sdns":
		return parseStamp(uu, opts)
	case "udp", "tcp":
		return newPlain(uu, opts)
	case "quic":
		return newDoQ(uu, opts)
	case "tls":
		return newDoT(uu, opts)
	case "h3", "https":
		return newDoH(uu, opts)
	default:
		return nil, fmt.Errorf("unsupported url scheme: %s", sch)
	}
}

func parseStamp(upsURL *url.URL, opts *Options) (Upstream, error) {
	stamp, err := dnsstamps.NewServerStampFromString(upsURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", upsURL, err)
	}

	// Memoize StaticResolver for the IP.
	if stamp.ServerAddrStr != "" {
		host, _, sErr := netutil.SplitHostPort(stamp.ServerAddrStr)
		if sErr != nil {
			host = stamp.ServerAddrStr
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			opts.Bootstrap = StaticResolver{ip}
		}
		// else ignore, fallback to whatever (don't wrap, error not fatal here)
	}

	switch stamp.Proto {
	case dnsstamps.StampProtoTypePlain:
		return newPlain(&url.URL{Scheme: "udp", Host: stamp.ServerAddrStr}, opts)
	case dnsstamps.StampProtoTypeDNSCrypt:
		return newDNSCrypt(upsURL, opts), nil
	case dnsstamps.StampProtoTypeDoH:
		return newDoH(&url.URL{Scheme: "https", Host: stamp.ProviderName, Path: stamp.Path}, opts)
	case dnsstamps.StampProtoTypeDoQ:
		return newDoQ(&url.URL{Scheme: "quic", Host: stamp.ProviderName, Path: stamp.Path}, opts)
	case dnsstamps.StampProtoTypeTLS:
		return newDoT(&url.URL{Scheme: "tls", Host: stamp.ProviderName}, opts)
	default:
		return nil, fmt.Errorf("unsupported stamp protocol %v", stamp.Proto)
	}
}

// Use memoized dialer per URL for repeat upstreams.
// Only do this for upstreams that are instantiated frequently!
type memoDialer struct {
	init DialerInitializer
	once sync.Once
	h    bootstrap.DialHandler
	err  error
}
func (md *memoDialer) Handler() (bootstrap.DialHandler, error) {
	md.once.Do(func() {
		md.h, md.err = md.init()
	})
	return md.h, md.err
}

func addPort(u *url.URL, port uint16) {
	if u != nil {
		if _, _, err := net.SplitHostPort(u.Host); err != nil {
			u.Host = netutil.JoinHostPort(u.Host, port)
		}
	}
}

func logBegin(l *slog.Logger, addr string, n network, req *dns.Msg) {
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		return
	}
	var qtype dns.Type
	var qname string
	if len(req.Question) != 0 {
		qtype = dns.Type(req.Question[0].Qtype)
		qname = req.Question[0].Name
	}
	l.Debug("sending request", "addr", addr, "proto", n, "qtype", qtype, "qname", qname)
}
func logFinish(l *slog.Logger, addr string, n network, err error) {
	if !l.Enabled(context.Background(), slog.LevelDebug) && err == nil {
		return
	}
	lvl := slog.LevelDebug
	status := "ok"
	if err != nil {
		status = err.Error()
		if isTimeout(err) {
			lvl = slog.LevelError
		}
	}
	l.Log(context.TODO(), lvl, "response received", "addr", addr, "proto", n, "status", status)
}
func isTimeout(err error) bool {
	var netErr net.Error
	switch {
	case
		errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, os.ErrDeadlineExceeded):
		return true
	case errors.As(err, &netErr):
		return netErr.Timeout()
	default:
		return false
	}
}

type DialerInitializer func() (handler bootstrap.DialHandler, err error)

func newDialerInitializer(u *url.URL, opts *Options) DialerInitializer {
	l := opts.Logger
	if l == nil {
		l = slog.Default()
	}
	if u == nil {
		panic("nil url")
	}
	if netutil.IsValidIPPortString(u.Host) {
		handler := bootstrap.NewDialContext(opts.Timeout, l, u.Host)
		return func() (bootstrap.DialHandler, error) {
			return handler, nil
		}
	}
	boot := opts.Bootstrap
	if boot == nil {
		boot = net.DefaultResolver
	}
	return func() (bootstrap.DialHandler, error) {
		return bootstrap.ResolveDialContext(u, opts.Timeout, boot, opts.PreferIPv6, l)
	}
}
