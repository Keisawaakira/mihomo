package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type Direct struct {
	*Base
	loopBack *loopback.Detector
}

type DirectOption struct {
	BasicOption
	Name string `proxy:"name"`
}

const (
	directLiteralIPv6FastFailTimeout = 1500 * time.Millisecond
	directLiteralIPv6LogInterval     = 30 * time.Second
)

type directLiteralIPv6TimeoutWindow struct {
	lastLog time.Time
	count   int
}

var (
	directLiteralIPv6TimeoutsMu sync.Mutex
	directLiteralIPv6Timeouts   = map[string]directLiteralIPv6TimeoutWindow{}
)

// DialContext implements C.ProxyAdapter
func (d *Direct) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := d.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	opts := d.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	dialCtx := ctx
	if shouldFastFailDirectLiteralIPv6(metadata) {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, directLiteralIPv6FastFailTimeout)
		defer cancel()
	}
	c, err := dialer.DialContext(dialCtx, "tcp", metadata.RemoteAddress(), opts...)
	if err != nil && shouldTraceDirectLiteralIPv6Timeout(metadata, err) {
		logDirectLiteralIPv6Timeout(metadata, err)
	}
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewConn(NewConn(c, d)), nil
}

// ListenPacketContext implements C.ProxyAdapter
func (d *Direct) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := d.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := d.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := dialer.NewDialer(d.DialOptions()...).ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return d.loopBack.NewPacketConn(NewPacketConn(pc, d)), nil
}

func (d *Direct) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || resolver.DirectHostResolver != resolver.DefaultResolver) && metadata.Host != "" {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, d.prefer, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (d *Direct) IsL3Protocol(metadata *C.Metadata) bool {
	return true // tell DNSDialer don't send domain to DialContext, avoid lookback to DefaultResolver
}

func NewDirectWithOption(option DirectOption) *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Type:         C.Direct,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewDirect() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "DIRECT",
			Type:   C.Direct,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func NewCompatible() *Direct {
	return &Direct{
		Base: NewBase(BaseOption{
			Name:   "COMPATIBLE",
			Type:   C.Compatible,
			UDP:    true,
			Prefer: C.DualStack,
		}),
		loopBack: loopback.NewDetector(),
	}
}

func shouldFastFailDirectLiteralIPv6(metadata *C.Metadata) bool {
	if metadata == nil {
		return false
	}
	if !metadata.DstIP.IsValid() || !metadata.DstIP.Is6() {
		return false
	}
	if metadata.Host != "" {
		return false
	}
	return true
}

func shouldTraceDirectLiteralIPv6Timeout(metadata *C.Metadata, err error) bool {
	if !shouldFastFailDirectLiteralIPv6(metadata) || err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

func currentInterfaceHint(destination netip.Addr) string {
	finder := dialer.DefaultInterfaceFinder.Load()
	if finder == nil || !destination.IsValid() {
		return ""
	}
	return finder.FindInterfaceName(destination)
}

func logDirectLiteralIPv6Timeout(metadata *C.Metadata, err error) {
	prefix := prefix64(metadata.DstIP)
	ifaceName := currentInterfaceHint(metadata.DstIP)
	key := prefix + "|" + ifaceName
	now := time.Now()
	directLiteralIPv6TimeoutsMu.Lock()
	window := directLiteralIPv6Timeouts[key]
	window.count++
	if now.Sub(window.lastLog) < directLiteralIPv6LogInterval {
		directLiteralIPv6Timeouts[key] = window
		directLiteralIPv6TimeoutsMu.Unlock()
		return
	}
	count := window.count
	window.lastLog = now
	window.count = 0
	directLiteralIPv6Timeouts[key] = window
	directLiteralIPv6TimeoutsMu.Unlock()
	log.Warnln("[DirectIPv6] timeout process=%s path=%s remote=%s dst_ip=%s prefix64=%s interface=%s fast_fail=%s count=%d err=%s", metadata.Process, metadata.ProcessPath, metadata.RemoteAddress(), metadata.DstIP, prefix, ifaceName, directLiteralIPv6FastFailTimeout, count, err.Error())
}

func prefix64(addr netip.Addr) string {
	if !addr.IsValid() || !addr.Is6() {
		return ""
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ""
	}
	return prefix.String()
}
