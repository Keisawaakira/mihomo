package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type packetSender struct {
	ctx    context.Context
	cancel context.CancelFunc
	ch     chan C.PacketAdapter

	// destination NAT mapping
	originToTarget map[string]netip.Addr
	targetToOrigin map[netip.Addr]netip.Addr
	mappingMutex   sync.RWMutex
}

// newPacketSender return a chan based C.PacketSender
// It ensures that packets can be sent sequentially and without blocking
func newPacketSender() C.PacketSender {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan C.PacketAdapter, senderCapacity)
	return &packetSender{
		ctx:    ctx,
		cancel: cancel,
		ch:     ch,

		originToTarget: make(map[string]netip.Addr),
		targetToOrigin: make(map[netip.Addr]netip.Addr),
	}
}

func (s *packetSender) AddMapping(originMetadata *C.Metadata, metadata *C.Metadata) {
	s.mappingMutex.Lock()
	defer s.mappingMutex.Unlock()
	originKey := originMetadata.String()
	originAddr := originMetadata.DstIP
	targetAddr := metadata.DstIP
	if addr := s.originToTarget[originKey]; !addr.IsValid() { // overwrite only if the record is illegal
		s.originToTarget[originKey] = targetAddr
	}
	if addr := s.targetToOrigin[targetAddr]; !addr.IsValid() { // overwrite only if the record is illegal
		s.targetToOrigin[targetAddr] = originAddr
	}
}

func (s *packetSender) RestoreReadFrom(addr netip.Addr) netip.Addr {
	s.mappingMutex.RLock()
	defer s.mappingMutex.RUnlock()
	if originAddr := s.targetToOrigin[addr]; originAddr.IsValid() {
		return originAddr
	}
	return addr
}

func (s *packetSender) processPacket(pc C.PacketConn, packet C.PacketAdapter) {
	defer packet.Drop()
	metadata := packet.Metadata()

	var addr *net.UDPAddr

	s.mappingMutex.RLock()
	targetAddr := s.originToTarget[metadata.String()]
	s.mappingMutex.RUnlock()

	if targetAddr.IsValid() {
		addr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetAddr, metadata.DstPort))
	}

	if addr == nil {
		originMetadata := metadata  // save origin metadata
		metadata = metadata.Clone() // don't modify PacketAdapter's metadata

		_ = preHandleMetadata(metadata) // error was pre-checked
		metadata = metadata.Pure()
		if metadata.Host != "" {
			// TODO: ResolveUDP may take a long time to block the Process loop
			//       but we want keep sequence sending so can't open a new goroutine
			if err := pc.ResolveUDP(s.ctx, metadata); err != nil {
				log.Warnln("[UDP] Resolve Ip error: %s", err)
				return
			}
		}

		if !metadata.DstIP.IsValid() {
			log.Warnln("[UDP] Destination ip not valid: %#v", metadata)
			return
		}
		s.AddMapping(originMetadata, metadata)
		addr = metadata.UDPAddr()
	}
	_ = handleUDPToRemote(packet, pc, addr)
}

func (s *packetSender) Process(pc C.PacketConn, proxy C.WriteBackProxy) {
	for {
		select {
		case <-s.ctx.Done():
			return // sender closed
		case packet := <-s.ch:
			if proxy != nil {
				proxy.UpdateWriteBack(packet)
			}
			s.processPacket(pc, packet)
		}
	}
}

func (s *packetSender) dropAll() {
	for {
		select {
		case data := <-s.ch:
			data.Drop() // drop all data still in chan
		default:
			return // no data, exit goroutine
		}
	}
}

func (s *packetSender) Send(packet C.PacketAdapter) {
	select {
	case <-s.ctx.Done():
		packet.Drop() // sender closed before Send()
		return
	default:
	}

	select {
	case s.ch <- packet:
		// put ok, so don't drop packet, will process by other side of chan
	case <-s.ctx.Done():
		packet.Drop() // sender closed when putting data to chan
	default:
		packet.Drop() // chan is full
	}
}

func (s *packetSender) Close() {
	s.cancel()
	s.dropAll()
}

func (s *packetSender) DoSniff(metadata *C.Metadata) error { return nil }

func handleUDPToRemote(packet C.UDPPacket, pc C.PacketConn, addr *net.UDPAddr) error {
	if addr == nil {
		return errors.New("udp addr invalid")
	}

	if _, err := pc.WriteTo(packet.Data(), addr); err != nil {
		return err
	}
	// reset timeout
	_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))

	return nil
}

func handleUDPToLocal(writeBack C.WriteBack, pc C.PacketConn, sender C.PacketSender, key string, oAddrPort netip.AddrPort) {
	defer func() {
		sender.Close()
		_ = pc.Close()
		closeAllLocalCoon(key)
		natTable.Delete(key)
	}()

	for {
		_ = pc.SetReadDeadline(time.Now().Add(udpTimeout))
		data, put, from, err := pc.WaitReadFrom()
		if err != nil {
			return
		}

		fromUDPAddr, isUDPAddr := from.(*net.UDPAddr)
		if !isUDPAddr {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a [%T](%s) which isn't a *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", from, from, oAddrPort)
		} else if fromUDPAddr == nil {
			fromUDPAddr = net.UDPAddrFromAddrPort(oAddrPort) // oAddrPort was Unmapped
			log.Warnln("server return a nil *net.UDPAddr, force replace to (%s), this may be caused by a wrongly implemented server", oAddrPort)
		}

		fromAddrPort := fromUDPAddr.AddrPort()
		fromAddr := fromAddrPort.Addr().Unmap()

		// restore DestinationNAT
		fromAddr = sender.RestoreReadFrom(fromAddr).Unmap()

		fromAddrPort = netip.AddrPortFrom(fromAddr, fromAddrPort.Port())

		_, err = writeBack.WriteBack(data, net.UDPAddrFromAddrPort(fromAddrPort))
		if put != nil {
			put()
		}
		if err != nil {
			return
		}
	}
}

func closeAllLocalCoon(lAddr string) {
	natTable.RangeForLocalConn(lAddr, func(key string, value *net.UDPConn) bool {
		conn := value

		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", lAddr, key)
		return true
	})
}

func handleSocket(inbound, outbound net.Conn) {
	N.Relay(inbound, outbound)
}

const relayTraceAliveAfter = 5 * time.Second

var relayTraceID uint64

type relayTraceSnapshot struct {
	traceID               uint64
	startedAt             time.Time
	lastProgressAt        time.Time
	lastProgressDirection string
	lastUploadAt          time.Time
	lastDownloadAt        time.Time
	age                   time.Duration
	idleFor               time.Duration
	uploadIdleFor         time.Duration
	downloadIdleFor       time.Duration
	uploadBytes           int64
	downloadBytes         int64
	inboundLocal          string
	inboundRemote         string
	outboundLocal         string
	outboundRemote        string
}

type relayCopyResult struct {
	direction   string
	bytes       int64
	readBytes   int64
	writeBytes  int64
	err         error
	errSource   string
	readErr     error
	writeErr    error
	closeErr    error
	closeAction string
	duration    time.Duration
}

type relayTraceResult struct {
	firstDirection      string
	forceClosedAfterErr bool
	upload              relayCopyResult
	download            relayCopyResult
	duration            time.Duration
	finalSnapshot       relayTraceSnapshot
}

type relayTraceState struct {
	traceID              uint64
	startedAt            time.Time
	uploadBytes          int64
	downloadBytes        int64
	lastUploadProgress   int64
	lastDownloadProgress int64
	inboundLocal         string
	inboundRemote        string
	outboundLocal        string
	outboundRemote       string
}

func newRelayTraceState(inbound, outbound net.Conn) *relayTraceState {
	now := time.Now()
	lastProgress := now.UnixNano()
	return &relayTraceState{
		traceID:              atomic.AddUint64(&relayTraceID, 1),
		startedAt:            now,
		lastUploadProgress:   lastProgress,
		lastDownloadProgress: lastProgress,
		inboundLocal:         netAddrString(inbound.LocalAddr()),
		inboundRemote:        netAddrString(inbound.RemoteAddr()),
		outboundLocal:        netAddrString(outbound.LocalAddr()),
		outboundRemote:       netAddrString(outbound.RemoteAddr()),
	}
}

func (s *relayTraceState) snapshot(now time.Time) relayTraceSnapshot {
	uploadLast := time.Unix(0, atomic.LoadInt64(&s.lastUploadProgress))
	downloadLast := time.Unix(0, atomic.LoadInt64(&s.lastDownloadProgress))
	lastProgress := uploadLast
	lastProgressDirection := "upload"
	if downloadLast.After(lastProgress) {
		lastProgress = downloadLast
		lastProgressDirection = "download"
	} else if downloadLast.Equal(uploadLast) {
		lastProgressDirection = "both"
	}
	return relayTraceSnapshot{
		traceID:               s.traceID,
		startedAt:             s.startedAt,
		lastProgressAt:        lastProgress,
		lastProgressDirection: lastProgressDirection,
		lastUploadAt:          uploadLast,
		lastDownloadAt:        downloadLast,
		age:                   now.Sub(s.startedAt),
		idleFor:               now.Sub(lastProgress),
		uploadIdleFor:         now.Sub(uploadLast),
		downloadIdleFor:       now.Sub(downloadLast),
		uploadBytes:           atomic.LoadInt64(&s.uploadBytes),
		downloadBytes:         atomic.LoadInt64(&s.downloadBytes),
		inboundLocal:          s.inboundLocal,
		inboundRemote:         s.inboundRemote,
		outboundLocal:         s.outboundLocal,
		outboundRemote:        s.outboundRemote,
	}
}

func handleSocketTrace(inbound, outbound net.Conn, watchdog func(relayTraceSnapshot)) relayTraceResult {
	state := newRelayTraceState(inbound, outbound)
	defer func() {
		_ = inbound.Close()
		_ = outbound.Close()
	}()

	stopWatchdog := make(chan struct{})
	if watchdog != nil {
		go watchRelayTrace(state, stopWatchdog, watchdog)
		defer close(stopWatchdog)
	}

	resultCh := make(chan relayCopyResult, 2)
	go traceSocketCopy("download", inbound, outbound, &state.downloadBytes, &state.lastDownloadProgress, resultCh)
	go traceSocketCopy("upload", outbound, inbound, &state.uploadBytes, &state.lastUploadProgress, resultCh)

	first := <-resultCh
	forceClosedAfterErr := first.err != nil || first.closeErr != nil
	if forceClosedAfterErr {
		_ = inbound.Close()
		_ = outbound.Close()
	}
	second := <-resultCh

	result := relayTraceResult{
		firstDirection:      first.direction,
		forceClosedAfterErr: forceClosedAfterErr,
		duration:            time.Since(state.startedAt),
		finalSnapshot:       state.snapshot(time.Now()),
	}
	result.set(first)
	result.set(second)
	return result
}

func watchRelayTrace(state *relayTraceState, stop <-chan struct{}, watchdog func(relayTraceSnapshot)) {
	ticker := time.NewTicker(relayTraceAliveAfter)
	defer ticker.Stop()

	for {
		select {
		case now := <-ticker.C:
			watchdog(state.snapshot(now))
		case <-stop:
			return
		}
	}
}

func (r *relayTraceResult) set(result relayCopyResult) {
	switch result.direction {
	case "upload":
		r.upload = result
	case "download":
		r.download = result
	}
}

func traceSocketCopy(direction string, dst, src net.Conn, counter *int64, lastProgress *int64, resultCh chan<- relayCopyResult) {
	startedAt := time.Now()
	readFrom, writeTo := relayDirectionEndpoints(direction)
	readBytes, writeBytes, readErr, writeErr := copySocketWithTrace(dst, src, counter, lastProgress)
	err := readErr
	errSource := ""
	if writeErr != nil {
		err = writeErr
		errSource = "write_" + writeTo
	} else if readErr != nil {
		errSource = "read_" + readFrom
	}
	var closeErr error
	closeAction := "close_write"
	if err == nil {
		closeErr = closeWriteConn(dst)
	} else {
		closeAction = "close"
		closeErr = dst.Close()
	}
	resultCh <- relayCopyResult{
		direction:   direction,
		bytes:       readBytes,
		readBytes:   readBytes,
		writeBytes:  writeBytes,
		err:         err,
		errSource:   errSource,
		readErr:     readErr,
		writeErr:    writeErr,
		closeErr:    closeErr,
		closeAction: closeAction,
		duration:    time.Since(startedAt),
	}
}

func copySocketWithTrace(dst, src net.Conn, counter *int64, lastProgress *int64) (readBytes int64, writeBytes int64, readErr error, writeErr error) {
	buffer := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buffer)
		if nr > 0 {
			readBytes += int64(nr)
			atomic.AddInt64(counter, int64(nr))
			atomic.StoreInt64(lastProgress, time.Now().UnixNano())
			nw, ew := writeFull(dst, buffer[:nr])
			writeBytes += int64(nw)
			if ew != nil {
				writeErr = ew
				return
			}
			if nw != nr {
				writeErr = io.ErrShortWrite
				return
			}
		}
		if er != nil {
			if er != io.EOF {
				readErr = er
			}
			return
		}
	}
}

func writeFull(dst net.Conn, payload []byte) (written int, err error) {
	for written < len(payload) {
		n, writeErr := dst.Write(payload[written:])
		if n > 0 {
			written += n
		}
		if writeErr != nil {
			return written, writeErr
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func relayDirectionEndpoints(direction string) (readFrom string, writeTo string) {
	if direction == "upload" {
		return "inbound", "outbound"
	}
	return "outbound", "inbound"
}

func closeWriteConn(conn net.Conn) error {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return conn.Close()
}

func netAddrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}
