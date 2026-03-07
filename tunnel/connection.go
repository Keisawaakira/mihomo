package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/sing/common/bufio"
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
		metadata := packet.Metadata()
		log.Warnln("[UDP] sender channel full, drop packet: %s --> %s, process=%s, host=%s", metadata.SourceDetail(), metadata.RemoteAddress(), metadata.Process, metadata.Host)
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


func handleSocket(metadata *C.Metadata, inbound, outbound net.Conn) {
	defer func() {
		_ = inbound.Close()
		_ = outbound.Close()
	}()

	ch := make(chan error, 1)
	go func() {
		ch <- relay(metadata, "download", inbound, outbound)
	}()

	_ = relay(metadata, "upload", outbound, inbound)
	<-ch
}

func relay(metadata *C.Metadata, direction string, writer net.Conn, reader net.Conn) error {
	startedAt := time.Now()
	written, err := bufio.Copy(writer, reader)
	if err == nil {
		_, closeErr := closeWrite(writer)
		_ = closeErr
		return nil
	}

	closeResult := softCloseRelaySide(writer)
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		duration := time.Since(startedAt).Round(time.Millisecond)
		log.Warnln(
			"[TCP] relay %s error after %d bytes in %s: %s (%s --> %s, process=%s, host=%s, close_write=%t, close_write_target=%T, close_write_err=%v, close_read=%t, close_read_target=%T, close_read_err=%v, hard_close=%t, hard_close_err=%v, writer_type=%T, reader_type=%T)",
			direction,
			written,
			duration,
			err.Error(),
			metadata.SourceDetail(),
			metadata.RemoteAddress(),
			metadata.Process,
			metadata.Host,
			closeResult.closeWrite,
			closeResult.closeWriteTarget,
			closeResult.closeWriteErr,
			closeResult.closeRead,
			closeResult.closeReadTarget,
			closeResult.closeReadErr,
			closeResult.hardClose,
			closeResult.hardCloseErr,
			writer,
			reader,
		)
	}
	return err
}

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

type upstreamer interface {
	Upstream() any
}

type relayCloseResult struct {
	closeWrite       bool
	closeWriteTarget any
	closeWriteErr    error
	closeRead        bool
	closeReadTarget  any
	closeReadErr     error
	hardClose        bool
	hardCloseErr     error
}

func softCloseRelaySide(conn net.Conn) relayCloseResult {
	var result relayCloseResult
	if writeCloser, ok := unwrapCloseWriter(conn); ok {
		result.closeWrite = true
		result.closeWriteTarget = writeCloser
		result.closeWriteErr = writeCloser.CloseWrite()
	}
	if readCloser, ok := unwrapCloseReader(conn); ok {
		result.closeRead = true
		result.closeReadTarget = readCloser
		result.closeReadErr = readCloser.CloseRead()
		return result
	}
	if !result.closeWrite {
		result.hardClose = true
		result.hardCloseErr = conn.Close()
	}
	return result
}

func closeWrite(conn net.Conn) (bool, error) {
	if writeCloser, ok := unwrapCloseWriter(conn); ok {
		return false, writeCloser.CloseWrite()
	}
	return true, conn.Close()
}

func unwrapCloseWriter(conn any) (closeWriter, bool) {
	for i := 0; i < 16 && conn != nil; i++ {
		if writeCloser, ok := conn.(closeWriter); ok {
			return writeCloser, true
		}
		if upstream, ok := conn.(upstreamer); ok {
			next := upstream.Upstream()
			if next != nil && next != conn {
				conn = next
				continue
			}
		}
		return nil, false
	}
	return nil, false
}

func unwrapCloseReader(conn any) (closeReader, bool) {
	for i := 0; i < 16 && conn != nil; i++ {
		if readCloser, ok := conn.(closeReader); ok {
			return readCloser, true
		}
		if upstream, ok := conn.(upstreamer); ok {
			next := upstream.Upstream()
			if next != nil && next != conn {
				conn = next
				continue
			}
		}
		return nil, false
	}
	return nil, false
}
